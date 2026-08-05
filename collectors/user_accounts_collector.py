"""
user_accounts_collector.py
==========================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 5.4 (User Accounts and Environment).

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgements. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def _run_cmd(cmd: list[str]) -> tuple[str, str, int]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def _get_login_defs_var(contents: str | None, var: str) -> str | None:
    if not contents:
        return None
    for line in contents.splitlines():
        line = line.strip()
        if line.startswith(var) and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def collect_user_accounts() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 5.4
    (User Accounts and Environment).

    Returns:
        dict: A JSON-serialisable structured dictionary with the following
              top-level keys:
            `shadow_password_suite`
            `root_and_system_accounts`
            `default_user_environment`
            `errors`
    """
    top_errors: list[dict[str, str]] = []

    # ------------------------------------------------------------------
    # 5.4.1 shadow_password_suite
    # ------------------------------------------------------------------
    login_defs_contents = _read_file("/etc/login.defs")
    login_defs = {
        "PASS_MAX_DAYS": _get_login_defs_var(login_defs_contents, "PASS_MAX_DAYS"),
        "PASS_MIN_DAYS": _get_login_defs_var(login_defs_contents, "PASS_MIN_DAYS"),
        "PASS_WARN_AGE": _get_login_defs_var(login_defs_contents, "PASS_WARN_AGE"),
        "ENCRYPT_METHOD": _get_login_defs_var(login_defs_contents, "ENCRYPT_METHOD")
    }

    useradd_out, _, _ = _run_cmd(["useradd", "-D"])
    useradd_inactive: str | None = None
    for line in useradd_out.splitlines():
        line = line.strip()
        if line.startswith("INACTIVE="):
            parts = line.split("=")
            if len(parts) > 1:
                useradd_inactive = parts[1]
            break

    pam_unix_hashing: str | None = None
    pam_common_password = _read_file("/etc/pam.d/common-password")
    if pam_common_password:
        for line in pam_common_password.splitlines():
            line = line.strip()
            if not line.startswith("#") and "pam_unix.so" in line:
                pam_unix_hashing = " ".join(line.split())
                break

    user_chage_info = []
    if os.geteuid() != 0:
        top_errors.append({
            "check": "shadow_read",
            "error": "Not running as root — /etc/shadow is unreadable. "
                     "Password aging data will be missing from the report.",
        })
        shadow_contents = None
    else:
        shadow_contents = _read_file("/etc/shadow")
    shadow_users = []
    if shadow_contents:
        for line in shadow_contents.splitlines():
            parts = line.split(":")
            if len(parts) >= 1:
                shadow_users.append(parts[0])

    for user in shadow_users:
        user = user.strip()
        if not user:
            continue
        chage_out, _, rc = _run_cmd(["chage", "-l", user])
        if rc == 0:
            chage_dict: dict[str, str | None] = {
                "user": user,
                "pass_max_days": None,
                "pass_min_days": None,
                "pass_warn_days": None,
                "account_inactive": None,
                "last_password_change": None
            }
            for line in chage_out.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "maximum number of days between password change":
                        chage_dict["pass_max_days"] = val
                    elif key == "minimum number of days between password change":
                        chage_dict["pass_min_days"] = val
                    elif key == "number of days of warning before password expires":
                        chage_dict["pass_warn_days"] = val
                    elif key == "password inactive":
                        chage_dict["account_inactive"] = val
                    elif key == "last password change":
                        chage_dict["last_password_change"] = val
            user_chage_info.append(chage_dict)

    shadow_password_suite = {
        "login_defs": login_defs,
        "pam_unix_hashing": pam_unix_hashing,
        "useradd_inactive": useradd_inactive,
        "user_chage_info": user_chage_info,
        "errors": []
    }

    # ------------------------------------------------------------------
    # 5.4.2 root_and_system_accounts
    # ------------------------------------------------------------------
    uid_0_accounts = []
    system_accounts = []
    passwd_contents = _read_file("/etc/passwd")
    if passwd_contents:
        for line in passwd_contents.splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                username = parts[0]
                uid_str = parts[2]
                shell = parts[6]
                if uid_str == "0":
                    uid_0_accounts.append(username)
                elif uid_str.isdigit() and int(uid_str) < 1000 and username != "root":
                    system_accounts.append({
                        "user": username,
                        "uid": int(uid_str),
                        "shell": shell,
                        "passwd_status": None
                    })

    # Add shadow password status for system accounts where possible
    for sys_acc in system_accounts:
        p_out, _, rc = _run_cmd(["passwd", "-S", sys_acc["user"]])
        if rc == 0 and p_out:
            parts = p_out.split()
            sys_acc["passwd_status"] = parts[1] if len(parts) >= 2 else None

    gid_0_groups = []
    primary_gid_0_accounts = []
    group_contents = _read_file("/etc/group")
    if group_contents:
        for line in group_contents.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                grp_name, gid_str = parts[0], parts[2]
                if gid_str == "0":
                    gid_0_groups.append(grp_name)

    if passwd_contents:
        for line in passwd_contents.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                username, gid_str = parts[0], parts[3]
                if gid_str == "0":
                    primary_gid_0_accounts.append(username)

    root_shadow_password_status = None
    if shadow_contents:
        for line in shadow_contents.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[0] == "root":
                root_shadow_password_status = parts[1]
                break

    securetty_exists = os.path.exists("/etc/securetty")
    securetty_contents = _read_file("/etc/securetty") if securetty_exists else None

    root_path_files = ["/root/.bash_profile", "/root/.bashrc", "/etc/profile", "/etc/bash.bashrc"]
    root_umask = {}
    for rpf in root_path_files:
        rpf_contents = _read_file(rpf)
        umask_val = None
        if rpf_contents:
            for line in rpf_contents.splitlines():
                line = line.strip()
                if line.startswith("umask ") and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) > 1:
                        umask_val = parts[1]
        root_umask[rpf] = umask_val

    root_umask["/etc/login.defs"] = _get_login_defs_var(login_defs_contents, "UMASK")

    root_and_system_accounts = {
        "uid_0_accounts": uid_0_accounts,
        "primary_gid_0_accounts": primary_gid_0_accounts,
        "gid_0_groups": gid_0_groups,
        "root_shadow_password_status": root_shadow_password_status,
        "securetty_exists": securetty_exists,
        "securetty_contents": securetty_contents,
        "root_umask": root_umask,
        "system_accounts": system_accounts,
        "root_path": None,
        "errors": []
    }

    if os.geteuid() == 0:
        p_out, _, rc = _run_cmd(["su", "-", "root", "-c", "echo $PATH"])
        if rc == 0 and p_out:
            root_and_system_accounts["root_path"] = p_out.strip()

    # ------------------------------------------------------------------
    # 5.4.3 default_user_environment
    # ------------------------------------------------------------------
    shells_contents = _read_file("/etc/shells")
    shells_lines = []
    nologin_in_shells = False
    if shells_contents:
        for line in shells_contents.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                shells_lines.append(line)
                if "nologin" in line:
                    nologin_in_shells = True

    tmout_settings: dict[str, list[str]] = {
        "/etc/profile": [],
        "/etc/profile.d": [],
        "/etc/bash.bashrc": []
    }

    def _extract_tmout(content: str | None) -> list[str]:
        found = []
        if content:
            for l in content.splitlines():
                l = l.strip()
                if not l.startswith("#"):
                    if "TMOUT=" in l or "readonly TMOUT" in l or "export TMOUT" in l:
                        found.append(l)
        return found

    tmout_settings["/etc/profile"] = _extract_tmout(_read_file("/etc/profile"))
    tmout_settings["/etc/bash.bashrc"] = _extract_tmout(_read_file("/etc/bash.bashrc"))
    
    if os.path.exists("/etc/profile.d"):
        try:
            for f in os.listdir("/etc/profile.d"):
                if f.endswith(".sh"):
                    p = os.path.join("/etc/profile.d", f)
                    tmout_settings["/etc/profile.d"].extend(_extract_tmout(_read_file(p)))
        except Exception as e:
            top_errors.append({"check": "/etc/profile.d scan", "error": str(e)})

    pam_umask = None
    common_session = _read_file("/etc/pam.d/common-session")
    if common_session:
        for line in common_session.splitlines():
            line = line.strip()
            if not line.startswith("#") and "pam_umask.so" in line:
                pam_umask = line
                break

    default_user_umask_dict = {
        "login_defs": _get_login_defs_var(login_defs_contents, "UMASK"),
        "profile": root_umask.get("/etc/profile"),
        "bash_bashrc": root_umask.get("/etc/bash.bashrc"),
        "pam_umask": pam_umask
    }

    default_user_environment = {
        "nologin_in_shells": nologin_in_shells,
        "shells_file_contents": shells_lines,
        "tmout_settings": tmout_settings,
        "default_user_umask": default_user_umask_dict,
        "errors": []
    }

    # ------------------------------------------------------------------
    # 7.2 local_users_and_groups_evidence
    # ------------------------------------------------------------------
    orphan_gids_in_passwd = []
    shadow_group_members = []
    duplicate_uids_dict = {}
    duplicate_gids_dict = {}
    duplicate_usernames_dict = {}
    duplicate_groupnames_dict = {}
    home_directory_issues = []
    dotfile_permission_issues = []

    # 1. Parse /etc/group for GIDs and names
    all_gids = set()
    gid_to_names = {}
    name_to_gids = {}
    if group_contents:
        for line in group_contents.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 4:
                gname = parts[0]
                gid = parts[2]
                members = parts[3]
                all_gids.add(gid)
                
                if gname == "shadow" or gid == "42":
                    for m in members.split(","):
                        if m.strip():
                            shadow_group_members.append(m.strip())
                            
                gid_to_names.setdefault(gid, []).append(gname)
                name_to_gids.setdefault(gname, []).append(gid)

    for gid, names in gid_to_names.items():
        if len(names) > 1:
            duplicate_gids_dict[gid] = names
    for gname, gids in name_to_gids.items():
        if len(gids) > 1:
            duplicate_groupnames_dict[gname] = gids

    # 2. Parse /etc/passwd for UIDs, names, orphans, and home directories
    uid_to_names = {}
    name_to_uids = {}
    if passwd_contents:
        for line in passwd_contents.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                uname = parts[0]
                uid = parts[2]
                gid = parts[3]
                homedir = parts[5]
                shell = parts[6]
                
                uid_to_names.setdefault(uid, []).append(uname)
                name_to_uids.setdefault(uname, []).append(uid)
                
                if gid not in all_gids:
                    orphan_gids_in_passwd.append({"user": uname, "missing_gid": gid})
                
                # Check interactive users
                is_interactive = False
                if shell.endswith("/bash") or shell.endswith("/sh") or shell.endswith("/zsh"):
                    is_interactive = True
                    
                if is_interactive:
                    if not os.path.isdir(homedir):
                        home_directory_issues.append({"user": uname, "home": homedir, "issue": "Does not exist or not a directory"})
                    else:
                        try:
                            # Also check dotfiles. Use os.lstat to avoid following symlinks blindly if they point outside? 
                            # os.listdir is fine for local check.
                            for f in os.listdir(homedir):
                                if f.startswith("."):
                                    fpath = os.path.join(homedir, f)
                                    if os.path.isfile(fpath):
                                        st = os.stat(fpath)
                                        mode_oct = oct(st.st_mode)[-4:]
                                        issues = []
                                        if st.st_mode & 0o022:  # group or other writable
                                            issues.append(f"Excessive permissions: {mode_oct}")
                                        if str(st.st_uid) != uid:
                                            issues.append(f"Not owned by user (uid {st.st_uid} vs expected {uid})")
                                        if issues:
                                            dotfile_permission_issues.append({
                                                "user": uname, "file": fpath, "issues": issues
                                            })
                        except Exception as e:
                            home_directory_issues.append({"user": uname, "home": homedir, "issue": f"Access error: {e}"})

    for uid, names in uid_to_names.items():
        if len(names) > 1:
            duplicate_uids_dict[uid] = names
    for uname, uids in name_to_uids.items():
        if len(uids) > 1:
            duplicate_usernames_dict[uname] = uids

    local_users_and_groups_evidence = {
        "orphan_gids_in_passwd": orphan_gids_in_passwd,
        "shadow_group_members": shadow_group_members,
        "duplicate_uids": duplicate_uids_dict,
        "duplicate_gids": duplicate_gids_dict,
        "duplicate_usernames": duplicate_usernames_dict,
        "duplicate_groupnames": duplicate_groupnames_dict,
        "home_directory_issues": home_directory_issues,
        "dotfile_permission_issues": dotfile_permission_issues
    }

    return {
        "shadow_password_suite": shadow_password_suite,
        "root_and_system_accounts": root_and_system_accounts,
        "default_user_environment": default_user_environment,
        "local_users_and_groups_evidence": local_users_and_groups_evidence,
        "errors": top_errors
    }


if __name__ == "__main__":
    print(json.dumps(collect_user_accounts()))
