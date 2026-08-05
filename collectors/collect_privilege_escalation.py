"""
collect_privilege_escalation.py
================================
Collector for SENTINEL to gather raw configuration data for auditing CIS
Ubuntu 24.04 Benchmark section 5.2 (privilege escalation via sudo).
"""

from __future__ import annotations

import os
import re
import subprocess
import pwd
from typing import Any


def collect_privilege_escalation() -> dict:
    """
    Collects raw configuration data required to audit CIS Ubuntu 24.04 Benchmark
    section 5.2 (privilege escalation via sudo).

    Returns:
        dict: A JSON-serializable structured dictionary containing collected details.
    """
    errors: list[dict[str, str]] = []

    # 1. Check if Sudo is installed
    sudo_installed = {
        "installed": False,
        "version_output": None,
        "dpkg_status": None,
    }

    # Query sudo version
    try:
        res_v = subprocess.run(["sudo", "-V"], capture_output=True, text=True, timeout=5)
        if res_v.returncode == 0 or res_v.stdout or res_v.stderr:
            sudo_installed["installed"] = True
            out = (res_v.stdout or res_v.stderr).strip()
            if out:
                sudo_installed["version_output"] = out.splitlines()[0]
    except FileNotFoundError:
        # Sudo not in PATH
        pass
    except Exception as e:
        errors.append({"check": "sudo_version", "error": str(e)})

    # Query dpkg status for sudo
    try:
        res_dpkg = subprocess.run(["dpkg", "-l", "sudo"], capture_output=True, text=True, timeout=5)
        if res_dpkg.returncode == 0:
            for line in res_dpkg.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "sudo":
                    sudo_installed["dpkg_status"] = line
                    break
    except FileNotFoundError:
        # dpkg command not available
        pass
    except Exception as e:
        errors.append({"check": "dpkg_sudo", "error": str(e)})

    # 2. Identify sudoers files to scan
    sudoers_files_scanned: list[str] = []
    files_to_scan = ["/etc/sudoers"]
    sudoers_d_path = "/etc/sudoers.d"

    if os.path.exists(sudoers_d_path):
        if os.path.isdir(sudoers_d_path):
            try:
                for entry in os.listdir(sudoers_d_path):
                    if entry.startswith(".") or entry.endswith(".bak"):
                        continue
                    full_p = os.path.join(sudoers_d_path, entry)
                    if os.path.isfile(full_p):
                        files_to_scan.append(full_p)
            except Exception as e:
                errors.append({"check": "list_sudoers_d", "error": str(e)})
        else:
            errors.append({"check": "list_sudoers_d", "error": f"{sudoers_d_path} is not a directory"})

    # 3. Read and scan sudoers files
    sudoers_defaults_lines: list[dict[str, Any]] = []
    use_pty_entries: list[dict[str, str]] = []
    logfile_entries: list[dict[str, str]] = []
    nopasswd_entries: list[dict[str, Any]] = []
    noauthenticate_entries: list[dict[str, Any]] = []
    timestamp_timeout_entries: list[dict[str, str]] = []

    logfile_paths: list[str] = []

    for filepath in files_to_scan:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            sudoers_files_scanned.append(filepath)

            for idx, line in enumerate(content.splitlines(), 1):
                # We do not strip the line before regex matches to keep formatting,
                # but we will check match conditions carefully.
                
                # Check Defaults
                if re.match(r"^\s*Defaults\b", line):
                    sudoers_defaults_lines.append({
                        "file": filepath,
                        "line_number": idx,
                        "content": line
                    })

                # Check use_pty
                if "use_pty" in line:
                    use_pty_entries.append({
                        "file": filepath,
                        "content": line
                    })

                # Check logfile=
                if "logfile=" in line:
                    logfile_entries.append({
                        "file": filepath,
                        "content": line
                    })
                    # Extract logfile path(s) from line
                    matches = re.finditer(r"logfile\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s,]+))", line)
                    for m in matches:
                        path = m.group(1) or m.group(2) or m.group(3)
                        if path and path not in logfile_paths:
                            logfile_paths.append(path)

                # Check NOPASSWD
                if "NOPASSWD" in line:
                    nopasswd_entries.append({
                        "file": filepath,
                        "line_number": idx,
                        "content": line
                    })

                # Check !authenticate
                if "!authenticate" in line:
                    noauthenticate_entries.append({
                        "file": filepath,
                        "line_number": idx,
                        "content": line
                    })

                # Check timestamp_timeout=
                if "timestamp_timeout=" in line:
                    timestamp_timeout_entries.append({
                        "file": filepath,
                        "content": line
                    })

        except Exception as e:
            errors.append({"check": f"read_file:{filepath}", "error": str(e)})

    # Check existence and permissions of extracted logfile paths
    logfile_exists_checks = []
    for path in logfile_paths:
        exists = os.path.exists(path)
        permissions = None
        owner = None
        if exists:
            try:
                stat_info = os.stat(path)
                permissions = f"{stat_info.st_mode & 0o7777:o}"
                try:
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                except KeyError:
                    owner = str(stat_info.st_uid)
            except Exception as e:
                errors.append({"check": f"stat_logfile:{path}", "error": str(e)})

        logfile_exists_checks.append({
            "configured_path": path,
            "exists": exists,
            "permissions": permissions,
            "owner": owner,
        })

    # 5. Syslog-based sudo logging detection (CIS 5.2.3 alternative path)
    #    Ubuntu's default sudo package writes to authpriv, captured by rsyslog
    #    into /var/log/auth.log.  Collect evidence so the LLM can evaluate
    #    5.2.3 even when no explicit Defaults logfile= is present.
    sudo_syslog_logging: dict[str, Any] = {
        "auth_log_exists": False,
        "syslog_log_exists": False,
        "rsyslog_authpriv_configured": False,
        "rsyslog_configs_checked": [],
        "syslog_ng_config_exists": False,
        "journald_sudo_evidence": None,
    }

    # Check for common log files
    sudo_syslog_logging["auth_log_exists"] = os.path.exists("/var/log/auth.log")
    sudo_syslog_logging["syslog_log_exists"] = os.path.exists("/var/log/syslog")

    # Scan rsyslog configs for authpriv or auth.* capture rules
    rsyslog_candidates = ["/etc/rsyslog.conf"]
    rsyslog_d_path = "/etc/rsyslog.d"
    if os.path.isdir(rsyslog_d_path):
        try:
            for _e in os.listdir(rsyslog_d_path):
                if _e.endswith(".conf"):
                    rsyslog_candidates.append(os.path.join(rsyslog_d_path, _e))
        except Exception:
            pass

    authpriv_re = re.compile(r"^\s*authpriv|^\s*auth\.\*|^\s*\*\.\*|\bauthpriv\b", re.IGNORECASE)
    for _rpath in rsyslog_candidates:
        if not os.path.isfile(_rpath):
            continue
        sudo_syslog_logging["rsyslog_configs_checked"].append(_rpath)
        try:
            with open(_rpath, "r", encoding="utf-8", errors="replace") as _rf:
                for _rline in _rf:
                    stripped = _rline.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    if authpriv_re.search(stripped):
                        sudo_syslog_logging["rsyslog_authpriv_configured"] = True
                        break
        except Exception as _re_err:
            errors.append({"check": f"read_rsyslog:{_rpath}", "error": str(_re_err)})
        if sudo_syslog_logging["rsyslog_authpriv_configured"]:
            break

    sudo_syslog_logging["syslog_ng_config_exists"] = os.path.isfile("/etc/syslog-ng/syslog-ng.conf")

    # Look for recent sudo entries in the systemd journal
    try:
        _jctl = subprocess.run(
            ["journalctl", "_COMM=sudo", "--no-pager", "-n", "1", "--output=short"],
            capture_output=True, text=True, timeout=5,
        )
        if _jctl.stdout.strip():
            sudo_syslog_logging["journald_sudo_evidence"] = _jctl.stdout.strip().splitlines()[0]
    except Exception:
        pass  # journalctl not available or no entries — not an error

    # 6. Pam su restriction checking
    pam_su_config = None
    pam_wheel_line = None
    pam_su_path = "/etc/pam.d/su"

    try:
        if os.path.exists(pam_su_path):
            with open(pam_su_path, "r", encoding="utf-8", errors="replace") as f:
                pam_su_config = f.read()

            for line in pam_su_config.splitlines():
                if "pam_wheel.so" in line:
                    pam_wheel_line = line.strip()
                    break
    except Exception as e:
        errors.append({"check": f"read_file:{pam_su_path}", "error": str(e)})

    # Retrieve wheel or sudo group membership
    wheel_group_members = None
    wheel_group_source = None

    def _get_group_members(group_name: str) -> list[str] | None:
        try:
            res = subprocess.run(["getent", "group", group_name], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                line = res.stdout.strip()
                if line:
                    parts = line.split(":")
                    if len(parts) >= 4:
                        members_str = parts[3].strip()
                        if members_str:
                            return [m.strip() for m in members_str.split(",") if m.strip()]
                        return []
            return None
        except Exception as ex:
            errors.append({"check": f"getent_group:{group_name}", "error": str(ex)})
            return None

    # Check "sudo" group first
    sudo_members = _get_group_members("sudo")
    if sudo_members is not None:
        wheel_group_source = "sudo"
        wheel_group_members = sudo_members
    else:
        # Check "wheel" group if "sudo" group not present
        wheel_members = _get_group_members("wheel")
        if wheel_members is not None:
            wheel_group_source = "wheel"
            wheel_group_members = wheel_members

    return {
        "sudo_installed": sudo_installed,
        "sudoers_files_scanned": sudoers_files_scanned,
        "sudoers_defaults_lines": sudoers_defaults_lines,
        "use_pty_entries": use_pty_entries,
        "logfile_entries": logfile_entries,
        "logfile_exists_checks": logfile_exists_checks,
        "sudo_syslog_logging": sudo_syslog_logging,
        "nopasswd_entries": nopasswd_entries,
        "noauthenticate_entries": noauthenticate_entries,
        "timestamp_timeout_entries": timestamp_timeout_entries,
        "su_restriction": {
            "pam_su_config": pam_su_config,
            "pam_wheel_line": pam_wheel_line,
            "wheel_group_members": wheel_group_members,
            "wheel_group_source": wheel_group_source,
        },
        "errors": errors,
    }
