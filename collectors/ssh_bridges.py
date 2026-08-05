"""
ssh_bridges.py
==============
SSH-based collector bridges for querying raw target settings.
"""

from __future__ import annotations

import os
import re
import base64
import json
import time
import paramiko
from typing import Any
from tools.ssh_transport import remote_run, remote_run_sudo
from tools.ssh_collector_runner import run_collector_over_ssh


def collect_privilege_escalation_from_ssh(
    ssh: paramiko.SSHClient,
    password: str = "",
) -> dict:
    """
    Collect raw privilege-escalation configuration data over SSH, mirroring the
    structure produced by `collect_privilege_escalation()` in the collectors
    module.
    """
    errors: list[dict] = []

    # 1. sudo installed?
    sudo_version_raw = remote_run(ssh, "sudo -V 2>&1 | head -1")
    dpkg_sudo_raw = remote_run(ssh, "dpkg -l sudo 2>/dev/null | awk '/^ii/ && /sudo/'")

    sudo_installed: dict = {
        "installed": bool(sudo_version_raw.strip()),
        "version_output": sudo_version_raw.strip() or None,
        "dpkg_status": dpkg_sudo_raw.strip() or None,
    }

    # 2. Discover sudoers files
    files_to_scan = ["/etc/sudoers"]
    sudoers_d_listing = remote_run_sudo(
        ssh,
        "ls /etc/sudoers.d/ 2>/dev/null",
        password,
    ).strip()
    if sudoers_d_listing:
        for entry in sudoers_d_listing.splitlines():
            entry = entry.strip()
            if entry and not entry.startswith(".") and not entry.endswith(".bak"):
                files_to_scan.append(f"/etc/sudoers.d/{entry}")

    # 3. Read and parse each sudoers file
    import re as _re

    sudoers_files_scanned: list[str] = []
    sudoers_defaults_lines: list[dict] = []
    use_pty_entries: list[dict] = []
    logfile_entries: list[dict] = []
    nopasswd_entries: list[dict] = []
    noauthenticate_entries: list[dict] = []
    timestamp_timeout_entries: list[dict] = []
    logfile_paths: list[str] = []

    for filepath in files_to_scan:
        raw = remote_run_sudo(ssh, f"cat {filepath} 2>/dev/null", password)
        if not raw and not remote_run(ssh, f"test -f {filepath} && echo exists").strip():
            # File genuinely missing — not just empty
            continue
        if "Permission denied" in raw:
            errors.append({"check": f"read_file:{filepath}", "error": "Permission denied"})
            continue

        sudoers_files_scanned.append(filepath)
        for idx, line in enumerate(raw.splitlines(), 1):
            if _re.match(r"^\s*Defaults\b", line):
                sudoers_defaults_lines.append({"file": filepath, "line_number": idx, "content": line})
            if "use_pty" in line:
                use_pty_entries.append({"file": filepath, "content": line})
            if "logfile=" in line:
                logfile_entries.append({"file": filepath, "content": line})
                for m in _re.finditer(r'logfile\s*=\s*(?:"([^"]*)"|\x27([^\x27]*)\x27|([^\s,]+))', line):
                    path = m.group(1) or m.group(2) or m.group(3)
                    if path and path not in logfile_paths:
                        logfile_paths.append(path)
            if "NOPASSWD" in line:
                nopasswd_entries.append({"file": filepath, "line_number": idx, "content": line})
            if "!authenticate" in line:
                noauthenticate_entries.append({"file": filepath, "line_number": idx, "content": line})
            if "timestamp_timeout=" in line:
                timestamp_timeout_entries.append({"file": filepath, "content": line})

    # 4. Logfile existence / permission checks
    logfile_exists_checks: list[dict] = []
    for lpath in logfile_paths:
        stat_out = remote_run_sudo(ssh, f"stat -c '%a %U' {lpath} 2>/dev/null", password).strip()
        if stat_out and "No such" not in stat_out:
            parts = stat_out.split()
            logfile_exists_checks.append({
                "configured_path": lpath,
                "exists": True,
                "permissions": parts[0] if len(parts) >= 1 else None,
                "owner": parts[1] if len(parts) >= 2 else None,
            })
        else:
            logfile_exists_checks.append({
                "configured_path": lpath,
                "exists": False,
                "permissions": None,
                "owner": None,
            })

    # 5. Syslog-based sudo logging detection
    sudo_syslog_logging: dict = {
        "auth_log_exists": False,
        "syslog_log_exists": False,
        "rsyslog_authpriv_configured": False,
        "rsyslog_configs_checked": [],
        "syslog_ng_config_exists": False,
        "journald_sudo_evidence": None,
    }

    sudo_syslog_logging["auth_log_exists"] = bool(remote_run(ssh, "test -f /var/log/auth.log && echo True").strip())
    sudo_syslog_logging["syslog_log_exists"] = bool(remote_run(ssh, "test -f /var/log/syslog && echo True").strip())

    # Find rsyslog configs
    rsyslog_candidates = ["/etc/rsyslog.conf"]
    rsyslog_d_list = remote_run(ssh, "ls /etc/rsyslog.d/*.conf 2>/dev/null").strip()
    if rsyslog_d_list:
        for _f in rsyslog_d_list.splitlines():
            _f = _f.strip()
            if _f:
                rsyslog_candidates.append(_f)

    for _rpath in rsyslog_candidates:
        sudo_syslog_logging["rsyslog_configs_checked"].append(_rpath)
        if remote_run(ssh, f"test -f {_rpath} && echo exists").strip():
            matches = remote_run(ssh, f"grep -v '^\\s*#' {_rpath} | grep -Ei 'authpriv|auth\\.\\*|\\*\\.\\*'").strip()
            if matches:
                sudo_syslog_logging["rsyslog_authpriv_configured"] = True
                break

    sudo_syslog_logging["syslog_ng_config_exists"] = bool(remote_run(ssh, "test -f /etc/syslog-ng/syslog-ng.conf && echo True").strip())

    j_out = remote_run(ssh, "journalctl _COMM=sudo --no-pager -n 1 --output=short 2>/dev/null").strip()
    if j_out:
        sudo_syslog_logging["journald_sudo_evidence"] = j_out.splitlines()[0]

    # 6. /etc/pam.d/su
    pam_su_config = remote_run_sudo(ssh, "cat /etc/pam.d/su 2>/dev/null", password).strip() or None
    pam_wheel_line: str | None = None
    if pam_su_config:
        for line in pam_su_config.splitlines():
            if "pam_wheel.so" in line:
                pam_wheel_line = line.strip()
                break

    # 7. Group membership (sudo first, wheel fallback)
    wheel_group_members: list[str] | None = None
    wheel_group_source: str | None = None

    for group_name in ("sudo", "wheel"):
        getent_out = remote_run(ssh, f"getent group {group_name} 2>/dev/null").strip()
        if getent_out:
            parts = getent_out.split(":")
            if len(parts) >= 4:
                members_str = parts[3].strip()
                wheel_group_members = [m.strip() for m in members_str.split(",") if m.strip()] if members_str else []
            else:
                wheel_group_members = []
            wheel_group_source = group_name
            break

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


def collect_system_logging_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/system_logging_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 6.1.
    """
    local_script = os.path.join(os.path.dirname(__file__), "system_logging_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,  # OS walk and dpkg commands can take a few seconds
        fallback_key="system_logging"
    )


def collect_network_config_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/network_config_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 3 (Network Configuration).
    """
    local_script = os.path.join(os.path.dirname(__file__), "network_config_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="network_config",
    )


def collect_pam_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/pam_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 5.3 (PAM).
    """
    local_script = os.path.join(os.path.dirname(__file__), "pam_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="pam",
    )


def collect_filesystem_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/filesystem_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.1 (Filesystem).
    """
    local_script = os.path.join(os.path.dirname(__file__), "filesystem_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="filesystem",
    )


def collect_package_management_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/package_management_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.2 (Package Management).
    """
    local_script = os.path.join(os.path.dirname(__file__), "package_management_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="package_management",
    )


def collect_apparmor_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/apparmor_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.3 (AppArmor).
    """
    local_script = os.path.join(os.path.dirname(__file__), "apparmor_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="apparmor",
    )


def collect_bootloader_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/bootloader_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.4 (Bootloader).
    """
    local_script = os.path.join(os.path.dirname(__file__), "bootloader_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="bootloader",
    )


def collect_process_hardening_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/process_hardening_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.5 (Process Hardening).
    """
    local_script = os.path.join(os.path.dirname(__file__), "process_hardening_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="process_hardening",
    )


def collect_warning_banners_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/warning_banners_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.6 (Warning Banners).
    """
    local_script = os.path.join(os.path.dirname(__file__), "warning_banners_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="warning_banners",
    )


def collect_gnome_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/gnome_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 1.7 (GNOME Display Manager).
    """
    local_script = os.path.join(os.path.dirname(__file__), "gnome_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="gnome",
    )


def collect_services_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/services_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 2.1 (Server Services) and
    section 2.2 (Client Services). Supersedes the old collect_ftp and collect_telnet bridges.
    """
    local_script = os.path.join(os.path.dirname(__file__), "services_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=90,  # Package checks can be slow on first run
        fallback_key="services",
    )


def collect_time_sync_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/time_sync_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 2.3 (Time Synchronization).
    """
    local_script = os.path.join(os.path.dirname(__file__), "time_sync_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="time_sync",
    )


def collect_job_schedulers_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/job_schedulers_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 2.4 (Job Schedulers).
    """
    local_script = os.path.join(os.path.dirname(__file__), "job_schedulers_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="job_schedulers",
    )


def collect_auditd_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/auditd_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 6.2.
    Also collects System Logging (6.1), Integrity Checking (6.3), Network
    Configuration (section 3), PAM (section 5.3), Filesystem (section 1.1),
    Package Management (section 1.2), AppArmor (1.3), Bootloader (1.4),
    Process Hardening (1.5), Warning Banners (1.6), and GNOME (1.7) data to bypass main.py constraints.
    """
    local_script = os.path.join(os.path.dirname(__file__), "auditd_collector.py")
    res = run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="system_auditing"
    )

    # Run the AIDE integrity checking collection and merge into the same return dict
    # so that main.py unpacks both system_auditing and aide_integrity_checking.
    aide_res = collect_integrity_checking_from_ssh(ssh, password)
    res.update(aide_res)

    # Run the System Logging collection and merge into the same return dict
    syslog_res = collect_system_logging_from_ssh(ssh, password)
    res.update(syslog_res)

    # Run the Network Configuration collection (CIS Section 3) and merge
    net_res = collect_network_config_from_ssh(ssh, password)
    res.update(net_res)

    # Run the PAM collection (CIS Section 5.3) and merge
    pam_res = collect_pam_from_ssh(ssh, password)
    res.update(pam_res)

    # Run Filesystem collection (CIS Section 1.1) and merge
    fs_res = collect_filesystem_from_ssh(ssh, password)
    res.update(fs_res)

    # Run Package Management collection (CIS Section 1.2) and merge
    pkg_res = collect_package_management_from_ssh(ssh, password)
    res.update(pkg_res)

    # Run AppArmor collection (CIS Section 1.3) and merge
    apparmor_res = collect_apparmor_from_ssh(ssh, password)
    res.update(apparmor_res)

    # Run Bootloader collection (CIS Section 1.4) and merge
    bootloader_res = collect_bootloader_from_ssh(ssh, password)
    res.update(bootloader_res)

    # Run Process Hardening collection (CIS Section 1.5) and merge
    proc_res = collect_process_hardening_from_ssh(ssh, password)
    res.update(proc_res)

    # Run Warning Banners collection (CIS Section 1.6) and merge
    banners_res = collect_warning_banners_from_ssh(ssh, password)
    res.update(banners_res)

    # Run GNOME collection (CIS Section 1.7) and merge
    gnome_res = collect_gnome_from_ssh(ssh, password)
    res.update(gnome_res)

    # Run Services collection (CIS Section 2.1 & 2.2) and merge
    services_res = collect_services_from_ssh(ssh, password)
    res.update(services_res)

    # Run Time Synchronization collection (CIS Section 2.3) and merge
    ts_res = collect_time_sync_from_ssh(ssh, password)
    res.update(ts_res)

    # Run Job Schedulers collection (CIS Section 2.4) and merge
    js_res = collect_job_schedulers_from_ssh(ssh, password)
    res.update(js_res)

    return res


def collect_integrity_checking_from_ssh(ssh: "paramiko.SSHClient", password: str = "") -> dict[str, Any]:
    """
    Run collectors/integrity_checking_collector.py on the remote machine via SSH and parse the JSON.
    Used for auditing CIS Ubuntu 24.04 Benchmark section 6.3.
    """
    local_script = os.path.join(os.path.dirname(__file__), "integrity_checking_collector.py")
    return run_collector_over_ssh(
        ssh=ssh,
        script_path=local_script,
        password=password,
        timeout=60,
        fallback_key="aide_integrity_checking"
    )


def collect_file_permissions_from_ssh(
    ssh: paramiko.SSHClient,
    password: str = "",
) -> dict:
    """
    Collect raw file-permission data over SSH, mirroring the structure produced
    by ``collect_file_permissions()`` in the collectors module.
    """
    errors: list[dict] = []

    _LOCAL_FSTYPES = frozenset(
        {"ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "f2fs", "reiserfs"}
    )
    _FIXED_FILES = [
        "/etc/passwd", "/etc/passwd-",
        "/etc/group", "/etc/group-",
        "/etc/shadow", "/etc/shadow-",
        "/etc/gshadow", "/etc/gshadow-",
        "/etc/shells",
        "/etc/security/opasswd",
    ]
    _CAP = 500

    # Part 1 – Fixed file stat checks
    fixed_files: list[dict] = []
    
    py_script = """
import os, stat, pwd, grp, json, sys
path = sys.argv[1]
res = {'path': path, 'exists': False, 'mode_octal': None, 'owner': None, 
       'owner_uid': None, 'group': None, 'group_gid': None, 'error': None}
try:
    st = os.stat(path)
    res['exists'] = True
    res['mode_octal'] = f"{stat.S_IMODE(st.st_mode):04o}"
    res['owner_uid'] = st.st_uid
    res['group_gid'] = st.st_gid
    try:
        res['owner'] = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        res['error'] = 'unable to resolve username'
    try:
        res['group'] = grp.getgrgid(st.st_gid).gr_name
    except Exception:
        if res['error']:
            res['error'] += '; unable to resolve groupname'
        else:
            res['error'] = 'unable to resolve groupname'
except FileNotFoundError:
    res['error'] = 'FileNotFoundError'
except PermissionError:
    res['exists'] = os.path.exists(path) or os.path.lexists(path)
    res['error'] = 'PermissionError'
except Exception as e:
    res['error'] = type(e).__name__
print(json.dumps(res))
    """
    b64_script = base64.b64encode(py_script.strip().encode()).decode()

    for path in _FIXED_FILES:
        cmd = f"python3 -c \"import base64,sys;exec(base64.b64decode('{b64_script}').decode())\" {path}"
        out = remote_run(ssh, cmd, timeout=10).strip()
        
        try:
            json_line = next(line for line in out.splitlines() if line.startswith("{"))
            entry = json.loads(json_line)
        except Exception:
            entry = {
                "path": path,
                "exists": False,
                "mode_octal": None,
                "owner": None,
                "owner_uid": None,
                "group": None,
                "group_gid": None,
                "error": "output unparseable",
            }
        fixed_files.append(entry)

    # Mount discovery
    scan_start = time.monotonic()
    local_mounts: list[str] = []
    skipped_mounts: list[dict] = []

    mounts_raw = remote_run(ssh, "findmnt -n -o TARGET,FSTYPE 2>/dev/null", timeout=10)
    if not mounts_raw.strip():
        local_mounts = ["/"]
        errors.append({"check": "findmnt", "error": "No output — defaulting to /"})
    else:
        for line in mounts_raw.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            target, fstype = parts[0], parts[1].lower()
            if fstype in _LOCAL_FSTYPES:
                if target not in local_mounts:
                    local_mounts.append(target)
            else:
                skipped_mounts.append({"mount": target, "fstype": fstype})

    def _remote_find(mountpoint: str, find_args: str, timeout: int = 130) -> tuple:
        cmd = (
            f"timeout 120 find {mountpoint} -xdev {find_args} 2>/dev/null"
            f" | head -{_CAP + 1}"
        )
        out = remote_run(ssh, cmd, timeout=timeout)
        lines = [l for l in out.splitlines() if l.strip()]
        truncated = len(lines) > _CAP
        return lines[:_CAP], truncated

    # Part 2 – World-writable files and directories
    ww_files: list[dict] = []
    ww_dirs: list[dict] = []

    for mp in local_mounts:
        paths_f, trunc_f = _remote_find(mp, "-type f -perm -0002")
        ww_files.append({"mount": mp, "paths": paths_f, "truncated": trunc_f})

        paths_d, trunc_d = _remote_find(mp, "-type d -perm -0002 ! -perm -1000")
        ww_dirs.append({"mount": mp, "paths": paths_d, "truncated": trunc_d})

    world_writable_data: dict = {
        "mounts_scanned": local_mounts,
        "mounts_skipped": skipped_mounts,
        "world_writable_files": ww_files,
        "world_writable_dirs_no_sticky": ww_dirs,
        "errors": [],
    }

    # Part 3 – Unowned / ungrouped files
    unowned: list[dict] = []
    for mp in local_mounts:
        paths, trunc = _remote_find(mp, r"\( -nouser -o -nogroup \)")
        unowned.append({"mount": mp, "paths": paths, "truncated": trunc})

    unowned_data: dict = {"unowned_or_ungrouped": unowned}

    # Part 4 – SUID / SGID files
    suid_sgid_files: list[dict] = []
    total_truncated = False
    remaining = _CAP

    for mp in local_mounts:
        if remaining <= 0:
            total_truncated = True
            break
        cmd = (
            f"timeout 120 find {mp} -xdev -type f"
            r" \( -perm -4000 -o -perm -2000 \)"
            f" -printf '%m %U %u %G %g %p\n' 2>/dev/null | head -{remaining + 1}"
        )
        out = remote_run(ssh, cmd, timeout=130)
        lines = [l for l in out.splitlines() if l.strip()]
        if len(lines) > remaining:
            total_truncated = True
            lines = lines[:remaining]
        for line in lines:
            parts = line.split(None, 5)
            if len(parts) == 6:
                mode_raw = parts[0]
                if len(mode_raw) < 4:
                    try:
                        mode_octal = f"{int(mode_raw, 8):04o}"
                    except ValueError:
                        mode_octal = mode_raw.zfill(4)
                else:
                    mode_octal = mode_raw

                try:
                    owner_uid = int(parts[1])
                except ValueError:
                    owner_uid = None

                try:
                    group_gid = int(parts[3])
                except ValueError:
                    group_gid = None

                suid_sgid_files.append(
                    {
                        "mount": mp,
                        "path": parts[5],
                        "mode_octal": mode_octal,
                        "owner_uid": owner_uid,
                        "owner": parts[2],
                        "group_gid": group_gid,
                        "group": parts[4],
                    }
                )
                remaining -= 1

    suid_sgid_data: dict = {
        "suid_sgid_files": suid_sgid_files,
        "truncated": total_truncated,
    }

    scan_duration = time.monotonic() - scan_start

    return {
        "fixed_files": fixed_files,
        "world_writable": world_writable_data,
        "unowned": unowned_data,
        "suid_sgid": suid_sgid_data,
        "mount_scan_meta": {
            "mounts_scanned": local_mounts,
            "mounts_skipped": [m["mount"] for m in skipped_mounts],
            "scan_duration_seconds": round(scan_duration, 3),
        },
        "errors": errors,
    }


def collect_user_accounts_from_ssh(
    ssh: paramiko.SSHClient,
    password: str = "",
) -> dict:
    """
    Collect raw user accounts data over SSH (CIS 5.4).
    Delegates to tools.ssh_collector_runner for transport.
    """
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "collectors", "user_accounts_collector.py")
    return run_collector_over_ssh(ssh, script, password, timeout=60,
                                  fallback_key="user_accounts")


def collect_ufw_from_ssh(
    ssh: paramiko.SSHClient,
    password: str = "",
) -> dict:
    """
    Collect raw UFW firewall data over SSH (CIS 4.1).
    Delegates to tools.ssh_collector_runner for transport.
    """
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "collectors", "ufw_collector.py")
    return run_collector_over_ssh(ssh, script, password, timeout=30,
                                  fallback_key="ufw_firewall")
