"""
system_logging_collector.py
===========================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 6.1 (System Logging).

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
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


def _read_conf_dir(dir_path: str, ext: str = ".conf") -> list[dict[str, str]]:
    """Read all configuration files in a directory matching an extension."""
    files_content = []
    if os.path.exists(dir_path):
        try:
            for fname in sorted(os.listdir(dir_path)):
                if fname.endswith(ext):
                    abs_path = os.path.join(dir_path, fname)
                    content = _read_file(abs_path)
                    if content is not None:
                        files_content.append({"path": abs_path, "content": content})
        except Exception:
            pass
    return files_content


def _stat_file_or_dir(path: str) -> dict[str, Any] | None:
    if not os.path.lexists(path):
        return None
    try:
        st = os.stat(path)
        return {
            "path": path,
            "mode": oct(st.st_mode)[-4:],
            "owner_uid": st.st_uid,
            "group_gid": st.st_gid
        }
    except Exception:
        return None


def collect_system_logging() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 6.1
    (System Logging - journald, rsyslog, logfile access).

    Returns:
        dict: A JSON-serializable dictionary with top-level key 'system_logging'
    """
    errors: list[dict[str, str]] = []

    # -------------------------------------------------------------------------
    # 1. journald
    # -------------------------------------------------------------------------
    journald_active_out, _, _ = _run_cmd(["systemctl", "is-active", "systemd-journald"])
    journald_enabled_out, _, _ = _run_cmd(["systemctl", "is-enabled", "systemd-journald"])
    
    jremote_installed_out, _, jremote_rc = _run_cmd(["dpkg", "-s", "systemd-journal-remote"])
    jremote_installed = (jremote_rc == 0 and "install ok installed" in jremote_installed_out.lower() or "installed" in jremote_installed_out.lower())
    
    jupload_active, _, _ = _run_cmd(["systemctl", "is-active", "systemd-journal-upload.service"])
    jupload_enabled, _, _ = _run_cmd(["systemctl", "is-enabled", "systemd-journal-upload.service"])
    jremote_sock_active, _, _ = _run_cmd(["systemctl", "is-active", "systemd-journal-remote.socket"])
    jremote_sock_enabled, _, _ = _run_cmd(["systemctl", "is-enabled", "systemd-journal-remote.socket"])

    journald_confs = []
    main_conf = _read_file("/etc/systemd/journald.conf")
    if main_conf is not None:
        journald_confs.append({"path": "/etc/systemd/journald.conf", "content": main_conf})
    journald_confs.extend(_read_conf_dir("/etc/systemd/journald.conf.d", ".conf"))

    journald_log_dirs = []
    for dpath in ["/run/log/journal", "/var/log/journal"]:
        st = _stat_file_or_dir(dpath)
        if st:
            # Also stat files statically right underneath
            children = []
            try:
                for entry in os.listdir(dpath):
                    ch_path = os.path.join(dpath, entry)
                    st_ch = _stat_file_or_dir(ch_path)
                    if st_ch:
                        children.append(st_ch)
            except Exception as e:
                errors.append({"check": f"listdir {dpath}", "error": str(e)})
            st["children"] = children
            journald_log_dirs.append(st)

    journald = {
        "systemd-journald_active": journald_active_out.strip(),
        "systemd-journald_enabled": journald_enabled_out.strip(),
        "systemd-journal-remote_installed": jremote_installed,
        "systemd-journal-upload_active": jupload_active.strip(),
        "systemd-journal-upload_enabled": jupload_enabled.strip(),
        "systemd-journal-remote_socket_active": jremote_sock_active.strip(),
        "systemd-journal-remote_socket_enabled": jremote_sock_enabled.strip(),
        "journald_configs": journald_confs,
        "journald_log_dirs": journald_log_dirs
    }

    # -------------------------------------------------------------------------
    # 2. rsyslog
    # -------------------------------------------------------------------------
    rsyslog_installed_out, _, rsyslog_rc = _run_cmd(["dpkg", "-s", "rsyslog"])
    rsyslog_installed = (rsyslog_rc == 0 and ("install ok installed" in rsyslog_installed_out.lower() or "installed" in rsyslog_installed_out.lower()))
    rsyslog_active_out, _, _ = _run_cmd(["systemctl", "is-active", "rsyslog"])
    rsyslog_enabled_out, _, _ = _run_cmd(["systemctl", "is-enabled", "rsyslog"])

    rsyslog_confs = []
    main_rsyslog_conf = _read_file("/etc/rsyslog.conf")
    if main_rsyslog_conf is not None:
        rsyslog_confs.append({"path": "/etc/rsyslog.conf", "content": main_rsyslog_conf})
    rsyslog_confs.extend(_read_conf_dir("/etc/rsyslog.d", ".conf"))

    logrotate_confs = []
    main_logrotate_conf = _read_file("/etc/logrotate.conf")
    if main_logrotate_conf is not None:
        logrotate_confs.append({"path": "/etc/logrotate.conf", "content": main_logrotate_conf})
    # logrotate often doesn't enforce .conf extension in /etc/logrotate.d/
    if os.path.exists("/etc/logrotate.d"):
        try:
            for fname in sorted(os.listdir("/etc/logrotate.d")):
                abspath = os.path.join("/etc/logrotate.d", fname)
                if os.path.isfile(abspath):
                    content = _read_file(abspath)
                    if content is not None:
                        logrotate_confs.append({"path": abspath, "content": content})
        except Exception as e:
            errors.append({"check": "logrotate configs", "error": str(e)})

    logrotate_tmr_active, _, _ = _run_cmd(["systemctl", "is-active", "logrotate.timer"])
    logrotate_tmr_enabled, _, _ = _run_cmd(["systemctl", "is-enabled", "logrotate.timer"])

    rgnutls_installed_out, _, rgnutls_rc = _run_cmd(["dpkg", "-s", "rsyslog-gnutls"])
    rgnutls_installed = (rgnutls_rc == 0 and ("install ok installed" in rgnutls_installed_out.lower() or "installed" in rgnutls_installed_out.lower()))

    rsyslog = {
        "rsyslog_installed": rsyslog_installed,
        "rsyslog_active": rsyslog_active_out.strip(),
        "rsyslog_enabled": rsyslog_enabled_out.strip(),
        "rsyslog_configs": rsyslog_confs,
        "logrotate_configs": logrotate_confs,
        "logrotate_timer_active": logrotate_tmr_active.strip(),
        "logrotate_timer_enabled": logrotate_tmr_enabled.strip(),
        "rsyslog_gnutls_installed": rgnutls_installed,
    }

    # -------------------------------------------------------------------------
    # 3. Logfiles access
    # -------------------------------------------------------------------------
    logfiles = []
    if os.path.exists("/var/log"):
        skip_exts = {".gz", ".xz", ".bz2", ".tar"}
        try:
            for root, dirs, files in os.walk("/var/log"):
                # limit depth or number of files if necessary, but /var/log is usually bounded.
                for fname in files:
                    # Ignore rotated compressed logs to save IO / JSON bloat
                    if any(fname.endswith(ext) for ext in skip_exts):
                        continue
                    # Ignore .1, .2 rotated extensions
                    if "." in fname and fname.rsplit(".", 1)[-1].isdigit():
                        continue
                    
                    full_path = os.path.join(root, fname)
                    st = _stat_file_or_dir(full_path)
                    if st:
                        logfiles.append(st)
                
                # Keep it under 200 files to avoid blowing up the LLM payload
                if len(logfiles) >= 200:
                    errors.append({"check": "logfiles_limit", "error": "Cap of 200 logfiles reached early"})
                    break
        except Exception as e:
            errors.append({"check": "var_log_walk", "error": str(e)})

    return {
        "system_logging": {
            "journald": journald,
            "rsyslog": rsyslog,
            "logfiles": logfiles,
            "errors": errors
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_system_logging()))
