"""
auditd_collector.py
===================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 6.2 (System Auditing).

This module ONLY collects and structures data — it does NOT make any
PASS/FAIL judgments.
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


def _read_conf_dir(dir_path: str, ext: str = ".rules") -> list[dict[str, str]]:
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


def _stat_file_or_dir(path: str) -> dict[str, Any]:
    if not os.path.lexists(path):
        return {"path": path, "exists": False}
    try:
        st = os.stat(path)
        return {
            "path": path,
            "exists": True,
            "mode": oct(st.st_mode)[-4:],
            "owner_uid": st.st_uid,
            "group_gid": st.st_gid
        }
    except Exception as e:
        return {"path": path, "exists": True, "error": str(e)}


def collect_auditd() -> dict[str, Any]:
    errors: list[dict[str, str]] = []

    # 1. auditd packages installed
    auditd_pkg, _, rc1 = _run_cmd(["dpkg", "-s", "auditd"])
    audispd_pkg, _, rc2 = _run_cmd(["dpkg", "-s", "audispd-plugins"])
    auditd_installed = rc1 == 0 and ("install ok installed" in auditd_pkg.lower() or "installed" in auditd_pkg.lower())
    audispd_installed = rc2 == 0 and ("install ok installed" in audispd_pkg.lower() or "installed" in audispd_pkg.lower())

    if not auditd_installed:
        # If auditd isn't even installed, return early to save time and avoid pointless errors
        return {
            "system_auditing": {
                "auditd_installed": False,
                "audispd_plugins_installed": audispd_installed,
                "errors": [{"check": "auditd_installed", "error": "auditd package is not installed."}]
            }
        }

    # 2. Service status
    active_out, _, _ = _run_cmd(["systemctl", "is-active", "auditd"])
    enabled_out, _, _ = _run_cmd(["systemctl", "is-enabled", "auditd"])

    # 3. Kernel boot params
    proc_cmdline = _read_file("/proc/cmdline") or ""
    grub_default = _read_file("/etc/default/grub") or ""

    auditd_service = {
        "auditd_active": active_out.strip(),
        "auditd_enabled": enabled_out.strip(),
        "proc_cmdline_raw": proc_cmdline.strip(),
        "grub_default_raw": grub_default
    }

    # 4. Data retention (6.2.2.1 - 6.2.2.4)
    auditd_conf_raw = _read_file("/etc/audit/auditd.conf")
    data_retention = {
        "auditd_conf_raw": auditd_conf_raw
    }

    # 5. Raw rules (6.2.3.1 - 6.2.3.30)
    auditctl_l_out, auditctl_l_err, l_rc = _run_cmd(["auditctl", "-l"])
    if l_rc != 0 and "permission" in auditctl_l_err.lower():
        errors.append({"check": "auditctl -l", "error": f"Permission denied: {auditctl_l_err.strip()}"})
    
    auditctl_s_out, auditctl_s_err, s_rc = _run_cmd(["auditctl", "-s"])
    if s_rc != 0 and "permission" in auditctl_s_err.lower():
        errors.append({"check": "auditctl -s", "error": f"Permission denied: {auditctl_s_err.strip()}"})

    augenrules_out, augenrules_err, aug_rc = _run_cmd(["augenrules", "--check"])
    if aug_rc != 0:
        errors.append({"check": "augenrules --check", "error": augenrules_err.strip()})

    uname_m_out, _, _ = _run_cmd(["uname", "-m"])
    
    rules_d = _read_conf_dir("/etc/audit/rules.d", ".rules")
    audit_rules_raw = _read_file("/etc/audit/audit.rules")

    audit_rules = {
        "kernel_arch": uname_m_out.strip(),
        "auditctl_l_raw": auditctl_l_out.strip(),
        "auditctl_s_raw": auditctl_s_out.strip(),
        "augenrules_check_raw": augenrules_out.strip(),
        "etc_audit_audit_rules": audit_rules_raw,
        "etc_audit_rules_d": rules_d
    }

    # 6. File Access (6.2.4.1 - 6.2.4.10)
    file_access: list[dict[str, Any]] = []
    
    # 6.2.4.1-4 Log dir
    for path in ["/var/log/audit"]:
        if os.path.exists(path):
            file_access.append(_stat_file_or_dir(path))
            try:
                for fname in os.listdir(path):
                    file_access.append(_stat_file_or_dir(os.path.join(path, fname)))
            except Exception as e:
                errors.append({"check": f"listdir {path}", "error": str(e)})

    # 6.2.4.5-7 Config files
    file_access.append(_stat_file_or_dir("/etc/audit/auditd.conf"))
    file_access.append(_stat_file_or_dir("/etc/audit/audit.rules"))
    if os.path.exists("/etc/audit/rules.d"):
        file_access.append(_stat_file_or_dir("/etc/audit/rules.d"))
        try:
            for fname in os.listdir("/etc/audit/rules.d"):
                if fname.endswith(".rules"):
                    file_access.append(_stat_file_or_dir(os.path.join("/etc/audit/rules.d", fname)))
        except Exception as e:
            errors.append({"check": "listdir /etc/audit/rules.d", "error": str(e)})

    # 6.2.4.8-10 Tools
    tools = [
        "/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", 
        "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules"
    ]
    for t in tools:
        file_access.append(_stat_file_or_dir(t))

    return {
        "system_auditing": {
            "auditd_installed": True,
            "audispd_plugins_installed": audispd_installed,
            "auditd_service": auditd_service,
            "data_retention": data_retention,
            "audit_rules_raw": audit_rules,
            "auditd_file_access": file_access,
            "errors": errors
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_auditd()))
