"""
integrity_checking_collector.py
===============================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 6.3 (Configure Integrity Checking / AIDE).

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


def collect_integrity_checking() -> dict[str, Any]:
    errors: list[dict[str, str]] = []

    # 1. AIDE installed
    aide_installed_out, _, rc1 = _run_cmd(["dpkg", "-s", "aide"])
    aide_common_out, _, rc2 = _run_cmd(["dpkg", "-s", "aide-common"])
    which_aide_out, _, rc3 = _run_cmd(["which", "aide"])
    
    dpkg_aide = (rc1 == 0 and ("install ok installed" in aide_installed_out.lower() or "installed" in aide_installed_out.lower()))
    dpkg_aide_common = (rc2 == 0 and ("install ok installed" in aide_common_out.lower() or "installed" in aide_common_out.lower()))
    aide_on_path = (rc3 == 0 and bool(which_aide_out.strip()))
    
    aide_installed = dpkg_aide or dpkg_aide_common or aide_on_path

    if not aide_installed:
        return {
            "aide_integrity_checking": {
                "aide_installed": False,
                "scheduled_checking": None,
                "audit_tools_integrity_tracked": None,
                "errors": errors
            }
        }

    # 2. Filesystem integrity regularly checked (6.3.2)
    cron_jobs = []
    cron_files_to_check = ["/etc/crontab"]
    if os.path.exists("/etc/cron.d"):
        try:
            for f in os.listdir("/etc/cron.d"):
                cron_files_to_check.append(os.path.join("/etc/cron.d", f))
        except Exception as e:
            errors.append({"check": "listdir /etc/cron.d", "error": str(e)})
            
    for cf in cron_files_to_check:
        content = _read_file(cf)
        if content:
            for line in content.splitlines():
                if "aide" in line and not line.strip().startswith("#"):
                    cron_jobs.append({"file": cf, "line": line.strip()})
                    
    root_cron_out, _, rc_cron = _run_cmd(["crontab", "-l"])
    if rc_cron == 0 and "aide" in root_cron_out:
        for line in root_cron_out.splitlines():
            if "aide" in line and not line.strip().startswith("#"):
                cron_jobs.append({"file": "root_crontab", "line": line.strip()})
                
    timers = ["dailyaidecheck.timer", "aidecheck.timer", "aidecheck.service"]
    systemd_checks = []
    for t in timers:
        active, _, _ = _run_cmd(["systemctl", "is-active", t])
        enabled, _, _ = _run_cmd(["systemctl", "is-enabled", t])
        
        systemd_checks.append({
            "unit": t,
            "active": active.strip(),
            "enabled": enabled.strip()
        })
        
    scheduled_checking = {
        "cron_jobs_found": cron_jobs,
        "systemd_units_found": systemd_checks
    }

    # 3. Cryptographic mechanisms protect audit tools (6.3.3)
    audit_tools = [
        "/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", 
        "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules"
    ]
    
    aide_conf = _read_file("/etc/aide/aide.conf")
    conf_files = []
    if aide_conf is not None:
        conf_files.append({"path": "/etc/aide/aide.conf", "content": aide_conf})

    if os.path.exists("/etc/aide/aide.conf.d"):
        try:
            for f in sorted(os.listdir("/etc/aide/aide.conf.d")):
                if f.endswith(".conf"):
                    path = os.path.join("/etc/aide/aide.conf.d", f)
                    c = _read_file(path)
                    if c is not None:
                        conf_files.append({"path": path, "content": c})
        except Exception as e:
            errors.append({"check": "listdir /etc/aide/aide.conf.d", "error": str(e)})
                
    matching_lines = []
    for cf in conf_files:
        lines = cf["content"].splitlines()
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("@@") or line_str.startswith("#"):
                continue
            if any(tool in line_str for tool in audit_tools):
                matching_lines.append({"file": cf["path"], "line": line_str})
                
    audit_tools_integrity_tracked = {
        "tools_checked": audit_tools,
        "matching_aide_config_lines": matching_lines
    }

    return {
        "aide_integrity_checking": {
            "aide_installed": True,
            "dpkg_aide": dpkg_aide,
            "dpkg_aide_common": dpkg_aide_common,
            "aide_on_path": aide_on_path,
            "scheduled_checking": scheduled_checking,
            "audit_tools_integrity_tracked": audit_tools_integrity_tracked,
            "errors": errors
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_integrity_checking()))
