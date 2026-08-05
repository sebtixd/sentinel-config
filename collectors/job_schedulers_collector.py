"""
job_schedulers_collector.py
===========================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 2.4 (Job Schedulers):

  2.4.1.1  cron daemon enabled and active
  2.4.1.2  access to /etc/crontab
  2.4.1.3  access to /etc/cron.hourly
  2.4.1.4  access to /etc/cron.daily
  2.4.1.5  access to /etc/cron.weekly
  2.4.1.6  access to /etc/cron.monthly
  2.4.1.7  access to /etc/cron.yearly
  2.4.1.8  access to /etc/cron.d
  2.4.1.9  access to crontab mechanism (/var/spool/cron/crontabs, crontab binary)
  2.4.2.1  access to at configured (/etc/at.allow, /etc/at.deny, package at)

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from collectors.common import run_cmd, stat_path

_run_cmd = run_cmd
_stat_path = stat_path


def _dpkg_installed(package: str) -> bool:
    out, _, rc = _run_cmd(["dpkg", "-s", package])
    return rc == 0 and "install ok installed" in out.lower()


def _systemctl_state(unit: str) -> dict:
    e, _, _ = _run_cmd(["systemctl", "is-enabled", unit])
    a, _, _ = _run_cmd(["systemctl", "is-active", unit])
    return {"unit": unit, "enabled": e.strip(), "active": a.strip()}



def collect_job_schedulers() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 2.4
    (Job Schedulers).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'job_schedulers'.
    """
    errors: list[dict[str, str]] = []

    # 2.4.1: cron daemon & permissions
    cron_installed = _dpkg_installed("cron")
    cron_service = _systemctl_state("cron.service")

    # 2.4.1.2 - 2.4.1.8 path permissions
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/cron.yearly",
        "/etc/cron.d",
    ]
    cron_paths_stat = [_stat_path(p) for p in cron_paths]

    # 2.4.1.9 crontab mechanism permissions
    crontabs_spool_stat = _stat_path("/var/spool/cron/crontabs")
    if not crontabs_spool_stat["exists"]:
        crontabs_spool_stat = _stat_path("/var/spool/cron")

    crontab_bin_path = shutil.which("crontab") or "/usr/bin/crontab"
    crontab_binary_stat = _stat_path(crontab_bin_path)

    cron_data = {
        "cron_installed": cron_installed,
        "cron_service": cron_service,
        "cron_paths_permissions": cron_paths_stat,
        "crontabs_spool_stat": crontabs_spool_stat,
        "crontab_binary_stat": crontab_binary_stat,
    }

    # 2.4.2: at daemon & permissions
    at_installed = _dpkg_installed("at")
    at_allow_stat = _stat_path("/etc/at.allow")
    at_deny_stat = _stat_path("/etc/at.deny")

    at_data = {
        "at_installed": at_installed,
        "at_allow_stat": at_allow_stat,
        "at_deny_stat": at_deny_stat,
    }

    return {
        "job_schedulers": {
            "cron": cron_data,
            "at": at_data,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_job_schedulers(), indent=2))
