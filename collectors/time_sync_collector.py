"""
time_sync_collector.py
======================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 2.3 (Time Synchronization):

  2.3.1.1  Single time synchronization daemon in use (systemd-timesyncd OR chrony)
  2.3.2.1  systemd-timesyncd timeserver configured (/etc/systemd/timesyncd.conf)
  2.3.2.2  systemd-timesyncd enabled and running
  2.3.3.1  chrony timeserver configured (/etc/chrony/chrony.conf)
  2.3.3.2  chrony process user (_chrony)
  2.3.3.3  chrony enabled and running

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import os
from typing import Any

from collectors.common import read_file, run_cmd

_run_cmd = run_cmd
_read_file = read_file


def _dpkg_installed(package: str) -> bool:
    out, _, rc = _run_cmd(["dpkg", "-s", package])
    return rc == 0 and "install ok installed" in out.lower()


def _systemctl_state(unit: str) -> dict:
    e, _, _ = _run_cmd(["systemctl", "is-enabled", unit])
    a, _, _ = _run_cmd(["systemctl", "is-active", unit])
    return {"unit": unit, "enabled": e.strip(), "active": a.strip()}



def _read_conf_files(main_conf: str, conf_d: str) -> list[str]:
    contents: list[str] = []
    main_text = _read_file(main_conf)
    if main_text:
        contents.append(main_text)

    if os.path.exists(conf_d):
        try:
            for fname in sorted(os.listdir(conf_d)):
                if fname.endswith(".conf"):
                    fpath = os.path.join(conf_d, fname)
                    text = _read_file(fpath)
                    if text:
                        contents.append(text)
        except Exception:
            pass
    return contents


def collect_time_sync() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 2.3
    (Time Synchronization).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'time_sync'.
    """
    errors: list[dict[str, str]] = []

    timesyncd_installed = _dpkg_installed("systemd-timesyncd")
    chrony_installed = _dpkg_installed("chrony")

    timesyncd_svc = _systemctl_state("systemd-timesyncd.service")
    chrony_svc = _systemctl_state("chrony.service")

    active_daemons: list[str] = []
    if timesyncd_svc["active"] == "active":
        active_daemons.append("systemd-timesyncd")
    if chrony_svc["active"] == "active":
        active_daemons.append("chrony")

    # 2.3.2: systemd-timesyncd configuration
    timesyncd_texts = _read_conf_files(
        "/etc/systemd/timesyncd.conf", "/etc/systemd/timesyncd.conf.d"
    )
    ntp_config_lines: list[str] = []
    for text in timesyncd_texts:
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith(";"):
                if s.startswith("NTP=") or s.startswith("FallbackNTP="):
                    ntp_config_lines.append(s)

    # 2.3.3: chrony configuration
    chrony_texts = _read_conf_files("/etc/chrony/chrony.conf", "/etc/chrony/conf.d")
    chrony_servers: list[str] = []
    chrony_user_directives: list[str] = []
    for text in chrony_texts:
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith(";"):
                if s.startswith("server ") or s.startswith("pool "):
                    chrony_servers.append(s)
                elif s.startswith("user "):
                    chrony_user_directives.append(s)

    # chrony running process user check
    ps_out, _, _ = _run_cmd(["ps", "-C", "chronyd", "-o", "user="])
    chrony_process_user = ps_out.strip() if ps_out else None

    # systemd unit user check
    unit_cat_out, _, _ = _run_cmd(["systemctl", "cat", "chrony.service"])
    unit_user: str | None = None
    if unit_cat_out:
        for line in unit_cat_out.splitlines():
            s = line.strip()
            if s.startswith("User="):
                unit_user = s.split("=", 1)[1].strip()

    return {
        "time_sync": {
            "time_sync_general": {
                "timesyncd_installed": timesyncd_installed,
                "chrony_installed": chrony_installed,
                "timesyncd_service": timesyncd_svc,
                "chrony_service": chrony_svc,
                "active_daemons": active_daemons,
                "active_daemon_count": len(active_daemons),
            },
            "systemd_timesyncd": {
                "service": timesyncd_svc,
                "ntp_config_lines": ntp_config_lines,
                "has_ntp_configured": len(ntp_config_lines) > 0,
            },
            "chrony": {
                "service": chrony_svc,
                "server_config_lines": chrony_servers,
                "has_servers_configured": len(chrony_servers) > 0,
                "process_user": chrony_process_user,
                "config_user_directive": (
                    chrony_user_directives[0] if chrony_user_directives else None
                ),
                "unit_user": unit_user,
            },
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_time_sync(), indent=2))
