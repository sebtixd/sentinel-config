"""
test_time_sync_collector.py
============================
Unit tests for collectors/time_sync_collector.py

Hermetic tests with mocked subprocess and file reads.
"""

from __future__ import annotations

import json
from unittest import mock

from collectors.time_sync_collector import (
    _dpkg_installed,
    _systemctl_state,
    collect_time_sync,
)


@mock.patch("collectors.time_sync_collector._run_cmd")
def test_dpkg_installed(mock_run):
    mock_run.return_value = ("Status: install ok installed\n", "", 0)
    assert _dpkg_installed("chrony") is True


@mock.patch("collectors.time_sync_collector._run_cmd")
def test_systemctl_state(mock_run):
    mock_run.side_effect = [
        ("enabled\n", "", 0),
        ("active\n", "", 0),
    ]
    state = _systemctl_state("chrony.service")
    assert state["enabled"] == "enabled"
    assert state["active"] == "active"


@mock.patch("os.path.exists", return_value=False)
@mock.patch("collectors.time_sync_collector._read_file")
@mock.patch("collectors.time_sync_collector._systemctl_state")
@mock.patch("collectors.time_sync_collector._dpkg_installed")
@mock.patch("collectors.time_sync_collector._run_cmd")
def test_collect_time_sync_chrony_active(mock_run, mock_dpkg, mock_svc, mock_rf, mock_exists):
    mock_dpkg.side_effect = lambda pkg: pkg == "chrony"
    mock_svc.side_effect = lambda unit: (
        {"unit": unit, "enabled": "enabled", "active": "active"}
        if "chrony" in unit
        else {"unit": unit, "enabled": "disabled", "active": "inactive"}
    )
    mock_rf.side_effect = lambda path: "server pool.ntp.org iburst\nuser _chrony\n" if "chrony.conf" in path else None
    mock_run.side_effect = [
        ("_chrony\n", "", 0),  # ps -C chronyd
        ("User=_chrony\n", "", 0),  # systemctl cat chrony.service
    ]

    res = collect_time_sync()
    assert "time_sync" in res
    ts = res["time_sync"]

    assert ts["time_sync_general"]["chrony_installed"] is True
    assert ts["time_sync_general"]["timesyncd_installed"] is False
    assert ts["time_sync_general"]["active_daemon_count"] == 1
    assert ts["time_sync_general"]["active_daemons"] == ["chrony"]

    assert ts["chrony"]["has_servers_configured"] is True
    assert ts["chrony"]["process_user"] == "_chrony"
    assert ts["chrony"]["config_user_directive"] == "user _chrony"


@mock.patch("os.path.exists", return_value=False)
@mock.patch("collectors.time_sync_collector._read_file")
@mock.patch("collectors.time_sync_collector._systemctl_state")
@mock.patch("collectors.time_sync_collector._dpkg_installed")
@mock.patch("collectors.time_sync_collector._run_cmd")
def test_collect_time_sync_timesyncd_active(mock_run, mock_dpkg, mock_svc, mock_rf, mock_exists):
    mock_dpkg.side_effect = lambda pkg: pkg == "systemd-timesyncd"
    mock_svc.side_effect = lambda unit: (
        {"unit": unit, "enabled": "enabled", "active": "active"}
        if "timesyncd" in unit
        else {"unit": unit, "enabled": "disabled", "active": "inactive"}
    )
    mock_rf.side_effect = lambda path: "NTP=time.cloudflare.com\nFallbackNTP=ntp.ubuntu.com\n" if "timesyncd.conf" in path else None
    mock_run.side_effect = [
        ("", "", 1),  # ps -C chronyd -> not running
        ("", "", 1),  # systemctl cat chrony.service -> not found
    ]

    res = collect_time_sync()
    ts = res["time_sync"]
    assert ts["time_sync_general"]["timesyncd_installed"] is True
    assert ts["time_sync_general"]["active_daemon_count"] == 1
    assert ts["systemd_timesyncd"]["has_ntp_configured"] is True
