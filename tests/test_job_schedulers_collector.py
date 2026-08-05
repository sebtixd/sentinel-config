"""
test_job_schedulers_collector.py
=================================
Unit tests for collectors/job_schedulers_collector.py

Hermetic tests with mocked subprocess and stat calls.
"""

from __future__ import annotations

import json
from unittest import mock

from collectors.job_schedulers_collector import (
    _dpkg_installed,
    _systemctl_state,
    _stat_path,
    collect_job_schedulers,
)


@mock.patch("collectors.job_schedulers_collector._run_cmd")
def test_dpkg_installed(mock_run):
    mock_run.return_value = ("Status: install ok installed\n", "", 0)
    assert _dpkg_installed("cron") is True


@mock.patch("collectors.job_schedulers_collector._run_cmd")
def test_systemctl_state(mock_run):
    mock_run.side_effect = [
        ("enabled\n", "", 0),
        ("active\n", "", 0),
    ]
    state = _systemctl_state("cron.service")
    assert state["enabled"] == "enabled"
    assert state["active"] == "active"


def test_stat_path_nonexistent():
    res = _stat_path("/nonexistent/file/path")
    assert res["exists"] is False
    assert res["mode_octal"] is None


@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.stat")
def test_stat_path_exists(mock_stat, mock_exists):
    st = mock.MagicMock()
    st.st_mode = 0o100600
    st.st_uid = 0
    st.st_gid = 0
    mock_stat.return_value = st

    res = _stat_path("/etc/crontab")
    assert res["exists"] is True
    assert res["mode_octal"] == "0o600"
    assert res["uid"] == 0
    assert res["gid"] == 0


@mock.patch("collectors.job_schedulers_collector._stat_path")
@mock.patch("collectors.job_schedulers_collector._systemctl_state")
@mock.patch("collectors.job_schedulers_collector._dpkg_installed")
def test_collect_job_schedulers_top_level(mock_dpkg, mock_svc, mock_stat):
    mock_dpkg.side_effect = lambda pkg: pkg in ("cron", "at")
    mock_svc.return_value = {"unit": "cron.service", "enabled": "enabled", "active": "active"}
    mock_stat.side_effect = lambda p: {
        "path": p,
        "exists": p != "/etc/at.deny",
        "is_dir": False,
        "mode_octal": "0o600",
        "uid": 0,
        "gid": 0,
        "owner": "root",
        "group": "root",
    }

    res = collect_job_schedulers()
    assert "job_schedulers" in res
    js = res["job_schedulers"]

    assert js["cron"]["cron_installed"] is True
    assert len(js["cron"]["cron_paths_permissions"]) == 7
    assert js["at"]["at_installed"] is True
    assert js["at"]["at_allow_stat"]["exists"] is True
    assert js["at"]["at_deny_stat"]["exists"] is False
