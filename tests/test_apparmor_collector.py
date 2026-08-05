"""
test_apparmor_collector.py
===========================
Unit tests for collectors/apparmor_collector.py
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.apparmor_collector import (
    _run_cmd,
    _read_file,
    _get_sysctl_runtime,
    _get_sysctl_persisted,
    collect_apparmor,
)


@mock.patch("subprocess.run")
def test_run_cmd(mock_run):
    mock_run.return_value = mock.Mock(stdout="Y\n", stderr="", returncode=0)
    out, err, rc = _run_cmd(["echo", "Y"])
    assert out == "Y\n"
    assert rc == 0


@mock.patch("collectors.apparmor_collector._run_cmd")
@mock.patch("collectors.apparmor_collector._read_file")
def test_collect_apparmor(mock_rf, mock_run):
    def side_run(cmd, timeout=10):
        if cmd[:3] == ["dpkg", "-s", "apparmor"]:
            return ("Status: install ok installed\n", "", 0)
        if cmd[:3] == ["dpkg", "-s", "apparmor-utils"]:
            return ("Status: install ok installed\n", "", 0)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return ("enabled\n", "", 0)
        if cmd[:2] == ["systemctl", "is-active"]:
            return ("active\n", "", 0)
        if cmd == ["aa-status"]:
            return ("apparmor module is loaded.\n32 profiles are loaded.\n0 profiles are in complain mode.\n0 processes are unconfined.\n", "", 0)
        if cmd[:2] == ["sysctl", "-n"]:
            return ("1\n", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_run

    def side_rf(path):
        if path == "/sys/module/apparmor/parameters/enabled":
            return "Y\n"
        if path == "/etc/default/grub":
            return 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"\n'
        return None

    mock_rf.side_effect = side_rf

    res = collect_apparmor()
    assert "apparmor" in res
    aa = res["apparmor"]
    assert aa["packages"]["apparmor_installed"] is True
    assert aa["enabled_status"]["sysfs_enabled_value"] == "Y"
    assert aa["enabled_status"]["grub_apparmor_flag"] is True
    assert aa["aa_status"]["return_code"] == 0
    assert aa["restrict_unprivileged_sysctl"]["runtime_value"] == "1"

    json_str = json.dumps(res)
    assert "apparmor" in json_str
