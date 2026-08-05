"""
test_process_hardening_collector.py
===================================
Unit tests for collectors/process_hardening_collector.py
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.process_hardening_collector import (
    _run_cmd,
    _read_file,
    _get_sysctl_runtime,
    _get_sysctl_persisted,
    collect_process_hardening,
)


@mock.patch("collectors.process_hardening_collector._run_cmd")
@mock.patch("collectors.process_hardening_collector._read_file")
@mock.patch("os.path.exists", return_value=True)
def test_collect_process_hardening(mock_exists, mock_rf, mock_run):
    def side_run(cmd, timeout=10):
        if cmd[:2] == ["sysctl", "-n"]:
            return ("1\n", "", 0)
        if cmd[:3] == ["dpkg", "-s", "prelink"]:
            return ("dpkg-query: package 'prelink' is not installed\n", "", 1)
        if cmd[:3] == ["dpkg", "-s", "apport"]:
            return ("Status: install ok installed\n", "", 0)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return ("disabled\n", "", 0)
        if cmd[:2] == ["systemctl", "is-active"]:
            return ("inactive\n", "", 0)
        if "ulimit" in cmd[-1]:
            return ("0\n", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_run

    def side_rf(path):
        if path == "/etc/default/apport":
            return "enabled=0\n"
        if path == "/etc/security/limits.conf":
            return "* hard core 0\n"
        if path == "/etc/systemd/coredump.conf":
            return "ProcessSizeMax=0\nStorage=none\n"
        return None

    mock_rf.side_effect = side_rf

    res = collect_process_hardening()
    assert "process_hardening" in res
    ph = res["process_hardening"]
    assert ph["prelink"]["prelink_installed"] is False
    assert ph["apport"]["apport_installed"] is True
    assert ph["apport"]["service_enabled"] == "disabled"
    assert ph["core_dumps"]["ulimit_soft_core"] == "0"
    assert len(ph["core_dumps"]["systemd_coredump_process_size_max"]) == 1

    json_str = json.dumps(res)
    assert "process_hardening" in json_str
