"""
test_common_collector_utils.py
===============================
Unit tests for collectors/common.py shared helper utilities.
"""

from __future__ import annotations

import os
from unittest import mock

from collectors.common import (
    dpkg_installed,
    get_sysctl_persisted,
    get_sysctl_runtime,
    load_sysctl_conf_lines,
    read_file,
    run_cmd,
    stat_path,
    systemctl_state,
)


def test_run_cmd_success():
    stdout, stderr, rc = run_cmd(["echo", "hello"])
    assert rc == 0
    assert "hello" in stdout


def test_run_cmd_error():
    stdout, stderr, rc = run_cmd(["nonexistent_cmd_12345"])
    assert rc == -1
    assert stderr != ""


def test_read_file_existing(tmp_path):
    fpath = tmp_path / "test.txt"
    fpath.write_text("sample content", encoding="utf-8")
    assert read_file(str(fpath)) == "sample content"


def test_read_file_nonexistent():
    assert read_file("/nonexistent/file/path/xyz") is None


@mock.patch("collectors.common.run_cmd")
def test_dpkg_installed(mock_run):
    mock_run.return_value = ("Status: install ok installed\n", "", 0)
    assert dpkg_installed("cron") is True

    mock_run.return_value = ("Status: deinstall ok config-files\n", "", 1)
    assert dpkg_installed("cron") is False


@mock.patch("collectors.common.run_cmd")
def test_systemctl_state(mock_run):
    mock_run.side_effect = [
        ("enabled\n", "", 0),
        ("active\n", "", 0),
    ]
    res = systemctl_state("cron.service")
    assert res == {"unit": "cron.service", "enabled": "enabled", "active": "active"}


def test_stat_path_nonexistent():
    res = stat_path("/nonexistent/path/xyz")
    assert res["exists"] is False
    assert res["mode_octal"] is None


def test_stat_path_existing(tmp_path):
    fpath = tmp_path / "file.txt"
    fpath.write_text("data")
    res = stat_path(str(fpath))
    assert res["exists"] is True
    assert res["is_dir"] is False
    assert res["mode_octal"] is not None


@mock.patch("collectors.common.run_cmd")
def test_get_sysctl_runtime(mock_run):
    mock_run.return_value = ("1\n", "", 0)
    assert get_sysctl_runtime("fs.protected_hardlinks") == "1"


def test_get_sysctl_persisted():
    lines = [
        ("/etc/sysctl.conf", "fs.protected_hardlinks = 0"),
        ("/etc/sysctl.d/99-sysctl.conf", "fs.protected_hardlinks = 1"),
    ]
    val, src = get_sysctl_persisted("fs.protected_hardlinks", lines)
    assert val == "1"
    assert src == "/etc/sysctl.d/99-sysctl.conf"


@mock.patch("collectors.common.read_file")
@mock.patch("os.path.exists")
def test_load_sysctl_conf_lines(mock_exists, mock_rf):
    mock_exists.side_effect = lambda p: p == "/etc/sysctl.d"
    mock_rf.side_effect = lambda p: (
        "fs.protected_hardlinks = 1\n# comment\n"
        if p == "/etc/sysctl.conf"
        else None
    )

    lines = load_sysctl_conf_lines()
    assert len(lines) == 1
    assert lines[0] == ("/etc/sysctl.conf", "fs.protected_hardlinks = 1")
