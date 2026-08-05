"""
test_filesystem_collector.py
=============================
Unit tests for collectors/filesystem_collector.py

Hermetic tests with mocked subprocess and file reads.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.filesystem_collector import (
    _run_cmd,
    _read_file,
    _collect_filesystem_kernel_modules,
    _parse_proc_mounts,
    _parse_fstab,
    _collect_filesystem_partitions,
    collect_filesystem,
)


@mock.patch("subprocess.run")
def test_run_cmd_success(mock_run):
    mock_run.return_value = mock.Mock(stdout="ok\n", stderr="", returncode=0)
    out, err, rc = _run_cmd(["echo", "ok"])
    assert out == "ok\n"
    assert rc == 0


@mock.patch("collectors.filesystem_collector._read_file")
@mock.patch("os.path.exists")
@mock.patch("os.listdir")
@mock.patch("collectors.filesystem_collector._run_cmd")
def test_collect_filesystem_kernel_modules(mock_run, mock_listdir, mock_exists, mock_rf):
    mock_run.return_value = ("cramfs 16384 0\noverlay 114688 2\n", "", 0)
    mock_exists.side_effect = lambda path: path == "/etc/modprobe.d"
    mock_listdir.return_value = ["cramfs.conf"]

    def side_rf(path):
        if path == "/etc/modprobe.d/cramfs.conf":
            return "install cramfs /bin/false\nblacklist cramfs\n"
        return None

    mock_rf.side_effect = side_rf

    errors: list = []
    modules, lsmod_raw = _collect_filesystem_kernel_modules(errors)

    cramfs_mod = next(m for m in modules if m["module_name"] == "cramfs")
    assert cramfs_mod["currently_loaded"] is True
    assert len(cramfs_mod["modprobe_config_lines"]) == 2

    freevxfs_mod = next(m for m in modules if m["module_name"] == "freevxfs")
    assert freevxfs_mod["currently_loaded"] is False
    assert len(lsmod_raw) == 2


@mock.patch("collectors.filesystem_collector._run_cmd")
def test_parse_proc_mounts_findmnt(mock_run):
    mock_run.return_value = (
        "/ ext4 rw,relatime /dev/sda1\n"
        "/tmp tmpfs rw,nosuid,nodev,noexec tmpfs\n"
        "/home ext4 rw,nodev,nosuid /dev/sda2\n",
        "",
        0,
    )
    mounts = _parse_proc_mounts()
    assert len(mounts) == 3
    assert mounts[1]["target"] == "/tmp"
    assert mounts[1]["fstype"] == "tmpfs"


@mock.patch("collectors.filesystem_collector._read_file")
def test_parse_fstab(mock_rf):
    mock_rf.return_value = (
        "# fstab sample\n"
        "UUID=1234 / ext4 defaults 0 1\n"
        "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0\n"
    )
    fstab = _parse_fstab()
    assert "/tmp" in fstab
    assert "defaults,noexec" in fstab["/tmp"]


@mock.patch("collectors.filesystem_collector._parse_fstab")
@mock.patch("collectors.filesystem_collector._parse_proc_mounts")
def test_collect_filesystem_partitions(mock_ppm, mock_pf):
    mock_ppm.return_value = [
        {"target": "/", "fstype": "ext4", "options": "rw,relatime", "source": "/dev/sda1"},
        {"target": "/tmp", "fstype": "tmpfs", "options": "rw,nosuid,nodev,noexec", "source": "tmpfs"},
        {"target": "/var", "fstype": "ext4", "options": "rw,nosuid,nodev", "source": "/dev/sda3"},
    ]
    mock_pf.return_value = {
        "/tmp": "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0"
    }

    errors: list = []
    parts = _collect_filesystem_partitions(errors)

    tmp_part = next(p for p in parts if p["mount_point"] == "/tmp")
    assert tmp_part["is_separate_partition"] is True
    assert tmp_part["fstype"] == "tmpfs"
    assert "nodev" in tmp_part["mount_options_list"]
    assert tmp_part["fstab_line"] is not None

    audit_part = next(p for p in parts if p["mount_point"] == "/var/log/audit")
    assert audit_part["is_separate_partition"] is False
    # Fallback to parent /var
    assert audit_part["fstype"] == "ext4"


@mock.patch("collectors.filesystem_collector._collect_filesystem_partitions")
@mock.patch("collectors.filesystem_collector._collect_filesystem_kernel_modules")
def test_collect_filesystem_top_level(mock_km, mock_fp):
    mock_km.return_value = ([], ["cramfs"])
    mock_fp.return_value = []

    res = collect_filesystem()
    assert "filesystem" in res
    fs = res["filesystem"]
    assert "filesystem_kernel_modules" in fs
    assert "filesystem_partitions" in fs
    assert "lsmod_raw" in fs

    # Verify JSON serialisability
    json_str = json.dumps(res)
    assert "filesystem_partitions" in json_str
