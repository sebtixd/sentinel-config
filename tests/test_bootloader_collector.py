"""
test_bootloader_collector.py
=============================
Unit tests for collectors/bootloader_collector.py
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.bootloader_collector import (
    _read_file,
    _stat_path,
    collect_bootloader,
)


@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.stat")
def test_stat_path(mock_stat, mock_exists):
    mock_st = mock.Mock()
    mock_st.st_mode = 0o100400
    mock_st.st_uid = 0
    mock_st.st_gid = 0
    mock_stat.return_value = mock_st

    with mock.patch("pwd.getpwuid") as mock_pwd, mock.patch("grp.getgrgid") as mock_grp:
        mock_pwd.return_value.pw_name = "root"
        mock_grp.return_value.gr_name = "root"

        res = _stat_path("/boot/grub/grub.cfg")
        assert res["exists"] is True
        assert res["mode_octal"] == "0o400"
        assert res["owner"] == "root"


@mock.patch("collectors.bootloader_collector._read_file")
@mock.patch("collectors.bootloader_collector._stat_path")
def test_collect_bootloader(mock_stat, mock_rf):
    def side_rf(path):
        if path == "/boot/grub/grub.cfg":
            return "set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.1000.xxx\n"
        return None

    mock_rf.side_effect = side_rf
    mock_stat.return_value = {"path": "/boot/grub/grub.cfg", "exists": True, "mode_octal": "0o400", "owner": "root", "group": "root"}

    res = collect_bootloader()
    assert "bootloader" in res
    bl = res["bootloader"]
    assert bl["password_config"]["has_superusers"] is True
    assert bl["password_config"]["has_password"] is True
    assert len(bl["grub_cfg_permissions"]) > 0

    json_str = json.dumps(res)
    assert "bootloader" in json_str
