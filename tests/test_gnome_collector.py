"""
test_gnome_collector.py
========================
Unit tests for collectors/gnome_collector.py
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.gnome_collector import (
    _run_cmd,
    _read_file,
    _search_dconf_dir,
    collect_gnome,
)


@mock.patch("collectors.gnome_collector._run_cmd")
def test_collect_gnome_not_installed(mock_run):
    mock_run.return_value = ("dpkg-query: package 'gdm3' is not installed\n", "", 1)

    res = collect_gnome()
    assert "gnome" in res
    gn = res["gnome"]
    assert gn["gdm_installed"] is False
    assert gn["gdm3_custom_conf"] is None


@mock.patch("collectors.gnome_collector._run_cmd")
@mock.patch("collectors.gnome_collector._read_file")
@mock.patch("os.path.exists")
@mock.patch("os.walk")
def test_collect_gnome_installed(mock_walk, mock_exists, mock_rf, mock_run):
    mock_run.return_value = ("Status: install ok installed\n", "", 0)
    mock_exists.side_effect = lambda path: path in ("/etc/dconf/db", "/etc/gdm3/custom.conf")
    mock_walk.return_value = [
        ("/etc/dconf/db/gdm.d", [], ["00-security-settings.conf"]),
        ("/etc/dconf/db/gdm.d/locks", [], ["00-security-settings-locks"]),
    ]

    def side_rf(path):
        if "00-security-settings.conf" in path:
            return "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized Use Only'\ndisable-user-list=true\n"
        if "00-security-settings-locks" in path:
            return "/org/gnome/login-screen/banner-message-enable\n/org/gnome/login-screen/banner-message-text\n"
        if path == "/etc/gdm3/custom.conf":
            return "[daemon]\nWaylandEnable=false\n[xdmcp]\nEnable=false\n"
        return None

    mock_rf.side_effect = side_rf

    res = collect_gnome()
    assert "gnome" in res
    gn = res["gnome"]
    assert gn["gdm_installed"] is True
    assert len(gn["dconf_settings"]) == 3
    assert len(gn["dconf_locks"]) == 2
    assert "WaylandEnable=false" in gn["gdm3_custom_conf_content"]

    json_str = json.dumps(res)
    assert "gnome" in json_str
