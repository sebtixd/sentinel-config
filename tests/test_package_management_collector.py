"""
test_package_management_collector.py
=====================================
Unit tests for collectors/package_management_collector.py

Hermetic tests with mocked subprocess, file reads, and os.stat.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.package_management_collector import (
    _run_cmd,
    _read_file,
    _stat_path,
    _collect_package_repositories,
    _collect_package_updates,
    collect_package_management,
)


@mock.patch("subprocess.run")
def test_run_cmd_success(mock_run):
    mock_run.return_value = mock.Mock(stdout="ok\n", stderr="", returncode=0)
    out, err, rc = _run_cmd(["echo", "ok"])
    assert out == "ok\n"
    assert rc == 0


@mock.patch("os.path.exists", return_value=False)
def test_stat_path_nonexistent(mock_exists):
    res = _stat_path("/nonexistent/path")
    assert res["exists"] is False
    assert res["mode_octal"] is None


@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.stat")
def test_stat_path_file(mock_stat, mock_exists):
    mock_st = mock.Mock()
    mock_st.st_mode = 0o100644  # regular file 644
    mock_st.st_uid = 0
    mock_st.st_gid = 0
    mock_stat.return_value = mock_st

    with mock.patch("pwd.getpwuid") as mock_pwd, mock.patch("grp.getgrgid") as mock_grp:
        mock_pwd.return_value.pw_name = "root"
        mock_grp.return_value.gr_name = "root"

        res = _stat_path("/etc/apt/sources.list")
        assert res["exists"] is True
        assert res["mode_octal"] == "0o644"
        assert res["owner"] == "root"
        assert res["group"] == "root"
        assert res["is_dir"] is False


@mock.patch("collectors.package_management_collector._read_file")
@mock.patch("os.path.exists")
@mock.patch("os.listdir")
def test_collect_package_repositories(mock_listdir, mock_exists, mock_rf):
    mock_exists.side_effect = lambda path: path in ("/etc/apt/sources.list.d", "/etc/apt/apt.conf.d")
    mock_listdir.side_effect = lambda path: ["ubuntu.sources"] if "sources" in path else ["99weak.conf"]

    def side_rf(path):
        if path == "/etc/apt/sources.list":
            return "deb http://archive.ubuntu.com/ubuntu noble main\n"
        if "ubuntu.sources" in path:
            return "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
        if "99weak.conf" in path:
            return 'APT::Install-Recommends "false";\n'
        return None

    mock_rf.side_effect = side_rf

    errors: list = []
    res = _collect_package_repositories(errors)

    assert len(res["sources_files"]) == 2
    sources_file = next(f for f in res["sources_files"] if "ubuntu.sources" in f["path"])
    assert sources_file["has_signed_by"] is True
    assert len(sources_file["matching_signed_by_lines"]) == 1

    assert len(res["weak_deps_config_lines"]) == 1
    assert 'Install-Recommends "false"' in res["weak_deps_config_lines"][0]["line"]


@mock.patch("collectors.package_management_collector._run_cmd")
@mock.patch("collectors.package_management_collector._read_file")
def test_collect_package_updates(mock_rf, mock_run):
    def side_run(cmd, timeout=15):
        if cmd[:3] == ["apt", "list", "--upgradable"]:
            return ("Listing...\ncurl/noble-updates 8.5.0-2ubuntu10.1 amd64 [upgradable from: 8.5.0-2ubuntu10]\n", "", 0)
        if cmd[:3] == ["dpkg", "-s", "unattended-upgrades"]:
            return ("Status: install ok installed\n", "", 0)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return ("enabled\n", "", 0)
        if cmd[:2] == ["systemctl", "is-active"]:
            return ("active\n", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_run
    mock_rf.return_value = 'APT::Periodic::Update-Package-Lists "1";\n'

    res = _collect_package_updates([])

    assert res["upgradable_package_count"] == 1
    assert "curl" in res["upgradable_packages"][0]
    assert res["unattended_upgrades_installed"] is True
    assert res["unattended_upgrades_service_enabled"] == "enabled"
    assert res["apt_cache_error"] is None


@mock.patch("collectors.package_management_collector._collect_package_updates")
@mock.patch("collectors.package_management_collector._collect_package_repositories")
def test_collect_package_management_top_level(mock_repos, mock_updates):
    mock_repos.return_value = {}
    mock_updates.return_value = {}

    res = collect_package_management()
    assert "package_management" in res
    pkg = res["package_management"]
    assert "package_repositories" in pkg
    assert "package_updates" in pkg

    # Verify JSON serialisability
    json_str = json.dumps(res)
    assert "package_repositories" in json_str
