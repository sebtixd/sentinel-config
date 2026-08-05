import json
import os
import subprocess
from unittest import mock

import pytest

from collectors.system_logging_collector import (
    _run_cmd,
    _read_file,
    _read_conf_dir,
    _stat_file_or_dir,
    collect_system_logging,
)

@mock.patch("subprocess.run")
def test_run_cmd(mock_run):
    mock_run.return_value = mock.Mock(stdout="active\n", stderr="", returncode=0)
    stdout, stderr, rc = _run_cmd(["systemctl", "is-active", "something"])
    assert stdout == "active\n"
    assert rc == 0
    mock_run.assert_called_once()

@mock.patch("builtins.open", mock.mock_open(read_data="test data"))
def test_read_file():
    assert _read_file("/fake/path") == "test data"

@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.listdir", return_value=["a.conf", "b.conf", "c.txt"])
@mock.patch("collectors.system_logging_collector._read_file", return_value="contents")
def test_read_conf_dir(mock_read_file, mock_listdir, mock_exists):
    res = _read_conf_dir("/fake/dir", ".conf")
    assert len(res) == 2
    assert res[0]["path"] == "/fake/dir/a.conf"
    assert res[1]["path"] == "/fake/dir/b.conf"

@mock.patch("os.path.lexists", return_value=True)
@mock.patch("os.stat")
def test_stat_file_or_dir(mock_stat, mock_lexists):
    mock_st = mock.Mock()
    mock_st.st_mode = 0o100644
    mock_st.st_uid = 1000
    mock_st.st_gid = 1000
    mock_stat.return_value = mock_st
    
    res = _stat_file_or_dir("/fake/file")
    assert res == {
        "path": "/fake/file",
        "mode": "0644",
        "owner_uid": 1000,
        "group_gid": 1000,
    }


@mock.patch("collectors.system_logging_collector._run_cmd")
@mock.patch("collectors.system_logging_collector._read_file")
@mock.patch("collectors.system_logging_collector._read_conf_dir")
@mock.patch("collectors.system_logging_collector._stat_file_or_dir")
@mock.patch("os.path.exists")
@mock.patch("os.listdir")
@mock.patch("os.walk")
def test_collect_system_logging(
    mock_walk, mock_listdir, mock_exists, mock_stat,
    mock_read_conf, mock_read_file, mock_run_cmd
):
    # Setup mocks
    mock_run_cmd.return_value = ("active", "", 0)
    mock_read_file.return_value = "config_stuff"
    mock_read_conf.return_value = [{"path": "a.conf", "content": "conf"}]
    
    mock_stat.return_value = {
        "path": "/some/path",
        "mode": "0640",
        "owner_uid": 0,
        "group_gid": 0,
    }
    
    mock_exists.return_value = True
    mock_listdir.return_value = []
    
    # Let os.walk return one file matching rules, and one .gz to be skipped
    mock_walk.return_value = [
        ("/var/log", [], ["auth.log", "syslog.1", "messages.gz", "wtmp"])
    ]
    
    res = collect_system_logging()
    
    assert "system_logging" in res
    sl = res["system_logging"]
    assert "journald" in sl
    assert "rsyslog" in sl
    assert "logfiles" in sl
    assert "errors" in sl
    
    # Check journald
    assert sl["journald"]["systemd-journald_active"] == "active"
    assert sl["journald"]["systemd-journal-remote_installed"] is False # because "install ok installed" not in "active"
    assert len(sl["journald"]["journald_configs"]) == 2  # main conf + 1 dir conf
    
    # Check rsyslog
    assert sl["rsyslog"]["rsyslog_active"] == "active"
    assert sl["rsyslog"]["rsyslog_gnutls_installed"] is False
    
    # Check logfiles filtration
    # auth.log and wtmp should be kept. syslog.1 and messages.gz skipped.
    assert len(sl["logfiles"]) == 2
