import json
import os
import subprocess
from unittest import mock

import pytest

from collectors.auditd_collector import (
    _run_cmd,
    _read_file,
    _read_conf_dir,
    _stat_file_or_dir,
    collect_auditd,
)

@mock.patch("subprocess.run")
def test_collect_auditd_not_installed(mock_run):
    # Simulate dpkg failing
    mock_run.return_value = mock.Mock(stdout="", stderr="", returncode=1)
    
    res = collect_auditd()
    assert "system_auditing" in res
    sa = res["system_auditing"]
    assert sa["auditd_installed"] is False
    assert len(sa["errors"]) == 1
    assert "not installed" in sa["errors"][0]["error"]

@mock.patch("collectors.auditd_collector._run_cmd")
@mock.patch("collectors.auditd_collector._read_file")
@mock.patch("collectors.auditd_collector._read_conf_dir")
@mock.patch("collectors.auditd_collector._stat_file_or_dir")
@mock.patch("os.path.exists")
@mock.patch("os.path.lexists")
@mock.patch("os.listdir")
def test_collect_auditd_installed(
    mock_listdir, mock_lexists, mock_exists, mock_stat,
    mock_read_conf, mock_read_file, mock_run_cmd
):
    def mock_run_side_effect(cmd, *args, **kwargs):
        if cmd == ["dpkg", "-s", "auditd"]:
            return ("install ok installed", "", 0)
        elif cmd == ["dpkg", "-s", "audispd-plugins"]:
            return ("install ok installed", "", 0)
        elif cmd == ["uname", "-m"]:
            return ("x86_64", "", 0)
        elif cmd[0] == "auditctl":
            if "-l" in cmd:
                return ("-w /etc/sudoers -p wa -k scope", "", 0)
            if "-s" in cmd:
                return ("enabled 2", "", 0)
        return ("active", "", 0)
        
    mock_run_cmd.side_effect = mock_run_side_effect
    mock_read_file.return_value = "config_stuff"
    mock_read_conf.return_value = [{"path": "/etc/audit/rules.d/test.rules", "content": "conf"}]
    
    # ensure it returns a stat standard
    mock_stat.return_value = {
        "path": "/sbin/auditctl",
        "exists": True,
        "mode": "0755",
        "owner_uid": 0,
        "group_gid": 0,
    }
    
    mock_exists.return_value = True
    mock_lexists.return_value = True
    mock_listdir.return_value = ["file1", "file2"]
    
    res = collect_auditd()
    sa = res["system_auditing"]
    
    assert sa["auditd_installed"] is True
    assert sa["auditd_service"]["auditd_active"] == "active"
    assert sa["data_retention"]["auditd_conf_raw"] == "config_stuff"
    
    # verify rules explicitly mapped
    rules = sa["audit_rules_raw"]
    assert rules["kernel_arch"] == "x86_64"
    assert rules["auditctl_l_raw"] == "-w /etc/sudoers -p wa -k scope"
    assert rules["auditctl_s_raw"] == "enabled 2"
    assert rules["etc_audit_audit_rules"] == "config_stuff"
    
    # 6.2.4 file access verification should populate heavily via lists
    assert len(sa["auditd_file_access"]) > 0
    # ensure one of the stat targets is there
    paths_statted = [item["path"] for item in sa["auditd_file_access"]]
    assert "/etc/audit/auditd.conf" in [x.split('/')[-1] if not x.startswith('/') else x for x in paths_statted] or "/sbin/auditctl" in paths_statted
