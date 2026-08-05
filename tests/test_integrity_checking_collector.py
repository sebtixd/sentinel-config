import pytest
from unittest.mock import patch
from collectors.integrity_checking_collector import collect_integrity_checking


@patch("collectors.integrity_checking_collector.os.listdir")
@patch("collectors.integrity_checking_collector.os.path.exists")
@patch("collectors.integrity_checking_collector._read_file")
@patch("collectors.integrity_checking_collector._run_cmd")
def test_integrity_checking_collector_not_installed(mock_run_cmd, mock_read, mock_exists, mock_listdir):
    # Simulate not installed
    def run_cmd_side_effect(cmd):
        if cmd[0] == "dpkg":
            return "", "", 1  # Not found
        if cmd[0] == "which":
            return "", "", 1
        return "", "", 0

    mock_run_cmd.side_effect = run_cmd_side_effect
    
    result = collect_integrity_checking()
    assert "aide_integrity_checking" in result
    data = result["aide_integrity_checking"]
    assert data["aide_installed"] is False
    assert data["scheduled_checking"] is None
    assert data["audit_tools_integrity_tracked"] is None
    

@patch("collectors.integrity_checking_collector.os.listdir")
@patch("collectors.integrity_checking_collector.os.path.exists")
@patch("collectors.integrity_checking_collector._read_file")
@patch("collectors.integrity_checking_collector._run_cmd")
def test_integrity_checking_collector_installed(mock_run_cmd, mock_read, mock_exists, mock_listdir):
    # Simulate installed aide
    def run_cmd_side_effect(cmd):
        if cmd == ["dpkg", "-s", "aide"]:
            return "Status: install ok installed", "", 0
        elif cmd == ["dpkg", "-s", "aide-common"]:
            return "", "not installed", 1
        elif cmd == ["which", "aide"]:
            return "/usr/bin/aide", "", 0
        elif cmd == ["crontab", "-l"]:
            return "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check\n# some comment\n", "", 0
        elif cmd[0] == "systemctl":
            if cmd[1] == "is-active":
                return "active\n", "", 0
            elif cmd[1] == "is-enabled":
                return "enabled\n", "", 0
        return "", "", 0

    mock_run_cmd.side_effect = run_cmd_side_effect

    def read_file_side_effect(path):
        if path == "/etc/crontab":
            return "0 5 * * * root /usr/bin/aide --check\n"
        if path == "/etc/aide/aide.conf":
            return "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512\n/etc/other  p+i+n\n# /sbin/ausearch test"
        if "aide.conf.d" in path:
            return ""
        return None

    mock_read.side_effect = read_file_side_effect
    
    def exists_side_effect(path):
        if path in ["/etc/cron.d", "/etc/aide/aide.conf.d"]:
            return True
        return False
        
    mock_exists.side_effect = exists_side_effect
    
    def listdir_side_effect(path):
        if path == "/etc/cron.d":
            return ["aidecheck"]
        if path == "/etc/aide/aide.conf.d":
            return ["31_aide_audit.conf"]
        return []
        
    mock_listdir.side_effect = listdir_side_effect

    result = collect_integrity_checking()
    data = result["aide_integrity_checking"]
    
    assert data["aide_installed"] is True
    assert data["dpkg_aide"] is True
    assert data["dpkg_aide_common"] is False
    
    # Check scheduled checking
    checks = data["scheduled_checking"]
    assert len(checks["cron_jobs_found"]) == 2  # one from /etc/crontab, one from crontab -l (because cron.d check returns None from _read_file here)
    systemd_checks = checks["systemd_units_found"]
    assert len(systemd_checks) == 3
    assert systemd_checks[0]["active"] == "active"
    
    # Check audit tools
    audit_tools = data["audit_tools_integrity_tracked"]
    assert "/sbin/auditctl" in audit_tools["tools_checked"]
    assert len(audit_tools["matching_aide_config_lines"]) == 1
    assert "p+i+n+u" in audit_tools["matching_aide_config_lines"][0]["line"]
