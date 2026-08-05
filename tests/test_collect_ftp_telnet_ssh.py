"""
test_collect_ssh_bridge.py
===========================
Unit tests for the SSH collector bridge (collect_ssh).

Note: collect_ftp and collect_telnet have been migrated into
collectors/services_collector.py (CIS Section 2). Their tests are in
tests/test_services_collector.py.
"""

from unittest.mock import MagicMock, patch

from collectors.collect_ssh import collect_ssh_from_ssh


@patch("subprocess.run")
def test_collect_ssh_from_ssh(mock_sub_run):
    """Verify collect_ssh_from_ssh runs ssh-audit locally and collects sshd config remotely."""
    mock_ssh = MagicMock()

    # Mock local ssh-audit subprocess run with a sample CVE warning
    mock_audit_res = MagicMock()
    mock_audit_res.stdout = (
        "(gen) banner: SSH-2.0-OpenSSH_9.3\n"
        "(rec) -kex diffie-hellman-group1-sha1 -- CVE-2023-48795 Terrapin attack\n"
    )
    mock_sub_run.return_value = mock_audit_res

    def exec_side_effect(cmd, timeout=None):
        mock_stdout = MagicMock()
        if "sshd -T" in cmd:
            mock_stdout.read.return_value = b"port 22\nprotocol 2\npermitrootlogin no"
        elif "stat" in cmd and "sshd_config" in cmd:
            mock_stdout.read.return_value = b"600 root root /etc/ssh/sshd_config"
        else:
            mock_stdout.read.return_value = b""
        return MagicMock(), mock_stdout, MagicMock()

    mock_ssh.exec_command.side_effect = exec_side_effect

    profile = collect_ssh_from_ssh(mock_ssh, hostname="127.0.0.1", port=22, password="pass")

    assert profile["ssh"]["port"] == 22
    assert profile["ssh"]["authentication"]["permit_root_login"] is False
    assert profile["ssh"]["sshd_config_permissions"] == "600 root root /etc/ssh/sshd_config"
    assert len(profile["vulnerabilities"]) > 0
    assert profile["vulnerabilities"][0]["cve"] == "CVE-2023-48795"
