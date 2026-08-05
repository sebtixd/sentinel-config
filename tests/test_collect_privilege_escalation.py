"""
test_collect_privilege_escalation.py
=====================================
Unit tests for collect_privilege_escalation.py execution and parsing logic.
"""

import os
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from collectors.collect_privilege_escalation import collect_privilege_escalation


def test_collect_privilege_escalation_sudo_not_installed(tmp_path):
    """
    Test scenario: sudo command is missing from PATH (sudo not installed).
    """
    original_exists = os.path.exists
    # Helper to redirect path checks to tmp_path
    def mock_exists(p):
        if p.startswith("/etc/") or p.startswith("/var/"):
            return False
        return original_exists(p)

    def mock_run(cmd, *args, **kwargs):
        if cmd[0] == "sudo":
            raise FileNotFoundError("[Errno 2] No such file or directory: 'sudo'")
        if cmd[0] == "dpkg":
            raise FileNotFoundError("[Errno 2] No such file or directory: 'dpkg'")
        if cmd[0:2] == ["getent", "group"]:
            # mock getent groups not found
            res = MagicMock()
            res.returncode = 2
            res.stdout = ""
            res.stderr = ""
            return res
        raise ValueError(f"Unexpected subprocess call: {cmd}")

    with patch("os.path.exists", side_effect=mock_exists), \
         patch("subprocess.run", side_effect=mock_run):
        data = collect_privilege_escalation()

        assert data["sudo_installed"] == {
            "installed": False,
            "version_output": None,
            "dpkg_status": None,
        }
        assert data["sudoers_files_scanned"] == []
        assert data["sudoers_defaults_lines"] == []
        assert data["use_pty_entries"] == []
        assert data["logfile_entries"] == []
        assert data["logfile_exists_checks"] == []
        assert data["sudo_syslog_logging"] == {
            "auth_log_exists": False,
            "syslog_log_exists": False,
            "rsyslog_authpriv_configured": False,
            "rsyslog_configs_checked": [],
            "syslog_ng_config_exists": False,
            "journald_sudo_evidence": None,
        }
        assert data["nopasswd_entries"] == []
        assert data["noauthenticate_entries"] == []
        assert data["timestamp_timeout_entries"] == []
        assert data["su_restriction"] == {
            "pam_su_config": None,
            "pam_wheel_line": None,
            "wheel_group_members": None,
            "wheel_group_source": None,
        }
        # errors might contain check failures or show empty if everything was handled gracefully
        assert isinstance(data["errors"], list)


def test_collect_privilege_escalation_full_mock(tmp_path):
    """
    Test scenario: Sudo is installed. Full config exists on disk with specific settings.
    """
    fake_sudoers_content = (
        "Defaults use_pty,logfile=/var/log/sudo.log\n"
        "Defaults timestamp_timeout=15\n"
        "Defaults env_keep += \"LANG\"\n"
    )
    fake_rule1_content = (
        "alice ALL=(ALL) NOPASSWD: ALL\n"
        "bob ALL=(ALL) !authenticate: ALL\n"
    )
    fake_pam_su_content = (
        "#%PAM-1.0\n"
        "auth            sufficient      pam_rootok.so\n"
        "auth            required        pam_wheel.so use_uid\n"
    )
    fake_logfile_content = "some logs"

    # Set up folders and files physically inside tmp_path
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc/sudoers").write_text(fake_sudoers_content, encoding="utf-8")
    (tmp_path / "etc/sudoers.d").mkdir(exist_ok=True)
    (tmp_path / "etc/sudoers.d/01_rule").write_text(fake_rule1_content, encoding="utf-8")
    (tmp_path / "etc/sudoers.d/.ignored").write_text("ignore me", encoding="utf-8")
    (tmp_path / "etc/sudoers.d/rule.bak").write_text("ignore me bak", encoding="utf-8")
    
    (tmp_path / "etc/pam.d").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc/pam.d/su").write_text(fake_pam_su_content, encoding="utf-8")
    
    (tmp_path / "var/log").mkdir(parents=True, exist_ok=True)
    (tmp_path / "var/log/sudo.log").write_text(fake_logfile_content, encoding="utf-8")
    (tmp_path / "var/log/auth.log").write_text("auth log logs", encoding="utf-8")
    
    (tmp_path / "etc/rsyslog.conf").write_text("authpriv.* /var/log/auth.log\n", encoding="utf-8")

    # Helper paths mapping logic
    def redirect_path(p):
        if p.startswith("/etc/") or p.startswith("/var/"):
            return str(tmp_path / p.lstrip("/"))
        if p in ("/etc", "/var"):
            return str(tmp_path / p.lstrip("/"))
        return p

    original_exists = os.path.exists
    original_isdir = os.path.isdir
    original_isfile = os.path.isfile
    original_listdir = os.listdir
    original_open = open
    original_stat = os.stat

    def mock_exists(p):
        return original_exists(redirect_path(p))

    def mock_isdir(p):
        return original_isdir(redirect_path(p))

    def mock_isfile(p):
        return original_isfile(redirect_path(p))

    def mock_listdir(p):
        return original_listdir(redirect_path(p))

    def mock_stat(p, *args, **kwargs):
        return original_stat(redirect_path(p), *args, **kwargs)

    def mock_open_func(file, *args, **kwargs):
        return original_open(redirect_path(file), *args, **kwargs)

    # Subprocess queries
    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        if cmd[0] == "sudo" and cmd[1] == "-V":
            res.stdout = "Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\n"
            res.stderr = ""
        elif cmd[0] == "dpkg" and cmd[1:3] == ["-l", "sudo"]:
            res.stdout = "ii  sudo           1.9.15p5-3   amd64        Provide limited super privileges\n"
            res.stderr = ""
        elif cmd[0:2] == ["getent", "group"]:
            # Ubuntu uses "sudo" group
            if cmd[2] == "sudo":
                res.stdout = "sudo:x:27:alice,bob,charlie\n"
            elif cmd[2] == "wheel":
                # Ensure we don't query wheel if sudo is found, but just in case
                res.stdout = "wheel:x:998:admin\n"
            res.stderr = ""
        elif cmd[0] == "journalctl":
            res.stdout = "Jul 08 17:50:00 hostname sudo[123]: session opened for user root\n"
            res.stderr = ""
        else:
            raise ValueError(f"Unexpected command: {cmd}")
        return res

    with patch("os.path.exists", side_effect=mock_exists), \
         patch("os.path.isdir", side_effect=mock_isdir), \
         patch("os.path.isfile", side_effect=mock_isfile), \
         patch("os.listdir", side_effect=mock_listdir), \
         patch("os.stat", side_effect=mock_stat), \
         patch("builtins.open", side_effect=mock_open_func), \
         patch("subprocess.run", side_effect=mock_run), \
         patch("collectors.collect_privilege_escalation.pwd.getpwuid") as mock_pwd:

        mock_user = MagicMock()
        mock_user.pw_name = "root"
        mock_pwd.return_value = mock_user

        data = collect_privilege_escalation()

        # Check sudo version & package details
        assert data["sudo_installed"]["installed"] is True
        assert "Sudo version 1.9.15p5" in data["sudo_installed"]["version_output"]
        assert "ii  sudo           1.9.15p5-3" in data["sudo_installed"]["dpkg_status"]

        # Check scanned files
        assert "/etc/sudoers" in data["sudoers_files_scanned"]
        assert "/etc/sudoers.d/01_rule" in data["sudoers_files_scanned"]
        # Ignored files should not be in there
        assert "/etc/sudoers.d/.ignored" not in data["sudoers_files_scanned"]
        assert "/etc/sudoers.d/rule.bak" not in data["sudoers_files_scanned"]

        # Check Defaults lines
        defaults = data["sudoers_defaults_lines"]
        assert len(defaults) == 3
        assert defaults[0] == {"file": "/etc/sudoers", "line_number": 1, "content": "Defaults use_pty,logfile=/var/log/sudo.log"}
        assert defaults[1] == {"file": "/etc/sudoers", "line_number": 2, "content": "Defaults timestamp_timeout=15"}
        
        # Check use_pty
        assert len(data["use_pty_entries"]) == 1
        assert data["use_pty_entries"][0]["file"] == "/etc/sudoers"
        assert "use_pty" in data["use_pty_entries"][0]["content"]

        # Check logfile entries
        assert len(data["logfile_entries"]) == 1
        assert data["logfile_entries"][0]["file"] == "/etc/sudoers"
        assert "logfile=/var/log/sudo.log" in data["logfile_entries"][0]["content"]

        # Check logfile existence checks
        assert len(data["logfile_exists_checks"]) == 1
        chk = data["logfile_exists_checks"][0]
        assert chk["configured_path"] == "/var/log/sudo.log"
        assert chk["exists"] is True
        assert chk["owner"] == "root"
        assert chk["permissions"] is not None

        # Check syslog checks
        sys_l = data["sudo_syslog_logging"]
        assert sys_l["auth_log_exists"] is True
        assert sys_l["syslog_log_exists"] is False
        assert sys_l["rsyslog_authpriv_configured"] is True
        assert "/etc/rsyslog.conf" in sys_l["rsyslog_configs_checked"]
        assert sys_l["journald_sudo_evidence"] is not None
        assert "session opened" in sys_l["journald_sudo_evidence"]

        # Check NOPASSWD and !authenticate entries
        assert len(data["nopasswd_entries"]) == 1
        assert data["nopasswd_entries"][0]["file"] == "/etc/sudoers.d/01_rule"
        assert data["nopasswd_entries"][0]["line_number"] == 1
        assert "NOPASSWD" in data["nopasswd_entries"][0]["content"]

        assert len(data["noauthenticate_entries"]) == 1
        assert data["noauthenticate_entries"][0]["file"] == "/etc/sudoers.d/01_rule"
        assert data["noauthenticate_entries"][0]["line_number"] == 2
        assert "!authenticate" in data["noauthenticate_entries"][0]["content"]

        # Check timestamp_timeout_entries
        assert len(data["timestamp_timeout_entries"]) == 1
        assert data["timestamp_timeout_entries"][0]["file"] == "/etc/sudoers"
        assert "timestamp_timeout=15" in data["timestamp_timeout_entries"][0]["content"]

        # Check su restrictions
        su_r = data["su_restriction"]
        assert su_r["pam_su_config"] == fake_pam_su_content
        assert su_r["pam_wheel_line"] == "auth            required        pam_wheel.so use_uid"
        assert su_r["wheel_group_source"] == "sudo"
        assert su_r["wheel_group_members"] == ["alice", "bob", "charlie"]

        # No errors should have occurred
        assert len(data["errors"]) == 0


def test_collect_privilege_escalation_wheel_fallback(tmp_path):
    """
    Test scenario: sudo group doesn't exist, fall back to wheel group.
    """
    def mock_exists(p):
        return False

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        if cmd[0:2] == ["getent", "group"]:
            if cmd[2] == "sudo":
                res.returncode = 2
                res.stdout = ""
            elif cmd[2] == "wheel":
                res.returncode = 0
                res.stdout = "wheel:x:10:root,sebtixd\n"
            res.stderr = ""
        elif cmd[0] == "journalctl":
            res.stdout = ""
            res.returncode = 1
        else:
            raise ValueError(f"Unpredicted command: {cmd}")
        return res

    with patch("os.path.exists", side_effect=mock_exists), \
         patch("subprocess.run", side_effect=mock_run):
        
        data = collect_privilege_escalation()
        su_r = data["su_restriction"]
        assert su_r["wheel_group_source"] == "wheel"
        assert su_r["wheel_group_members"] == ["root", "sebtixd"]


def test_collect_privilege_escalation_permission_errors(tmp_path):
    """
    Test scenario: Reading files raises permission errors.
    """
    def mock_exists(p):
        if p in ("/etc/sudoers", "/etc/pam.d/su"):
            return True
        return False

    def mock_open_func(file, *args, **kwargs):
        raise PermissionError(f"[Errno 13] Permission denied: '{file}'")

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 1
        res.stdout = ""
        res.stderr = "Permission denied"
        return res

    with patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_func), \
         patch("subprocess.run", side_effect=mock_run):

        data = collect_privilege_escalation()

        assert data["sudoers_files_scanned"] == []
        assert data["su_restriction"]["pam_su_config"] is None
        # We should have error entries for sudoers read and pam.d su read
        errors_checks = [e["check"] for e in data["errors"]]
        assert any("read_file:/etc/sudoers" in c for c in errors_checks)
        assert any("read_file:/etc/pam.d/su" in c for c in errors_checks)
