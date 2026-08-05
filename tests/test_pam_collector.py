"""
test_pam_collector.py
======================
Unit tests for collectors/pam_collector.py

Mirrors the patterns of test_network_config_collector.py and test_auditd_collector.py:
all external calls (subprocess, file I/O) are mocked so tests are hermetic and run without
a live Linux system or sudo rights.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.pam_collector import (
    _run_cmd,
    _read_file,
    _read_conf_dir,
    _extract_module_lines,
    _extract_conf_settings,
    _dpkg_and_apt_info,
    _collect_pam_packages,
    _collect_pam_profiles_raw,
    _collect_pam_faillock,
    _collect_pam_pwquality,
    _collect_pam_pwhistory,
    _collect_pam_unix,
    collect_pam,
    _PAM_PACKAGES,
    _PAM_D_FILES,
    _PAM_MODULES_OF_INTEREST,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

@mock.patch("subprocess.run")
def test_run_cmd_success(mock_run):
    mock_run.return_value = mock.Mock(stdout="ok\n", stderr="", returncode=0)
    out, err, rc = _run_cmd(["echo", "ok"])
    assert out == "ok\n"
    assert rc == 0


@mock.patch("subprocess.run", side_effect=Exception("command failed"))
def test_run_cmd_exception(mock_run):
    out, err, rc = _run_cmd(["invalid"])
    assert rc == -1
    assert "command failed" in err


@mock.patch("builtins.open", mock.mock_open(read_data="sample data\n"))
def test_read_file_success():
    assert _read_file("/fake/path") == "sample data\n"


@mock.patch("builtins.open", side_effect=FileNotFoundError)
def test_read_file_missing(mock_open):
    assert _read_file("/nonexistent") is None


def test_extract_module_lines():
    sample_pam_content = (
        "# Comment line\n"
        "auth required pam_unix.so nullok\n"
        "password requisite pam_pwquality.so retry=3 minlen=14\n"
        "# auth optional pam_faillock.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
    )
    lines_unix = _extract_module_lines(sample_pam_content, "pam_unix.so")
    assert len(lines_unix) == 1
    assert "nullok" in lines_unix[0]

    lines_faillock = _extract_module_lines(sample_pam_content, "pam_faillock.so")
    assert len(lines_faillock) == 1
    assert "authfail" in lines_faillock[0]

    lines_missing = _extract_module_lines(sample_pam_content, "pam_pwhistory.so")
    assert lines_missing == []


def test_extract_conf_settings():
    conf_content = (
        "# Configuration file\n"
        "deny = 5\n"
        "unlock_time = 900\n"
        "even_deny_root\n"
    )
    keys = ["deny", "unlock_time", "even_deny_root", "fail_interval"]
    res = _extract_conf_settings(conf_content, keys)

    assert res["deny"] == "5"
    assert res["unlock_time"] == "900"
    assert res["even_deny_root"] is None or res["even_deny_root"] == "" or isinstance(res["even_deny_root"], str)
    assert res["fail_interval"] is None


# ---------------------------------------------------------------------------
# Package Info
# ---------------------------------------------------------------------------

@mock.patch("collectors.pam_collector._run_cmd")
def test_dpkg_and_apt_info_installed_and_latest(mock_run):
    def side_cmd(cmd, timeout=15):
        if cmd[0] == "dpkg":
            return ("Package: libpam-pwquality\nStatus: install ok installed\nVersion: 1.5.0-2build1\n", "", 0)
        if cmd[0] == "apt-cache":
            return ("libpam-pwquality:\n  Installed: 1.5.0-2build1\n  Candidate: 1.5.0-2build1\n", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_cmd

    info = _dpkg_and_apt_info("libpam-pwquality")
    assert info["package"] == "libpam-pwquality"
    assert info["installed"] is True
    assert info["installed_version"] == "1.5.0-2build1"
    assert info["candidate_version"] == "1.5.0-2build1"
    assert info["candidate_version_error"] is None


@mock.patch("collectors.pam_collector._run_cmd")
def test_dpkg_and_apt_info_not_installed(mock_run):
    def side_cmd(cmd, timeout=15):
        if cmd[0] == "dpkg":
            return ("", "dpkg-query: package 'cracklib-runtime' is not installed", 1)
        if cmd[0] == "apt-cache":
            return ("cracklib-runtime:\n  Installed: (none)\n  Candidate: 2.9.6-5\n", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_cmd

    info = _dpkg_and_apt_info("cracklib-runtime")
    assert info["installed"] is False
    assert info["installed_version"] is None
    assert info["candidate_version"] == "2.9.6-5"


@mock.patch("collectors.pam_collector._run_cmd")
def test_dpkg_and_apt_info_apt_cache_unavailable(mock_run):
    def side_cmd(cmd, timeout=15):
        if cmd[0] == "dpkg":
            return ("Package: libpam-runtime\nStatus: install ok installed\nVersion: 1.5.2\n", "", 0)
        if cmd[0] == "apt-cache":
            return ("", "W: Unable to read /etc/apt/preferences.d/", 100)
        return ("", "", 0)

    mock_run.side_effect = side_cmd

    info = _dpkg_and_apt_info("libpam-runtime")
    assert info["installed"] is True
    assert info["candidate_version"] is None
    assert info["candidate_version_error"] is not None


# ---------------------------------------------------------------------------
# Profiles & Module extraction
# ---------------------------------------------------------------------------

@mock.patch("collectors.pam_collector._run_cmd")
@mock.patch("collectors.pam_collector._read_file")
def test_collect_pam_profiles_raw(mock_rf, mock_run):
    mock_run.return_value = ("pam_unix\npam_faillock\npam_pwquality\n", "", 0)

    def side_rf(path):
        if path == "/etc/pam.d/common-auth":
            return "auth required pam_unix.so nullok\nauth required pam_faillock.so preauth\n"
        if path == "/etc/pam.d/common-password":
            return "password requisite pam_pwquality.so retry=3 minlen=14\npassword required pam_pwhistory.so remember=24\n"
        return ""

    mock_rf.side_effect = side_rf
    errors: list = []
    res = _collect_pam_profiles_raw(errors)

    assert "pam_d_files_raw" in res
    assert res["pam_auth_update_list"] is not None
    assert len(res["module_lines"]["pam_unix.so"]) == 1
    assert len(res["module_lines"]["pam_faillock.so"]) == 1
    assert len(res["module_lines"]["pam_pwquality.so"]) == 1
    assert len(res["module_lines"]["pam_pwhistory.so"]) == 1


# ---------------------------------------------------------------------------
# Subsystem collectors: Faillock, Pwquality, Pwhistory, Pam_unix
# ---------------------------------------------------------------------------

@mock.patch("collectors.pam_collector._read_file")
def test_collect_pam_faillock(mock_rf):
    mock_rf.return_value = "deny = 5\nunlock_time = 900\neven_deny_root\n"
    profiles_mock = {
        "module_lines": {
            "pam_faillock.so": [
                {"file": "/etc/pam.d/common-auth", "line": "auth required pam_faillock.so preauth audit deny=5 unlock_time=900"}
            ]
        }
    }
    res = _collect_pam_faillock(profiles_mock)

    assert res["faillock_conf_settings"]["deny"] == "5"
    assert res["faillock_conf_settings"]["unlock_time"] == "900"
    assert len(res["faillock_pam_lines"]) == 1
    assert res["faillock_inline_pam_settings"]["deny"] == "5"


@mock.patch("collectors.pam_collector._read_conf_dir")
@mock.patch("collectors.pam_collector._read_file")
def test_collect_pam_pwquality(mock_rf, mock_rcd):
    mock_rf.return_value = "minlen = 14\ndifok = 2\n"
    mock_rcd.return_value = [{"path": "/etc/security/pwquality.conf.d/99-cis.conf", "content": "minlen = 16\n"}]

    profiles_mock = {
        "module_lines": {
            "pam_pwquality.so": [
                {"file": "/etc/pam.d/common-password", "line": "password requisite pam_pwquality.so retry=3 minlen=14 difok=2"}
            ]
        }
    }
    res = _collect_pam_pwquality(profiles_mock)

    # Drop-in should override main pwquality.conf
    assert res["pwquality_conf_settings"]["minlen"] == "16"
    assert res["pwquality_conf_settings"]["difok"] == "2"
    assert len(res["pwquality_pam_lines"]) == 1


@mock.patch("os.path.lexists", return_value=True)
def test_collect_pam_pwhistory(mock_lexists):
    profiles_mock = {
        "module_lines": {
            "pam_pwhistory.so": [
                {"file": "/etc/pam.d/common-password", "line": "password required pam_pwhistory.so remember=24 enforce_for_root use_authtok"}
            ]
        }
    }
    res = _collect_pam_pwhistory(profiles_mock)

    assert res["pwhistory_inline_pam_settings"]["remember"] == "24"
    assert res["pwhistory_inline_pam_settings"]["enforce_for_root"] == "present"
    assert res["pwhistory_inline_pam_settings"]["use_authtok"] == "present"
    assert res["opasswd_exists"] is True


def test_collect_pam_unix():
    profiles_mock = {
        "module_lines": {
            "pam_unix.so": [
                {"file": "/etc/pam.d/common-auth", "line": "auth required pam_unix.so try_first_pass nullok"},
                {"file": "/etc/pam.d/common-password", "line": "password required pam_unix.so yescrypt use_authtok"}
            ]
        }
    }
    res = _collect_pam_unix(profiles_mock)

    assert res["pam_unix_flag_presence"]["nullok"] == "present"
    assert res["pam_unix_flag_presence"]["yescrypt"] == "present"
    assert res["pam_unix_flag_presence"]["use_authtok"] == "present"
    assert res["pam_unix_flag_presence"]["remember"] is None


# ---------------------------------------------------------------------------
# Top-level collect_pam integration test
# ---------------------------------------------------------------------------

@mock.patch("os.path.lexists", return_value=False)
@mock.patch("os.path.exists", return_value=False)
@mock.patch("collectors.pam_collector._run_cmd")
@mock.patch("collectors.pam_collector._read_file")
def test_collect_pam_schema_and_json_serializable(mock_rf, mock_run, mock_exists, mock_lexists):
    mock_run.return_value = ("", "", 0)
    mock_rf.return_value = None

    result = collect_pam()

    assert "pam" in result
    pam = result["pam"]
    assert "pam_packages" in pam
    assert "pam_profiles_raw" in pam
    assert "pam_faillock" in pam
    assert "pam_pwquality" in pam
    assert "pam_pwhistory" in pam
    assert "pam_unix" in pam
    assert "errors" in pam

    # Verify JSON serialisability
    dumped = json.dumps(result)
    assert "pam_packages" in dumped
