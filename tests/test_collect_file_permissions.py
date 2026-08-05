"""
test_collect_file_permissions.py
==================================
Unit tests for collectors/collect_file_permissions.py.

Mocks os.stat / pwd / grp for Part 1 (fixed-file stat checks) and
monkeypatches subprocess.run for Parts 2–4 (filesystem scans).
"""

from __future__ import annotations

import json
import stat
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

from collectors.collect_file_permissions import (
    _stat_file,
    collect_file_permissions,
    _PATH_CAP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_stat(mode: int, uid: int = 0, gid: int = 0) -> MagicMock:
    """Return a mock os.stat_result-like object."""
    st = MagicMock()
    st.st_mode = mode
    st.st_uid = uid
    st.st_gid = gid
    return st


def _mock_findmnt_result(mounts: list[dict]) -> MagicMock:
    """Return a fake subprocess.run result for findmnt."""
    res = MagicMock()
    res.returncode = 0
    res.stdout = json.dumps({"filesystems": mounts})
    return res


def _mock_find_result(paths: list[str]) -> MagicMock:
    """Return a fake subprocess.run result for find."""
    res = MagicMock()
    res.returncode = 0
    res.stdout = "\n".join(paths) + ("\n" if paths else "")
    return res


# ---------------------------------------------------------------------------
# Test 1 – _stat_file: file exists, all fields resolved
# ---------------------------------------------------------------------------

def test_stat_file_exists():
    """
    When os.stat succeeds and pwd/grp resolve the UID/GID, all fields must
    be populated correctly.
    """
    fake_mode = stat.S_IFREG | 0o644  # regular file, 644
    fake_st = _make_stat(fake_mode, uid=0, gid=0)

    fake_pw = SimpleNamespace(pw_name="root")
    fake_gr = SimpleNamespace(gr_name="root")

    with patch("collectors.collect_file_permissions.os.stat", return_value=fake_st), \
         patch("collectors.collect_file_permissions.pwd.getpwuid", return_value=fake_pw), \
         patch("collectors.collect_file_permissions.grp.getgrgid", return_value=fake_gr):

        result = _stat_file("/etc/passwd")

    assert result["path"] == "/etc/passwd"
    assert result["exists"] is True
    assert result["mode_octal"] == "0644"
    assert result["owner"] == "root"
    assert result["owner_uid"] == 0
    assert result["group"] == "root"
    assert result["group_gid"] == 0
    assert result["error"] is None


# ---------------------------------------------------------------------------
# Test 1.5 – _stat_file: unknown UID/GID
# ---------------------------------------------------------------------------

def test_stat_file_unknown_uid_gid():
    """
    When pwd or grp fails to resolve the ID, the error field must accumulate
    the errors and fields must remain None, but it shouldn't fail.
    """
    fake_mode = stat.S_IFREG | 0o600
    fake_st = _make_stat(fake_mode, uid=12345, gid=67890)

    with patch("collectors.collect_file_permissions.os.stat", return_value=fake_st), \
         patch("collectors.collect_file_permissions.pwd.getpwuid", side_effect=KeyError()), \
         patch("collectors.collect_file_permissions.grp.getgrgid", side_effect=KeyError()):

        result = _stat_file("/etc/security/opasswd")

    assert result["exists"] is True
    assert result["mode_octal"] == "0600"
    assert result["owner_uid"] == 12345
    assert result["owner"] is None
    assert result["group_gid"] == 67890
    assert result["group"] is None
    assert result["error"] == "unable to resolve username; unable to resolve groupname"



# ---------------------------------------------------------------------------
# Test 2 – _stat_file: file does not exist
# ---------------------------------------------------------------------------

def test_stat_file_not_found():
    """
    When os.stat raises FileNotFoundError, exists must be False, error must
    be set, and all other fields must remain None without raising.
    """
    with patch(
        "collectors.collect_file_permissions.os.stat",
        side_effect=FileNotFoundError("No such file"),
    ):
        result = _stat_file("/etc/shadow-")

    assert result["exists"] is False
    assert result["error"] == "FileNotFoundError"
    assert result["mode_octal"] is None
    assert result["owner"] is None
    assert result["group"] is None


# ---------------------------------------------------------------------------
# Test 3 – _stat_file: permission denied
# ---------------------------------------------------------------------------

def test_stat_file_permission_denied():
    """
    When os.stat raises PermissionError (e.g. /etc/shadow without root),
    the error field must capture the message and exists must reflect if the file
    actually exists on the filesystem.
    """
    with patch("collectors.collect_file_permissions.os.stat", side_effect=PermissionError(13, "Permission denied")), \
         patch("collectors.collect_file_permissions.os.path.exists", return_value=True), \
         patch("collectors.collect_file_permissions.os.path.lexists", return_value=True):
        result = _stat_file("/etc/shadow")

    assert result["exists"] is True
    assert result["error"] is not None
    assert "PermissionError" in result["error"]
    assert result["mode_octal"] is None


# ---------------------------------------------------------------------------
# Test 4 – World-writable scan: paths parsed correctly
# ---------------------------------------------------------------------------

def test_world_writable_scan():
    """
    Verify that the world_writable section correctly parses paths returned
    by ``find`` and maps them to the right mount entry.
    """
    findmnt_out = _mock_findmnt_result(
        [{"target": "/", "fstype": "ext4"}, {"target": "/proc", "fstype": "proc"}]
    )
    # Files result  / dirs result (no sticky) / unowned / suid/sgid
    find_files = _mock_find_result(["/tmp/bad_file", "/var/world_w"])
    find_dirs  = _mock_find_result(["/srv/open_dir"])
    find_unown = _mock_find_result([])
    find_suid  = _mock_find_result([])

    call_seq = [findmnt_out, find_files, find_dirs, find_unown, find_suid]

    # os.stat for every fixed file raises FileNotFoundError (not the focus here)
    with patch("collectors.collect_file_permissions.os.stat", side_effect=FileNotFoundError()), \
         patch("collectors.collect_file_permissions.subprocess.run", side_effect=call_seq):

        data = collect_file_permissions()

    ww = data["world_writable"]
    assert "/" in ww["mounts_scanned"]
    # Proc should be skipped
    assert any(s["mount"] == "/proc" for s in ww["mounts_skipped"])

    # Check world-writable files for "/"
    mount_entry = next(e for e in ww["world_writable_files"] if e["mount"] == "/")
    assert "/tmp/bad_file" in mount_entry["paths"]
    assert "/var/world_w" in mount_entry["paths"]
    assert mount_entry["truncated"] is False

    # Check world-writable dirs for "/"
    dir_entry = next(e for e in ww["world_writable_dirs_no_sticky"] if e["mount"] == "/")
    assert "/srv/open_dir" in dir_entry["paths"]
    assert dir_entry["truncated"] is False


# ---------------------------------------------------------------------------
# Test 5 – Truncation: more than _PATH_CAP results are capped
# ---------------------------------------------------------------------------

def test_world_writable_truncation():
    """
    When ``find`` returns more than _PATH_CAP lines, the paths list must be
    capped at _PATH_CAP and ``truncated`` must be True.
    """
    excess = [f"/some/path/{i}" for i in range(_PATH_CAP + 50)]

    findmnt_out = _mock_findmnt_result([{"target": "/", "fstype": "ext4"}])
    find_files  = _mock_find_result(excess)
    find_dirs   = _mock_find_result([])
    find_unown  = _mock_find_result([])
    find_suid   = _mock_find_result([])

    call_seq = [findmnt_out, find_files, find_dirs, find_unown, find_suid]

    with patch("collectors.collect_file_permissions.os.stat", side_effect=FileNotFoundError()), \
         patch("collectors.collect_file_permissions.subprocess.run", side_effect=call_seq):

        data = collect_file_permissions()

    mount_entry = next(e for e in data["world_writable"]["world_writable_files"] if e["mount"] == "/")
    assert len(mount_entry["paths"]) == _PATH_CAP
    assert mount_entry["truncated"] is True


# ---------------------------------------------------------------------------
# Test 6 – SUID/SGID: mode_octal and owner are resolved per file
# ---------------------------------------------------------------------------

def test_suid_sgid_collection():
    """
    SUID/SGID file entries must include the correct mode_octal string, the resolved
    owner username and UID, and the resolved group name (or fallback to GID) and GID.
    """
    suid_path = "/usr/bin/sudo"
    # Mode: SUID + executable = 4755
    fake_mode = stat.S_IFREG | 0o4755
    fake_st = _make_stat(fake_mode, uid=0, gid=1000)
    fake_pw = SimpleNamespace(pw_name="root")
    fake_gr = SimpleNamespace(gr_name="sudo")

    findmnt_out = _mock_findmnt_result([{"target": "/", "fstype": "ext4"}])
    find_files_ww  = _mock_find_result([])
    find_dirs_ww   = _mock_find_result([])
    find_unown     = _mock_find_result([])
    find_suid      = _mock_find_result([suid_path])

    call_seq = [findmnt_out, find_files_ww, find_dirs_ww, find_unown, find_suid]

    def stat_side_effect(path, *args, **kwargs):
        if path == suid_path:
            return fake_st
        raise FileNotFoundError()

    with patch("collectors.collect_file_permissions.os.stat", side_effect=stat_side_effect), \
         patch("collectors.collect_file_permissions.pwd.getpwuid", return_value=fake_pw), \
         patch("collectors.collect_file_permissions.grp.getgrgid", return_value=fake_gr), \
         patch("collectors.collect_file_permissions.subprocess.run", side_effect=call_seq):

        data = collect_file_permissions()

    suid_files = data["suid_sgid"]["suid_sgid_files"]
    assert len(suid_files) == 1
    entry = suid_files[0]
    assert entry["path"] == suid_path
    assert entry["mode_octal"] == "4755"
    assert entry["owner"] == "root"
    assert entry["owner_uid"] == 0
    assert entry["group"] == "sudo"
    assert entry["group_gid"] == 1000
    assert data["suid_sgid"]["truncated"] is False


def test_collect_file_permissions_from_ssh():
    """
    Verify that collect_file_permissions_from_ssh runs the proper find and stat
    commands and parses the outputs (including owner_uid, group, group_gid) correctly.
    """
    from collectors.ssh_bridges import collect_file_permissions_from_ssh

    mock_ssh = MagicMock()

    # 1. Output for fixed files: 10 files (we can just return a standard stat response JSON)
    fake_fixed_response = json.dumps({
        "path": "/etc/passwd",
        "exists": True,
        "mode_octal": "0644",
        "owner": "root",
        "owner_uid": 0,
        "group": "root",
        "group_gid": 0,
        "error": None
    })

    # 2. Output for findmnt TARGET,FSTYPE
    findmnt_out = "/ ext4\n/proc proc\n"

    # 3. Outputs for find commands:
    # - world-writable files find -> empty
    # - world-writable dirs find -> empty
    # - unowned find -> empty
    # - suid find -> we return one SUID file
    # We used: -printf '%m %U %u %G %g %p\n'
    # E.g. '4755 0 root 0 root /usr/bin/sudo\n'
    suid_find_out = "4755 0 root 0 root /usr/bin/sudo\n"

    call_responses = (
        [fake_fixed_response] * 10
        + [findmnt_out]
        + ["", ""]
        + [""]
        + [suid_find_out]
    )

    with patch("collectors.ssh_bridges.remote_run", side_effect=call_responses):
        data = collect_file_permissions_from_ssh(mock_ssh, password="test")

    # Check fixed files parsed correctly
    assert len(data["fixed_files"]) == 10
    assert data["fixed_files"][0]["path"] == "/etc/passwd"
    assert data["fixed_files"][0]["mode_octal"] == "0644"

    # Check SUID/SGID parsed correctly
    suid_section = data["suid_sgid"]
    assert suid_section["truncated"] is False
    assert len(suid_section["suid_sgid_files"]) == 1
    entry = suid_section["suid_sgid_files"][0]
    assert entry["path"] == "/usr/bin/sudo"
    assert entry["mode_octal"] == "4755"
    assert entry["owner"] == "root"
    assert entry["owner_uid"] == 0
    assert entry["group"] == "root"
    assert entry["group_gid"] == 0

