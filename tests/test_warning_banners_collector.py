"""
test_warning_banners_collector.py
=================================
Unit tests for collectors/warning_banners_collector.py
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.warning_banners_collector import (
    _read_file,
    _stat_path,
    collect_warning_banners,
)


@mock.patch("collectors.warning_banners_collector._read_file")
@mock.patch("collectors.warning_banners_collector._stat_path")
@mock.patch("os.path.exists")
@mock.patch("os.listdir")
def test_collect_warning_banners(mock_listdir, mock_exists, mock_stat, mock_rf):
    mock_exists.side_effect = lambda path: path in ("/etc/pam.d", "/etc/update-motd.d")
    mock_listdir.side_effect = lambda path: ["sshd"] if "pam.d" in path else ["00-header"]

    def side_rf(path):
        if path == "/etc/motd":
            return "Authorized uses only.\n"
        if path == "/etc/issue":
            return "Authorized uses only.\n"
        if path == "/etc/issue.net":
            return "Authorized uses only.\n"
        if path == "/etc/pam.d/sshd":
            return "session optional pam_motd.so motd=/run/motd.dynamic\n"
        if path == "/etc/update-motd.d/00-header":
            return "#!/bin/sh\nprintf 'Welcome'\n"
        return None

    mock_rf.side_effect = side_rf
    mock_stat.return_value = {"path": "/etc/motd", "exists": True, "mode_octal": "0o644", "owner": "root", "group": "root"}

    res = collect_warning_banners()
    assert "warning_banners" in res
    wb = res["warning_banners"]
    assert wb["motd"]["content"] == "Authorized uses only.\n"
    assert len(wb["pam_motd"]["pam_references"]) == 1
    assert len(wb["pam_motd"]["update_motd_files_content"]) == 1

    json_str = json.dumps(res)
    assert "warning_banners" in json_str
