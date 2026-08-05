"""
warning_banners_collector.py
============================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.6 (Warning Banners):

  1.6.1   Command line warning banners (/etc/issue, /etc/issue.net, /etc/motd)
  1.6.2   GDM warning banner (/etc/gdm3/custom.conf or dconf profile)

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import os
from typing import Any

from collectors.common import read_file, stat_path

_read_file = read_file
_stat_path = stat_path


def collect_warning_banners() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.6
    (Warning Banners).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'warning_banners'.
    """
    errors: list[dict[str, str]] = []

    # 1.6.1: Command-line banners
    issue_content = _read_file("/etc/issue")
    issue_net_content = _read_file("/etc/issue.net")
    motd_content = _read_file("/etc/motd")

    issue_stat = _stat_path("/etc/issue")
    issue_net_stat = _stat_path("/etc/issue.net")
    motd_stat = _stat_path("/etc/motd")

    # PAM motd references
    pam_references: list[dict[str, str]] = []
    pam_d = "/etc/pam.d"
    if os.path.exists(pam_d):
        try:
            for fname in sorted(os.listdir(pam_d)):
                fpath = os.path.join(pam_d, fname)
                content = _read_file(fpath)
                if content:
                    for line in content.splitlines():
                        stripped = line.strip()
                        if "pam_motd" in stripped and not stripped.startswith("#"):
                            pam_references.append({"file": fpath, "line": stripped})
        except Exception as exc:
            errors.append({"check": "pam.d_listdir", "error": str(exc)})

    # update-motd.d dynamic motd scripts
    update_motd_files: list[dict[str, str]] = []
    update_motd_d = "/etc/update-motd.d"
    if os.path.exists(update_motd_d):
        try:
            for fname in sorted(os.listdir(update_motd_d)):
                fpath = os.path.join(update_motd_d, fname)
                content = _read_file(fpath)
                if content is not None:
                    update_motd_files.append({"file": fpath, "content": content})
        except Exception as exc:
            errors.append({"check": "update-motd.d_listdir", "error": str(exc)})

    # GDM Banner settings
    gdm_custom = _read_file("/etc/gdm3/custom.conf")
    dconf_banner = _read_file("/etc/dconf/db/gdm.d/01-banner-message")

    return {
        "warning_banners": {
            "issue": {
                "content": issue_content,
                "stat": issue_stat,
            },
            "issue_net": {
                "content": issue_net_content,
                "stat": issue_net_stat,
            },
            "motd": {
                "content": motd_content,
                "stat": motd_stat,
            },
            "pam_motd": {
                "pam_references": pam_references,
                "update_motd_files_content": update_motd_files,
            },
            "gdm_custom_conf": gdm_custom,
            "dconf_banner_conf": dconf_banner,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_warning_banners(), indent=2))
