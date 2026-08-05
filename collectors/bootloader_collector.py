"""
bootloader_collector.py
=======================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.4 (Bootloader Configuration):

  1.4.1  Bootloader password set (grub.cfg, /etc/grub.d/*)
  1.4.2  Bootloader config file permissions (/boot/grub/grub.cfg)

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
from typing import Any

from collectors.common import read_file, stat_path

_read_file = read_file
_stat_path = stat_path


def collect_bootloader() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.4 (Bootloader).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'bootloader'.
    """
    errors: list[dict[str, str]] = []

    # 1.4.1: Password configuration
    grub_cfg_content = _read_file("/boot/grub/grub.cfg")
    custom_40_content = _read_file("/etc/grub.d/40_custom")
    password_01_content = _read_file("/etc/grub.d/01_password")

    grub_password_lines: list[str] = []
    superusers_lines: list[str] = []

    if grub_cfg_content:
        for line in grub_cfg_content.splitlines():
            stripped = line.strip()
            if stripped.startswith("password") or stripped.startswith("password_pbkdf2"):
                grub_password_lines.append(stripped)
            elif stripped.startswith("set superusers"):
                superusers_lines.append(stripped)

    has_superusers = bool(superusers_lines)
    has_password = bool(grub_password_lines)

    # Also check /etc/grub.d/ files for password hints
    if custom_40_content and "password" in custom_40_content:
        has_password = True
    if password_01_content and "password" in password_01_content:
        has_password = True

    # 1.4.2: File permissions for /boot/grub/grub.cfg
    grub_cfg_stat = _stat_path("/boot/grub/grub.cfg")

    return {
        "bootloader": {
            "password_config": {
                "superusers_lines": superusers_lines,
                "password_lines": grub_password_lines,
                "has_superusers": has_superusers,
                "has_password": has_password,
                "custom_40_has_password": "password" in (custom_40_content or ""),
                "password_01_has_password": "password" in (password_01_content or ""),
            },
            "grub_cfg_permissions": [grub_cfg_stat] if grub_cfg_stat["exists"] else [],
            "file_permissions": {
                "grub_cfg_stat": grub_cfg_stat,
            },
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_bootloader(), indent=2))
