"""
gnome_collector.py
==================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.7 (GNOME Display Manager):

  1.7.1   GDM installed and active status
  1.7.2   GDM login banner enabled
  1.7.3   GDM screen lock enabled and delay <= 900s
  1.7.4   GDM automount / automount-open disabled
  1.7.5   GDM autorun-never enabled
  1.7.6   GDM XDMCP disabled
  1.7.7   GDM Xwayland disabled / configured

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import os
from typing import Any

from collectors.common import read_file, run_cmd

_run_cmd = run_cmd
_read_file = read_file


def _dpkg_installed(package: str) -> bool:
    out, _, rc = _run_cmd(["dpkg", "-s", package])
    return rc == 0 and "install ok installed" in out.lower()


def _systemctl_state(unit: str) -> dict:
    e, _, _ = _run_cmd(["systemctl", "is-enabled", unit])
    a, _, _ = _run_cmd(["systemctl", "is-active", unit])
    return {"unit": unit, "enabled": e.strip(), "active": a.strip()}



def _search_dconf_dir(dconf_dir: str, dconf_settings: dict[str, str], dconf_locks: list[str], errors: list[dict[str, str]]) -> None:
    if os.path.exists(dconf_dir):
        try:
            for root, _, files in os.walk(dconf_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    content = _read_file(fpath)
                    if not content:
                        continue
                    if "locks" in root:
                        for line in content.splitlines():
                            s = line.strip()
                            if s and not s.startswith("#"):
                                dconf_locks.append(s)
                    else:
                        for line in content.splitlines():
                            s = line.strip()
                            if s and "=" in s and not s.startswith("#"):
                                k, _, v = s.partition("=")
                                dconf_settings[k.strip()] = v.strip()
        except Exception as exc:
            errors.append({"check": "dconf_walk", "error": str(exc)})


def collect_gnome() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.7 (GNOME/GDM).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'gnome'.
    """
    errors: list[dict[str, str]] = []

    # 1.7.1: GDM installed / active
    gdm_installed = _dpkg_installed("gdm3")
    gdm_svc = _systemctl_state("gdm3.service")

    # 1.7.6 & 1.7.7: GDM configuration files
    gdm3_custom = _read_file("/etc/gdm3/custom.conf")

    # dconf key/value database scanning under /etc/dconf/db/
    dconf_locks: list[str] = []
    dconf_settings: dict[str, str] = {}

    _search_dconf_dir("/etc/dconf/db", dconf_settings, dconf_locks, errors)

    return {
        "gnome": {
            "gdm_installed": gdm_installed,
            "gdm_service": gdm_svc,
            "gdm3_custom_conf": gdm3_custom,
            "gdm3_custom_conf_content": gdm3_custom,
            "dconf_settings": dconf_settings,
            "dconf_locks": dconf_locks,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_gnome(), indent=2))
