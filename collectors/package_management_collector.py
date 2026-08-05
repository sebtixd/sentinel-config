"""
package_management_collector.py
================================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.2 (Package Management):

  1.2.1  Configure Package Repositories
         - 1.2.1.1 Signed-By option in sources files
         - 1.2.1.2 Weak dependencies (Install-Recommends / Install-Suggests)
         - 1.2.1.3 - 1.2.1.9 Permissions on GPG keys, keyrings, auth.conf.d, sources.list.d
  1.2.2  Configure Package Updates
         - 1.2.2.1 Upgradable packages list & unattended-upgrades status/confs

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import glob
import json
import os
import stat
import subprocess
from typing import Any

try:
    import pwd
    import grp
except ImportError:
    pwd = None  # type: ignore
    grp = None  # type: ignore


from collectors.common import read_file, run_cmd, stat_path

_run_cmd = run_cmd
_read_file = read_file
_stat_path = stat_path



# ---------------------------------------------------------------------------
# 1.2.1 – Configure Package Repositories
# ---------------------------------------------------------------------------

def _collect_package_repositories(errors: list[dict[str, str]]) -> dict[str, Any]:
    """
    Collect facts for CIS 1.2.1.x:
      - Signed-By in sources files (.list and .sources)
      - APT weak dependencies configuration
      - File/directory permissions for GPG keys, keyrings, auth.conf.d, sources.list.d
    """
    # --- 1.2.1.1: Signed-By in sources files ---
    sources_files: list[dict[str, Any]] = []

    paths_to_check = ["/etc/apt/sources.list"]
    sources_d = "/etc/apt/sources.list.d"
    if os.path.exists(sources_d):
        try:
            for fname in sorted(os.listdir(sources_d)):
                if fname.endswith(".list") or fname.endswith(".sources"):
                    paths_to_check.append(os.path.join(sources_d, fname))
        except Exception as exc:
            errors.append({"check": "sources.list.d_listdir", "error": str(exc)})

    for fpath in paths_to_check:
        content = _read_file(fpath)
        if content is None:
            continue

        signed_by_lines: list[str] = []
        repo_lines: list[str] = []

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            repo_lines.append(stripped)
            lower = stripped.lower()
            if "signed-by" in lower:
                signed_by_lines.append(stripped)

        sources_files.append({
            "path": fpath,
            "raw_content": content,
            "active_repo_lines": repo_lines,
            "matching_signed_by_lines": signed_by_lines,
            "has_signed_by": bool(signed_by_lines),
        })

    # --- 1.2.1.2: Weak dependencies (Install-Recommends / Install-Suggests) ---
    apt_conf_lines: list[dict[str, str]] = []
    apt_conf_dir = "/etc/apt/apt.conf.d"
    if os.path.exists(apt_conf_dir):
        try:
            for fname in sorted(os.listdir(apt_conf_dir)):
                if fname.endswith(".conf") or fname.startswith("99") or fname.startswith("20") or fname.startswith("00"):
                    fpath = os.path.join(apt_conf_dir, fname)
                    content = _read_file(fpath)
                    if content is not None:
                        for line in content.splitlines():
                            stripped = line.strip()
                            if stripped.startswith("#") or stripped.startswith("//"):
                                continue
                            lower = stripped.lower()
                            if "install-recommends" in lower or "install-suggests" in lower:
                                apt_conf_lines.append({"file": fpath, "line": stripped})
        except Exception as exc:
            errors.append({"check": "apt.conf.d_listdir", "error": str(exc)})

    # Also check /etc/apt/apt.conf main file if it exists
    main_apt_conf = _read_file("/etc/apt/apt.conf")
    if main_apt_conf:
        for line in main_apt_conf.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            lower = stripped.lower()
            if "install-recommends" in lower or "install-suggests" in lower:
                apt_conf_lines.append({"file": "/etc/apt/apt.conf", "line": stripped})

    # --- 1.2.1.3: GPG key files access ---
    gpg_key_files_stat: list[dict[str, Any]] = []
    trusted_gpg = "/etc/apt/trusted.gpg"
    if os.path.exists(trusted_gpg):
        gpg_key_files_stat.append(_stat_path(trusted_gpg))

    trusted_gpg_d = "/etc/apt/trusted.gpg.d"
    if os.path.exists(trusted_gpg_d):
        try:
            for fname in sorted(os.listdir(trusted_gpg_d)):
                fpath = os.path.join(trusted_gpg_d, fname)
                if os.path.isfile(fpath):
                    gpg_key_files_stat.append(_stat_path(fpath))
        except Exception as exc:
            errors.append({"check": "trusted.gpg.d_listdir", "error": str(exc)})

    # --- 1.2.1.4: /etc/apt/trusted.gpg.d directory access ---
    trusted_gpg_d_stat = _stat_path("/etc/apt/trusted.gpg.d")

    # --- 1.2.1.5 & 1.2.1.6: /etc/apt/auth.conf.d directory and files access ---
    auth_conf_d_stat = _stat_path("/etc/apt/auth.conf.d")
    auth_conf_d_files_stat: list[dict[str, Any]] = []
    auth_conf_stat = _stat_path("/etc/apt/auth.conf")

    if os.path.exists("/etc/apt/auth.conf.d"):
        try:
            for fname in sorted(os.listdir("/etc/apt/auth.conf.d")):
                fpath = os.path.join("/etc/apt/auth.conf.d", fname)
                auth_conf_d_files_stat.append(_stat_path(fpath))
        except Exception as exc:
            errors.append({"check": "auth.conf.d_listdir", "error": str(exc)})

    # --- 1.2.1.7: /usr/share/keyrings directory access ---
    keyrings_dir_stat = _stat_path("/usr/share/keyrings")

    # --- 1.2.1.8 & 1.2.1.9: /etc/apt/sources.list.d directory and files access ---
    sources_list_d_stat = _stat_path("/etc/apt/sources.list.d")
    sources_list_d_files_stat: list[dict[str, Any]] = []

    if os.path.exists("/etc/apt/sources.list.d"):
        try:
            for fname in sorted(os.listdir("/etc/apt/sources.list.d")):
                fpath = os.path.join("/etc/apt/sources.list.d", fname)
                sources_list_d_files_stat.append(_stat_path(fpath))
        except Exception as exc:
            errors.append({"check": "sources.list.d_files_listdir", "error": str(exc)})

    return {
        "sources_files": sources_files,
        "weak_deps_config_lines": apt_conf_lines,
        "gpg_key_files_stat": gpg_key_files_stat,
        "trusted_gpg_d_stat": trusted_gpg_d_stat,
        "auth_conf_stat": auth_conf_stat,
        "auth_conf_d_stat": auth_conf_d_stat,
        "auth_conf_d_files_stat": auth_conf_d_files_stat,
        "keyrings_dir_stat": keyrings_dir_stat,
        "sources_list_d_stat": sources_list_d_stat,
        "sources_list_d_files_stat": sources_list_d_files_stat,
    }


# ---------------------------------------------------------------------------
# 1.2.2 – Configure Package Updates
# ---------------------------------------------------------------------------

def _collect_package_updates(errors: list[dict[str, str]]) -> dict[str, Any]:
    """
    Collect facts for CIS 1.2.2.1 — upgradable packages and unattended-upgrades status.
    """
    apt_out, apt_err, apt_rc = _run_cmd(["apt", "list", "--upgradable"])

    apt_cache_error: str | None = None
    upgradable_packages: list[str] = []

    if apt_rc != 0 or "error" in apt_err.lower() or "unable" in apt_err.lower():
        apt_cache_error = apt_err.strip() or f"apt command exited with code {apt_rc}"

    if apt_rc == 0 and apt_out:
        for line in apt_out.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("Listing..."):
                upgradable_packages.append(stripped)

    # Check unattended-upgrades status
    dpkg_out, _, dpkg_rc = _run_cmd(["dpkg", "-s", "unattended-upgrades"])
    unattended_installed = dpkg_rc == 0 and "install ok installed" in dpkg_out.lower()

    svc_enabled_out, _, _ = _run_cmd(["systemctl", "is-enabled", "unattended-upgrades.service"])
    svc_active_out, _, _ = _run_cmd(["systemctl", "is-active", "unattended-upgrades.service"])

    auto_upgrades_conf = _read_file("/etc/apt/apt.conf.d/20auto-upgrades")
    unattended_conf = _read_file("/etc/apt/apt.conf.d/50unattended-upgrades")

    return {
        "upgradable_packages": upgradable_packages,
        "upgradable_package_count": len(upgradable_packages),
        "apt_cache_error": apt_cache_error,
        "unattended_upgrades_installed": unattended_installed,
        "unattended_upgrades_dpkg_status": dpkg_out.strip() if dpkg_rc == 0 else None,
        "unattended_upgrades_service_enabled": svc_enabled_out.strip(),
        "unattended_upgrades_service_active": svc_active_out.strip(),
        "auto_upgrades_conf_content": auto_upgrades_conf,
        "unattended_upgrades_conf_content": unattended_conf,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_package_management() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.2
    (Package Management).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key
              'package_management' containing sub-keys:
                package_repositories, package_updates, errors
    """
    errors: list[dict[str, str]] = []

    repos = _collect_package_repositories(errors)
    updates = _collect_package_updates(errors)

    return {
        "package_management": {
            "package_repositories": repos,
            "package_updates": updates,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_package_management(), indent=2))
