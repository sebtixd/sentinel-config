"""
process_hardening_collector.py
==============================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.5 (Process Hardening):

  1.5.1   fs.protected_hardlinks (sysctl)
  1.5.2   fs.protected_symlinks (sysctl)
  1.5.3   kernel.yama.ptrace_scope (sysctl)
  1.5.4   fs.suid_dumpable (sysctl)
  1.5.5   kernel.dmesg_restrict (sysctl)
  1.5.6   prelink package not installed
  1.5.7   apport Automatic Error Reporting status
  1.5.8   kernel.kptr_restrict (sysctl)
  1.5.9   kernel.randomize_va_space (sysctl)
  1.5.10  core file size limits (ulimit -Sc, limits.conf)
  1.5.11  systemd-coredump ProcessSizeMax (coredump.conf)
  1.5.12  systemd-coredump Storage (coredump.conf)

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import os
from typing import Any

from collectors.common import (
    load_sysctl_conf_lines as _common_load_sysctl,
    read_file,
    run_cmd,
)

_run_cmd = run_cmd
_read_file = read_file


def _dpkg_installed(package: str) -> bool:
    out, _, rc = _run_cmd(["dpkg", "-s", package])
    return rc == 0 and "install ok installed" in out.lower()


def _systemctl_state(unit: str) -> dict:
    e, _, _ = _run_cmd(["systemctl", "is-enabled", unit])
    a, _, _ = _run_cmd(["systemctl", "is-active", unit])
    return {"unit": unit, "enabled": e.strip(), "active": a.strip()}


def _get_sysctl_runtime(key: str) -> str | None:
    out, _, rc = _run_cmd(["sysctl", "-n", key])
    return out.strip() if rc == 0 and out.strip() else None


def _get_sysctl_persisted(key: str, lines: list) -> tuple:
    last_val, last_src = None, None
    prefix = key + "="
    for file_path, line in lines:
        compact = line.replace(" ", "").replace("\t", "")
        if compact.startswith(prefix):
            parts = line.split("=", 1)
            if len(parts) == 2:
                last_val = parts[1].strip()
                last_src = file_path
    return last_val, last_src


def _load_sysctl_conf_lines() -> list:
    return _common_load_sysctl()


_SYSCTL_HARDENING_KEYS = [
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
    "kernel.yama.ptrace_scope",
    "fs.suid_dumpable",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "kernel.randomize_va_space",
]


def collect_process_hardening() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.5
    (Process Hardening).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'process_hardening'.
    """
    errors: list[dict[str, str]] = []

    # Sysctl values
    sysctl_lines = _load_sysctl_conf_lines()
    sysctl_results: dict[str, Any] = {}
    for key in _SYSCTL_HARDENING_KEYS:
        r_val = _get_sysctl_runtime(key)
        p_val, p_src = _get_sysctl_persisted(key, sysctl_lines)
        sysctl_results[key] = {
            "key": key,
            "runtime_value": r_val,
            "persisted_value": p_val,
            "persisted_config_source_file": p_src,
        }

    # 1.5.6: prelink package
    prelink_installed = _dpkg_installed("prelink")
    prelink_dpkg, _, prelink_rc = _run_cmd(["dpkg", "-s", "prelink"])

    # 1.5.7: Automatic Error Reporting (apport)
    apport_installed = _dpkg_installed("apport")
    apport_dpkg, _, apport_rc = _run_cmd(["dpkg", "-s", "apport"])

    apport_svc = _systemctl_state("apport.service")

    default_apport = _read_file("/etc/default/apport")
    apport_enabled_setting: str | None = None
    if default_apport:
        for line in default_apport.splitlines():
            stripped = line.strip()
            if stripped.startswith("enabled=") and not stripped.startswith("#"):
                apport_enabled_setting = stripped

    # 1.5.10: Core file size limits
    ulimit_out, _, _ = _run_cmd(["bash", "-c", "ulimit -Sc"])
    ulimit_core_soft = ulimit_out.strip() if ulimit_out else None

    limits_lines: list[dict[str, str]] = []
    limits_conf = "/etc/security/limits.conf"
    if os.path.exists(limits_conf):
        content = _read_file(limits_conf)
        if content:
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    if "core" in stripped.lower():
                        limits_lines.append({"file": limits_conf, "line": stripped})

    limits_d = "/etc/security/limits.d"
    if os.path.exists(limits_d):
        try:
            for fname in sorted(os.listdir(limits_d)):
                if fname.endswith(".conf"):
                    fpath = os.path.join(limits_d, fname)
                    content = _read_file(fpath)
                    if content:
                        for line in content.splitlines():
                            stripped = line.strip()
                            if stripped and not stripped.startswith("#"):
                                if "core" in stripped.lower():
                                    limits_lines.append({"file": fpath, "line": stripped})
        except Exception as exc:
            errors.append({"check": "limits.d_listdir", "error": str(exc)})

    # 1.5.11 & 1.5.12: systemd-coredump configuration
    coredump_config_files: list[dict[str, str]] = []
    process_size_max_lines: list[dict[str, str]] = []
    storage_lines: list[dict[str, str]] = []

    coredump_paths = ["/etc/systemd/coredump.conf"]
    coredump_d = "/etc/systemd/coredump.conf.d"
    if os.path.exists(coredump_d):
        try:
            for fname in sorted(os.listdir(coredump_d)):
                if fname.endswith(".conf"):
                    coredump_paths.append(os.path.join(coredump_d, fname))
        except Exception as exc:
            errors.append({"check": "coredump.conf.d_listdir", "error": str(exc)})

    for cpath in coredump_paths:
        content = _read_file(cpath)
        if content is None:
            continue
        coredump_config_files.append({"file": cpath, "content": content})
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if lower.startswith("processsizemax="):
                process_size_max_lines.append({"file": cpath, "line": stripped})
            if lower.startswith("storage="):
                storage_lines.append({"file": cpath, "line": stripped})

    return {
        "process_hardening": {
            "sysctl_parameters": sysctl_results,
            "prelink": {
                "prelink_installed": prelink_installed,
                "dpkg_status": prelink_dpkg.strip() if prelink_rc == 0 else None,
            },
            "apport": {
                "apport_installed": apport_installed,
                "dpkg_status": apport_dpkg.strip() if apport_rc == 0 else None,
                "service_enabled": apport_svc["enabled"],
                "service_active": apport_svc["active"],
                "etc_default_setting": apport_enabled_setting,
            },
            "core_dumps": {
                "ulimit_soft_core": ulimit_core_soft,
                "limits_conf_lines": limits_lines,
                "systemd_coredump_process_size_max": process_size_max_lines,
                "systemd_coredump_storage": storage_lines,
            },
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_process_hardening(), indent=2))
