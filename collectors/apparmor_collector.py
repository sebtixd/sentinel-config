"""
apparmor_collector.py
=====================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.3 (Mandatory Access Control / AppArmor):

  1.3.1.1  AppArmor packages installed (apparmor, apparmor-utils)
  1.3.1.2  AppArmor enabled (sysfs, systemd, kernel command line)
  1.3.1.3  AppArmor profiles status (raw aa-status output)
  1.3.1.4  apparmor_restrict_unprivileged_unconfined sysctl parameter

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
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


def _get_sysctl_runtime(key: str) -> str | None:
    out, _, rc = _run_cmd(["sysctl", "-n", key])
    return out.strip() if rc == 0 and out.strip() else None


def _get_sysctl_persisted(key: str, sysctl_lines: list) -> tuple:
    persisted_value: str | None = None
    source_file: str | None = None
    key_normalised = key.replace("/", ".")
    for file_path, line in sysctl_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        lhs, _, rhs = stripped.partition("=")
        if lhs.strip().replace("/", ".") == key_normalised:
            persisted_value = rhs.strip()
            source_file = file_path
    return persisted_value, source_file


def _load_sysctl_conf_lines() -> list:
    import os
    all_lines: list = []
    main_conf = "/etc/sysctl.conf"
    content = _read_file(main_conf)
    if content:
        for line in content.splitlines():
            all_lines.append((main_conf, line))
    sysctl_d = "/etc/sysctl.d"
    if os.path.exists(sysctl_d):
        try:
            for fname in sorted(os.listdir(sysctl_d)):
                if fname.endswith(".conf"):
                    fpath = os.path.join(sysctl_d, fname)
                    sub = _read_file(fpath)
                    if sub:
                        for line in sub.splitlines():
                            all_lines.append((fpath, line))
        except Exception:
            pass
    return all_lines





def collect_apparmor() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.3 (AppArmor).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'apparmor'.
    """
    errors: list[dict[str, str]] = []

    # 1.3.1.1: Packages
    apparmor_installed = _dpkg_installed("apparmor")
    apparmor_dpkg, _, aa_rc = _run_cmd(["dpkg", "-s", "apparmor"])

    utils_installed = _dpkg_installed("apparmor-utils")
    utils_dpkg, _, utils_rc = _run_cmd(["dpkg", "-s", "apparmor-utils"])

    # 1.3.1.2: Enabled status
    sysfs_content = _read_file("/sys/module/apparmor/parameters/enabled")
    sysfs_enabled = sysfs_content.strip() if sysfs_content else None

    apparmor_svc = _systemctl_state("apparmor.service")

    grub_content = _read_file("/etc/default/grub")
    grub_cmdline: str | None = None
    grub_apparmor_flag: bool = False
    grub_security_flag: bool = False

    if grub_content:
        for line in grub_content.splitlines():
            stripped = line.strip()
            if stripped.startswith("GRUB_CMDLINE_LINUX=") and not stripped.startswith("#"):
                grub_cmdline = stripped
                grub_apparmor_flag = "apparmor=1" in stripped
                grub_security_flag = "security=apparmor" in stripped
                break

    # 1.3.1.3: aa-status raw output
    aa_status_out, aa_status_err, aa_status_rc = _run_cmd(["aa-status"])
    if aa_status_rc != 0:
        aa_status_out_alt, _, aa_alt_rc = _run_cmd(["apparmor_status"])
        if aa_alt_rc == 0:
            aa_status_out = aa_status_out_alt
            aa_status_rc = 0

    # 1.3.1.4: kernel.apparmor_restrict_unprivileged_unconfined
    sysctl_lines = _load_sysctl_conf_lines()
    key = "kernel.apparmor_restrict_unprivileged_unconfined"
    runtime_val = _get_sysctl_runtime(key)
    persisted_val, persisted_src = _get_sysctl_persisted(key, sysctl_lines)

    return {
        "apparmor": {
            "packages": {
                "apparmor_installed": apparmor_installed,
                "apparmor_dpkg_status": apparmor_dpkg.strip() if aa_rc == 0 else None,
                "apparmor_utils_installed": utils_installed,
                "apparmor_utils_dpkg_status": utils_dpkg.strip() if utils_rc == 0 else None,
            },
            "enabled_status": {
                "sysfs_enabled_value": sysfs_enabled,
                "service_enabled": apparmor_svc["enabled"],
                "service_active": apparmor_svc["active"],
                "grub_cmdline_raw": grub_cmdline,
                "grub_apparmor_flag": grub_apparmor_flag,
                "grub_security_flag": grub_security_flag,
            },
            "aa_status": {
                "raw_output": aa_status_out,
                "error_output": aa_status_err,
                "return_code": aa_status_rc,
            },
            "restrict_unprivileged_sysctl": {
                "key": key,
                "runtime_value": runtime_val,
                "persisted_value": persisted_val,
                "persisted_config_source_file": persisted_src,
            },
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_apparmor(), indent=2))
