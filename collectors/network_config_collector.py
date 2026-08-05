"""
network_config_collector.py
===========================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 3 (Network Configuration):

  3.1  Network Devices
  3.2  Network Kernel Modules
  3.3  Network Kernel Parameters (sysctl – IPv4 and IPv6)

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
from typing import Any


from collectors.common import (
    get_sysctl_persisted,
    get_sysctl_runtime,
    load_sysctl_conf_lines,
    read_file,
    run_cmd,
)

_run_cmd = run_cmd
_read_file = read_file
_get_sysctl_runtime = get_sysctl_runtime
_get_sysctl_persisted = get_sysctl_persisted


def _load_sysctl_conf_lines(errors: list[dict[str, str]]) -> list[tuple[str, str]]:
    return load_sysctl_conf_lines()



def _read_conf_dir(dir_path: str, ext: str = ".conf") -> list[dict[str, str]]:
    """Read all configuration files in a directory matching an extension."""
    files_content: list[dict[str, str]] = []
    if os.path.exists(dir_path):
        try:
            for fname in sorted(os.listdir(dir_path)):
                if fname.endswith(ext):
                    abs_path = os.path.join(dir_path, fname)
                    content = _read_file(abs_path)
                    if content is not None:
                        files_content.append({"path": abs_path, "content": content})
        except Exception:
            pass
    return files_content


# ---------------------------------------------------------------------------
# 3.1 – Network Devices
# ---------------------------------------------------------------------------

def _collect_network_devices(errors: list[dict[str, str]]) -> dict[str, Any]:
    """
    Collect facts for CIS 3.1.x (Network Devices).

    Returns a dict with sub-keys:
        ipv6_status, wireless_interfaces, bluetooth
    """

    # ------------------------------------------------------------------
    # 3.1.1 – IPv6 status (informational / Manual — facts only, no verdict)
    # ------------------------------------------------------------------
    ipv6_sysfs_disable: str | None = None
    sysfs_content = _read_file("/sys/module/ipv6/parameters/disable")
    if sysfs_content is not None:
        ipv6_sysfs_disable = sysfs_content.strip()  # "0" = enabled, "1" = disabled

    grub_cmdline: str | None = None
    grub_ipv6_disabled_flag: bool | None = None
    grub_content = _read_file("/etc/default/grub")
    if grub_content is not None:
        for line in grub_content.splitlines():
            stripped = line.strip()
            if stripped.startswith("GRUB_CMDLINE_LINUX=") and not stripped.startswith("#"):
                grub_cmdline = stripped
                grub_ipv6_disabled_flag = "ipv6.disable=1" in stripped
                break

    # Count inet6 addresses visible on any interface
    ip6_addr_out, ip6_addr_err, ip6_rc = _run_cmd(["ip", "-6", "addr", "show"])
    inet6_addresses: list[str] = []
    if ip6_rc == 0 and ip6_addr_out:
        for line in ip6_addr_out.splitlines():
            line = line.strip()
            if line.startswith("inet6"):
                inet6_addresses.append(line)

    ipv6_status = {
        "sysfs_disable_value": ipv6_sysfs_disable,   # "0"=enabled, "1"=disabled, None=not available
        "grub_cmdline_linux_raw": grub_cmdline,
        "grub_ipv6_disable_flag": grub_ipv6_disabled_flag,
        "inet6_addresses_found": inet6_addresses,
        "inet6_address_count": len(inet6_addresses),
    }

    # ------------------------------------------------------------------
    # 3.1.2 – Wireless interfaces
    # ------------------------------------------------------------------
    ip_link_out, _, ip_link_rc = _run_cmd(["ip", "link", "show"])
    wireless_devices: list[dict[str, str]] = []

    # Heuristic: look for "wlan", "wifi", "wlp" prefix in interface names
    if ip_link_rc == 0 and ip_link_out:
        for line in ip_link_out.splitlines():
            if ": " in line and line[0].isdigit():
                parts = line.split(": ")
                if len(parts) >= 2:
                    iface = parts[1].split("@")[0].strip()
                    lower = iface.lower()
                    if any(lower.startswith(p) for p in ("wlan", "wlp", "wl", "wifi", "ath", "ra")):
                        wireless_devices.append({"interface": iface, "source": "ip_link"})

    # Try nmcli (may not be installed — graceful)
    nmcli_out, _, nmcli_rc = _run_cmd(["nmcli", "device", "status"])
    nmcli_wireless: list[dict[str, str]] = []
    nmcli_available: bool = nmcli_rc != -1  # -1 means tool not found at all
    if nmcli_rc == 0 and nmcli_out:
        for line in nmcli_out.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 2:
                iface, dev_type = parts[0], parts[1].lower()
                if dev_type in ("wifi", "802-11-wireless"):
                    nmcli_wireless.append({"interface": iface, "type": parts[1]})

    # Wireless kernel modules (cfg80211 is the primary indicator on Linux)
    wireless_module_names = ["cfg80211", "mac80211", "iwlwifi", "ath9k", "ath10k_core", "rtl8xxxu"]
    loaded_wireless_modules: list[str] = []
    lsmod_out, _, lsmod_rc = _run_cmd(["lsmod"])
    if lsmod_rc == 0 and lsmod_out:
        loaded_modules_lower = lsmod_out.lower()
        for mod in wireless_module_names:
            if mod in loaded_modules_lower:
                loaded_wireless_modules.append(mod)

    wireless_interfaces = {
        "wireless_devices_ip_link": wireless_devices,
        "wireless_devices_nmcli": nmcli_wireless,
        "nmcli_available": nmcli_available,
        "loaded_wireless_kernel_modules": loaded_wireless_modules,
        # Convenience summary: any wireless found at all?
        "any_wireless_found": bool(wireless_devices or nmcli_wireless or loaded_wireless_modules),
    }

    # ------------------------------------------------------------------
    # 3.1.3 – Bluetooth services
    # ------------------------------------------------------------------
    bluez_dpkg_out, _, bluez_rc = _run_cmd(["dpkg", "-s", "bluez"])
    bluez_installed = (bluez_rc == 0 and (
        "install ok installed" in bluez_dpkg_out.lower()
        or ("status: install" in bluez_dpkg_out.lower())
    ))

    bt_enabled_out, _, _ = _run_cmd(["systemctl", "is-enabled", "bluetooth.service"])
    bt_active_out, _, _ = _run_cmd(["systemctl", "is-active", "bluetooth.service"])

    bluetooth = {
        "bluez_installed": bluez_installed,
        "bluez_dpkg_status": bluez_dpkg_out.strip() if bluez_rc == 0 else None,
        "bluetooth_service_enabled": bt_enabled_out.strip(),
        "bluetooth_service_active": bt_active_out.strip(),
    }

    return {
        "ipv6_status": ipv6_status,
        "wireless_interfaces": wireless_interfaces,
        "bluetooth": bluetooth,
    }


# ---------------------------------------------------------------------------
# 3.2 – Network Kernel Modules
# ---------------------------------------------------------------------------

_NETWORK_MODULES = ["atm", "can", "dccp", "rds", "sctp", "tipc"]


def _collect_kernel_modules(errors: list[dict[str, str]]) -> dict[str, Any]:
    """
    Collect facts for CIS 3.2.x — whether each restricted network kernel
    module is loaded and whether it is disabled via modprobe.d config.

    Returns a dict keyed by module name, each value:
      {module_name, currently_loaded, modprobe_config_lines}
    """
    # Read lsmod output once
    lsmod_out, lsmod_err, lsmod_rc = _run_cmd(["lsmod"])
    lsmod_lines: list[str] = lsmod_out.splitlines() if lsmod_rc == 0 else []

    # Collect all modprobe.d config files
    modprobe_files: list[dict[str, str]] = []
    modprobe_main = _read_file("/etc/modprobe.conf")
    if modprobe_main is not None:
        modprobe_files.append({"path": "/etc/modprobe.conf", "content": modprobe_main})

    modprobe_d_dir = "/etc/modprobe.d"
    if os.path.exists(modprobe_d_dir):
        try:
            for fname in sorted(os.listdir(modprobe_d_dir)):
                if fname.endswith(".conf"):
                    fpath = os.path.join(modprobe_d_dir, fname)
                    content = _read_file(fpath)
                    if content is not None:
                        modprobe_files.append({"path": fpath, "content": content})
        except Exception as exc:
            errors.append({"check": "modprobe.d_listdir", "error": str(exc)})

    modules: dict[str, Any] = {}
    for mod in _NETWORK_MODULES:
        # Is the module currently loaded?
        currently_loaded = any(
            line.lower().startswith(mod + " ") or line.lower().startswith(mod + "\t")
            for line in lsmod_lines
        )

        # Grep all modprobe.d files for relevant lines
        config_lines: list[dict[str, str]] = []
        for mf in modprobe_files:
            for line in mf["content"].splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                lower = stripped.lower()
                # Match: install <mod> /bin/false|/bin/true  OR  blacklist <mod>
                if (lower.startswith(f"install {mod} ") or
                        lower.startswith(f"blacklist {mod}") or
                        lower == f"blacklist {mod}"):
                    config_lines.append({"file": mf["path"], "line": stripped})

        modules[mod] = {
            "module_name": mod,
            "currently_loaded": currently_loaded,
            "modprobe_config_lines": config_lines,
        }

    return modules


# ---------------------------------------------------------------------------
# 3.3 – Network Kernel Parameters (sysctl)
# ---------------------------------------------------------------------------

_SYSCTL_IPV4_KEYS = [
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.forwarding",
    "net.ipv4.conf.default.forwarding",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.default.secure_redirects",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.default.log_martians",
    "net.ipv4.tcp_syncookies",
]

_SYSCTL_IPV6_KEYS = [
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.default.forwarding",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.default.accept_source_route",
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.default.accept_ra",
]


def _get_sysctl_runtime(key: str) -> str | None:
    """Return the live runtime value for a sysctl key, or None if unavailable."""
    out, err, rc = _run_cmd(["sysctl", "-n", key])
    if rc == 0 and out.strip():
        return out.strip()
    return None


def _get_sysctl_persisted(
    key: str,
    sysctl_conf_lines: list[tuple[str, str]],
) -> tuple[str | None, str | None]:
    """
    Search pre-loaded sysctl config lines for the last matching non-comment
    assignment of *key*.

    Parameters
    ----------
    key:
        Fully-qualified sysctl key (e.g. "net.ipv4.ip_forward").
    sysctl_conf_lines:
        List of (source_file_path, line) tuples from /etc/sysctl.conf and
        /etc/sysctl.d/*.conf. Lines are processed in file order; last match wins.

    Returns
    -------
    (persisted_value, source_file) — both None if not found.
    """
    persisted_value: str | None = None
    source_file: str | None = None

    # Normalise key for matching: dots and slashes are interchangeable
    key_normalised = key.replace("/", ".")

    for file_path, line in sysctl_conf_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        lhs, _, rhs = stripped.partition("=")
        lhs_norm = lhs.strip().replace("/", ".")
        if lhs_norm == key_normalised:
            persisted_value = rhs.strip()
            source_file = file_path

    return persisted_value, source_file


def _load_sysctl_conf_lines(errors: list[dict[str, str]]) -> list[tuple[str, str]]:
    """
    Load all sysctl configuration lines from /etc/sysctl.conf and
    /etc/sysctl.d/*.conf (sorted, so last file wins on duplicates).

    Returns a flat list of (source_file_path, raw_line) tuples.
    """
    all_lines: list[tuple[str, str]] = []

    main_conf = "/etc/sysctl.conf"
    content = _read_file(main_conf)
    if content is not None:
        for line in content.splitlines():
            all_lines.append((main_conf, line))

    sysctl_d = "/etc/sysctl.d"
    if os.path.exists(sysctl_d):
        try:
            for fname in sorted(os.listdir(sysctl_d)):
                if fname.endswith(".conf"):
                    fpath = os.path.join(sysctl_d, fname)
                    sub_content = _read_file(fpath)
                    if sub_content is not None:
                        for line in sub_content.splitlines():
                            all_lines.append((fpath, line))
        except Exception as exc:
            errors.append({"check": "sysctl.d_listdir", "error": str(exc)})

    return all_lines


def _collect_sysctl(
    keys: list[str],
    sysctl_conf_lines: list[tuple[str, str]],
) -> dict[str, Any]:
    """
    For each key in *keys*, collect both the live runtime value and the
    highest-precedence persisted config value.

    Returns a dict keyed by sysctl parameter name.
    Each value:
      {key, runtime_value, persisted_value, persisted_config_source_file}
    """
    result: dict[str, Any] = {}
    for key in keys:
        runtime_val = _get_sysctl_runtime(key)
        persisted_val, persisted_src = _get_sysctl_persisted(key, sysctl_conf_lines)
        result[key] = {
            "key": key,
            "runtime_value": runtime_val,
            "persisted_value": persisted_val,
            "persisted_config_source_file": persisted_src,
        }
    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_network_config() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 3
    (Network Configuration).

    Returns:
        dict: A JSON-serialisable dictionary with the top-level key
              'network_config' containing sub-keys:
                network_devices, kernel_modules, sysctl_ipv4, sysctl_ipv6, errors
    """
    errors: list[dict[str, str]] = []

    # Pre-load sysctl persisted config (shared across IPv4 and IPv6)
    sysctl_conf_lines = _load_sysctl_conf_lines(errors)

    network_devices = _collect_network_devices(errors)
    kernel_modules = _collect_kernel_modules(errors)
    sysctl_ipv4 = _collect_sysctl(_SYSCTL_IPV4_KEYS, sysctl_conf_lines)
    sysctl_ipv6 = _collect_sysctl(_SYSCTL_IPV6_KEYS, sysctl_conf_lines)

    return {
        "network_config": {
            "network_devices": network_devices,
            "kernel_modules": kernel_modules,
            "sysctl_ipv4": sysctl_ipv4,
            "sysctl_ipv6": sysctl_ipv6,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_network_config(), indent=2))
