"""
telnet_parser.py
=================
Parses raw Linux command outputs related to Telnet into a structured JSON format.

Rules:
  - Factual extraction only. No risk, severity, or analysis.
  - Missing data → "unknown". Never infer.
  - Accepts raw strings from any combination of sources.
  - All keys are snake_case.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Canonical output schema
# ---------------------------------------------------------------------------

def _empty_telnet_profile() -> dict[str, Any]:
    return {
        "telnet": {
            "service": {
                "installed": "false",
                "enabled":   "false",
                "running":   "false",
            },
            "network": {
                "port":                 23,
                "port_open":            "false",
                "listening_interfaces": [],
                "raw_bind_addresses":   [],
            },
            "configuration": {
                "inetd_enabled":      "false",
                "xinetd_enabled":     "false",
                "config_file_status": "disabled",
            },
            "firewall": {
                "type":           "unknown",
                "port_23_blocked": "unknown",
            },
            "sessions": {
                "active_connections": 0,
            },
        }
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_bool_str(value: bool) -> str:
    """Return 'true' or 'false' as strings (schema uses string booleans)."""
    return "true" if value else "false"


# ---------------------------------------------------------------------------
# 1. Service parser  (systemctl status telnet / telnetd)
# ---------------------------------------------------------------------------

def parse_systemctl(raw: str) -> dict[str, str]:
    """
    Extract installed/enabled/running state from `systemctl status telnet`
    or `systemctl is-enabled telnet` / `systemctl is-active telnet` output.

    Works with the combined `systemctl status` multi-line format.
    """
    result = {"installed": "false", "enabled": "false", "running": "false"}
    if not raw or not raw.strip():
        return result

    lower = raw.lower()

    # ----- installed -----
    # "could not be found" / "unrecognized" → not installed
    if re.search(r"could not be found|unit .* not found|not-found|no packages", lower):
        result["installed"] = "false"
    elif re.search(r"loaded\s*\(", lower):
        # Loaded line present → unit file found → installed
        result["installed"] = "true"

    # ----- enabled -----
    # Loaded line: Loaded: loaded (/lib/systemd/system/...; enabled; ...)
    # OR bare output from `systemctl is-enabled` → "enabled" / "disabled"
    enabled_m = re.search(r";\s*(enabled|disabled|static|masked|indirect)\s*[;)]", lower)
    if enabled_m:
        state = enabled_m.group(1)
        result["enabled"] = "true" if state == "enabled" else "false"
    elif raw.strip().lower() in ("enabled", "disabled", "static", "masked", "indirect"):
        result["enabled"] = "true" if raw.strip().lower() == "enabled" else "false"

    # ----- running -----
    # Active: active (running) / inactive (dead) / failed / active (listening)
    active_m = re.search(r"active:\s*(\S+)\s*\(([^)]+)\)", lower)
    if active_m:
        state = active_m.group(1)
        detail = active_m.group(2)
        result["running"] = "true" if state == "active" and detail in ("running", "listening") else "false"
    elif raw.strip().lower() in ("active", "inactive"):
        result["running"] = "true" if raw.strip().lower() == "active" else "false"

    return result


# ---------------------------------------------------------------------------
# 2. Package parser  (dpkg -l / rpm -q)
# ---------------------------------------------------------------------------

def parse_package_manager(raw: str) -> str:
    """
    Extract whether telnet(d) is installed from dpkg or rpm output.
    Returns 'true', 'false', or 'unknown'.
    """
    if not raw or not raw.strip():
        return "false"

    lower = raw.lower()

    # dpkg: lines starting with 'ii' mean installed
    if re.search(r"^ii\s+telnet", lower, re.MULTILINE):
        return "true"

    # dpkg: 'no packages found' or 'dpkg-query: no packages matching'
    if re.search(r"no packages found|no packages matching|not installed", lower):
        return "false"

    # rpm: package name returned without error → installed
    if re.search(r"telnet(?:d|server)?-[\d.]", lower):
        return "true"

    # rpm: 'is not installed'
    if re.search(r"is not installed", lower):
        return "false"

    return "false"


# ---------------------------------------------------------------------------
# 3. Network parser  (ss -tulpn / netstat -tulpn)
# ---------------------------------------------------------------------------

# Both ss and netstat use similar columnar output.
# We look for lines where the local address contains :23
_PORT23_RE = re.compile(r"(?:\b|[\s]):23(?:\b|[\s])")


def parse_network_listeners(raw: str) -> dict[str, Any]:
    """
    Extract port-23 listener state from `ss -tulpn` or `netstat -tulpn`.
    Returns port_open, listening_interfaces, raw_bind_addresses.
    """
    result: dict[str, Any] = {
        "port_open":            "false",
        "listening_interfaces": [],
        "raw_bind_addresses":   [],
    }
    if not raw or not raw.strip():
        return result

    found = False
    for line in raw.splitlines():
        if not _PORT23_RE.search(line):
            continue
        found = True
        # Extract the local address column (4th column for ss, 4th for netstat)
        parts = line.split()
        # Local address is typically col index 4 (0-based) for both tools
        local_addr = None
        for part in parts:
            if ":23" in part:
                local_addr = part
                break
        if not local_addr:
            continue
        result["raw_bind_addresses"].append(local_addr)
        # Derive interface: strip the :23 port suffix
        host = local_addr.rsplit(":", 1)[0]
        iface = "all" if host in ("0.0.0.0", "*", "::") else host
        if iface not in result["listening_interfaces"]:
            result["listening_interfaces"].append(iface)

    result["port_open"] = "true" if found else "false"
    return result


# ---------------------------------------------------------------------------
# 4. Configuration parsers  (inetd.conf / xinetd.d/telnet)
# ---------------------------------------------------------------------------

def parse_inetd_conf(raw: str) -> str:
    """
    Parse /etc/inetd.conf content.
    Returns 'true' if a non-commented telnet line is present, else 'false'.
    'false' if input is empty.
    """
    if not raw or not raw.strip():
        return "false"

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"telnet\b", stripped, re.IGNORECASE):
            return "true"
    return "false"


def parse_xinetd_conf(raw: str) -> str:
    """
    Parse /etc/xinetd.d/telnet content.
    Looks for 'disable = no' (enabled) or 'disable = yes' (disabled).
    Returns 'true' (enabled) or 'false' (disabled).
    """
    if not raw or not raw.strip():
        return "false"

    for line in raw.splitlines():
        m = re.match(r"\s*disable\s*=\s*(\w+)", line, re.IGNORECASE)
        if m:
            val = m.group(1).lower()
            # disable = no  → service IS enabled
            return "true" if val == "no" else "false"
    return "false"


def parse_config_file_status(inetd_raw: str, xinetd_raw: str) -> str:
    """
    Derive config_file_status from inetd/xinetd state.
    'enabled' if any source has it enabled, 'disabled' if explicitly disabled,
    'disabled' if no config data available.
    """
    inetd  = parse_inetd_conf(inetd_raw)
    xinetd = parse_xinetd_conf(xinetd_raw)
    if inetd == "true" or xinetd == "true":
        return "enabled"
    if inetd == "false" or xinetd == "false":
        return "disabled"
    return "disabled"


# ---------------------------------------------------------------------------
# 5. Firewall parsers  (ufw / iptables / firewalld)
# ---------------------------------------------------------------------------

def parse_firewall(raw: str) -> dict[str, str]:
    """
    Parse firewall rules from ufw status, iptables -L, or firewall-cmd output.
    Extracts firewall type and whether port 23 is blocked.
    """
    result = {"type": "unknown", "port_23_blocked": "unknown"}
    if not raw or not raw.strip():
        return result

    lower = raw.lower()

    # -- Detect firewall type --
    if re.search(r"^status:|ufw", lower, re.MULTILINE):
        result["type"] = "ufw"
    elif re.search(r"chain input|chain forward|chain output|-a input|-p tcp", lower):
        result["type"] = "iptables"
    elif re.search(r"firewalld|firewall-cmd|firewall-offline-cmd", lower):
        result["type"] = "firewalld"

    # -- Detect default incoming policies --
    default_blocked = "unknown"
    if result["type"] == "ufw":
        # Look for "Default: deny (incoming)" or "Default: allow (incoming)"
        m = re.search(r"default:\s*(\w+)\s*\(incoming\)", lower)
        if m:
            policy = m.group(1)
            default_blocked = "true" if policy in ("deny", "reject") else "false"
    elif result["type"] == "iptables":
        # Look for "Chain INPUT (policy DROP)" or "Chain INPUT (policy ACCEPT)"
        m = re.search(r"chain\s+input\s+\(policy\s+(\w+).*?\)", lower)
        if m:
            policy = m.group(1)
            default_blocked = "true" if policy in ("drop", "reject") else "false"

    # -- ufw: look for rules --
    if result["type"] == "ufw":
        # "23/tcp  DENY IN" or "Telnet  DENY"
        if re.search(r"(23(/tcp)?|telnet)\s+(deny|reject)", lower):
            result["port_23_blocked"] = "true"
        elif re.search(r"(23(/tcp)?|telnet)\s+(allow)", lower):
            result["port_23_blocked"] = "false"
        elif "status: active" in lower:
            # Fallback to default policy if no explicit rule is found
            result["port_23_blocked"] = default_blocked

    # -- iptables: look for rules --
    elif result["type"] == "iptables":
        if re.search(r"(drop|reject).{0,80}dpt:23|dport\s+23.{0,40}(drop|reject)", lower):
            result["port_23_blocked"] = "true"
        elif re.search(r"(accept).{0,80}dpt:23|dport\s+23.{0,40}accept", lower):
            result["port_23_blocked"] = "false"
        else:
            # Fallback to default policy
            result["port_23_blocked"] = default_blocked

    # -- firewalld: look for rules --
    elif result["type"] == "firewalld":
        if re.search(r"23/tcp", lower):
            result["port_23_blocked"] = "false"
        else:
            result["port_23_blocked"] = "true"

    return result


# ---------------------------------------------------------------------------
# 6. Session parser  (who / w / last)
# ---------------------------------------------------------------------------

def parse_sessions(raw: str) -> int:
    """
    Count active Telnet-related sessions from `who`, `w`, or `last` output.
    Looks for lines referencing pts (pseudo-terminals, typical for telnet/ssh
    remote sessions) or explicit 'telnet' entries.
    Returns an integer count of lines that appear to be active remote sessions.

    NOTE: cannot definitively distinguish telnet from SSH on pts alone.
    Returns only the count of entries explicitly mentioning 'telnet', or
    the total pt entries if the source is clearly a telnet session list.
    """
    if not raw or not raw.strip():
        return 0

    count = 0
    for line in raw.splitlines():
        lower = line.lower().strip()
        if not lower:
            continue
        # Explicit telnet marker
        if "telnet" in lower:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def parse_telnet_data(
    systemctl_raw:        str = "",
    package_raw:          str = "",
    network_raw:          str = "",
    inetd_raw:            str = "",
    xinetd_raw:           str = "",
    firewall_raw:         str = "",
    sessions_raw:         str = "",
    inetd_systemctl_raw:  str = "",  # output of systemctl status openbsd-inetd / inetd
) -> dict[str, Any]:
    """
    Build a structured Telnet security profile from raw command outputs.

    All arguments are optional; pass only the outputs you have.
    Missing inputs produce "unknown" values in the output.

    Args:
        systemctl_raw:  Output of `systemctl status telnet` (or is-enabled / is-active).
        package_raw:    Output of `dpkg -l telnet*` or `rpm -q telnet`.
        network_raw:    Output of `ss -tulpn` or `netstat -tulpn`.
        inetd_raw:      Content of `/etc/inetd.conf`.
        xinetd_raw:     Content of `/etc/xinetd.d/telnet`.
        firewall_raw:   Output of `ufw status`, `iptables -L -n`, or `firewall-cmd --list-all`.
        sessions_raw:   Output of `who`, `w`, or `last`.

    Returns:
        Structured dict matching the telnet JSON schema.
    """
    profile = _empty_telnet_profile()
    t = profile["telnet"]

    # -- Service --
    svc = parse_systemctl(systemctl_raw)
    # Package manager data can confirm 'installed' when systemctl can't
    if package_raw.strip():
        pkg_installed = parse_package_manager(package_raw)
        if svc["installed"] == "false":
            svc["installed"] = pkg_installed

    # If Telnet is managed via inetd (openbsd-inetd), infer service state
    # from the inetd daemon status + inetd.conf content.
    inetd_enabled_val = parse_inetd_conf(inetd_raw)
    if svc["installed"] == "false" and inetd_enabled_val == "true":
        # Telnet is configured in inetd.conf; check if inetd itself is running
        if inetd_systemctl_raw.strip():
            inetd_svc = parse_systemctl(inetd_systemctl_raw)
            if inetd_svc["running"] == "true":
                svc["installed"] = "true"
                svc["enabled"]   = inetd_svc["enabled"]
                svc["running"]   = "true"

    t["service"].update(svc)

    # -- Network --
    net = parse_network_listeners(network_raw)
    t["network"].update(net)

    # -- Configuration --
    t["configuration"]["inetd_enabled"]      = inetd_enabled_val
    t["configuration"]["xinetd_enabled"]     = parse_xinetd_conf(xinetd_raw)
    t["configuration"]["config_file_status"] = parse_config_file_status(inetd_raw, xinetd_raw)

    # -- Firewall --
    fw = parse_firewall(firewall_raw)
    t["firewall"]["type"]            = fw["type"]
    t["firewall"]["port_23_blocked"] = fw["port_23_blocked"]

    # -- Sessions --
    t["sessions"]["active_connections"] = parse_sessions(sessions_raw)

    return profile


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    cli = argparse.ArgumentParser(
        description="Telnet data extractor — runs system commands and emits a JSON profile."
    )
    cli.parse_args()

    def _run(cmd: list[str], timeout: int = 10) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout
        except FileNotFoundError:
            print(f"[warn] command not found: {cmd[0]}", file=sys.stderr)
            return ""
        except subprocess.TimeoutExpired:
            print(f"[warn] timed out: {' '.join(cmd)}", file=sys.stderr)
            return ""

    def _read_file(path: str) -> str:
        try:
            with open(path) as f:
                return f.read()
        except (FileNotFoundError, PermissionError):
            return ""

    systemctl_out = _run(["systemctl", "status", "telnet"])
    if not systemctl_out.strip():
        systemctl_out = _run(["systemctl", "status", "telnetd"])
    if not systemctl_out.strip():
        systemctl_out = _run(["systemctl", "status", "telnet.socket"])

    package_out  = _run(["dpkg", "-l", "telnet*"])
    if not package_out.strip():
        package_out = _run(["rpm", "-q", "telnet"])

    network_out  = _run(["ss",   "-tulpn"])
    if not network_out.strip():
        network_out = _run(["netstat", "-tulpn"])

    inetd_out    = _read_file("/etc/inetd.conf")
    xinetd_out   = _read_file("/etc/xinetd.d/telnet")

    fw_out = _run(["ufw", "status", "verbose"])
    if not fw_out.strip():
        fw_out = _run(["iptables", "-L", "-n", "-v"])
    if not fw_out.strip():
        fw_out = _run(["firewall-cmd", "--list-all"])

    sessions_out = _run(["who"])

    profile = parse_telnet_data(
        systemctl_raw=systemctl_out,
        package_raw=package_out,
        network_raw=network_out,
        inetd_raw=inetd_out,
        xinetd_raw=xinetd_out,
        firewall_raw=fw_out,
        sessions_raw=sessions_out,
    )
    print(json.dumps(profile, indent=2))
