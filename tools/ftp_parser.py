"""
ftp_parser.py
==============
Parses raw Linux command outputs related to FTP services (vsftpd, proftpd, pure-ftpd)
into a structured JSON format.

Rules:
  - Factual extraction only. No risk, severity, or analysis.
  - Missing data → "unknown". Never infer.
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

def _empty_ftp_profile() -> dict[str, Any]:
    return {
        "ftp": {
            "service": {
                "name":      "",
                "installed": "unknown",
                "enabled":   "unknown",
                "running":   "unknown",
            },
            "network": {
                "port":                 21,
                "port_open":            "unknown",
                "listening_interfaces": [],
                "raw_bind_addresses":   [],
            },
            "configuration": {
                "anonymous_enable":  "true",
                "local_enable":      "false",
                "write_enable":      "false",
                "chroot_local_user": "false",
                "ssl_enabled":       "false",
                "force_tls":         "false",
                "userlist_enable":   "false",
                "userlist_deny":     "true",
            },
            "firewall": {
                "type":            "unknown",
                "port_21_blocked": "unknown",
            },
            "activity": {
                "active_connections": 0,
            },
        }
    }


# ---------------------------------------------------------------------------
# 1. Service parser (systemctl status vsftpd / proftpd / pure-ftpd)
# ---------------------------------------------------------------------------

def parse_systemctl(raw: str) -> dict[str, str]:
    """
    Extract installed/enabled/running state from `systemctl status` output.
    Can detect vsftpd, proftpd, or pure-ftpd if present in the output.
    """
    result = {"name": "", "installed": "unknown", "enabled": "unknown", "running": "unknown"}
    if not raw or not raw.strip():
        return result

    lower = raw.lower()

    # Detect service name
    for name in ("vsftpd", "proftpd", "pure-ftpd"):
        if name in lower:
            result["name"] = name
            break

    # ----- installed -----
    if re.search(r"could not be found|unit .* not found|not-found", lower):
        result["installed"] = "false"
    elif re.search(r"loaded\s*\(", lower):
        result["installed"] = "true"

    # ----- enabled -----
    enabled_m = re.search(r";\s*(enabled|disabled|static|masked|indirect)\s*[;)]", lower)
    if enabled_m:
        state = enabled_m.group(1)
        result["enabled"] = "true" if state == "enabled" else "false"
    elif raw.strip().lower() in ("enabled", "disabled", "static", "masked", "indirect"):
        result["enabled"] = "true" if raw.strip().lower() == "enabled" else "false"

    # ----- running -----
    active_m = re.search(r"active:\s*(\S+)\s*\(([^)]+)\)", lower)
    if active_m:
        state = active_m.group(1)
        detail = active_m.group(2)
        result["running"] = "true" if state == "active" and detail == "running" else "false"
    elif raw.strip().lower() in ("active", "inactive"):
        result["running"] = "true" if raw.strip().lower() == "active" else "false"

    return result


# ---------------------------------------------------------------------------
# 2. Network parser (ss -tulpn / netstat -tulpn)
# ---------------------------------------------------------------------------

_PORT21_RE = re.compile(r":21(?:\s|$)")

def parse_network_listeners(raw: str) -> dict[str, Any]:
    """
    Extract port-21 listener state from `ss -tulpn` or `netstat -tulpn`.
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
        if not _PORT21_RE.search(line):
            continue
        found = True
        parts = line.split()
        local_addr = None
        for part in parts:
            if ":21" in part:
                local_addr = part
                break
        if not local_addr:
            continue
        result["raw_bind_addresses"].append(local_addr)
        host = local_addr.rsplit(":", 1)[0]
        iface = "all" if host in ("0.0.0.0", "*", "::") else host
        if iface not in result["listening_interfaces"]:
            result["listening_interfaces"].append(iface)

    result["port_open"] = "true" if found else "false"
    return result


# ---------------------------------------------------------------------------
# 3. Configuration Parsers
# ---------------------------------------------------------------------------

def _parse_generic_conf(raw: str, key_map: dict[str, str]) -> dict[str, str]:
    """
    Helper to parse generic KEY=VALUE configuration files.
    key_map maps file keys (e.g. 'anonymous_enable') to target JSON keys.
    """
    # Initialize result as empty; only keys found in the file will be returned.
    # This allow callers to use their own defaults for missing/commented keys.
    result = {}
    if not raw or not raw.strip():
        return result

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Handle formats like 'key=value', 'key value', 'key: value'
        m = re.match(r"^\s*([\w.]+)\s*[=:\s]\s*(\S+)", line, re.IGNORECASE)
        if m:
            key = m.group(1).lower()
            val = m.group(2).lower().strip('"\'')
            if key in key_map:
                json_key = key_map[key]
                # Map booleans
                if val in ("yes", "true", "1", "on"):
                    result[json_key] = "true"
                elif val in ("no", "false", "0", "off"):
                    result[json_key] = "false"
                else:
                    result[json_key] = val
    return result

def parse_vsftpd_conf(raw: str) -> dict[str, str]:
    key_map = {
        "anonymous_enable":  "anonymous_enable",
        "local_enable":      "local_enable",
        "write_enable":      "write_enable",
        "chroot_local_user": "chroot_local_user",
        "ssl_enable":        "ssl_enabled",
        "force_local_data_ssl": "force_tls",
        "userlist_enable":   "userlist_enable",
        "userlist_deny":     "userlist_deny",
    }
    return _parse_generic_conf(raw, key_map)

def parse_proftpd_conf(raw: str) -> dict[str, str]:
    # ProFTPD often uses XML-like blocks but also key-value pairs.
    # We expand the map to ensure we don't leave fields as "unknown" if they exist.
    key_map = {
        "anonymous_enable":  "anonymous_enable",
        "local_enable":      "local_enable",
        "write_enable":      "write_enable",
        "chroot_local_user": "chroot_local_user",
        "ssl_enable":        "ssl_enabled",
        "userlist_enable":   "userlist_enable",
        "userlist_deny":     "userlist_deny",
    }
    return _parse_generic_conf(raw, key_map)

# ---------------------------------------------------------------------------
# 4. Firewall parser
# ---------------------------------------------------------------------------

def parse_firewall(raw: str) -> dict[str, str]:
    result = {"type": "unknown", "port_21_blocked": "unknown"}
    if not raw or not raw.strip():
        return result

    lower = raw.lower()

    # -- Detect firewall type --
    if re.search(r"^status:|ufw", lower, re.MULTILINE):
        result["type"] = "ufw"
    elif re.search(r"chain input|chain forward|chain output|-a input", lower):
        result["type"] = "iptables"
    elif re.search(r"firewalld|firewall-cmd", lower):
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
        if re.search(r"(21(/tcp)?|ftp)\s+(deny|reject)", lower):
            result["port_21_blocked"] = "true"
        elif re.search(r"(21(/tcp)?|ftp)\s+(allow)", lower):
            result["port_21_blocked"] = "false"
        elif "status: active" in lower:
            # Fallback to default policy if no explicit rule is found
            result["port_21_blocked"] = default_blocked

    # -- iptables: look for rules --
    elif result["type"] == "iptables":
        if re.search(r"(drop|reject).{0,80}dpt:21|dport\s+21.{0,40}(drop|reject)", lower):
            result["port_21_blocked"] = "true"
        elif re.search(r"(accept).{0,80}dpt:21|dport\s+21.{0,40}accept", lower):
            result["port_21_blocked"] = "false"
        else:
            # Fallback to default policy
            result["port_21_blocked"] = default_blocked

    # -- firewalld: look for services/ports --
    elif result["type"] == "firewalld":
        if re.search(r"21/tcp|ftp", lower):
            result["port_21_blocked"] = "false"
        else:
            result["port_21_blocked"] = "true"

    return result


# ---------------------------------------------------------------------------
# 5. Activity parser
# ---------------------------------------------------------------------------

def parse_activity(raw: str) -> int:
    """Count active FTP connections from `ss -tnp` or similar output."""
    if not raw or not raw.strip():
        return 0
    count = 0
    for line in raw.splitlines():
        # Look for established connections on port 21
        if re.search(r"ESTAB.*:21\s", line) or re.search(r":21\s+ESTAB", line):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def parse_ftp_data(
    systemctl_raw: str = "",
    network_raw:   str = "",
    config_raw:    str = "",
    firewall_raw:  str = "",
    activity_raw:  str = "",
) -> dict[str, Any]:
    profile = _empty_ftp_profile()
    ftp = profile["ftp"]

    # Service
    svc = parse_systemctl(systemctl_raw)
    ftp["service"].update(svc)

    # Network
    net = parse_network_listeners(network_raw)
    ftp["network"].update(net)

    # Configuration
    # We assume one config file is provided at a time for normalization.
    # If it looks like vsftpd, use vsftpd parser. 
    # Added more indicators for vsftpd detection.
    is_vsftpd = (
        svc["name"] == "vsftpd" or 
        "vsftpd" in config_raw or 
        "anonymous_enable" in config_raw or
        "chroot_local_user" in config_raw
    )
    
    if is_vsftpd:
        conf = parse_vsftpd_conf(config_raw)
        ftp["configuration"].update(conf)
    else:
        conf = parse_proftpd_conf(config_raw)
        ftp["configuration"].update(conf)

    # Firewall
    fw = parse_firewall(firewall_raw)
    ftp["firewall"]["type"] = fw["type"]
    ftp["firewall"]["port_21_blocked"] = fw["port_21_blocked"]

    # Activity
    ftp["activity"]["active_connections"] = parse_activity(activity_raw)

    return profile


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    def _run(cmd: list[str]) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except: return ""

    def _read_file(path: str) -> str:
        try:
            with open(path) as f: return f.read()
        except: return ""

    # Try various FTP services
    systemctl_out = ""
    for svc in ["vsftpd", "proftpd", "pure-ftpd"]:
        out = _run(["systemctl", "status", svc])
        if out:
            systemctl_out = out
            break

    network_out = _run(["ss", "-tulpn"])
    if not network_out: network_out = _run(["netstat", "-tulpn"])

    config_out = _read_file("/etc/vsftpd.conf")
    if not config_out: config_out = _read_file("/etc/proftpd/proftpd.conf")
    if not config_out: config_out = _read_file("/etc/pure-ftpd.conf")

    fw_out = _run(["ufw", "status", "verbose"])
    if not fw_out: fw_out = _run(["iptables", "-L", "-n"])
    if not fw_out: fw_out = _run(["firewall-cmd", "--list-all"])

    activity_out = _run(["ss", "-tnp"])

    profile = parse_ftp_data(
        systemctl_raw=systemctl_out,
        network_raw=network_out,
        config_raw=config_out,
        firewall_raw=fw_out,
        activity_raw=activity_out
    )
    print(json.dumps(profile, indent=2))
