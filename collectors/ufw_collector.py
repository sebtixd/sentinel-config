"""
ufw_collector.py
================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 4.1 (Configure Uncomplicated Firewall / ufw).

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def _run_cmd(cmd: list[str]) -> tuple[str, str, int]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def collect_ufw() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 4.1
    (Uncomplicated Firewall).

    Returns:
        dict: A JSON-serializable dictionary with the top-level 'ufw_firewall'
    """
    errors: list[dict[str, str]] = []

    ufw_installed = False
    ufw_dpkg_status: str | None = None

    # dpkg -s ufw
    dpkg_out, _, rc = _run_cmd(["dpkg-query", "-W", "-f=${Status}", "ufw"])
    if rc == 0 and dpkg_out:
        ufw_dpkg_status = dpkg_out.strip()
        if "install ok installed" in ufw_dpkg_status.lower() or "ok installed" in ufw_dpkg_status.lower() or "installed" in ufw_dpkg_status.lower():
            ufw_installed = True

    # 4.1.1 - Alternatives
    nftables_active = False
    iptables_persistent_active = False

    nft_out, _, _ = _run_cmd(["systemctl", "is-active", "nftables"])
    if nft_out.strip() == "active":
        nftables_active = True

    ipt_out, _, _ = _run_cmd(["systemctl", "is-active", "iptables-persistent"])
    if ipt_out.strip() == "active":
        iptables_persistent_active = True

    alternative_firewalls_active = {
        "nftables": nftables_active,
        "iptables-persistent": iptables_persistent_active
    }

    # If ufw is completely missing, we map empty states
    service_configured: dict[str, Any] = {
        "is_enabled": None,
        "is_active": None,
        "status_verbose": None,
        "other_firewall_services_running": []
    }

    default_policies: dict[str, Any] = {
        "incoming": None,
        "outgoing": None,
        "routed": None,
        "etc_default_ufw": None
    }

    if nftables_active:
        service_configured["other_firewall_services_running"].append("nftables")
    if iptables_persistent_active:
        service_configured["other_firewall_services_running"].append("iptables-persistent")

    if ufw_installed:
        # systemctl is-enabled
        is_en_out, _, rc_en = _run_cmd(["systemctl", "is-enabled", "ufw"])
        service_configured["is_enabled"] = is_en_out.strip() if rc_en == 0 else "disabled"

        # systemctl is-active
        is_act_out, _, _ = _run_cmd(["systemctl", "is-active", "ufw"])
        service_configured["is_active"] = is_act_out.strip()

        # ufw status verbose
        status_out, status_err, rc_stat = _run_cmd(["ufw", "status", "verbose"])
        service_configured["status_verbose"] = status_out.strip() if status_out else status_err.strip()

        # Parse the status string for defaults
        if status_out:
            for line in status_out.splitlines():
                line = line.strip().lower()
                if line.startswith("default:"):
                    # Example: "Default: deny (incoming), allow (outgoing), disabled (routed)"
                    # We can rely on LLM or do simple string matching. The prompt asked us to parse default paths implicitly:
                    if "deny (incoming)" in line or "drop (incoming)" in line or "reject (incoming)" in line:
                        if "deny" in line.split("(incoming)")[0][-6:]:
                            default_policies["incoming"] = "deny"
                        elif "drop" in line.split("(incoming)")[0][-6:]:
                            default_policies["incoming"] = "drop"
                        elif "reject" in line.split("(incoming)")[0][-8:]:
                            default_policies["incoming"] = "reject"
                    elif "allow (incoming)" in line:
                        default_policies["incoming"] = "allow"

                    if "deny (outgoing)" in line or "drop (outgoing)" in line or "reject (outgoing)" in line:
                        if "deny" in line.split("(outgoing)")[0][-6:]:
                            default_policies["outgoing"] = "deny"
                        elif "drop" in line.split("(outgoing)")[0][-6:]:
                            default_policies["outgoing"] = "drop"
                        elif "reject" in line.split("(outgoing)")[0][-8:]:
                            default_policies["outgoing"] = "reject"
                    elif "allow (outgoing)" in line:
                        default_policies["outgoing"] = "allow"

                    if "disabled (routed)" in line:
                        default_policies["routed"] = "disabled"
                    elif "allow (routed)" in line:
                        default_policies["routed"] = "allow"
                    elif "deny (routed)" in line or "drop (routed)" in line or "reject (routed)" in line:
                        # find the word preceding (routed)
                        if "deny" in line.split("(routed)")[0][-6:]:
                            default_policies["routed"] = "deny"
                        elif "drop" in line.split("(routed)")[0][-6:]:
                            default_policies["routed"] = "drop"
                        elif "reject" in line.split("(routed)")[0][-8:]:
                            default_policies["routed"] = "reject"

        # Read /etc/default/ufw
        etc_default_ufw_contents = _read_file("/etc/default/ufw")
        etc_default_ufw_parsed = {
            "DEFAULT_INPUT_POLICY": None,
            "DEFAULT_OUTPUT_POLICY": None,
            "DEFAULT_FORWARD_POLICY": None
        }

        if etc_default_ufw_contents:
            for line in etc_default_ufw_contents.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.startswith("DEFAULT_INPUT_POLICY="):
                        val = line.split("=")[1].strip()
                        etc_default_ufw_parsed["DEFAULT_INPUT_POLICY"] = val.strip('"').strip("'")
                    elif line.startswith("DEFAULT_OUTPUT_POLICY="):
                        val = line.split("=")[1].strip()
                        etc_default_ufw_parsed["DEFAULT_OUTPUT_POLICY"] = val.strip('"').strip("'")
                    elif line.startswith("DEFAULT_FORWARD_POLICY="):
                        val = line.split("=")[1].strip()
                        etc_default_ufw_parsed["DEFAULT_FORWARD_POLICY"] = val.strip('"').strip("'")

            default_policies["etc_default_ufw"] = etc_default_ufw_parsed
        else:
            errors.append({"check": "read_/etc/default/ufw", "error": "file not found or access denied"})

    return {
        "ufw_firewall": {
            "ufw_installed": ufw_installed,
            "ufw_dpkg_status": ufw_dpkg_status,
            "alternative_firewalls_active": alternative_firewalls_active,
            "service_configured": service_configured,
            "default_policies": default_policies,
            "errors": errors
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_ufw()))
