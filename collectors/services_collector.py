"""
services_collector.py
======================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 2 (Services):

  2.1   Configure Server Services (23 rules)
  2.2   Configure Client Services (6 rules)

This module REPLACES and consolidates the logic previously in
collect_ftp.py (2.1.8 ftp server, 2.1.20 tftp, 2.2.6 ftp client)
and collect_telnet.py (2.1.19 telnet server, 2.2.4 telnet client).

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import json
import os
import subprocess
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




def _check_service(
    service_name: str,
    cis_rule: str,
    packages: list[str],
    units: list[str],
) -> dict[str, Any]:
    """
    Build a standard service check entry covering packages + systemd units.
    Returns one object per service in the schema used throughout Section 2.
    """
    packages_status = [
        {"package": pkg, "installed": _dpkg_installed(pkg)}
        for pkg in packages
    ]

    units_status = [_systemctl_state(unit) for unit in units]

    any_installed = any(p["installed"] for p in packages_status)
    any_active = any(u["active"] == "active" for u in units_status)

    return {
        "cis_rule": cis_rule,
        "service_name": service_name,
        "packages_status": packages_status,
        "any_package_installed": any_installed,
        "units_status": units_status,
        "any_unit_active": any_active,
    }


# ---------------------------------------------------------------------------
# 2.1.2 – Mail Transfer Agent (special: local-only mode check)
# ---------------------------------------------------------------------------

def _collect_mta() -> dict[str, Any]:
    """
    For CIS 2.1.2, determine which MTA is installed and collect its
    local-only mode configuration.
    """
    # Check installed MTAs
    mta_detected = "none"
    postfix_installed = _dpkg_installed("postfix")
    exim4_installed = _dpkg_installed("exim4")
    sendmail_installed = _dpkg_installed("sendmail")

    if postfix_installed:
        mta_detected = "postfix"
    elif exim4_installed:
        mta_detected = "exim4"
    elif sendmail_installed:
        mta_detected = "sendmail"

    # Postfix: collect inet_interfaces setting
    postfix_inet_interfaces: str | None = None
    if postfix_installed:
        out, _, rc = _run_cmd(["postconf", "inet_interfaces"])
        postfix_inet_interfaces = out.strip() if rc == 0 else None
        if postfix_inet_interfaces is None:
            # Fallback: parse /etc/postfix/main.cf
            content = _read_file("/etc/postfix/main.cf")
            if content:
                for line in content.splitlines():
                    s = line.strip()
                    if s.startswith("inet_interfaces") and "=" in s:
                        postfix_inet_interfaces = s

    # Exim4: collect dc_local_interfaces setting
    exim4_local_interfaces: str | None = None
    if exim4_installed:
        content = _read_file("/etc/exim4/update-exim4.conf.conf")
        if content:
            for line in content.splitlines():
                s = line.strip()
                if s.startswith("dc_local_interfaces"):
                    exim4_local_interfaces = s

    return {
        "cis_rule": "2.1.2",
        "service_name": "mail_transfer_agent",
        "mta_detected": mta_detected,
        "packages_status": [
            {"package": "postfix", "installed": postfix_installed},
            {"package": "exim4", "installed": exim4_installed},
            {"package": "sendmail", "installed": sendmail_installed},
        ],
        "any_package_installed": mta_detected != "none",
        "units_status": [
            _systemctl_state("postfix"),
            _systemctl_state("exim4"),
            _systemctl_state("sendmail"),
        ],
        "postfix_inet_interfaces": postfix_inet_interfaces,
        "exim4_local_interfaces": exim4_local_interfaces,
    }


# ---------------------------------------------------------------------------
# 2.1.4 – Approved listening sockets (Manual/Informational)
# ---------------------------------------------------------------------------

def _collect_listening_sockets() -> list[dict[str, str]]:
    """
    Collect all current listening network sockets for manual review.
    Returns a list of {protocol, local_address, port, process}.
    """
    out, _, rc = _run_cmd(["ss", "-tulnp"])
    if rc != 0 or not out.strip():
        return []

    sockets: list[dict[str, str]] = []
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Netid"):
            continue
        parts = stripped.split()
        if len(parts) >= 5:
            sockets.append({
                "protocol": parts[0],
                "state": parts[1],
                "recv_q": parts[2],
                "send_q": parts[3],
                "local_address": parts[4],
                "peer_address": parts[5] if len(parts) > 5 else "",
                "process": parts[6] if len(parts) > 6 else "",
                "raw": stripped,
            })

    return sockets


# ---------------------------------------------------------------------------
# 2.1.23 – X window server (package + process check)
# ---------------------------------------------------------------------------

def _check_x_window_server() -> dict[str, Any]:
    """
    CIS 2.1.23: Check for X window server package and whether Xorg is running.
    Both installed and running state are returned separately.
    """
    packages = ["xserver-xorg", "xserver-xorg-core", "xserver-common"]
    packages_status = [
        {"package": pkg, "installed": _dpkg_installed(pkg)}
        for pkg in packages
    ]
    any_installed = any(p["installed"] for p in packages_status)

    # Check if Xorg process is running
    pgrep_out, _, pgrep_rc = _run_cmd(["pgrep", "-c", "Xorg"])
    xorg_running = pgrep_rc == 0 and pgrep_out.strip().isdigit() and int(pgrep_out.strip()) > 0

    return {
        "cis_rule": "2.1.23",
        "service_name": "x_window_server",
        "packages_status": packages_status,
        "any_package_installed": any_installed,
        "xorg_process_running": xorg_running,
        "units_status": [_systemctl_state("xdm"), _systemctl_state("lightdm")],
    }


# ---------------------------------------------------------------------------
# 2.1 – Server Services definitions
# ---------------------------------------------------------------------------

_SERVER_SERVICES: list[dict[str, Any]] = [
    # (cis_rule, service_name, packages, units)
    # 2.1.1
    {"cis_rule": "2.1.1", "service_name": "autofs",
     "packages": ["autofs"], "units": ["autofs.service"]},
    # 2.1.3
    {"cis_rule": "2.1.3", "service_name": "avahi_daemon",
     "packages": ["avahi-daemon"], "units": ["avahi-daemon.service", "avahi-daemon.socket"]},
    # 2.1.5
    {"cis_rule": "2.1.5", "service_name": "dhcp_server",
     "packages": ["isc-dhcp-server"], "units": ["isc-dhcp-server.service", "isc-dhcp-server6.service"]},
    # 2.1.6
    {"cis_rule": "2.1.6", "service_name": "web_server",
     "packages": ["apache2", "nginx", "lighttpd"],
     "units": ["apache2.service", "nginx.service", "lighttpd.service"]},
    # 2.1.7
    {"cis_rule": "2.1.7", "service_name": "dns_server",
     "packages": ["bind9"], "units": ["bind9.service", "named.service"]},
    # 2.1.8 (migrated from collect_ftp.py)
    {"cis_rule": "2.1.8", "service_name": "ftp_server",
     "packages": ["vsftpd", "proftpd-basic", "pure-ftpd"],
     "units": ["vsftpd.service", "proftpd.service", "pure-ftpd.service"]},
    # 2.1.9
    {"cis_rule": "2.1.9", "service_name": "dnsmasq",
     "packages": ["dnsmasq"], "units": ["dnsmasq.service"]},
    # 2.1.10
    {"cis_rule": "2.1.10", "service_name": "ldap_server",
     "packages": ["slapd"], "units": ["slapd.service"]},
    # 2.1.11
    {"cis_rule": "2.1.11", "service_name": "message_access_server",
     "packages": ["dovecot-imapd", "dovecot-pop3d", "cyrus-imapd"],
     "units": ["dovecot.service"]},
    # 2.1.12
    {"cis_rule": "2.1.12", "service_name": "nfs_server",
     "packages": ["nfs-kernel-server"], "units": ["nfs-kernel-server.service"]},
    # 2.1.13
    {"cis_rule": "2.1.13", "service_name": "nis_server",
     "packages": ["nis"], "units": ["ypserv.service"]},
    # 2.1.14
    {"cis_rule": "2.1.14", "service_name": "print_server",
     "packages": ["cups"], "units": ["cups.service"]},
    # 2.1.15
    {"cis_rule": "2.1.15", "service_name": "rpcbind",
     "packages": ["rpcbind"], "units": ["rpcbind.service", "rpcbind.socket"]},
    # 2.1.16
    {"cis_rule": "2.1.16", "service_name": "rsync_daemon",
     "packages": ["rsync"], "units": ["rsync.service"]},
    # 2.1.17
    {"cis_rule": "2.1.17", "service_name": "samba",
     "packages": ["samba"], "units": ["smbd.service"]},
    # 2.1.18
    {"cis_rule": "2.1.18", "service_name": "snmp",
     "packages": ["snmpd"], "units": ["snmpd.service"]},
    # 2.1.19 (migrated from collect_telnet.py)
    {"cis_rule": "2.1.19", "service_name": "telnet_server",
     "packages": ["telnetd", "inetutils-telnetd"],
     "units": ["telnet.socket", "telnetd.service", "inetd.service", "openbsd-inetd.service"]},
    # 2.1.20 (migrated from collect_ftp.py)
    {"cis_rule": "2.1.20", "service_name": "tftp_server",
     "packages": ["tftpd", "tftpd-hpa", "atftpd"],
     "units": ["tftpd-hpa.service", "tftp.socket"]},
    # 2.1.21
    {"cis_rule": "2.1.21", "service_name": "web_proxy",
     "packages": ["squid", "squid3"], "units": ["squid.service"]},
    # 2.1.22
    {"cis_rule": "2.1.22", "service_name": "xinetd",
     "packages": ["xinetd"], "units": ["xinetd.service"]},
]


# ---------------------------------------------------------------------------
# 2.2 – Client Services definitions (package-only checks)
# ---------------------------------------------------------------------------

_CLIENT_SERVICES: list[dict[str, Any]] = [
    {"cis_rule": "2.2.1", "service_name": "nis_client", "packages": ["nis"]},
    {"cis_rule": "2.2.2", "service_name": "rsh_client", "packages": ["rsh-client"]},
    {"cis_rule": "2.2.3", "service_name": "talk_client", "packages": ["talk"]},
    # 2.2.4 (migrated from collect_telnet.py)
    {"cis_rule": "2.2.4", "service_name": "telnet_client", "packages": ["telnet", "inetutils-telnet"]},
    {"cis_rule": "2.2.5", "service_name": "ldap_client", "packages": ["ldap-utils"]},
    # 2.2.6 (migrated from collect_ftp.py)
    {"cis_rule": "2.2.6", "service_name": "ftp_client", "packages": ["ftp"]},
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_services() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 2
    (Configure Server and Client Services).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'services'
              containing sub-keys:
                server_services, client_services, listening_sockets_raw
    """
    errors: list[dict[str, str]] = []

    # --- 2.1 Server services ---
    server_services: list[dict[str, Any]] = []

    for svc in _SERVER_SERVICES:
        try:
            entry = _check_service(
                service_name=svc["service_name"],
                cis_rule=svc["cis_rule"],
                packages=svc["packages"],
                units=svc["units"],
            )
            server_services.append(entry)
        except Exception as exc:
            errors.append({"check": svc["cis_rule"], "error": str(exc)})

    # 2.1.2: MTA (special)
    try:
        server_services.insert(1, _collect_mta())  # insert after 2.1.1
    except Exception as exc:
        errors.append({"check": "2.1.2", "error": str(exc)})

    # 2.1.23: X window server (special)
    try:
        server_services.append(_check_x_window_server())
    except Exception as exc:
        errors.append({"check": "2.1.23", "error": str(exc)})

    # 2.1.4: Listening sockets (Manual/Informational)
    try:
        listening_sockets_raw = _collect_listening_sockets()
    except Exception as exc:
        listening_sockets_raw = []
        errors.append({"check": "2.1.4", "error": str(exc)})

    # --- 2.2 Client services ---
    client_services: list[dict[str, Any]] = []
    for svc in _CLIENT_SERVICES:
        try:
            packages_status = [
                {"package": pkg, "installed": _dpkg_installed(pkg)}
                for pkg in svc["packages"]
            ]
            client_services.append({
                "cis_rule": svc["cis_rule"],
                "service_name": svc["service_name"],
                "packages_status": packages_status,
                "any_package_installed": any(p["installed"] for p in packages_status),
            })
        except Exception as exc:
            errors.append({"check": svc["cis_rule"], "error": str(exc)})

    return {
        "services": {
            "server_services": server_services,
            "client_services": client_services,
            "listening_sockets_raw": listening_sockets_raw,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_services(), indent=2))
