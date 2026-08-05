"""
collect_ssh.py
===============
Collects and parses SSH configuration details, file permissions, and ssh-audit
details from a remote Linux host.
"""

from __future__ import annotations
import subprocess
from typing import Any

from tools.ssh_audit_parser import build_security_profile as parse_ssh_data


def remote_run_sudo(ssh, cmd: str, password: str = "", timeout: int = 10) -> str:
    """Execute a command on the remote machine via sudo -S and return its stdout."""
    if not password:
        sudo_cmd = f"sudo -n {cmd}"
    else:
        sudo_cmd = f"sudo -S {cmd}"
    try:
        stdin, stdout, stderr = ssh.exec_command(sudo_cmd, timeout=timeout)
        if password:
            stdin.write(password + "\n")
            stdin.flush()
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def collect_ssh_from_ssh(ssh, hostname: str, port: int, password: str = "") -> dict[str, Any]:
    """
    Collect SSH server configuration (sshd -T), config/key permissions remotely,
    run local ssh-audit, and return the parsed and structured profile.
    """
    # Collect sshd output
    sshd_attempts = [
        "/usr/sbin/sshd -T",
        "sshd -T",
        "cat /etc/ssh/sshd_config",
    ]
    sshd_out = ""
    for cmd in sshd_attempts:
        sshd_out = remote_run_sudo(ssh, cmd, password)
        if sshd_out.strip():
            if "cat /etc/ssh/sshd_config" in cmd:
                # Get drop-in configuration too
                dropin = remote_run_sudo(ssh, "cat /etc/ssh/sshd_config.d/*.conf", password)
                if dropin.strip():
                    sshd_out += "\n" + dropin
            break

    # CIS 5.1.1/5.1.2/5.1.3 – File permission checks for SSH config and host keys
    ssh_config_perms = remote_run_sudo(
        ssh, "stat -c '%a %U %G %n' /etc/ssh/sshd_config", password
    )
    ssh_privkey_perms = remote_run_sudo(
        ssh, "stat -c '%a %U %G %n' /etc/ssh/ssh_host_*_key", password
    )
    ssh_pubkey_perms = remote_run_sudo(
        ssh, "stat -c '%a %U %G %n' /etc/ssh/ssh_host_*_key.pub", password
    )

    # Run local ssh-audit against the remote host
    ssh_audit_out = ""
    try:
        res = subprocess.run(
            ["ssh-audit", "-n", "-p", str(port), hostname],
            capture_output=True, text=True, timeout=30,
        )
        ssh_audit_out = res.stdout
    except Exception:
        # Fail gracefully if ssh-audit is missing locally
        pass

    # Parse and construct the final SSH profile
    ssh_profile = parse_ssh_data(
        sshd_output=sshd_out,
        ssh_audit_output=ssh_audit_out,
    )
    
    ssh_profile.setdefault("ssh", {})
    ssh_profile["ssh"]["sshd_config_permissions"]  = ssh_config_perms.strip() or "unknown"
    ssh_profile["ssh"]["ssh_privkey_permissions"]  = ssh_privkey_perms.strip() or "unknown"
    ssh_profile["ssh"]["ssh_pubkey_permissions"]   = ssh_pubkey_perms.strip() or "unknown"

    return ssh_profile
