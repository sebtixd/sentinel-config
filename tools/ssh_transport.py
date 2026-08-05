"""
ssh_transport.py
================
Simple SSH execution helpers for remote auditing.

Security note
-------------
Passwords are delivered to ``sudo -S`` exclusively through the channel's
stdin and the channel is immediately closed (EOF) to prevent sudo from
blocking.  Passwords are **never** embedded in the shell command string to
avoid leakage in process lists, audit logs, or exception messages.
"""

from __future__ import annotations

import logging

import paramiko

log = logging.getLogger(__name__)


def remote_run(ssh: paramiko.SSHClient, cmd: str, timeout: int = 10) -> str:
    """Execute a command on the remote machine and return its stdout."""
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception as exc:
        log.debug("remote_run failed: %s", exc)
        return ""


def remote_run_sudo(ssh: paramiko.SSHClient, cmd: str, password: str = "", timeout: int = 10) -> str:
    """Execute a privileged command on the remote machine via ``sudo -S``.

    The password is written to stdin only — it is never part of the command
    string itself.  After writing, the write-end of the channel is closed so
    that sudo does not block waiting for more input.
    """
    sudo_cmd = f"sudo -S {cmd}" if password else f"sudo -n {cmd}"
    try:
        stdin, stdout, stderr = ssh.exec_command(sudo_cmd, timeout=timeout)
        if password:
            stdin.write(password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()  # EOF — prevents sudo deadlock
        return stdout.read().decode("utf-8", errors="replace")
    except Exception as exc:
        log.debug("remote_run_sudo failed for command (redacted): %s", exc)
        return ""
