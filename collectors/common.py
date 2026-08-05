"""
common.py
=========
Shared deterministic system query utilities and helpers for SENTINEL Linux collectors.

Provides standardized helper functions for:
  - Command execution (`run_cmd`)
  - File reading (`read_file`)
  - Package installation checks (`dpkg_installed`)
  - Systemd service state checks (`systemctl_state`)
  - Path permissions and owner stat (`stat_path`)
  - Sysctl parameter checks (`get_sysctl_runtime`, `get_sysctl_persisted`, `load_sysctl_conf_lines`)
"""

from __future__ import annotations

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


def run_cmd(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    """
    Execute a system command safely via subprocess.run and return (stdout, stderr, returncode).
    """
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1


def read_file(path: str) -> str | None:
    """
    Safely read and return text contents of a file, or None if unreadable.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def dpkg_installed(package: str) -> bool:
    """
    Check if a Debian/Ubuntu package is installed via dpkg -s.
    """
    out, _, rc = run_cmd(["dpkg", "-s", package])
    return rc == 0 and "install ok installed" in out.lower()


def systemctl_state(unit: str) -> dict[str, str]:
    """
    Query systemd unit is-enabled and is-active status.
    Returns {"unit": unit, "enabled": str, "active": str}.
    """
    enabled_out, _, _ = run_cmd(["systemctl", "is-enabled", unit])
    active_out, _, _ = run_cmd(["systemctl", "is-active", unit])
    return {
        "unit": unit,
        "enabled": enabled_out.strip(),
        "active": active_out.strip(),
    }


def stat_path(path: str) -> dict[str, Any]:
    """
    Stat a file or directory path safely and return structured permissions metadata.
    """
    if not os.path.exists(path):
        return {
            "path": path,
            "exists": False,
            "is_dir": False,
            "mode_octal": None,
            "uid": None,
            "gid": None,
            "owner": None,
            "group": None,
        }

    try:
        st = os.stat(path)
        mode_octal = oct(st.st_mode & 0o7777)
        is_dir = stat.S_ISDIR(st.st_mode)
        uid = st.st_uid
        gid = st.st_gid
        owner = pwd.getpwuid(uid).pw_name if pwd else str(uid)
        group = grp.getgrgid(gid).gr_name if grp else str(gid)
        return {
            "path": path,
            "exists": True,
            "is_dir": is_dir,
            "mode_octal": mode_octal,
            "uid": uid,
            "gid": gid,
            "owner": owner,
            "group": group,
        }
    except Exception as exc:
        return {
            "path": path,
            "exists": True,
            "is_dir": False,
            "mode_octal": None,
            "uid": None,
            "gid": None,
            "owner": None,
            "group": None,
            "error": str(exc),
        }


def get_sysctl_runtime(key: str) -> str | None:
    """
    Return the live runtime value for a sysctl key via `sysctl -n <key>`, or None if unavailable.
    """
    out, _, rc = run_cmd(["sysctl", "-n", key])
    return out.strip() if rc == 0 and out.strip() else None


def get_sysctl_persisted(
    key: str,
    sysctl_conf_lines: list[tuple[str, str]],
) -> tuple[str | None, str | None]:
    """
    Search pre-loaded sysctl config lines for the last matching non-comment definition of key.
    Returns (value, source_file_path) or (None, None).
    """
    last_val: str | None = None
    last_src: str | None = None
    prefix = key + "="

    for file_path, line in sysctl_conf_lines:
        compact = line.replace(" ", "").replace("\t", "")
        if compact.startswith(prefix):
            parts = line.split("=", 1)
            if len(parts) == 2:
                last_val = parts[1].strip()
                last_src = file_path

    return last_val, last_src


def load_sysctl_conf_lines() -> list[tuple[str, str]]:
    """
    Load all non-comment, non-empty assignment lines from /etc/sysctl.conf and /etc/sysctl.d/*.conf.
    Returns list of (source_file_path, raw_line).
    """
    sysctl_lines: list[tuple[str, str]] = []

    def _parse_file(fpath: str) -> None:
        content = read_file(fpath)
        if not content:
            return
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith(";"):
                if "=" in stripped:
                    sysctl_lines.append((fpath, stripped))

    _parse_file("/etc/sysctl.conf")

    sysctl_d = "/etc/sysctl.d"
    if os.path.exists(sysctl_d):
        try:
            for fname in sorted(os.listdir(sysctl_d)):
                if fname.endswith(".conf"):
                    _parse_file(os.path.join(sysctl_d, fname))
        except Exception:
            pass

    return sysctl_lines
