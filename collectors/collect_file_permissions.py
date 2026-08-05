"""
collect_file_permissions.py
============================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 7.1 (system file and directory access permissions).

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments.  All verdict logic is handled downstream
by the LLM analysis stage.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import stat
import subprocess
import time
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Filesystem types considered "local" and therefore worth scanning.
_LOCAL_FSTYPES: frozenset[str] = frozenset(
    {"ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "f2fs", "reiserfs"}
)

#: Hard cap on paths returned per mount point / per check.
_PATH_CAP = 500

#: Fixed file paths to stat for CIS 7.1.1 – 7.1.10.
_FIXED_FILES: list[str] = [
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/group",
    "/etc/group-",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/shells",
    "/etc/security/opasswd",
]


# ---------------------------------------------------------------------------
# Part 1 helper — single-file stat
# ---------------------------------------------------------------------------

def _stat_file(path: str) -> dict[str, Any]:
    """
    Collect stat data for a single file path.

    Returns a dict with the schema required by CIS 7.1.1–7.1.10:
    {
        "path": str,
        "exists": bool,
        "mode_octal": str | None,
        "owner": str | None,
        "owner_uid": int | None,
        "group": str | None,
        "group_gid": int | None,
        "error": str | None,
    }
    """
    result: dict[str, Any] = {
        "path": path,
        "exists": False,
        "mode_octal": None,
        "owner": None,
        "owner_uid": None,
        "group": None,
        "group_gid": None,
        "error": None,
    }

    try:
        st = os.stat(path)
    except FileNotFoundError:
        result["error"] = "FileNotFoundError"
        return result
    except PermissionError as exc:
        result["error"] = f"PermissionError: {exc}"
        result["exists"] = os.path.exists(path) or os.path.lexists(path)
        return result
    except OSError as exc:
        result["error"] = f"OSError: {exc}"
        return result

    result["exists"] = True
    result["mode_octal"] = f"{stat.S_IMODE(st.st_mode):04o}"

    # UID → username
    result["owner_uid"] = st.st_uid
    try:
        result["owner"] = pwd.getpwuid(st.st_uid).pw_name
    except (KeyError, Exception):
        result["owner"] = None
        result["error"] = "unable to resolve username"

    # GID → group name
    result["group_gid"] = st.st_gid
    try:
        result["group"] = grp.getgrgid(st.st_gid).gr_name
    except (KeyError, Exception):
        result["group"] = None
        if result["error"]:
            result["error"] += "; unable to resolve groupname"
        else:
            result["error"] = "unable to resolve groupname"

    return result


# ---------------------------------------------------------------------------
# Mount discovery helper — called ONCE and reused across Parts 2-4
# ---------------------------------------------------------------------------

def _get_local_mounts() -> tuple[list[str], list[dict[str, str]]]:
    """
    Query ``findmnt`` to build two lists:

    * ``local_mounts``  – TARGET paths whose FSTYPE is in ``_LOCAL_FSTYPES``
    * ``skipped``       – list of ``{"mount": str, "fstype": str}`` for every
                          mount point that was excluded (virtual / network FS).

    Returns (local_mounts, skipped).
    """
    local_mounts: list[str] = []
    skipped: list[dict[str, str]] = []

    try:
        res = subprocess.run(
            ["findmnt", "--json", "-o", "TARGET,FSTYPE"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0 or not res.stdout.strip():
            return local_mounts, skipped

        data = json.loads(res.stdout)
        filesystems = data.get("filesystems", [])

        def _walk(entries: list[dict]) -> None:
            for entry in entries:
                target = (entry.get("target") or "").strip()
                fstype = (entry.get("fstype") or "").strip().lower()
                if fstype in _LOCAL_FSTYPES:
                    if target and target not in local_mounts:
                        local_mounts.append(target)
                else:
                    if target:
                        skipped.append({"mount": target, "fstype": fstype})
                # findmnt JSON can be recursive
                children = entry.get("children")
                if children:
                    _walk(children)

        _walk(filesystems)

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception):
        # Fall back to a minimal default if findmnt is unavailable
        local_mounts = ["/"]

    return local_mounts, skipped


# ---------------------------------------------------------------------------
# Shared find helper
# ---------------------------------------------------------------------------

def _run_find(
    mountpoint: str,
    find_args: list[str],
    cap: int = _PATH_CAP,
    timeout: int = 120,
) -> tuple[list[str], bool]:
    """
    Run ``find <mountpoint> -xdev <find_args>`` and return ``(paths, truncated)``.

    *paths*     – up to *cap* absolute path strings from stdout (one per line).
    *truncated* – True if the raw output contained more than *cap* lines.
    """
    cmd = ["find", mountpoint, "-xdev"] + find_args
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        lines = [l for l in res.stdout.splitlines() if l.strip()]
        truncated = len(lines) > cap
        return lines[:cap], truncated
    except subprocess.TimeoutExpired:
        return [], False  # timed-out: report empty, caller adds error
    except Exception:
        return [], False


# ---------------------------------------------------------------------------
# Part 2 — world-writable files and directories (CIS 7.1.11)
# ---------------------------------------------------------------------------

def _collect_world_writable(
    mounts: list[str],
) -> dict[str, Any]:
    """
    Scan *mounts* for world-writable files and directories without the sticky
    bit.  Results are capped at ``_PATH_CAP`` entries per mount.

    Returns a dict with keys:
    ``world_writable_files``, ``world_writable_dirs_no_sticky``, ``errors``.
    """
    ww_files: list[dict[str, Any]] = []
    ww_dirs: list[dict[str, Any]] = []
    errors: list[str] = []

    for mp in mounts:
        # World-writable regular files
        paths_f, trunc_f = _run_find(
            mp,
            ["-type", "f", "-perm", "-0002"],
        )
        ww_files.append({"mount": mp, "paths": paths_f, "truncated": trunc_f})

        # World-writable directories without the sticky bit
        paths_d, trunc_d = _run_find(
            mp,
            ["-type", "d", "-perm", "-0002", "!", "-perm", "-1000"],
        )
        ww_dirs.append({"mount": mp, "paths": paths_d, "truncated": trunc_d})

    return {
        "world_writable_files": ww_files,
        "world_writable_dirs_no_sticky": ww_dirs,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Part 3 — unowned / ungrouped files and directories (CIS 7.1.12)
# ---------------------------------------------------------------------------

def _collect_unowned(
    mounts: list[str],
) -> dict[str, Any]:
    """
    Scan *mounts* for files or directories with no valid owner UID or GID.
    Results are capped at ``_PATH_CAP`` entries per mount.

    Returns a dict with key ``unowned_or_ungrouped``.
    """
    unowned: list[dict[str, Any]] = []

    for mp in mounts:
        paths, trunc = _run_find(
            mp,
            ["(", "-nouser", "-o", "-nogroup", ")"],
        )
        unowned.append({"mount": mp, "paths": paths, "truncated": trunc})

    return {"unowned_or_ungrouped": unowned}


# ---------------------------------------------------------------------------
# Part 4 — SUID / SGID files (CIS 7.1.13)
# ---------------------------------------------------------------------------

def _collect_suid_sgid(
    mounts: list[str],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    """
    Enumerate SUID/SGID files across *mounts*.  Pure enumeration — no attempt
    to classify expected-vs-unexpected binaries.

    Total results are capped at ``_PATH_CAP`` across **all** mounts.
    Returns a dict with keys ``suid_sgid_files`` and ``truncated``.
    """
    suid_sgid_files: list[dict[str, Any]] = []
    total_truncated = False
    remaining_cap = _PATH_CAP

    for mp in mounts:
        if remaining_cap <= 0:
            total_truncated = True
            break

        paths, _ = _run_find(
            mp,
            ["-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"],
        )

        for path in paths:
            if remaining_cap <= 0:
                total_truncated = True
                break
            mode_octal: str | None = None
            owner: str | None = None
            owner_uid: int | None = None
            group: str | None = None
            group_gid: int | None = None
            try:
                st = os.stat(path)
                mode_octal = f"{stat.S_IMODE(st.st_mode):04o}"
                owner_uid = st.st_uid
                group_gid = st.st_gid
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except (KeyError, Exception):
                    owner = str(st.st_uid)
                try:
                    group = grp.getgrgid(st.st_gid).gr_name
                except (KeyError, Exception):
                    group = str(st.st_gid)
            except OSError as exc:
                errors.append({"check": f"suid_sgid_stat:{path}", "error": str(exc)})
                continue

            suid_sgid_files.append(
                {
                    "mount": mp,
                    "path": path,
                    "mode_octal": mode_octal,
                    "owner": owner,
                    "owner_uid": owner_uid,
                    "group": group,
                    "group_gid": group_gid,
                }
            )
            remaining_cap -= 1

    return {"suid_sgid_files": suid_sgid_files, "truncated": total_truncated}


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def collect_file_permissions() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 7.1
    (system file and directory access permissions).

    This function performs only deterministic data collection.  It makes no
    PASS / FAIL / UNKNOWN verdicts.

    Returns:
        dict: A JSON-serialisable structured dictionary with the following
              top-level keys:

            ``fixed_files``       – Per-file stat data for the 10 fixed paths
                                    covered by CIS 7.1.1–7.1.10.
            ``world_writable``    – World-writable file/dir scan (CIS 7.1.11).
            ``unowned``           – Unowned / ungrouped file scan (CIS 7.1.12).
            ``suid_sgid``         – SUID/SGID file enumeration (CIS 7.1.13).
            ``mount_scan_meta``   – Summary of mounts scanned / skipped and
                                    total scan wall-clock duration.
            ``errors``            – Top-level error list for any check that
                                    raised an unexpected exception.
    """
    top_errors: list[dict[str, str]] = []
    scan_start = time.monotonic()

    # ------------------------------------------------------------------
    # Part 1 – Fixed file stat checks (CIS 7.1.1 – 7.1.10)
    # ------------------------------------------------------------------
    fixed_files: list[dict[str, Any]] = [_stat_file(p) for p in _FIXED_FILES]

    # ------------------------------------------------------------------
    # Mount discovery (shared across Parts 2 – 4)
    # ------------------------------------------------------------------
    try:
        local_mounts, skipped_mounts = _get_local_mounts()
    except Exception as exc:
        top_errors.append({"check": "get_local_mounts", "error": str(exc)})
        local_mounts = ["/"]
        skipped_mounts = []

    # ------------------------------------------------------------------
    # Part 2 – World-writable files and directories (CIS 7.1.11)
    # ------------------------------------------------------------------
    try:
        world_writable_data = _collect_world_writable(local_mounts)
    except Exception as exc:
        top_errors.append({"check": "world_writable_scan", "error": str(exc)})
        world_writable_data = {
            "world_writable_files": [],
            "world_writable_dirs_no_sticky": [],
            "errors": [],
        }

    # Add mounts_scanned / mounts_skipped to world_writable for spec compliance
    world_writable_data["mounts_scanned"] = local_mounts
    world_writable_data["mounts_skipped"] = skipped_mounts

    # ------------------------------------------------------------------
    # Part 3 – Unowned / ungrouped files (CIS 7.1.12)
    # ------------------------------------------------------------------
    try:
        unowned_data = _collect_unowned(local_mounts)
    except Exception as exc:
        top_errors.append({"check": "unowned_scan", "error": str(exc)})
        unowned_data = {"unowned_or_ungrouped": []}

    # ------------------------------------------------------------------
    # Part 4 – SUID / SGID files (CIS 7.1.13)
    # ------------------------------------------------------------------
    try:
        suid_sgid_data = _collect_suid_sgid(local_mounts, top_errors)
    except Exception as exc:
        top_errors.append({"check": "suid_sgid_scan", "error": str(exc)})
        suid_sgid_data = {"suid_sgid_files": [], "truncated": False}

    scan_duration = time.monotonic() - scan_start

    # ------------------------------------------------------------------
    # Assemble top-level result
    # ------------------------------------------------------------------
    return {
        "fixed_files": fixed_files,
        "world_writable": world_writable_data,
        "unowned": unowned_data,
        "suid_sgid": suid_sgid_data,
        "mount_scan_meta": {
            "mounts_scanned": local_mounts,
            "mounts_skipped": [m["mount"] for m in skipped_mounts],
            "scan_duration_seconds": round(scan_duration, 3),
        },
        "errors": top_errors,
    }
