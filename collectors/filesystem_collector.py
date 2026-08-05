"""
filesystem_collector.py
========================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 1.1 (Filesystem Kernel Modules & Partitions):

  1.1.1  Filesystem Kernel Modules (cramfs, freevxfs, hfs, hfsplus, jffs2,
         overlay, squashfs, udf, firewire-core, usb-storage, lsmod raw)
  1.1.2  Filesystem Partitions (/tmp, /dev/shm, /home, /var, /var/tmp,
         /var/log, /var/log/audit)

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



# ---------------------------------------------------------------------------
# 1.1.1 – Filesystem Kernel Modules
# ---------------------------------------------------------------------------

_FILESYSTEM_MODULES = [
    "cramfs",
    "freevxfs",
    "hfs",
    "hfsplus",
    "jffs2",
    "overlay",
    "squashfs",
    "udf",
    "firewire-core",
    "usb-storage",
]


def _collect_filesystem_kernel_modules(errors: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Collect facts for CIS 1.1.1 — whether each filesystem/device module is loaded
    and whether it is disabled via modprobe.d config, plus raw lsmod output.

    Returns:
        (filesystem_kernel_modules, lsmod_raw)
    """
    # Read lsmod output once
    lsmod_out, lsmod_err, lsmod_rc = _run_cmd(["lsmod"])
    lsmod_lines: list[str] = lsmod_out.splitlines() if lsmod_rc == 0 else []

    # Collect all modprobe config files
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

    modules: list[dict[str, Any]] = []
    for mod in _FILESYSTEM_MODULES:
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

        modules.append({
            "module_name": mod,
            "currently_loaded": currently_loaded,
            "modprobe_config_lines": config_lines,
        })

    return modules, lsmod_lines


# ---------------------------------------------------------------------------
# 1.1.2 – Filesystem Partitions
# ---------------------------------------------------------------------------

_TARGET_PARTITIONS = [
    "/tmp",
    "/dev/shm",
    "/home",
    "/var",
    "/var/tmp",
    "/var/log",
    "/var/log/audit",
]


def _parse_proc_mounts() -> list[dict[str, str]]:
    """Parse /proc/mounts or findmnt output into structured entries."""
    mounts: list[dict[str, str]] = []
    # Try findmnt first (more reliable on Linux)
    findmnt_out, _, findmnt_rc = _run_cmd(["findmnt", "-rn", "--output", "TARGET,FSTYPE,OPTIONS,SOURCE"])
    if findmnt_rc == 0 and findmnt_out:
        for line in findmnt_out.splitlines():
            parts = line.strip().split(maxsplit=3)
            if len(parts) >= 3:
                target, fstype, options = parts[0], parts[1], parts[2]
                source = parts[3] if len(parts) >= 4 else ""
                mounts.append({
                    "target": target,
                    "fstype": fstype,
                    "options": options,
                    "source": source,
                })
        return mounts

    # Fallback to /proc/mounts
    proc_mounts = _read_file("/proc/mounts")
    if proc_mounts:
        for line in proc_mounts.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4:
                source, target, fstype, options = parts[0], parts[1], parts[2], parts[3]
                mounts.append({
                    "target": target,
                    "fstype": fstype,
                    "options": options,
                    "source": source,
                })

    return mounts


def _parse_fstab() -> dict[str, str]:
    """Parse /etc/fstab and return mapping of mount_point -> raw_fstab_line."""
    fstab_lines: dict[str, str] = {}
    content = _read_file("/etc/fstab")
    if not content:
        return fstab_lines

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            target = parts[1]
            fstab_lines[target] = stripped

    return fstab_lines


def _collect_filesystem_partitions(errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    """
    Collect facts for CIS 1.1.2 — partition status, fstype, mount options,
    and /etc/fstab entry for key mount points.
    """
    active_mounts = _parse_proc_mounts()
    fstab_entries = _parse_fstab()

    # Index active mounts by target path
    mount_by_target = {m["target"]: m for m in active_mounts}

    partitions: list[dict[str, Any]] = []

    for target in _TARGET_PARTITIONS:
        is_separate = target in mount_by_target
        mount_info = mount_by_target.get(target)

        if mount_info:
            fstype = mount_info["fstype"]
            options_raw = mount_info["options"]
            options_list = [opt.strip() for opt in options_raw.split(",") if opt.strip()]
        else:
            # If not a separate partition, find parent or root mount for fallback info
            fstype = None
            options_raw = None
            options_list = []
            # Check parent paths e.g. /var/log -> /var -> /
            parent = target
            while parent and parent != "/":
                parent = os.path.dirname(parent)
                if parent in mount_by_target:
                    parent_info = mount_by_target[parent]
                    fstype = parent_info["fstype"]
                    options_raw = parent_info["options"]
                    options_list = [opt.strip() for opt in parent_info["options"].split(",") if opt.strip()]
                    break

        fstab_line = fstab_entries.get(target)

        partitions.append({
            "mount_point": target,
            "is_separate_partition": is_separate,
            "fstype": fstype,
            "mount_options_raw": options_raw,
            "mount_options_list": options_list,
            "fstab_line": fstab_line,
        })

    return partitions


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_filesystem() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 1.1
    (Filesystem Kernel Modules & Partitions).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'filesystem'
              containing:
                filesystem_kernel_modules, lsmod_raw, filesystem_partitions, errors
    """
    errors: list[dict[str, str]] = []

    kernel_modules, lsmod_raw = _collect_filesystem_kernel_modules(errors)
    partitions = _collect_filesystem_partitions(errors)

    return {
        "filesystem": {
            "filesystem_kernel_modules": kernel_modules,
            "lsmod_raw": lsmod_raw,
            "filesystem_partitions": partitions,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_filesystem(), indent=2))
