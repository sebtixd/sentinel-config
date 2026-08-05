"""
pam_collector.py
================
Collector for SENTINEL to gather raw data needed to audit CIS Ubuntu 24.04
Benchmark section 5.3 (Pluggable Authentication Modules / PAM):

  5.3.1  Configure PAM software packages
  5.3.2  Configure pam-auth-update profiles
  5.3.3  Configure PAM Arguments  (faillock, pwquality, pwhistory, pam_unix)

This module ONLY collects and structures data — it does NOT make any
PASS / FAIL / UNKNOWN judgments. All verdict logic is handled downstream
by the LLM analysis stage.

Approach (same as auditd_collector.py for audit rules):
  Raw config file contents are returned verbatim, plus convenience extracts
  of lines referencing each module. The LLM pattern-matches against them.
  No per-rule argument parsing is done here.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


# ---------------------------------------------------------------------------
# Internal helpers — same signatures as every other SENTINEL collector
# ---------------------------------------------------------------------------

def _run_cmd(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def _read_conf_dir(dir_path: str, ext: str = ".conf") -> list[dict[str, str]]:
    """Read all config files in a directory matching an extension."""
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


def _extract_module_lines(pam_file_content: str | None, module_name: str) -> list[str]:
    """
    Return all non-comment lines from a pam.d file content that reference
    *module_name* (e.g. "pam_pwquality.so").
    """
    if not pam_file_content:
        return []
    result = []
    for line in pam_file_content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if module_name in stripped:
            result.append(stripped)
    return result


def _extract_conf_settings(content: str | None, keys: list[str]) -> dict[str, str | None]:
    """
    Scan a .conf file content for `key = value` or `key value` assignments
    matching any of the given *keys* (case-insensitive). Returns a dict of
    key → last matched raw value string (or None if not found).
    No verdict logic — just raw extraction for the LLM.
    """
    result: dict[str, str | None] = {k: None for k in keys}
    if not content:
        return result
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for key in keys:
            # Match "key = val" or "key val" (allow optional whitespace/=)
            lower = stripped.lower()
            if lower.startswith(key.lower()):
                remainder = stripped[len(key):].strip()
                if remainder.startswith("="):
                    remainder = remainder[1:].strip()
                if remainder:
                    result[key] = remainder.split()[0]  # first token only
    return result


def _dpkg_and_apt_info(package: str) -> dict[str, Any]:
    """
    Return installed status + version info for *package* via dpkg -s and
    apt-cache policy, without pre-judging whether it's "latest".
    """
    dpkg_out, _, dpkg_rc = _run_cmd(["dpkg", "-s", package])
    installed = dpkg_rc == 0 and (
        "install ok installed" in dpkg_out.lower()
        or "status: install" in dpkg_out.lower()
    )

    installed_version: str | None = None
    if installed and dpkg_out:
        for line in dpkg_out.splitlines():
            if line.lower().startswith("version:"):
                installed_version = line.split(":", 1)[1].strip()
                break

    # apt-cache policy — may fail if apt cache is stale or network-only
    apt_out, apt_err, apt_rc = _run_cmd(["apt-cache", "policy", package])
    candidate_version: str | None = None
    candidate_version_error: str | None = None

    if apt_rc == 0 and apt_out:
        for line in apt_out.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("candidate:"):
                raw = line.strip().split(":", 1)[1].strip()
                if raw.lower() in ("(none)", "none", ""):
                    candidate_version_error = "apt cache shows no candidate — cache may be stale"
                else:
                    candidate_version = raw
                break
    else:
        candidate_version_error = (
            apt_err.strip() if apt_err.strip() else "apt-cache policy returned non-zero"
        )

    return {
        "package": package,
        "installed": installed,
        "installed_version": installed_version,
        "candidate_version": candidate_version,
        "candidate_version_error": candidate_version_error,
    }


# ---------------------------------------------------------------------------
# 5.3.1 – PAM software packages
# ---------------------------------------------------------------------------

_PAM_PACKAGES = [
    "libpam-runtime",    # 5.3.1.1 – core pam meta-package
    "libpam-modules",    # 5.3.1.2
    "libpam-pwquality",  # 5.3.1.3
    "cracklib-runtime",  # 5.3.1.4
]


def _collect_pam_packages() -> list[dict[str, Any]]:
    return [_dpkg_and_apt_info(pkg) for pkg in _PAM_PACKAGES]


# ---------------------------------------------------------------------------
# 5.3.2 – pam-auth-update profiles / raw pam.d files
# ---------------------------------------------------------------------------

_PAM_D_FILES = [
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-session",
]

_PAM_MODULES_OF_INTEREST = [
    "pam_unix.so",
    "pam_faillock.so",
    "pam_pwquality.so",
    "pam_pwhistory.so",
]


def _collect_pam_profiles_raw(errors: list[dict[str, str]]) -> dict[str, Any]:
    """
    Collect raw contents of the four pam-auth-update-managed files plus
    a cross-file extract of lines for each module of interest.
    """
    # Raw contents keyed by file path
    raw_files: dict[str, str | None] = {}
    for path in _PAM_D_FILES:
        raw_files[path] = _read_file(path)
        if raw_files[path] is None:
            errors.append({"check": f"read_{path}", "error": "file not found or unreadable"})

    # pam-auth-update --list (may require sudo or may not exist)
    pam_auth_update_out, pam_auth_update_err, pau_rc = _run_cmd(
        ["pam-auth-update", "--list"]
    )
    pam_auth_update_list: str | None = (
        pam_auth_update_out.strip() if pau_rc == 0 and pam_auth_update_out.strip()
        else None
    )
    if pau_rc != 0 and pam_auth_update_err.strip():
        errors.append({
            "check": "pam-auth-update --list",
            "error": pam_auth_update_err.strip(),
        })

    # Per-module line extracts across all four files
    module_lines: dict[str, list[dict[str, str]]] = {}
    for module in _PAM_MODULES_OF_INTEREST:
        module_lines[module] = []
        for path in _PAM_D_FILES:
            for line in _extract_module_lines(raw_files.get(path), module):
                module_lines[module].append({"file": path, "line": line})

    return {
        "pam_d_files_raw": raw_files,
        "pam_auth_update_list": pam_auth_update_list,
        "module_lines": module_lines,
    }


# ---------------------------------------------------------------------------
# 5.3.3.1 – pam_faillock
# ---------------------------------------------------------------------------

_FAILLOCK_CONF_KEYS = [
    "deny", "fail_interval", "unlock_time",
    "even_deny_root", "root_unlock_time",
    "audit", "silent",
]


def _collect_pam_faillock(pam_profiles_raw: dict[str, Any]) -> dict[str, Any]:
    """
    Collect faillock.conf and extract convenience fields.
    Raw pam.d lines are pulled from already-collected pam_profiles_raw.
    """
    faillock_conf_raw = _read_file("/etc/security/faillock.conf")
    faillock_conf_settings = _extract_conf_settings(faillock_conf_raw, _FAILLOCK_CONF_KEYS)

    # Convenience: all pam_faillock.so lines from common-auth + common-account
    faillock_pam_lines: list[dict[str, str]] = pam_profiles_raw["module_lines"].get(
        "pam_faillock.so", []
    )

    # Surface key arguments directly from PAM lines (raw, not interpreted)
    inline_settings: dict[str, str | None] = {k: None for k in _FAILLOCK_CONF_KEYS}
    for entry in faillock_pam_lines:
        for token in entry["line"].split():
            for key in _FAILLOCK_CONF_KEYS:
                if token.lower().startswith(f"{key}="):
                    inline_settings[key] = token.split("=", 1)[1]
                elif token.lower() == key:  # bare flag (e.g. even_deny_root)
                    inline_settings[key] = "present"

    return {
        "faillock_conf_raw": faillock_conf_raw,
        "faillock_conf_settings": faillock_conf_settings,
        "faillock_pam_lines": faillock_pam_lines,
        "faillock_inline_pam_settings": inline_settings,
    }


# ---------------------------------------------------------------------------
# 5.3.3.2 – pam_pwquality
# ---------------------------------------------------------------------------

_PWQUALITY_CONF_KEYS = [
    "difok", "minlen", "dcredit", "ucredit", "lcredit", "ocredit",
    "maxrepeat", "maxsequence", "dictcheck", "enforcing", "enforce_for_root",
    "retry",
]


def _collect_pam_pwquality(pam_profiles_raw: dict[str, Any]) -> dict[str, Any]:
    """
    Collect pwquality.conf (and .d/ drop-ins) plus extracted pam.d lines.
    """
    pwquality_conf_raw = _read_file("/etc/security/pwquality.conf")
    pwquality_conf_d = _read_conf_dir("/etc/security/pwquality.conf.d", ".conf")
    pwquality_conf_settings = _extract_conf_settings(pwquality_conf_raw, _PWQUALITY_CONF_KEYS)

    # Also scan .conf.d drop-ins — later files can override earlier
    for drop_in in pwquality_conf_d:
        overrides = _extract_conf_settings(drop_in["content"], _PWQUALITY_CONF_KEYS)
        for k, v in overrides.items():
            if v is not None:
                pwquality_conf_settings[k] = v  # last writer wins

    pwquality_pam_lines: list[dict[str, str]] = pam_profiles_raw["module_lines"].get(
        "pam_pwquality.so", []
    )

    # Surface inline pam.d arguments for pwquality
    inline_settings: dict[str, str | None] = {k: None for k in _PWQUALITY_CONF_KEYS}
    for entry in pwquality_pam_lines:
        for token in entry["line"].split():
            for key in _PWQUALITY_CONF_KEYS:
                if token.lower().startswith(f"{key}="):
                    inline_settings[key] = token.split("=", 1)[1]
                elif token.lower() == key:
                    inline_settings[key] = "present"

    return {
        "pwquality_conf_raw": pwquality_conf_raw,
        "pwquality_conf_d": pwquality_conf_d,
        "pwquality_conf_settings": pwquality_conf_settings,
        "pwquality_pam_lines": pwquality_pam_lines,
        "pwquality_inline_pam_settings": inline_settings,
    }


# ---------------------------------------------------------------------------
# 5.3.3.3 – pam_pwhistory
# ---------------------------------------------------------------------------

_PWHISTORY_CONF_KEYS = ["remember", "enforce_for_root", "use_authtok"]


def _collect_pam_pwhistory(pam_profiles_raw: dict[str, Any]) -> dict[str, Any]:
    """
    Collect pam_pwhistory settings. There is no separate pwhistory.conf on
    most Ubuntu systems; configuration lives entirely in pam.d lines.
    We still include opasswd path stat for completeness.
    """
    pwhistory_pam_lines: list[dict[str, str]] = pam_profiles_raw["module_lines"].get(
        "pam_pwhistory.so", []
    )

    inline_settings: dict[str, str | None] = {k: None for k in _PWHISTORY_CONF_KEYS}
    for entry in pwhistory_pam_lines:
        for token in entry["line"].split():
            for key in _PWHISTORY_CONF_KEYS:
                if token.lower().startswith(f"{key}="):
                    inline_settings[key] = token.split("=", 1)[1]
                elif token.lower() == key:
                    inline_settings[key] = "present"

    # /etc/security/opasswd — existence / permissions matter for CIS 7.1
    opasswd_exists = os.path.lexists("/etc/security/opasswd")

    return {
        "pwhistory_pam_lines": pwhistory_pam_lines,
        "pwhistory_inline_pam_settings": inline_settings,
        "opasswd_exists": opasswd_exists,
    }


# ---------------------------------------------------------------------------
# 5.3.3.4 – pam_unix
# ---------------------------------------------------------------------------

_PAM_UNIX_FLAGS_OF_INTEREST = [
    "nullok", "remember", "use_authtok",
    "yescrypt", "sha512", "blowfish", "md5",  # hashing options
]


def _collect_pam_unix(pam_profiles_raw: dict[str, Any]) -> dict[str, Any]:
    """
    Collect pam_unix.so lines across all four pam.d files plus a surface of
    the flags CIS cares about. No interpretation — raw presence/value only.
    """
    pam_unix_lines: list[dict[str, str]] = pam_profiles_raw["module_lines"].get(
        "pam_unix.so", []
    )

    # Surface key flags/arguments per file
    flag_presence: dict[str, str | None] = {f: None for f in _PAM_UNIX_FLAGS_OF_INTEREST}
    for entry in pam_unix_lines:
        for token in entry["line"].split():
            tl = token.lower()
            for flag in _PAM_UNIX_FLAGS_OF_INTEREST:
                if tl == flag or tl.startswith(f"{flag}="):
                    val = token.split("=", 1)[1] if "=" in token else "present"
                    flag_presence[flag] = val

    return {
        "pam_unix_lines": pam_unix_lines,
        "pam_unix_flag_presence": flag_presence,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_pam() -> dict[str, Any]:
    """
    Collect raw data needed to audit CIS Ubuntu 24.04 Benchmark section 5.3
    (Pluggable Authentication Modules / PAM).

    Returns:
        dict: A JSON-serialisable dictionary with top-level key 'pam' containing:
            pam_packages, pam_profiles_raw, pam_faillock,
            pam_pwquality, pam_pwhistory, pam_unix, errors
    """
    errors: list[dict[str, str]] = []

    pam_packages = _collect_pam_packages()
    pam_profiles_raw = _collect_pam_profiles_raw(errors)
    pam_faillock = _collect_pam_faillock(pam_profiles_raw)
    pam_pwquality = _collect_pam_pwquality(pam_profiles_raw)
    pam_pwhistory = _collect_pam_pwhistory(pam_profiles_raw)
    pam_unix = _collect_pam_unix(pam_profiles_raw)

    return {
        "pam": {
            "pam_packages": pam_packages,
            "pam_profiles_raw": pam_profiles_raw,
            "pam_faillock": pam_faillock,
            "pam_pwquality": pam_pwquality,
            "pam_pwhistory": pam_pwhistory,
            "pam_unix": pam_unix,
            "errors": errors,
        }
    }


if __name__ == "__main__":
    print(json.dumps(collect_pam(), indent=2))
