"""
ssh_audit_parser.py
====================
Converts raw outputs from `sshd -T` and `ssh-audit` into a compact, structured
JSON object suitable for LLM-based security analysis.

Design principles:
  - Only security-relevant fields are extracted; noisy/redundant data is dropped.
  - Weak algorithm detection: only failing/warning algorithms are kept, not the
    full list, dramatically reducing token count for downstream LLM consumption.
  - Regex-driven parsing: no reliance on fixed line numbers or column positions.
  - Fail-safe: every field falls back to a safe empty value; the parser never
    raises on missing or malformed input.
"""

import re
import json
from typing import Any
from .ssh_profile_normalizer import normalize_profile


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHFJABCDsu]")


def _strip_ansi(text: str) -> str:
    """Remove all ANSI/VT100 terminal escape sequences from a string."""
    return _ANSI_RE.sub("", text)





# ---------------------------------------------------------------------------
# Weak-algorithm reference sets
# ---------------------------------------------------------------------------
# These are well-known deprecated/broken algorithms. We use them to filter the
# full cipher/MAC/KEX lists that sshd -T emits (sshd -T doesn't tag weak ones;
# ssh-audit does, so for sshd output we rely on our own knowledge base).

WEAK_CIPHERS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256",
    "rijndael-cbc@lysator.liu.se",
}

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com", "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com", "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
}

WEAK_KEX = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1", "gss-gex-sha1-",
    "gss-group1-sha1-", "gss-group14-sha1-",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
}

WEAK_HOST_KEYS = {
    "ssh-rsa", "ssh-dss", "pgp-sign-rsa", "pgp-sign-dss",
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _empty_profile() -> dict[str, Any]:
    """Return the canonical empty security profile structure."""
    return {
        "ssh": {
            "version": "",
            "banner": "",
            "port": 22,
            "network": {},
            "authentication": {},
            "session": {},
            "forwarding": {},
            "features": {},
        },
        "crypto": {
            "weak_ciphers": [],
            "weak_macs": [],
            "weak_kex": [],
            "weak_host_keys": [],
        },
        "vulnerabilities": [],
    }


def _parse_kv_block(text: str, keys: list[str]) -> dict[str, str]:
    """
    Extract specific key=value pairs from sshd -T output.
    sshd -T emits one directive per line: `<key> <value>` (space-separated).
    Returns a dict with only the requested keys (lower-cased), or empty string
    for any key not found in the text.
    """
    result: dict[str, str] = {}
    key_pattern = re.compile(
        r"^(" + "|".join(re.escape(k) for k in keys) + r")\s+(.+)$",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in key_pattern.finditer(text):
        result[match.group(1).lower()] = match.group(2).strip()
    # Fill missing keys with empty string so callers always get a value
    for k in keys:
        result.setdefault(k.lower(), "")
    return result


# ---------------------------------------------------------------------------
# Parser 1: sshd -T
# ---------------------------------------------------------------------------

def parse_sshd_config(raw_output: str) -> dict[str, Any]:
    """
    Parse the output of `sshd -T` (full effective configuration dump).

    Only security-relevant directives are extracted. Crypto lists are filtered
    to retain only known-weak algorithms instead of the full list.

    Args:
        raw_output: Raw string output from `sshd -T`.

    Returns:
        A dict with keys: authentication, session, forwarding, features,
        network, logging, weak_ciphers, weak_macs, weak_kex.
    """
    if not raw_output or not raw_output.strip():
        return {}

    raw_output = _strip_ansi(raw_output)

    # -- Authentication directives --
    auth_keys = [
        "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
        "permitemptypasswords", "maxauthtries", "authenticationmethods",
        "gssapiauthentication", "hostbasedauthentication", "ignorerhosts",
        "usepam", "allowusers", "denyusers", "allowgroups", "denygroups",
    ]
    auth = _parse_kv_block(raw_output, auth_keys)

    # -- Session security directives --
    session_keys = [
        "clientaliveinterval", "clientalivecountmax", "maxsessions", "logingracetime",
        "maxstartups",
    ]
    session = _parse_kv_block(raw_output, session_keys)

    # Convert numeric strings to ints where sensible
    for k in ("clientaliveinterval", "clientalivecountmax", "maxsessions",
              "logingracetime", "maxauthtries"):
        for src in (auth, session):
            if k in src and isinstance(src[k], str) and src[k].isdigit():
                src[k] = int(src[k])

    # -- Forwarding directives --
    forwarding_keys = [
        "allowtcpforwarding", "allowagentforwarding", "allowstreamlocalforwarding",
        "gatewayports", "permitopen", "permitlisten",
    ]
    forwarding = _parse_kv_block(raw_output, forwarding_keys)

    # -- Security feature directives --
    feature_keys = [
        "x11forwarding", "permituserenvironment", "usedns",
        "compression", "banner", "strictmodes",
    ]
    features = _parse_kv_block(raw_output, feature_keys)

    # -- Network directives --
    network_keys = ["port", "listenaddress", "addressfamily"]
    network = _parse_kv_block(raw_output, network_keys)
    if network.get("port", "").isdigit():
        network["port"] = int(network["port"])

    # -- Logging directives --
    logging_keys = ["loglevel", "syslogfacility"]
    logging_cfg = _parse_kv_block(raw_output, logging_keys)

    # -- Weak algorithm extraction --
    # sshd -T lists full algorithm sets as comma-separated values on one line.
    # We filter each set against our known-weak reference sets.
    def _extract_weak(directive: str, weak_set: set[str]) -> list[str]:
        """Find the directive line and return only the weak algorithms from it."""
        m = re.search(rf"^{directive}\s+(.+)$", raw_output, re.IGNORECASE | re.MULTILINE)
        if not m:
            return []
        algos = [a.strip().lower() for a in m.group(1).split(",")]
        return [a for a in algos if a in weak_set]

    weak_ciphers = _extract_weak("ciphers", WEAK_CIPHERS)
    weak_macs    = _extract_weak("macs", WEAK_MACS)
    weak_kex     = _extract_weak("kexalgorithms", WEAK_KEX)

    # Full ciphers list (for CIS 5.1.6 — rule needs to verify specific ciphers present)
    _ciphers_m = re.search(r"^ciphers\s+(.+)$", raw_output, re.IGNORECASE | re.MULTILINE)
    all_ciphers = [c.strip() for c in _ciphers_m.group(1).split(",")] if _ciphers_m else []

    return {
        "authentication": auth,
        "session":        session,
        "forwarding":     forwarding,
        "features":       features,
        "network":        network,
        "logging":        logging_cfg,
        "weak_ciphers":   weak_ciphers,
        "weak_macs":      weak_macs,
        "weak_kex":       weak_kex,
        "all_ciphers":    all_ciphers,
    }


# ---------------------------------------------------------------------------
# Parser 2: ssh-audit
# ---------------------------------------------------------------------------

# ssh-audit prefixes lines with category tags like:
#   (kex)   ecdh-sha2-nistp256                  -- [fail] ...
#   (enc)   aes128-cbc                           -- [warn] ...
#   (mac)   hmac-sha1                            -- [fail] ...
#   (key)   ssh-rsa                              -- [fail] ...
# General info lines start with: (gen) ...
# Vulnerability / recommendation lines start with (rec), (cve), or end with CVE ids.

_AUDIT_ALGO_RE = re.compile(
    r"^\s*\((?P<cat>kex|enc|mac|key)\)\s+(?P<algo>\S+).*?\[(?P<status>fail|warn)\]",
    re.IGNORECASE | re.MULTILINE,
)

_AUDIT_GEN_RE = re.compile(
    r"^\s*\(gen\)\s+(?P<key>[^:]+):\s*(?P<value>.+)$",
    re.IGNORECASE | re.MULTILINE,
)

# CVE identifiers can appear inline anywhere in a line
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def parse_ssh_audit(raw_output: str) -> dict[str, Any]:
    """
    Parse the output of `ssh-audit` (or `ssh-audit -j` JSON is NOT expected here;
    this handles the default human-readable text output).

    Extracts:
      - General server info (version, banner, compression)
      - Only fail/warn-tagged algorithms per category (kex, enc, mac, key)
      - CVE identifiers and their associated descriptions

    Args:
        raw_output: Raw string output from `ssh-audit`.

    Returns:
        A dict with keys: version, banner, compression,
        weak_kex, weak_ciphers, weak_macs, weak_host_keys, vulnerabilities.
    """
    if not raw_output or not raw_output.strip():
        return {}

    raw_output = _strip_ansi(raw_output)

    result: dict[str, Any] = {
        "version":        "",
        "banner":         "",
        "compression":    "",
        "weak_kex":       [],
        "weak_ciphers":   [],
        "weak_macs":      [],
        "weak_host_keys": [],
        "vulnerabilities": [],
    }

    # -- General server metadata --
    for m in _AUDIT_GEN_RE.finditer(raw_output):
        key   = m.group("key").strip().lower()
        value = m.group("value").strip()
        if "version" in key or "software" in key:
            result["version"] = value
        elif "banner" in key:
            result["banner"] = value
        elif "compression" in key:
            result["compression"] = value

    # Some versions of ssh-audit print banner differently
    banner_m = re.search(r"banner:\s*(.+)", raw_output, re.IGNORECASE)
    if banner_m and not result["banner"]:
        result["banner"] = banner_m.group(1).strip()

    # -- Algorithm weakness extraction --
    category_map = {
        "kex": "weak_kex",
        "enc": "weak_ciphers",
        "mac": "weak_macs",
        "key": "weak_host_keys",
    }
    seen: set[tuple[str, str]] = set()
    for m in _AUDIT_ALGO_RE.finditer(raw_output):
        cat   = m.group("cat").lower()
        algo  = m.group("algo").strip()
        field = category_map.get(cat)
        if field and (cat, algo) not in seen:
            result[field].append({
                "algorithm": algo,
                "severity":  m.group("status").lower(),  # "fail" | "warn"
            })
            seen.add((cat, algo))

    # -- Vulnerability / CVE extraction --
    # ssh-audit prints CVE lines like:
    #   -- [CVE-2023-48795] Terrapin attack -- ...
    # or inline in recommendation lines
    vuln_entries: dict[str, dict] = {}

    for line in raw_output.splitlines():
        cves = _CVE_RE.findall(line)
        if not cves:
            continue

        # Strip ssh-audit formatting chars to get a clean description
        clean = re.sub(r"\[(?:fail|warn|info)\]", "", line, flags=re.IGNORECASE)
        clean = re.sub(r"\((?:rec|cve|aut|nfo)\)", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"CVE-\d{4}-\d+", "", clean)  # remove CVE ids from desc
        clean = re.sub(r"[-–,;]+", " ", clean)        # remove punctuation artefacts
        clean = re.sub(r"\s{2,}", " ", clean).strip()

        desc = clean if clean else "No description available"

        for cve in cves:
            cve_upper = cve.upper()
            if cve_upper not in vuln_entries:
                vuln_entries[cve_upper] = {
                    "cve":         cve_upper,
                    "description": desc,
                }
            # If a later line has a richer description, prefer it
            elif len(desc) > len(vuln_entries[cve_upper]["description"]):
                vuln_entries[cve_upper]["description"] = desc

    result["vulnerabilities"] = list(vuln_entries.values())
    return result


# ---------------------------------------------------------------------------
# Profile builder: merge both parsers into the unified JSON schema
# ---------------------------------------------------------------------------

def build_security_profile(
    sshd_output: str = "",
    ssh_audit_output: str = "",
) -> dict[str, Any]:
    """
    Merge outputs from `sshd -T` and `ssh-audit` into a single, compact
    security profile JSON ready for LLM consumption.

    Either argument may be empty; the function degrades gracefully and returns
    whatever fields are available from the inputs provided.

    Args:
        sshd_output:      Raw string from `sshd -T`, or "" to skip.
        ssh_audit_output: Raw string from `ssh-audit`, or "" to skip.

    Returns:
        Unified security profile dict matching the documented JSON schema.
    """
    profile = _empty_profile()

    sshd  = parse_sshd_config(sshd_output) if sshd_output.strip() else {}
    audit = parse_ssh_audit(ssh_audit_output) if ssh_audit_output.strip() else {}

    # -- ssh section --
    if audit.get("version"):
        profile["ssh"]["version"] = audit["version"]
    if audit.get("banner"):
        profile["ssh"]["banner"] = audit["banner"]
    if audit.get("compression"):
        profile["ssh"]["compression"] = audit["compression"]

    if sshd.get("network"):
        net = sshd["network"]
        profile["ssh"]["port"] = net.get("port", 22)
        profile["ssh"]["network"] = {
            k: v for k, v in net.items()
            if k != "port" and v  # skip port (already top-level) and empty vals
        }

    profile["ssh"]["authentication"] = sshd.get("authentication", {})
    profile["ssh"]["session"]        = sshd.get("session", {})
    profile["ssh"]["forwarding"]     = sshd.get("forwarding", {})
    profile["ssh"]["features"]       = sshd.get("features", {})

    # Expose full cipher list so AI can audit rule 5.1.6
    if sshd.get("all_ciphers"):
        profile["ssh"]["all_ciphers"] = sshd["all_ciphers"]

    # Merge logging into features to keep the schema slim
    if sshd.get("logging"):
        profile["ssh"]["features"].update(sshd["logging"])

    # -- crypto section: union of weak algorithms from both sources --
    # For sshd, we get plain strings. For ssh-audit, we get dicts with severity.
    # We store them as-is from ssh-audit (richer), falling back to sshd strings.
    def _merge_algo_lists(
        sshd_list: list[str], audit_list: list[dict]
    ) -> list[Any]:
        """
        Prefer ssh-audit enriched dicts; supplement with any sshd-found algos
        that ssh-audit didn't flag (audit may not have run or may differ in scope).
        """
        known = {entry["algorithm"] for entry in audit_list}
        extras = [a for a in sshd_list if a not in known]
        return audit_list + [{"algorithm": a, "severity": "warn"} for a in extras]

    profile["crypto"]["weak_ciphers"] = _merge_algo_lists(
        sshd.get("weak_ciphers", []),
        audit.get("weak_ciphers", []),
    )
    profile["crypto"]["weak_macs"] = _merge_algo_lists(
        sshd.get("weak_macs", []),
        audit.get("weak_macs", []),
    )
    profile["crypto"]["weak_kex"] = _merge_algo_lists(
        sshd.get("weak_kex", []),
        audit.get("weak_kex", []),
    )
    # host keys only from ssh-audit (sshd -T doesn't tag weakness explicitly)
    profile["crypto"]["weak_host_keys"] = audit.get("weak_host_keys", [])

    # -- vulnerabilities: exclusively from ssh-audit --
    profile["vulnerabilities"] = audit.get("vulnerabilities", [])

    # Remove empty-string top-level ssh fields to keep the JSON compact
    profile["ssh"] = {k: v for k, v in profile["ssh"].items() if v != ""}

    # Normalize and enrich the profile before returning
    return normalize_profile(profile)


# ---------------------------------------------------------------------------
# CLI / example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import subprocess
    import sys

    cli = argparse.ArgumentParser(
        description="SSH security auditor — runs sshd -T and ssh-audit then emits a JSON profile."
    )
    cli.add_argument(
        "target",
        nargs="?",
        default="localhost",
        help="Host to pass to ssh-audit (default: localhost)",
    )
    cli.add_argument(
        "--port", "-p",
        default="22",
        help="SSH port (default: 22)",
    )
    args = cli.parse_args()

    # ------------------------------------------------------------------ #
    # 1. Run sshd -T  (reads the effective sshd configuration)
    #    Requires root or the sshd binary to be in PATH.
    # ------------------------------------------------------------------ #
    sshd_output = ""
    try:
        result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            sshd_output = result.stdout
        else:
            print(
                f"[warn] sshd -T exited with code {result.returncode}: {result.stderr.strip()}",
                file=sys.stderr,
            )
    except FileNotFoundError:
        print("[warn] sshd not found in PATH — skipping sshd -T", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("[warn] sshd -T timed out", file=sys.stderr)
    except PermissionError as exc:
        print(f"[warn] Permission denied running sshd -T: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------ #
    # 2. Run ssh-audit <target>  (active scan of the target SSH service)
    #    ssh-audit exits non-zero when it finds issues, so we accept any
    #    exit code and use the stdout as long as it's non-empty.
    # ------------------------------------------------------------------ #
    audit_output = ""
    try:
        result = subprocess.run(
            ["ssh-audit", "-n", "-p", args.port, args.target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        audit_output = result.stdout
        if not audit_output.strip() and result.stderr.strip():
            print(
                f"[warn] ssh-audit produced no output: {result.stderr.strip()}",
                file=sys.stderr,
            )
    except FileNotFoundError:
        print("[warn] ssh-audit not found in PATH — skipping ssh-audit scan", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("[warn] ssh-audit timed out", file=sys.stderr)

    # ------------------------------------------------------------------ #
    # 3. Build and print the security profile
    # ------------------------------------------------------------------ #
    profile = build_security_profile(
        sshd_output=sshd_output,
        ssh_audit_output=audit_output,
    )
    print(json.dumps(profile, indent=2))
