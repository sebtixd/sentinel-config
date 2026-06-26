"""
ssh_profile_normalizer.py
==========================
Post-processing normalizer for the JSON profile produced by ssh_audit_parser.py.

Applies ten transformations to make the output clean, consistent, and ready
for LLM-based security analysis:

  1. Strip ANSI escape codes from all string values.
  2. Convert "yes"/"no" strings to true/false booleans.
  3. Promote ambiguous sentinel values ("any", "none", "0") to risk-annotated objects.
  4. Clean the SSH banner field to extract only the version token.
  5. Standardize severity labels: info→low, warn→medium, fail→high.
  6. Enrich vulnerability entries with name, risk, affected_algorithms, notes.
  7. Add human-readable "reason" fields to all cryptographic findings.
  8. Rename all keys to strict snake_case.
  9. Remove empty / null fields recursively.
 10. Return a fully serialisable, consistent JSON-ready dict.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# 1. ANSI escape code stripper
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHFJABCDsu]")


def _strip_ansi(text: str) -> str:
    """Remove all ANSI/VT100 terminal escape sequences from a string."""
    return _ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# 2. Boolean normalizer
# ---------------------------------------------------------------------------

_BOOL_MAP = {
    "yes": True, "true": True, "enabled": True,
    "no": False, "false": False, "disabled": False,
}


def _to_bool(value: str) -> bool | str:
    """Convert 'yes'/'no' strings to Python booleans; leave others unchanged."""
    return _BOOL_MAP.get(value.lower().strip(), value)


# ---------------------------------------------------------------------------
# 3. Ambiguous sentinel values → risk-annotated objects
# ---------------------------------------------------------------------------

# These directives have security implications when set to "any" or similar.
# Risk levels are based on CIS SSH Benchmark and NIST SP 800-53 guidance.
_AMBIGUOUS_RISK: dict[str, dict[str, str]] = {
    # Field name → {sentinel → risk}
    "permit_open":              {"any": "medium", "none": "low"},
    "permit_listen":            {"any": "medium", "none": "low"},
    "authentication_methods":  {"any": "high"},
    "address_family":          {"any": "low"},
    "compression":             {"delayed": "low", "0": "low"},
    "login_grace_time":        {"0": "medium"},   # 0 = unlimited wait
    "client_alive_interval":   {"0": "medium"},   # 0 = no keepalive
    "max_auth_tries":          {"0": "medium"},
}

# Directives that are risky when set to a specific boolean-like value
_BOOL_RISK: dict[str, dict[bool, str]] = {
    "permit_root_login":       {True: "critical"},
    "password_authentication": {True: "high"},
    "permit_empty_passwords":  {True: "critical"},
    "x11_forwarding":          {True: "medium"},
    "allow_tcp_forwarding":    {True: "medium"},
    "allow_agent_forwarding":  {True: "medium"},
    "allow_streamlocal_forwarding": {True: "medium"},
    "gateway_ports":           {True: "high"},
    "permit_user_environment": {True: "high"},
    "use_dns":                 {False: "low"},
    "strict_modes":            {False: "high"},
}


def _annotate_ambiguous(key: str, value: Any) -> Any:
    """
    If a value is a known ambiguous sentinel (like "any" or "0") or a risky
    boolean state, promote it to a dict {value, risk}. Otherwise return as-is.
    """
    # 1. Check for ambiguous sentinels
    if key in _AMBIGUOUS_RISK:
        sentinel_map = _AMBIGUOUS_RISK[key]
        lookup = str(value).lower()
        if lookup in sentinel_map:
            return {"value": value, "risk": sentinel_map[lookup]}

    # 2. Check for risky booleans
    if key in _BOOL_RISK and isinstance(value, bool):
        risk_map = _BOOL_RISK[key]
        if value in risk_map:
            return {"value": value, "risk": risk_map[value]}

    return value


# ---------------------------------------------------------------------------
# 4. SSH banner cleaner
# ---------------------------------------------------------------------------

_BANNER_RE = re.compile(r"SSH-[\d.]+-([\w.]+(?:_[\w.]+)*)", re.IGNORECASE)


def _clean_banner(banner: str) -> str:
    """
    Extract the software/version token from an SSH banner string.
    'SSH-2.0-OpenSSH_9.3p1 Ubuntu-3' → 'OpenSSH_9.3p1'
    """
    banner = _strip_ansi(banner).strip()
    m = _BANNER_RE.search(banner)
    return m.group(1) if m else banner


# ---------------------------------------------------------------------------
# 5. Severity normalizer
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "info":     "low",
    "low":      "low",
    "warn":     "medium",
    "warning":  "medium",
    "medium":   "medium",
    "fail":     "high",
    "high":     "high",
    "critical": "critical",
    "error":    "high",
}


def _norm_severity(severity: str) -> str:
    return _SEVERITY_MAP.get(severity.lower().strip(), severity.lower().strip())


# ---------------------------------------------------------------------------
# 6. Vulnerability enricher
# ---------------------------------------------------------------------------

# Known CVE metadata used to enrich bare vulnerability descriptions.
# Structured as: CVE-ID → {name, risk, short_description, notes}
_CVE_DB: dict[str, dict[str, str]] = {
    "CVE-2023-48795": {
        "name": "Terrapin Attack",
        "risk": "high",
        "description": "Prefix truncation attack on SSH handshake via ChaCha20-Poly1305 or CBC-EtM, allowing downgrade of security extensions.",
        "notes": "Mitigated by removing CBC-EtM MACs and ensuring strict KEX.",
    },
    "CVE-2002-20001": {
        "name": "DROWN (Diffie-Hellman Key Reuse)",
        "risk": "high",
        "description": "Use of weak Diffie-Hellman groups allows a man-in-the-middle to decrypt or forge session traffic.",
        "notes": "Remove DH group sizes below 3072 bits.",
    },
    "CVE-2016-20012": {
        "name": "OpenSSH Username Enumeration",
        "risk": "medium",
        "description": "Timing difference in authentication responses allows enumeration of valid usernames.",
        "notes": "Apply upstream patches; limit failed login attempts.",
    },
    "CVE-2018-15473": {
        "name": "Username Enumeration via Timing",
        "risk": "medium",
        "description": "Invalid users receive a different response time than valid users, enabling account enumeration.",
        "notes": "Upgrade to OpenSSH 7.8 or later.",
    },
    "CVE-2021-28041": {
        "name": "SSH Agent Double-Free",
        "risk": "high",
        "description": "A double-free memory corruption in ssh-agent allows a compromised agent client to execute arbitrary code.",
        "notes": "Upgrade to OpenSSH 8.5 or later.",
    },
    "CVE-2023-38408": {
        "name": "Remote Code Execution via ssh-agent",
        "risk": "critical",
        "description": "Forwarded ssh-agent can be exploited remotely to load arbitrary PKCS#11 providers and execute code.",
        "notes": "Disable agent forwarding; upgrade to OpenSSH 9.3p2.",
    },
}

# Algorithm patterns → set of affected CVEs (for cross-referencing)
_ALGO_CVE_MAP: dict[str, list[str]] = {
    "diffie-hellman-group1-sha1":   ["CVE-2002-20001"],
    "diffie-hellman-group14-sha1":  ["CVE-2002-20001"],
    "chacha20-poly1305@openssh.com": ["CVE-2023-48795"],
    "aes128-cbc":                   ["CVE-2023-48795"],
    "hmac-sha1-etm@openssh.com":    ["CVE-2023-48795"],
    "ecdh-sha2-nistp256":           ["CVE-2002-20001"],
    "ecdh-sha2-nistp384":           ["CVE-2002-20001"],
    "ecdh-sha2-nistp521":           ["CVE-2002-20001"],
}


def _enrich_vulnerability(vuln: dict[str, Any], all_weak_algos: list[str]) -> dict[str, Any]:
    """
    Enrich a raw vulnerability entry with structured metadata.
    Falls back gracefully when the CVE is not in the local DB.
    """
    cve = vuln.get("cve", "").upper()
    raw_desc = _strip_ansi(vuln.get("description", ""))

    db_entry = _CVE_DB.get(cve, {})

    # Determine which weak algorithms from the profile are associated with this CVE
    affected = [
        algo for algo, cves in _ALGO_CVE_MAP.items()
        if cve in cves and algo in all_weak_algos
    ]

    return {
        "cve":                 cve,
        "name":                db_entry.get("name") or _derive_vuln_name(raw_desc),
        "risk":                db_entry.get("risk") or _norm_severity(vuln.get("severity", "medium")),
        "description":         db_entry.get("description") or _clean_vuln_desc(raw_desc),
        "affected_algorithms": affected,
        "notes":               db_entry.get("notes", ""),
    }


def _derive_vuln_name(desc: str) -> str:
    """Derive a short name from the first significant words of the description."""
    # Take first 5 words, capitalize properly
    words = re.split(r"\s+", desc.strip())[:5]
    return " ".join(w.capitalize() for w in words if w) or "Unknown Vulnerability"


def _clean_vuln_desc(desc: str) -> str:
    """Strip formatting noise from a raw vulnerability description string."""
    clean = re.sub(r"\(rec\)|\(cve\)|\[fail\]|\[warn\]|\[info\]", "", desc, flags=re.IGNORECASE)
    clean = re.sub(r"[-–]{2,}", " ", clean)
    clean = re.sub(r"\s{2,}", " ", clean).strip()
    return clean[:300]  # Cap at 300 chars to keep LLM context lean


# ---------------------------------------------------------------------------
# 7. Crypto reason database
# ---------------------------------------------------------------------------

_ALGO_REASONS: dict[str, str] = {
    # Key exchange
    "diffie-hellman-group1-sha1":         "768/1024-bit Oakley Group 1 modulus; breakable by state-level actors (Logjam).",
    "diffie-hellman-group14-sha1":        "2048-bit modulus with SHA-1; SHA-1 is cryptographically broken.",
    "diffie-hellman-group-exchange-sha1": "SHA-1 hashing deprecated; vulnerable to collision attacks.",
    "ecdh-sha2-nistp256":                 "NIST P-256 curve has suspected NIST/NSA backdoor per Dual_EC_DRBG concerns.",
    "ecdh-sha2-nistp384":                 "NIST P-384 curve; same NSA-standardized curve trust concerns as nistp256.",
    "ecdh-sha2-nistp521":                 "NIST P-521 curve; same NSA-standardized curve trust concerns as nistp256.",
    "gss-gex-sha1-":                      "GSS key exchange using SHA-1; SHA-1 collision resistance broken.",
    "gss-group1-sha1-":                   "GSS group 1 with SHA-1; 1024-bit modulus and broken hash.",
    "gss-group14-sha1-":                  "GSS group 14 with SHA-1; broken hash algorithm.",
    # Ciphers
    "3des-cbc":                           "Triple-DES in CBC mode; 64-bit block size vulnerable to SWEET32 birthday attack.",
    "aes128-cbc":                         "AES-128 in CBC mode; padding oracle and BEAST attack vectors.",
    "aes192-cbc":                         "AES-192 in CBC mode; same CBC padding oracle concerns as aes128-cbc.",
    "aes256-cbc":                         "AES-256 in CBC mode; same CBC padding oracle concerns.",
    "blowfish-cbc":                       "Blowfish in CBC mode; 64-bit block size (SWEET32) and broken design.",
    "cast128-cbc":                        "CAST-128 in CBC mode; 64-bit block and weak key schedule.",
    "arcfour":                            "RC4 stream cipher; broken, RFC 7465 prohibits it.",
    "arcfour128":                         "RC4 variant; same fundamental weaknesses as arcfour.",
    "arcfour256":                         "RC4 variant; same fundamental weaknesses as arcfour.",
    "rijndael-cbc@lysator.liu.se":        "Non-standard AES alias in CBC mode; same CBC weaknesses.",
    # MACs
    "hmac-md5":                           "MD5 hash; broken collision resistance, practical attacks known since 2004.",
    "hmac-md5-96":                        "MD5 variant truncated to 96 bits; same underlying MD5 weaknesses.",
    "hmac-sha1":                          "SHA-1 hash; collision attacks demonstrated; deprecated in RFC 6194.",
    "hmac-sha1-96":                       "SHA-1 truncated to 96 bits; same SHA-1 weaknesses with smaller MAC.",
    "umac-64@openssh.com":                "UMAC with 64-bit tag; birthday attack risk at ~2^32 messages.",
    "hmac-md5-etm@openssh.com":           "MD5-based MAC in EtM mode; MD5 is cryptographically broken.",
    "hmac-md5-96-etm@openssh.com":        "MD5 96-bit variant in EtM; same MD5 breakage.",
    "hmac-sha1-etm@openssh.com":          "SHA-1 in EtM mode; enables Terrapin attack (CVE-2023-48795).",
    "hmac-sha1-96-etm@openssh.com":       "SHA-1 96-bit in EtM; SHA-1 broken and Terrapin-vulnerable.",
    "umac-64-etm@openssh.com":            "UMAC-64 in EtM; 64-bit birthday bound too small for long sessions.",
    # Host keys
    "ssh-rsa":                            "RSA with SHA-1 signature; SHA-1 is cryptographically broken (RFC 8332).",
    "ssh-dss":                            "DSA with 1024-bit key and SHA-1; both parameters broken.",
    "pgp-sign-rsa":                       "PGP RSA signature; deprecated in modern SSH.",
    "pgp-sign-dss":                       "PGP DSA signature; 1024-bit key size and SHA-1 both broken.",
}

_DEFAULT_REASON = "Algorithm is deprecated or has known cryptographic weaknesses."


def _enrich_crypto_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """
    Add human-readable 'reason' and normalize 'severity' for a crypto finding.
    """
    algo = entry.get("algorithm", "").lower()
    severity = _norm_severity(entry.get("severity", "warn"))

    return {
        "algorithm": entry.get("algorithm", ""),
        "severity":  severity,
        "reason":    _ALGO_REASONS.get(algo, _DEFAULT_REASON),
    }


# ---------------------------------------------------------------------------
# 8. Key renamer: camelCase / flat-lowercase → snake_case
# ---------------------------------------------------------------------------

# Explicit mapping covers all directives emitted by sshd -T and the profile schema.
_KEY_MAP: dict[str, str] = {
    # Authentication
    "permitrootlogin":           "permit_root_login",
    "passwordauthentication":    "password_authentication",
    "pubkeyauthentication":      "pubkey_authentication",
    "permitemptypasswords":      "permit_empty_passwords",
    "maxauthtries":              "max_auth_tries",
    "authenticationmethods":    "authentication_methods",
    # Session
    "clientaliveinterval":       "client_alive_interval",
    "clientalivecountmax":       "client_alive_count_max",
    "maxsessions":               "max_sessions",
    "logingracetime":            "login_grace_time",
    # Forwarding
    "allowtcpforwarding":        "allow_tcp_forwarding",
    "allowagentforwarding":      "allow_agent_forwarding",
    "allowstreamlocalforwarding":"allow_streamlocal_forwarding",
    "gatewayports":              "gateway_ports",
    "permitopen":                "permit_open",
    "permitlisten":              "permit_listen",
    # Features
    "x11forwarding":             "x11_forwarding",
    "permituserenvironment":     "permit_user_environment",
    "usedns":                    "use_dns",
    "strictmodes":               "strict_modes",
    # Logging
    "loglevel":                  "log_level",
    "syslogfacility":            "syslog_facility",
    # Network
    "listenaddress":             "listen_address",
    "addressfamily":             "address_family",
    # Crypto
    "weakciphers":               "weak_ciphers",
    "weakmacs":                  "weak_macs",
    "weakkex":                   "weak_kex",
    "weakhostkeys":              "weak_host_keys",
    # Misc – pass-through for already-correct names
    "algorithm":                 "algorithm",
    "severity":                  "severity",
    "reason":                    "reason",
    "version":                   "version",
    "banner":                    "banner",
    "port":                      "port",
    "compression":               "compression",
    "network":                   "network",
    "authentication":            "authentication",
    "session":                   "session",
    "forwarding":                "forwarding",
    "features":                  "features",
    "ssh":                       "ssh",
    "crypto":                    "crypto",
    "vulnerabilities":           "vulnerabilities",
    "cve":                       "cve",
    "name":                      "name",
    "risk":                      "risk",
    "description":               "description",
    "affected_algorithms":       "affected_algorithms",
    "notes":                     "notes",
    "value":                     "value",
    "log_level":                 "log_level",
    "syslog_facility":           "syslog_facility",
    "listen_address":            "listen_address",
    "address_family":            "address_family",
}


def _to_snake(key: str) -> str:
    """
    Convert a key to snake_case.
    Priority: explicit _KEY_MAP lookup → auto camelCase→snake conversion.
    """
    if key in _KEY_MAP:
        return _KEY_MAP[key]
    # Auto-convert camelCase
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower()


# ---------------------------------------------------------------------------
# 9. Recursive empty-field remover
# ---------------------------------------------------------------------------

def _drop_empty(obj: Any) -> Any:
    """
    Recursively remove keys whose values are:
      - None
      - empty string ""
      - empty list []
      - empty dict {}
    Leaves False, 0, and structured objects intact.
    """
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            v_clean = _drop_empty(v)
            if v_clean is None:
                continue
            if v_clean == "" or v_clean == [] or v_clean == {}:
                continue
            cleaned[k] = v_clean
        return cleaned or None
    if isinstance(obj, list):
        cleaned_list = [_drop_empty(item) for item in obj]
        return [i for i in cleaned_list if i is not None and i != "" and i != {} and i != []]
    return obj


# ---------------------------------------------------------------------------
# 10. Main entry point
# ---------------------------------------------------------------------------

def normalize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Apply all ten normalization transformations to a raw SSH security profile
    produced by build_security_profile().

    Args:
        profile: Raw dict from build_security_profile().

    Returns:
        Cleaned, normalized dict ready for LLM consumption.
    """
    # Collect all weak algorithm names for CVE cross-referencing (step 6)
    all_weak_algos: list[str] = []
    for field in ("weak_ciphers", "weak_macs", "weak_kex", "weak_host_keys"):
        for entry in profile.get("crypto", {}).get(field, []):
            algo = entry.get("algorithm", "") if isinstance(entry, dict) else entry
            all_weak_algos.append(algo.lower())

    # -- Build normalized 'ssh' block --
    raw_ssh = profile.get("ssh", {})
    ssh_out: dict[str, Any] = {}

    for raw_key, raw_val in raw_ssh.items():
        norm_key = _to_snake(raw_key)

        # Step 1: strip ANSI from strings
        if isinstance(raw_val, str):
            raw_val = _strip_ansi(raw_val)

        # Step 4: clean banner
        if norm_key == "banner" and isinstance(raw_val, str):
            raw_val = _clean_banner(raw_val)

        # Step 2: normalize booleans
        if isinstance(raw_val, str):
            raw_val = _to_bool(raw_val)

        # Step 8 recursive rename on nested dicts (network, auth, session, etc.)
        if isinstance(raw_val, dict):
            raw_val = _normalize_section(raw_val)

        # Step 3 / step 2 risk annotations (applied after booleans are resolved)
        raw_val = _annotate_ambiguous(norm_key, raw_val)

        ssh_out[norm_key] = raw_val

    # -- Build normalized 'crypto' block (steps 5 + 7) --
    raw_crypto = profile.get("crypto", {})
    crypto_out: dict[str, Any] = {}
    for field in ("weak_ciphers", "weak_macs", "weak_kex", "weak_host_keys"):
        entries = raw_crypto.get(field, [])
        crypto_out[field] = [_enrich_crypto_entry(e) for e in entries]

    # -- Build normalized 'vulnerabilities' block (step 6) --
    vulns_out = [
        _enrich_vulnerability(v, all_weak_algos)
        for v in profile.get("vulnerabilities", [])
    ]

    normalized: dict[str, Any] = {
        "ssh":            ssh_out,
        "crypto":         crypto_out,
        "vulnerabilities": vulns_out,
    }

    # Step 9: remove empty fields
    normalized = _drop_empty(normalized) or {}
    return normalized


def _normalize_section(section: dict[str, Any]) -> dict[str, Any]:
    """
    Apply steps 1–3, 5, 8 recursively to a nested dict section
    (authentication, session, forwarding, features, network).
    """
    out: dict[str, Any] = {}
    for raw_key, raw_val in section.items():
        norm_key = _to_snake(raw_key)

        if isinstance(raw_val, str):
            raw_val = _strip_ansi(raw_val)

        if isinstance(raw_val, str):
            raw_val = _to_bool(raw_val)

        if isinstance(raw_val, dict):
            raw_val = _normalize_section(raw_val)

        raw_val = _annotate_ambiguous(norm_key, raw_val)
        out[norm_key] = raw_val
    return out
