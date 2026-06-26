"""
test_ssh_profile_normalizer.py
===============================
Unit tests for ssh_profile_normalizer.py
Run with: python -m unittest test_ssh_profile_normalizer -v
"""

import json
import unittest
from tools.ssh_profile_normalizer import (
    normalize_profile,
    _strip_ansi,
    _to_bool,
    _clean_banner,
    _norm_severity,
    _enrich_crypto_entry,
    _enrich_vulnerability,
    _to_snake,
    _drop_empty,
    _annotate_ambiguous,
)

# ---------------------------------------------------------------------------
# Minimal raw profile fixture (as produced by build_security_profile BEFORE
# normalization, so we can test the normalizer in isolation)
# ---------------------------------------------------------------------------

RAW_PROFILE = {
    "ssh": {
        "version": "OpenSSH 8.9p1",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "port": 22,
        "compression": "enabled (zlib@openssh.com)",
        "network": {
            "listenaddress": "0.0.0.0",
            "addressfamily": "any",
        },
        "authentication": {
            "permitrootlogin": "yes",
            "passwordauthentication": "yes",
            "pubkeyauthentication": "yes",
            "permitemptypasswords": "no",
            "maxauthtries": 6,
            "authenticationmethods": "any",
        },
        "session": {
            "clientaliveinterval": 0,
            "clientalivecountmax": 3,
            "maxsessions": 10,
            "logingracetime": 120,
        },
        "forwarding": {
            "allowtcpforwarding": "yes",
            "allowagentforwarding": "yes",
            "allowstreamlocalforwarding": "yes",
            "gatewayports": "no",
            "permitopen": "any",
            "permitlisten": "any",
        },
        "features": {
            "x11forwarding": "yes",
            "permituserenvironment": "no",
            "usedns": "no",
            "compression": "delayed",
            "banner": "none",
            "strictmodes": "yes",
            "loglevel": "INFO",
            "syslogfacility": "AUTH",
        },
    },
    "crypto": {
        "weak_ciphers": [
            {"algorithm": "aes128-cbc", "severity": "fail"},
            {"algorithm": "3des-cbc",   "severity": "fail"},
        ],
        "weak_macs": [
            {"algorithm": "hmac-md5",  "severity": "fail"},
            {"algorithm": "hmac-sha1", "severity": "warn"},
        ],
        "weak_kex": [
            {"algorithm": "diffie-hellman-group1-sha1",  "severity": "fail"},
            {"algorithm": "ecdh-sha2-nistp256",          "severity": "warn"},
        ],
        "weak_host_keys": [
            {"algorithm": "ssh-rsa", "severity": "fail"},
        ],
    },
    "vulnerabilities": [
        {"cve": "CVE-2023-48795", "description": "Terrapin attack via SSH prefix truncation"},
        {"cve": "CVE-2002-20001", "description": "DROWN attack variant"},
        {"cve": "CVE-9999-00000", "description": "Unknown novel vulnerability"},  # not in DB
    ],
}

ANSI_PROFILE = dict(RAW_PROFILE)


class TestStripAnsi(unittest.TestCase):
    def test_removes_color_codes(self):
        self.assertEqual(_strip_ansi("\x1b[33mwarning\x1b[0m"), "warning")

    def test_removes_reset(self):
        self.assertEqual(_strip_ansi("\x1b[0mtext"), "text")

    def test_clean_string_unchanged(self):
        self.assertEqual(_strip_ansi("plain text"), "plain text")

    def test_empty_string(self):
        self.assertEqual(_strip_ansi(""), "")

    def test_multiple_codes(self):
        self.assertEqual(_strip_ansi("\x1b[1m\x1b[31mbold red\x1b[0m"), "bold red")


class TestToBool(unittest.TestCase):
    def test_yes_to_true(self):
        self.assertIs(_to_bool("yes"), True)

    def test_no_to_false(self):
        self.assertIs(_to_bool("no"), False)

    def test_case_insensitive(self):
        self.assertIs(_to_bool("YES"), True)
        self.assertIs(_to_bool("No"), False)

    def test_non_bool_unchanged(self):
        self.assertEqual(_to_bool("any"), "any")
        self.assertEqual(_to_bool("publickey"), "publickey")
        self.assertEqual(_to_bool("INFO"), "INFO")

    def test_enabled_disabled(self):
        self.assertIs(_to_bool("enabled"), True)
        self.assertIs(_to_bool("disabled"), False)


class TestCleanBanner(unittest.TestCase):
    def test_standard_banner(self):
        self.assertEqual(_clean_banner("SSH-2.0-OpenSSH_8.9p1"), "OpenSSH_8.9p1")

    def test_banner_with_distro(self):
        self.assertEqual(_clean_banner("SSH-2.0-OpenSSH_9.3p1 Ubuntu-3"), "OpenSSH_9.3p1")

    def test_banner_with_ansi(self):
        self.assertEqual(_clean_banner("\x1b[0mSSH-2.0-OpenSSH_10.3\x1b[0m"), "OpenSSH_10.3")

    def test_banner_no_match_returns_cleaned_input(self):
        result = _clean_banner("unknown banner format")
        self.assertEqual(result, "unknown banner format")

    def test_older_version(self):
        self.assertEqual(_clean_banner("SSH-1.99-OpenSSH_7.4"), "OpenSSH_7.4")


class TestNormSeverity(unittest.TestCase):
    def test_fail_to_high(self):
        self.assertEqual(_norm_severity("fail"), "high")

    def test_warn_to_medium(self):
        self.assertEqual(_norm_severity("warn"), "medium")

    def test_info_to_low(self):
        self.assertEqual(_norm_severity("info"), "low")

    def test_already_normalized(self):
        self.assertEqual(_norm_severity("critical"), "critical")
        self.assertEqual(_norm_severity("high"), "high")
        self.assertEqual(_norm_severity("medium"), "medium")
        self.assertEqual(_norm_severity("low"), "low")

    def test_case_insensitive(self):
        self.assertEqual(_norm_severity("FAIL"), "high")
        self.assertEqual(_norm_severity("WARN"), "medium")


class TestAnnotateAmbiguous(unittest.TestCase):
    def test_allow_tcp_forwarding_true_is_risky(self):
        result = _annotate_ambiguous("allow_tcp_forwarding", True)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["risk"], "medium")
        self.assertTrue(result["value"])

    def test_permit_root_login_true_is_critical(self):
        result = _annotate_ambiguous("permit_root_login", True)
        self.assertEqual(result["risk"], "critical")

    def test_permit_root_login_false_is_not_annotated(self):
        result = _annotate_ambiguous("permit_root_login", False)
        # False is not in the risky booleans for this key
        self.assertIs(result, False)

    def test_permit_open_any_is_medium(self):
        result = _annotate_ambiguous("permit_open", "any")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["value"], "any")
        self.assertEqual(result["risk"], "medium")

    def test_authentication_methods_any_is_high(self):
        result = _annotate_ambiguous("authentication_methods", "any")
        self.assertEqual(result["risk"], "high")

    def test_non_ambiguous_value_unchanged(self):
        self.assertEqual(_annotate_ambiguous("permit_open", "192.168.1.0/24"), "192.168.1.0/24")

    def test_unknown_key_unchanged(self):
        self.assertEqual(_annotate_ambiguous("unknown_key", "any"), "any")

    def test_strict_modes_false_is_high_risk(self):
        result = _annotate_ambiguous("strict_modes", False)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["risk"], "high")


class TestEnrichCryptoEntry(unittest.TestCase):
    def test_known_algo_gets_reason(self):
        entry = {"algorithm": "3des-cbc", "severity": "fail"}
        result = _enrich_crypto_entry(entry)
        self.assertIn("reason", result)
        self.assertIn("SWEET32", result["reason"])

    def test_severity_normalized(self):
        entry = {"algorithm": "hmac-sha1", "severity": "warn"}
        result = _enrich_crypto_entry(entry)
        self.assertEqual(result["severity"], "medium")

    def test_fail_severity(self):
        entry = {"algorithm": "ssh-rsa", "severity": "fail"}
        result = _enrich_crypto_entry(entry)
        self.assertEqual(result["severity"], "high")

    def test_unknown_algo_gets_default_reason(self):
        entry = {"algorithm": "hypothetical-algo", "severity": "warn"}
        result = _enrich_crypto_entry(entry)
        self.assertIn("reason", result)
        self.assertNotEqual(result["reason"], "")

    def test_output_schema(self):
        entry = {"algorithm": "aes128-cbc", "severity": "fail"}
        result = _enrich_crypto_entry(entry)
        self.assertIn("algorithm", result)
        self.assertIn("severity", result)
        self.assertIn("reason", result)


class TestEnrichVulnerability(unittest.TestCase):
    def test_known_cve_enriched(self):
        vuln = {"cve": "CVE-2023-48795", "description": "Terrapin attack"}
        result = _enrich_vulnerability(vuln, ["aes128-cbc", "chacha20-poly1305@openssh.com"])
        self.assertEqual(result["cve"], "CVE-2023-48795")
        self.assertEqual(result["name"], "Terrapin Attack")
        self.assertEqual(result["risk"], "high")
        # affected_algorithms is a list of plain algorithm name strings
        if result["affected_algorithms"]:
            self.assertIsInstance(result["affected_algorithms"][0], str)


    def test_known_cve_affected_algorithms_populated(self):
        vuln = {"cve": "CVE-2023-48795", "description": ""}
        result = _enrich_vulnerability(vuln, ["chacha20-poly1305@openssh.com", "aes128-cbc"])
        self.assertGreater(len(result["affected_algorithms"]), 0)

    def test_unknown_cve_fallback(self):
        vuln = {"cve": "CVE-9999-00000", "description": "Novel attack on SSH"}
        result = _enrich_vulnerability(vuln, [])
        self.assertEqual(result["cve"], "CVE-9999-00000")
        self.assertIsNotNone(result["name"])
        self.assertNotEqual(result["name"], "")
        self.assertIn("description", result)

    def test_output_schema_complete(self):
        vuln = {"cve": "CVE-2002-20001", "description": "DROWN"}
        result = _enrich_vulnerability(vuln, [])
        for key in ("cve", "name", "risk", "description", "affected_algorithms", "notes"):
            self.assertIn(key, result)

    def test_cve_uppercased(self):
        vuln = {"cve": "cve-2023-48795", "description": ""}
        result = _enrich_vulnerability(vuln, [])
        self.assertEqual(result["cve"], "CVE-2023-48795")


class TestToSnake(unittest.TestCase):
    def test_explicit_map_lookup(self):
        self.assertEqual(_to_snake("permitrootlogin"), "permit_root_login")
        self.assertEqual(_to_snake("passwordauthentication"), "password_authentication")
        self.assertEqual(_to_snake("maxauthtries"), "max_auth_tries")
        self.assertEqual(_to_snake("clientaliveinterval"), "client_alive_interval")
        self.assertEqual(_to_snake("x11forwarding"), "x11_forwarding")
        self.assertEqual(_to_snake("syslogfacility"), "syslog_facility")

    def test_already_correct_passthrough(self):
        self.assertEqual(_to_snake("algorithm"), "algorithm")
        self.assertEqual(_to_snake("severity"), "severity")

    def test_camel_case_auto_conversion(self):
        # Falls back to auto-conversion for unknown keys
        self.assertEqual(_to_snake("camelCaseKey"), "camel_case_key")


class TestDropEmpty(unittest.TestCase):
    def test_removes_none(self):
        self.assertIsNone(_drop_empty(None))

    def test_removes_empty_string(self):
        result = _drop_empty({"key": ""})
        self.assertIsNone(result)  # entire dict becomes None when all values are empty

    def test_removes_empty_list(self):
        result = _drop_empty({"key": []})
        self.assertIsNone(result)

    def test_preserves_false(self):
        result = _drop_empty({"enabled": False})
        self.assertIsNotNone(result)
        self.assertIs(result["enabled"], False)

    def test_preserves_zero(self):
        result = _drop_empty({"port": 0})
        self.assertIsNotNone(result)
        self.assertEqual(result["port"], 0)

    def test_nested_cleanup(self):
        result = _drop_empty({"outer": {"inner": ""}})
        self.assertIsNone(result)  # inner empties, outer empties, whole thing is None

    def test_list_filters_nones(self):
        result = _drop_empty([None, "value", "", None])
        self.assertEqual(result, ["value"])


class TestNormalizeProfile(unittest.TestCase):
    """Integration tests for the full normalize_profile() pipeline."""

    def setUp(self):
        import copy
        self.result = normalize_profile(copy.deepcopy(RAW_PROFILE))

    def test_output_is_json_serialisable(self):
        try:
            json.dumps(self.result)
        except (TypeError, ValueError) as exc:
            self.fail(f"normalize_profile output is not JSON-serialisable: {exc}")

    def test_top_level_keys_present(self):
        for key in ("ssh", "crypto", "vulnerabilities"):
            self.assertIn(key, self.result)

    # -- Step 1: ANSI --
    def test_ansi_stripped_from_strings(self):
        ansi_profile = {
            "ssh": {"version": "\x1b[33mOpenSSH 8.9\x1b[0m", "port": 22, "banner": ""},
            "crypto": {"weak_ciphers": [], "weak_macs": [], "weak_kex": [], "weak_host_keys": []},
            "vulnerabilities": [],
        }
        result = normalize_profile(ansi_profile)
        self.assertEqual(result["ssh"]["version"], "OpenSSH 8.9")

    # -- Step 2: Boolean normalization --
    def test_yes_converted_to_bool_true(self):
        # permitrootlogin: "yes" — but since it's risky, it becomes an annotated dict
        auth = self.result["ssh"]["authentication"]
        permit = auth["permit_root_login"]
        # Value must either be True or a risk-annotated dict with value=True
        if isinstance(permit, dict):
            self.assertTrue(permit["value"])
        else:
            self.assertIs(permit, True)

    def test_no_converted_to_bool_false(self):
        auth = self.result["ssh"]["authentication"]
        # permitemptypasswords: "no" → False (not risky when False, stays as False)
        self.assertIs(auth["permit_empty_passwords"], False)

    # -- Step 3: Ambiguous value annotation --
    def test_permitopen_any_annotated(self):
        fwd = self.result["ssh"]["forwarding"]
        self.assertIsInstance(fwd["permit_open"], dict)
        self.assertEqual(fwd["permit_open"]["value"], "any")
        self.assertIn("risk", fwd["permit_open"])

    def test_authentication_methods_any_is_high_risk(self):
        auth = self.result["ssh"]["authentication"]
        methods = auth["authentication_methods"]
        self.assertIsInstance(methods, dict)
        self.assertEqual(methods["risk"], "high")

    # -- Step 4: Banner cleaning --
    def test_banner_cleaned(self):
        banner = self.result["ssh"]["banner"]
        # Should be just the version token, not the full banner string
        self.assertNotIn("SSH-2.0-", banner)
        self.assertIn("OpenSSH", banner)

    # -- Step 5: Severity normalization --
    def test_severity_fail_becomes_high(self):
        ciphers = self.result["crypto"]["weak_ciphers"]
        for c in ciphers:
            if c["algorithm"] == "aes128-cbc":
                self.assertEqual(c["severity"], "high")

    def test_severity_warn_becomes_medium(self):
        kex = self.result["crypto"]["weak_kex"]
        for k in kex:
            if k["algorithm"] == "ecdh-sha2-nistp256":
                self.assertEqual(k["severity"], "medium")

    # -- Step 6: Vulnerability enrichment --
    def test_known_cve_has_name(self):
        cves = {v["cve"]: v for v in self.result["vulnerabilities"]}
        self.assertIn("CVE-2023-48795", cves)
        self.assertEqual(cves["CVE-2023-48795"]["name"], "Terrapin Attack")

    def test_vulnerability_has_full_schema(self):
        for vuln in self.result["vulnerabilities"]:
            for field in ("cve", "name", "risk", "description"):
                self.assertIn(field, vuln)

    def test_unknown_cve_still_has_name(self):
        cves = {v["cve"]: v for v in self.result["vulnerabilities"]}
        unk = cves.get("CVE-9999-00000")
        self.assertIsNotNone(unk)
        self.assertNotEqual(unk["name"], "")

    # -- Step 7: Crypto reasons --
    def test_crypto_entries_have_reason(self):
        for field in ("weak_ciphers", "weak_macs", "weak_kex", "weak_host_keys"):
            for entry in self.result["crypto"][field]:
                self.assertIn("reason", entry)
                self.assertNotEqual(entry["reason"], "")

    # -- Step 8: snake_case keys --
    def test_authentication_keys_snake_case(self):
        auth = self.result["ssh"]["authentication"]
        self.assertIn("permit_root_login", auth)
        self.assertIn("password_authentication", auth)
        self.assertIn("max_auth_tries", auth)
        self.assertNotIn("permitrootlogin", auth)

    def test_session_keys_snake_case(self):
        session = self.result["ssh"]["session"]
        self.assertIn("client_alive_interval", session)
        self.assertIn("client_alive_count_max", session)
        self.assertIn("login_grace_time", session)

    def test_forwarding_keys_snake_case(self):
        fwd = self.result["ssh"]["forwarding"]
        self.assertIn("allow_tcp_forwarding", fwd)
        self.assertIn("gateway_ports", fwd)

    def test_feature_keys_snake_case(self):
        feats = self.result["ssh"]["features"]
        self.assertIn("x11_forwarding", feats)
        self.assertIn("log_level", feats)
        self.assertIn("syslog_facility", feats)

    # -- Step 9: Empty field removal --
    def test_empty_string_fields_removed(self):
        flat = json.dumps(self.result)
        # No bare empty string values should appear in meaningful positions
        import re
        # Check no key maps to "" beyond what's structurally necessary
        self.assertNotIn('""', flat)


if __name__ == "__main__":
    unittest.main(verbosity=2)
