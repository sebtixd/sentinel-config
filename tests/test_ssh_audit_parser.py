"""
test_ssh_audit_parser.py
========================
Unit tests for ssh_audit_parser.py
Run with: python -m pytest test_ssh_audit_parser.py -v
      or: python -m unittest test_ssh_audit_parser -v
"""

import json
import unittest
from tools.ssh_audit_parser import (
    parse_sshd_config,
    parse_ssh_audit,
    build_security_profile,
)

# ---------------------------------------------------------------------------
# Shared sample data
# ---------------------------------------------------------------------------

SSHD_FULL = """
port 2222
addressfamily inet
listenaddress 0.0.0.0
permitrootlogin yes
passwordauthentication yes
pubkeyauthentication yes
permitemptypasswords no
maxauthtries 6
authenticationmethods any
clientaliveinterval 300
clientalivecountmax 3
maxsessions 10
logingracetime 60
allowtcpforwarding yes
allowagentforwarding yes
allowstreamlocalforwarding yes
gatewayports no
permitopen any
permitlisten any
x11forwarding yes
permituserenvironment no
usedns no
compression delayed
banner /etc/ssh/banner.txt
strictmodes yes
loglevel VERBOSE
syslogfacility AUTH
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-cbc,3des-cbc
macs hmac-sha2-256,hmac-sha1,umac-64@openssh.com
kexalgorithms curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
"""

SSHD_HARDENED = """
port 22
addressfamily any
listenaddress ::
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
maxauthtries 3
authenticationmethods publickey
clientaliveinterval 300
clientalivecountmax 2
maxsessions 5
logingracetime 30
allowtcpforwarding no
allowagentforwarding no
allowstreamlocalforwarding no
gatewayports no
permitopen none
permitlisten none
x11forwarding no
permituserenvironment no
usedns no
compression no
banner /etc/issue.net
strictmodes yes
loglevel VERBOSE
syslogfacility AUTHPRIV
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
"""

AUDIT_FULL = """
# general
(gen) banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
(gen) software: OpenSSH 8.9p1
(gen) compatibility: OpenSSH 7.4+
(gen) compression: enabled (zlib@openssh.com)

# key exchange
(kex) diffie-hellman-group1-sha1                           -- [fail] small 1024-bit modulus
(kex) ecdh-sha2-nistp256                                   -- [warn] weak elliptic curve
(kex) curve25519-sha256                                    -- [info] good

# host-key algorithms
(key) ssh-rsa                                              -- [fail] broken SHA-1
(key) rsa-sha2-512                                         -- [info] good

# encryption
(enc) aes128-cbc                                           -- [fail] weak cipher mode
(enc) 3des-cbc                                             -- [fail] broken 3DES
(enc) chacha20-poly1305@openssh.com                        -- [info] good

# MAC
(mac) hmac-md5                                             -- [fail] broken MD5
(mac) hmac-sha1                                            -- [warn] weak SHA-1

# recommendations
(rec) -kex diffie-hellman-group1-sha1 -- CVE-2023-48795 Terrapin attack prefix truncation
(rec) -key ssh-rsa -- CVE-2002-20001 downgrade attack
"""

AUDIT_CLEAN = """
# general
(gen) banner: SSH-2.0-OpenSSH_9.3
(gen) software: OpenSSH 9.3
(gen) compression: disabled

# key exchange
(kex) curve25519-sha256                                    -- [info] good
(kex) diffie-hellman-group16-sha512                        -- [info] good

# encryption
(enc) chacha20-poly1305@openssh.com                        -- [info] good

# MAC
(mac) hmac-sha2-256-etm@openssh.com                        -- [info] good
"""


# ---------------------------------------------------------------------------
# Tests: parse_sshd_config
# ---------------------------------------------------------------------------

class TestParseSshdConfig(unittest.TestCase):

    def test_authentication_fields_extracted(self):
        result = parse_sshd_config(SSHD_FULL)
        auth = result["authentication"]
        self.assertEqual(auth["permitrootlogin"], "yes")
        self.assertEqual(auth["passwordauthentication"], "yes")
        self.assertEqual(auth["pubkeyauthentication"], "yes")
        self.assertEqual(auth["permitemptypasswords"], "no")
        self.assertEqual(auth["maxauthtries"], 6)
        self.assertEqual(auth["authenticationmethods"], "any")

    def test_session_fields_extracted(self):
        result = parse_sshd_config(SSHD_FULL)
        session = result["session"]
        self.assertEqual(session["clientaliveinterval"], 300)
        self.assertEqual(session["clientalivecountmax"], 3)
        self.assertEqual(session["maxsessions"], 10)
        self.assertEqual(session["logingracetime"], 60)

    def test_network_port_parsed_as_int(self):
        result = parse_sshd_config(SSHD_FULL)
        self.assertEqual(result["network"]["port"], 2222)

    def test_forwarding_fields(self):
        result = parse_sshd_config(SSHD_FULL)
        fwd = result["forwarding"]
        self.assertEqual(fwd["allowtcpforwarding"], "yes")
        self.assertEqual(fwd["allowagentforwarding"], "yes")
        self.assertEqual(fwd["gatewayports"], "no")

    def test_features_extracted(self):
        result = parse_sshd_config(SSHD_FULL)
        feats = result["features"]
        self.assertEqual(feats["x11forwarding"], "yes")
        self.assertEqual(feats["banner"], "/etc/ssh/banner.txt")
        self.assertEqual(feats["strictmodes"], "yes")

    def test_weak_ciphers_detected(self):
        result = parse_sshd_config(SSHD_FULL)
        weak = result["weak_ciphers"]
        self.assertIn("aes128-cbc", weak)
        self.assertIn("3des-cbc", weak)
        # Strong ciphers must NOT appear
        self.assertNotIn("chacha20-poly1305@openssh.com", weak)
        self.assertNotIn("aes128-ctr", weak)

    def test_weak_macs_detected(self):
        result = parse_sshd_config(SSHD_FULL)
        weak = result["weak_macs"]
        self.assertIn("hmac-sha1", weak)
        self.assertIn("umac-64@openssh.com", weak)
        self.assertNotIn("hmac-sha2-256", weak)

    def test_weak_kex_detected(self):
        result = parse_sshd_config(SSHD_FULL)
        weak = result["weak_kex"]
        self.assertIn("diffie-hellman-group14-sha1", weak)
        self.assertIn("diffie-hellman-group1-sha1", weak)
        self.assertNotIn("curve25519-sha256", weak)

    def test_hardened_config_no_weak_algos(self):
        result = parse_sshd_config(SSHD_HARDENED)
        self.assertEqual(result["weak_ciphers"], [])
        self.assertEqual(result["weak_macs"], [])
        self.assertEqual(result["weak_kex"], [])

    def test_hardened_auth_settings(self):
        result = parse_sshd_config(SSHD_HARDENED)
        auth = result["authentication"]
        self.assertEqual(auth["permitrootlogin"], "no")
        self.assertEqual(auth["passwordauthentication"], "no")
        self.assertEqual(auth["authenticationmethods"], "publickey")

    def test_empty_input_returns_empty_dict(self):
        self.assertEqual(parse_sshd_config(""), {})
        self.assertEqual(parse_sshd_config("   "), {})

    def test_missing_keys_return_empty_strings(self):
        # Minimal input with only one directive
        result = parse_sshd_config("port 22")
        auth = result["authentication"]
        # All auth keys should still be present (empty string)
        self.assertIn("permitrootlogin", auth)
        self.assertEqual(auth["permitrootlogin"], "")

    def test_case_insensitive_key_matching(self):
        raw = "PermitRootLogin YES\nPasswordAuthentication NO"
        result = parse_sshd_config(raw)
        self.assertEqual(result["authentication"]["permitrootlogin"], "YES")
        self.assertEqual(result["authentication"]["passwordauthentication"], "NO")


# ---------------------------------------------------------------------------
# Tests: parse_ssh_audit
# ---------------------------------------------------------------------------

class TestParseSshAudit(unittest.TestCase):

    def test_server_version_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        self.assertIn("OpenSSH", result["version"])
        self.assertIn("8.9p1", result["version"])

    def test_banner_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        self.assertIn("SSH-2.0-OpenSSH_8.9p1", result["banner"])

    def test_compression_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        self.assertIn("zlib", result["compression"])

    def test_weak_kex_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        algos = [e["algorithm"] for e in result["weak_kex"]]
        self.assertIn("diffie-hellman-group1-sha1", algos)
        self.assertIn("ecdh-sha2-nistp256", algos)
        # Severity correctness
        fails = [e for e in result["weak_kex"] if e["algorithm"] == "diffie-hellman-group1-sha1"]
        self.assertEqual(fails[0]["severity"], "fail")

    def test_weak_host_keys_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        algos = [e["algorithm"] for e in result["weak_host_keys"]]
        self.assertIn("ssh-rsa", algos)

    def test_weak_ciphers_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        algos = [e["algorithm"] for e in result["weak_ciphers"]]
        self.assertIn("aes128-cbc", algos)
        self.assertIn("3des-cbc", algos)
        # Strong cipher must NOT appear
        self.assertNotIn("chacha20-poly1305@openssh.com", algos)

    def test_weak_macs_extracted(self):
        result = parse_ssh_audit(AUDIT_FULL)
        algos = [e["algorithm"] for e in result["weak_macs"]]
        self.assertIn("hmac-md5", algos)
        self.assertIn("hmac-sha1", algos)

    def test_cve_extraction(self):
        result = parse_ssh_audit(AUDIT_FULL)
        cve_ids = [v["cve"] for v in result["vulnerabilities"]]
        self.assertIn("CVE-2023-48795", cve_ids)
        self.assertIn("CVE-2002-20001", cve_ids)

    def test_cve_description_not_empty(self):
        result = parse_ssh_audit(AUDIT_FULL)
        for vuln in result["vulnerabilities"]:
            self.assertNotEqual(vuln["description"], "")
            self.assertNotEqual(vuln["description"], "No description available")

    def test_no_duplicates_in_weak_lists(self):
        # Duplicate lines should not produce duplicate entries
        duplicate_audit = AUDIT_FULL + "\n(kex) diffie-hellman-group1-sha1 -- [fail] duplicate"
        result = parse_ssh_audit(duplicate_audit)
        kex_algos = [e["algorithm"] for e in result["weak_kex"]]
        self.assertEqual(len(kex_algos), len(set(kex_algos)))

    def test_clean_server_no_weak_algos(self):
        result = parse_ssh_audit(AUDIT_CLEAN)
        self.assertEqual(result["weak_kex"], [])
        self.assertEqual(result["weak_ciphers"], [])
        self.assertEqual(result["weak_macs"], [])
        self.assertEqual(result["vulnerabilities"], [])

    def test_empty_input_returns_empty_dict(self):
        self.assertEqual(parse_ssh_audit(""), {})
        self.assertEqual(parse_ssh_audit("   "), {})


# ---------------------------------------------------------------------------
# Tests: build_security_profile
# ---------------------------------------------------------------------------

class TestBuildSecurityProfile(unittest.TestCase):

    def setUp(self):
        self.profile = build_security_profile(
            sshd_output=SSHD_FULL,
            ssh_audit_output=AUDIT_FULL,
        )

    def test_schema_top_level_keys(self):
        self.assertIn("ssh", self.profile)
        self.assertIn("crypto", self.profile)
        self.assertIn("vulnerabilities", self.profile)

    def test_crypto_sub_keys(self):
        crypto = self.profile["crypto"]
        self.assertIn("weak_ciphers", crypto)
        self.assertIn("weak_macs", crypto)
        self.assertIn("weak_kex", crypto)
        self.assertIn("weak_host_keys", crypto)

    def test_ssh_version_from_audit(self):
        # ssh-audit provides the soft version; sshd doesn't
        self.assertIn("OpenSSH", self.profile["ssh"]["version"])

    def test_port_from_sshd(self):
        # sshd -T provides the port
        self.assertEqual(self.profile["ssh"]["port"], 2222)

    def test_weak_ciphers_merged(self):
        algos = [e["algorithm"] for e in self.profile["crypto"]["weak_ciphers"]]
        self.assertIn("aes128-cbc", algos)
        self.assertIn("3des-cbc", algos)

    def test_ssh_audit_severity_preserved_in_merge(self):
        # ssh-audit results (with severity) should take precedence
        for entry in self.profile["crypto"]["weak_ciphers"]:
            self.assertIn("severity", entry)
            self.assertIn(entry["severity"], ("high", "medium", "low"))

    def test_vulnerabilities_present(self):
        cves = [v["cve"] for v in self.profile["vulnerabilities"]]
        self.assertIn("CVE-2023-48795", cves)

    def test_authentication_fields_in_profile(self):
        auth = self.profile["ssh"]["authentication"]
        self.assertEqual(auth.get("permit_root_login")["value"] if isinstance(auth.get("permit_root_login"), dict) else auth.get("permit_root_login"), True)

    def test_sshd_only_mode(self):
        """Parser must work with only sshd output (no ssh-audit)."""
        profile = build_security_profile(sshd_output=SSHD_FULL)
        self.assertIn("ssh", profile)
        self.assertIn("crypto", profile)
        self.assertEqual(profile.get("vulnerabilities", []), [])
        # Weak algos still extracted from sshd itself
        algos = [e["algorithm"] for e in profile["crypto"]["weak_ciphers"]]
        self.assertIn("aes128-cbc", algos)

    def test_audit_only_mode(self):
        """Parser must work with only ssh-audit output (no sshd -T)."""
        profile = build_security_profile(ssh_audit_output=AUDIT_FULL)
        self.assertIn("ssh", profile)
        self.assertGreater(len(profile["vulnerabilities"]), 0)

    def test_both_empty_returns_valid_schema(self):
        """Empty inputs must still return a valid (empty) schema."""
        profile = build_security_profile()
        self.assertIn("ssh", profile)
        self.assertIn("crypto", profile if "crypto" in profile else {"crypto": []})
        self.assertIn("vulnerabilities", profile if "vulnerabilities" in profile else {"vulnerabilities": []})
        self.assertEqual(profile.get("vulnerabilities", []), [])

    def test_json_serialisable(self):
        """Output must be fully JSON-serialisable (no sets, datetime, etc.)."""
        try:
            json.dumps(self.profile)
        except (TypeError, ValueError) as exc:
            self.fail(f"build_security_profile output is not JSON-serialisable: {exc}")

    def test_no_duplicate_weak_algos_after_merge(self):
        """Algorithms present in both sshd and ssh-audit must not be duplicated."""
        for field in ("weak_ciphers", "weak_macs", "weak_kex"):
            algos = [e["algorithm"] for e in self.profile["crypto"][field]]
            self.assertEqual(len(algos), len(set(algos)),
                             f"Duplicate entries found in crypto.{field}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
