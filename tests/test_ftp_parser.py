"""
test_ftp_parser.py
===================
Unit tests for ftp_parser.py
"""

import unittest
import json
from tools.ftp_parser import (
    parse_systemctl,
    parse_network_listeners,
    parse_vsftpd_conf,
    parse_firewall,
    parse_activity,
    parse_ftp_data
)

class TestFtpParser(unittest.TestCase):

    def test_parse_systemctl_vsftpd(self):
        raw = """
● vsftpd.service - vsftpd FTP server
     Loaded: loaded (/lib/systemd/system/vsftpd.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2026-06-23 15:06:05 UTC; 1h ago
        """
        result = parse_systemctl(raw)
        self.assertEqual(result["name"], "vsftpd")
        self.assertEqual(result["installed"], "true")
        self.assertEqual(result["enabled"], "true")
        self.assertEqual(result["running"], "true")

    def test_parse_network_listeners(self):
        raw = "tcp LISTEN 0 32 *:21 *:* users:((\"vsftpd\",pid=1234,fd=3))"
        result = parse_network_listeners(raw)
        self.assertEqual(result["port_open"], "true")
        self.assertIn("all", result["listening_interfaces"])

    def test_parse_vsftpd_conf(self):
        raw = """
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
ssl_enable=YES
        """
        result = parse_vsftpd_conf(raw)
        self.assertEqual(result["anonymous_enable"], "false")
        self.assertEqual(result["local_enable"], "true")
        self.assertEqual(result["ssl_enabled"], "true")

    def test_parse_firewall_ufw(self):
        raw = "Status: active\n21/tcp ALLOW Anywhere"
        result = parse_firewall(raw)
        self.assertEqual(result["type"], "ufw")
        self.assertEqual(result["port_21_blocked"], "false")

    def test_parse_activity_count(self):
        raw = "ESTAB 0 0 192.168.1.1:21 192.168.1.2:54321"
        self.assertEqual(parse_activity(raw), 1)

    def test_parse_ftp_data_integration(self):
        result = parse_ftp_data(
            systemctl_raw="Active: active (running)\nvsftpd",
            network_raw="LISTEN 0.0.0.0:21",
            config_raw="anonymous_enable=YES"
        )
        ftp = result["ftp"]
        self.assertEqual(ftp["service"]["running"], "true")
        self.assertEqual(ftp["configuration"]["anonymous_enable"], "true")

    def test_parse_vsftpd_conf_commented(self):
        raw = """
        anonymous_enable=NO
        #local_enable=YES
        write_enable=YES
        """
        result = parse_vsftpd_conf(raw)
        self.assertEqual(result.get("anonymous_enable"), "false")
        # local_enable is commented out, so it should not be in the parse result at all,
        # allowing the top-level default to persist.
        self.assertNotIn("local_enable", result)
        self.assertEqual(result.get("write_enable"), "true")

    def test_parse_ftp_data_detection_fallback(self):
        # Even without service name, 'chroot_local_user' should trigger vsftpd parser
        result = parse_ftp_data(
            config_raw="chroot_local_user=YES\nanonymous_enable=NO"
        )
        ftp = result["ftp"]
        self.assertEqual(ftp["configuration"]["chroot_local_user"], "true")
        self.assertEqual(ftp["configuration"]["anonymous_enable"], "false")

    def test_parse_firewall_ufw_default_deny(self):
        raw = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
"""
        result = parse_firewall(raw)
        self.assertEqual(result["type"], "ufw")
        # No port 21 rule, should follow default deny
        self.assertEqual(result["port_21_blocked"], "true")

if __name__ == "__main__":
    unittest.main()
