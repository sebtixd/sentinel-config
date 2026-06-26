"""
test_telnet_parser.py
======================
Unit tests for telnet_parser.py
"""

import unittest
import json
from tools.telnet_parser import (
    parse_systemctl,
    parse_package_manager,
    parse_network_listeners,
    parse_inetd_conf,
    parse_xinetd_conf,
    parse_firewall,
    parse_sessions,
    parse_telnet_data
)

class TestTelnetParser(unittest.TestCase):

    def test_parse_systemctl_active_running(self):
        raw = """
● telnet.service - Telnet Server
     Loaded: loaded (/lib/systemd/system/telnet.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2026-06-23 13:46:42 UTC; 1h 2min ago
   Main PID: 1234 (telnetd)
        """
        result = parse_systemctl(raw)
        self.assertEqual(result["installed"], "true")
        self.assertEqual(result["enabled"], "true")
        self.assertEqual(result["running"], "true")

    def test_parse_systemctl_socket_listening(self):
        raw = """
● telnet.socket - Telnet Server Activation Socket
     Loaded: loaded (/usr/lib/systemd/system/telnet.socket; enabled; preset: disabled)
     Active: active (listening) since Thu 2026-06-25 22:23:09 CET; 3min 0s ago
        """
        result = parse_systemctl(raw)
        self.assertEqual(result["installed"], "true")
        self.assertEqual(result["enabled"], "true")
        self.assertEqual(result["running"], "true")

    def test_parse_systemctl_not_found(self):
        raw = "Unit telnet.service could not be found."
        result = parse_systemctl(raw)
        self.assertEqual(result["installed"], "false")
        self.assertEqual(result["enabled"], "false")
        self.assertEqual(result["running"], "false")

    def test_parse_package_dpkg_installed(self):
        raw = "ii  telnetd                0.17-44               amd64        Telnet server"
        self.assertEqual(parse_package_manager(raw), "true")

    def test_parse_package_rpm_not_installed(self):
        raw = "package telnet is not installed"
        self.assertEqual(parse_package_manager(raw), "false")

    def test_parse_network_ss_open(self):
        raw = """
Netid State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
tcp   LISTEN     0      128    0.0.0.0:23                       0.0.0.0:*                   users:(("telnetd",pid=1234,fd=3))
        """
        result = parse_network_listeners(raw)
        self.assertEqual(result["port_open"], "true")
        self.assertIn("all", result["listening_interfaces"])
        self.assertIn("0.0.0.0:23", result["raw_bind_addresses"])

    def test_parse_inetd_enabled(self):
        raw = "telnet          stream  tcp     nowait  root    /usr/sbin/tcpd  /usr/sbin/in.telnetd"
        self.assertEqual(parse_inetd_conf(raw), "true")

    def test_parse_inetd_commented(self):
        raw = "#telnet          stream  tcp     nowait  root    /usr/sbin/tcpd  /usr/sbin/in.telnetd"
        self.assertEqual(parse_inetd_conf(raw), "false")

    def test_parse_xinetd_disabled(self):
        raw = """
service telnet
{
    disable = yes
    flags           = REUSE
    socket_type     = stream
}
        """
        self.assertEqual(parse_xinetd_conf(raw), "false")

    def test_parse_firewall_ufw_blocked(self):
        raw = """
Status: active
To                         Action      From
--                         ------      ----
23/tcp                     DENY        Anywhere
        """
        result = parse_firewall(raw)
        self.assertEqual(result["type"], "ufw")
        self.assertEqual(result["port_23_blocked"], "true")

    def test_parse_sessions_count(self):
        raw = """
sebtixd  pts/0        2026-06-23 13:46 (telnet)
other    pts/1        2026-06-23 14:00 (ssh)
        """
        self.assertEqual(parse_sessions(raw), 1)

    def test_parse_telnet_data_integration(self):
        result = parse_telnet_data(
            systemctl_raw="Active: active (running)\nLoaded: loaded (...; enabled; ...)",
            network_raw="LISTEN 0.0.0.0:23",
            firewall_raw="Status: active\n23/tcp ALLOW Anywhere"
        )

        t = result["telnet"]
        self.assertEqual(t["service"]["running"], "true")
        self.assertEqual(t["network"]["port_open"], "true")
        self.assertEqual(t["firewall"]["port_23_blocked"], "false")

    def test_parse_firewall_iptables_default_drop(self):
        # Sample iptables -L -n -v output
        raw = """Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0           
"""
        result = parse_firewall(raw)
        self.assertEqual(result["type"], "iptables")
        # No port 23 rule, should follow default DROP
        self.assertEqual(result["port_23_blocked"], "true")

if __name__ == "__main__":
    unittest.main()
