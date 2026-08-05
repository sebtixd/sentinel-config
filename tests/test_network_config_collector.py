"""
test_network_config_collector.py
=================================
Unit tests for collectors/network_config_collector.py

Mirrors the patterns of test_system_logging_collector.py and
test_auditd_collector.py — all external calls (subprocess, file I/O) are
mocked so the tests are fully hermetic and run without a live Linux system.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.network_config_collector import (
    _run_cmd,
    _read_file,
    _read_conf_dir,
    _collect_network_devices,
    _collect_kernel_modules,
    _collect_sysctl,
    _load_sysctl_conf_lines,
    collect_network_config,
    _SYSCTL_IPV4_KEYS,
    _SYSCTL_IPV6_KEYS,
    _NETWORK_MODULES,
)


# ---------------------------------------------------------------------------
# Helper-function unit tests
# ---------------------------------------------------------------------------

@mock.patch("subprocess.run")
def test_run_cmd_success(mock_run):
    mock_run.return_value = mock.Mock(stdout="output\n", stderr="", returncode=0)
    out, err, rc = _run_cmd(["echo", "output"])
    assert out == "output\n"
    assert rc == 0


@mock.patch("subprocess.run", side_effect=Exception("tool not found"))
def test_run_cmd_exception(mock_run):
    out, err, rc = _run_cmd(["nonexistent"])
    assert rc == -1
    assert "tool not found" in err


@mock.patch("builtins.open", mock.mock_open(read_data="key = value\n"))
def test_read_file_success():
    assert _read_file("/fake/path") == "key = value\n"


@mock.patch("builtins.open", side_effect=FileNotFoundError)
def test_read_file_missing(mock_open):
    assert _read_file("/nonexistent/path") is None


@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.listdir", return_value=["a.conf", "b.conf", "skip.txt"])
@mock.patch(
    "collectors.network_config_collector._read_file",
    return_value="contents",
)
def test_read_conf_dir(mock_rf, mock_ls, mock_exists):
    result = _read_conf_dir("/fake/dir", ".conf")
    assert len(result) == 2
    assert result[0]["path"] == "/fake/dir/a.conf"
    assert result[1]["content"] == "contents"


# ---------------------------------------------------------------------------
# 3.1 – Network devices
# ---------------------------------------------------------------------------

@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_network_devices_no_wireless_no_bt(mock_rf, mock_run):
    """No wireless, no Bluetooth — should return empty lists and False flags."""

    def side_run(cmd, timeout=10):
        if cmd[0] == "ip":
            return ("1: lo: <LOOPBACK> state UNKNOWN\n"
                    "2: eth0: <BROADCAST> state UP", "", 0)
        if cmd[0] == "nmcli":
            return ("DEVICE  TYPE      STATE\neth0    ethernet  connected", "", 0)
        if cmd[0] == "lsmod":
            return ("Module  Size  Used by\next4   1234  1\n", "", 0)
        if cmd[0] == "dpkg":
            return ("", "", 1)  # bluez not installed
        if cmd[0] == "systemctl":
            return ("inactive", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_run
    mock_rf.return_value = None  # no sysfs, no grub

    errors: list = []
    result = _collect_network_devices(errors)

    assert result["wireless_interfaces"]["any_wireless_found"] is False
    assert result["wireless_interfaces"]["wireless_devices_ip_link"] == []
    assert result["wireless_interfaces"]["loaded_wireless_kernel_modules"] == []
    assert result["bluetooth"]["bluez_installed"] is False


@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_network_devices_wireless_detected_ip_link(mock_rf, mock_run):
    """Wireless device visible in ip link output."""

    def side_run(cmd, timeout=10):
        if cmd[0] == "ip":
            return ("1: lo: <LOOPBACK>\n3: wlp2s0: <BROADCAST> state UP", "", 0)
        if cmd[0] == "nmcli":
            return ("", "", -1)  # nmcli not installed
        if cmd[0] == "lsmod":
            return ("cfg80211 1234 1\n", "", 0)
        if cmd[0] == "dpkg":
            return ("", "", 1)
        if cmd[0] == "systemctl":
            return ("inactive", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_run
    mock_rf.return_value = None

    errors: list = []
    result = _collect_network_devices(errors)

    wi = result["wireless_interfaces"]
    assert wi["any_wireless_found"] is True
    assert any(d["interface"] == "wlp2s0" for d in wi["wireless_devices_ip_link"])
    assert "cfg80211" in wi["loaded_wireless_kernel_modules"]


@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_network_devices_bluetooth_installed_and_active(mock_rf, mock_run):
    """Bluetooth package installed and service active."""

    def side_run(cmd, timeout=10):
        if cmd[0] == "ip":
            return ("1: lo: <LOOPBACK>\n2: eth0: state UP", "", 0)
        if cmd[0] == "nmcli":
            return ("DEVICE  TYPE      STATE\neth0    ethernet  connected", "", 0)
        if cmd[0] == "lsmod":
            return ("Module  Size\next4 1234\n", "", 0)
        if cmd[0] == "dpkg":
            return ("Status: install ok installed\nVersion: 5.66\n", "", 0)
        if cmd[0] == "systemctl":
            if "is-enabled" in cmd:
                return ("enabled", "", 0)
            return ("active", "", 0)
        return ("", "", 0)

    mock_run.side_effect = side_run
    mock_rf.return_value = None

    errors: list = []
    result = _collect_network_devices(errors)

    bt = result["bluetooth"]
    assert bt["bluez_installed"] is True
    assert bt["bluetooth_service_enabled"] == "enabled"
    assert bt["bluetooth_service_active"] == "active"


@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_ipv6_status_disabled_sysfs(mock_rf, mock_run):
    """IPv6 disabled via sysfs."""

    def side_run(cmd, timeout=10):
        # ip -6 addr show returns nothing (IPv6 disabled)
        return ("", "", 0)

    mock_run.side_effect = side_run

    def side_rf(path):
        if path == "/sys/module/ipv6/parameters/disable":
            return "1\n"
        if path == "/etc/default/grub":
            return 'GRUB_CMDLINE_LINUX="ipv6.disable=1 quiet"\n'
        return None

    mock_rf.side_effect = side_rf

    errors: list = []
    result = _collect_network_devices(errors)

    ipv6 = result["ipv6_status"]
    assert ipv6["sysfs_disable_value"] == "1"
    assert ipv6["grub_ipv6_disable_flag"] is True
    assert ipv6["inet6_address_count"] == 0


# ---------------------------------------------------------------------------
# 3.2 – Kernel modules
# ---------------------------------------------------------------------------

@mock.patch("os.path.exists", return_value=False)
@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_kernel_modules_not_loaded(mock_rf, mock_run, mock_exists):
    """All modules absent from lsmod, no modprobe.d config."""
    mock_run.return_value = ("Module  Size  Used by\next4 100 1\n", "", 0)
    mock_rf.return_value = None  # /etc/modprobe.conf
    mock_exists.return_value = False  # /etc/modprobe.d absent

    errors: list = []
    result = _collect_kernel_modules(errors)

    for mod in _NETWORK_MODULES:
        assert mod in result
        assert result[mod]["currently_loaded"] is False
        assert result[mod]["modprobe_config_lines"] == []


@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.listdir", return_value=["CIS.conf"])
@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_kernel_modules_blacklisted(mock_rf, mock_run, mock_listdir, mock_exists):
    """Modules are blacklisted and install-disabled in a modprobe.d file."""

    modprobe_content = "\n".join(
        f"install {m} /bin/false\nblacklist {m}" for m in _NETWORK_MODULES
    )

    def side_rf(path):
        if path == "/etc/modprobe.conf":
            return None
        # any .conf inside /etc/modprobe.d/
        return modprobe_content

    mock_rf.side_effect = side_rf
    # Simulate module NOT loaded (lsmod shows only unrelated modules)
    mock_run.return_value = ("Module  Size\next4 100\n", "", 0)

    errors: list = []
    result = _collect_kernel_modules(errors)

    for mod in _NETWORK_MODULES:
        assert result[mod]["currently_loaded"] is False
        lines = result[mod]["modprobe_config_lines"]
        line_texts = [l["line"].lower() for l in lines]
        assert any(f"install {mod}" in t for t in line_texts)
        assert any(f"blacklist {mod}" in t for t in line_texts)


@mock.patch("os.path.exists", return_value=True)
@mock.patch("os.listdir", return_value=[])
@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_kernel_modules_loaded(mock_rf, mock_run, mock_listdir, mock_exists):
    """A module that is currently loaded."""
    mock_run.return_value = ("sctp  12345  0\next4 100 1\n", "", 0)
    mock_rf.return_value = None

    errors: list = []
    result = _collect_kernel_modules(errors)

    assert result["sctp"]["currently_loaded"] is True
    # Other modules should still be unloaded
    assert result["dccp"]["currently_loaded"] is False


# ---------------------------------------------------------------------------
# 3.3 – sysctl (IPv4 and IPv6)
# ---------------------------------------------------------------------------

def test_load_sysctl_conf_lines_no_files():
    """Gracefully returns [] when no sysctl config files exist."""
    with (
        mock.patch("collectors.network_config_collector._read_file", return_value=None),
        mock.patch("os.path.exists", return_value=False),
    ):
        errors: list = []
        lines = _load_sysctl_conf_lines(errors)
        assert lines == []
        assert errors == []


def test_load_sysctl_conf_lines_reads_main_and_d():
    """Combines /etc/sysctl.conf with entries from /etc/sysctl.d/."""
    main_content = "net.ipv4.ip_forward = 1\n# comment\n"
    d_content = "net.ipv4.tcp_syncookies = 1\n"

    def side_rf(path):
        if path == "/etc/sysctl.conf":
            return main_content
        return d_content  # any sysctl.d file

    with (
        mock.patch("collectors.network_config_collector._read_file", side_effect=side_rf),
        mock.patch("os.path.exists", return_value=True),
        mock.patch("os.listdir", return_value=["99-cis.conf"]),
    ):
        errors: list = []
        lines = _load_sysctl_conf_lines(errors)

    paths = [p for p, _ in lines]
    assert "/etc/sysctl.conf" in paths
    assert any("sysctl.d" in p for p in paths)


@mock.patch("collectors.network_config_collector._run_cmd")
def test_sysctl_runtime_and_persisted(mock_run):
    """Each sysctl key has both runtime_value and persisted_value fields."""

    def side_run(cmd, timeout=10):
        # sysctl -n <key> returns "0" for all keys
        return ("0", "", 0)

    mock_run.side_effect = side_run

    # Build a fake persisted config with a known value for one key
    conf_lines = [
        ("/etc/sysctl.conf", "net.ipv4.ip_forward = 0"),
        ("/etc/sysctl.d/99-cis.conf", "net.ipv4.tcp_syncookies = 1"),
    ]

    result = _collect_sysctl(_SYSCTL_IPV4_KEYS, conf_lines)

    for key in _SYSCTL_IPV4_KEYS:
        assert key in result
        entry = result[key]
        assert "runtime_value" in entry
        assert "persisted_value" in entry
        assert "persisted_config_source_file" in entry
        assert entry["runtime_value"] == "0"

    # Check specific persisted values were correctly resolved
    assert result["net.ipv4.ip_forward"]["persisted_value"] == "0"
    assert result["net.ipv4.ip_forward"]["persisted_config_source_file"] == "/etc/sysctl.conf"
    assert result["net.ipv4.tcp_syncookies"]["persisted_value"] == "1"
    assert result["net.ipv4.tcp_syncookies"]["persisted_config_source_file"] == "/etc/sysctl.d/99-cis.conf"


@mock.patch("collectors.network_config_collector._run_cmd")
def test_sysctl_missing_key_returns_null(mock_run):
    """If sysctl returns non-zero, runtime_value is None (not a crash)."""
    mock_run.return_value = ("", "sysctl: cannot stat /proc/sys/net/ipv4/ip_forward: No such file", 255)

    result = _collect_sysctl(["net.ipv4.ip_forward"], [])
    assert result["net.ipv4.ip_forward"]["runtime_value"] is None


@mock.patch("collectors.network_config_collector._run_cmd")
def test_sysctl_no_persisted_returns_null(mock_run):
    """If a key is not in any config file, persisted_value is None."""
    mock_run.return_value = ("1", "", 0)  # runtime present

    result = _collect_sysctl(["net.ipv4.tcp_syncookies"], [])
    assert result["net.ipv4.tcp_syncookies"]["runtime_value"] == "1"
    assert result["net.ipv4.tcp_syncookies"]["persisted_value"] is None
    assert result["net.ipv4.tcp_syncookies"]["persisted_config_source_file"] is None


# ---------------------------------------------------------------------------
# Top-level collect_network_config — structural / integration test
# ---------------------------------------------------------------------------

@mock.patch("os.path.exists", return_value=False)
@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_collect_network_config_schema(mock_rf, mock_run, mock_exists):
    """Top-level function returns the expected JSON schema keys."""
    mock_run.return_value = ("", "", 0)
    mock_rf.return_value = None

    result = collect_network_config()

    assert "network_config" in result
    nc = result["network_config"]
    assert "network_devices" in nc
    assert "kernel_modules" in nc
    assert "sysctl_ipv4" in nc
    assert "sysctl_ipv6" in nc
    assert "errors" in nc

    # network_devices sub-keys
    nd = nc["network_devices"]
    assert "ipv6_status" in nd
    assert "wireless_interfaces" in nd
    assert "bluetooth" in nd

    # All target IPv4 sysctl keys present
    for key in _SYSCTL_IPV4_KEYS:
        assert key in nc["sysctl_ipv4"]

    # All target IPv6 sysctl keys present
    for key in _SYSCTL_IPV6_KEYS:
        assert key in nc["sysctl_ipv6"]

    # All network module names present
    for mod in _NETWORK_MODULES:
        assert mod in nc["kernel_modules"]
        m = nc["kernel_modules"][mod]
        assert "module_name" in m
        assert "currently_loaded" in m
        assert "modprobe_config_lines" in m


@mock.patch("os.path.exists", return_value=False)
@mock.patch("collectors.network_config_collector._run_cmd")
@mock.patch("collectors.network_config_collector._read_file")
def test_collect_network_config_json_serializable(mock_rf, mock_run, mock_exists):
    """Output must be JSON-serializable (no sets, datetimes, etc.)."""
    mock_run.return_value = ("", "", 0)
    mock_rf.return_value = None

    result = collect_network_config()
    # Should not raise
    dumped = json.dumps(result)
    assert "network_config" in dumped
