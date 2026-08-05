"""
test_services_collector.py
===========================
Unit tests for collectors/services_collector.py

Hermetic tests with mocked subprocess and file reads.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from collectors.services_collector import (
    _dpkg_installed,
    _systemctl_state,
    _check_service,
    _collect_mta,
    _collect_listening_sockets,
    _check_x_window_server,
    collect_services,
)


@mock.patch("collectors.services_collector._run_cmd")
def test_dpkg_installed_true(mock_run):
    mock_run.return_value = ("Status: install ok installed\n", "", 0)
    assert _dpkg_installed("vsftpd") is True


@mock.patch("collectors.services_collector._run_cmd")
def test_dpkg_installed_false(mock_run):
    mock_run.return_value = ("package 'vsftpd' is not installed and no information is available\n", "", 1)
    assert _dpkg_installed("vsftpd") is False


@mock.patch("collectors.services_collector._run_cmd")
def test_systemctl_state(mock_run):
    mock_run.side_effect = [
        ("disabled\n", "", 0),
        ("inactive\n", "", 0),
    ]
    state = _systemctl_state("autofs.service")
    assert state["enabled"] == "disabled"
    assert state["active"] == "inactive"


@mock.patch("collectors.services_collector._systemctl_state")
@mock.patch("collectors.services_collector._dpkg_installed")
def test_check_service_not_installed(mock_dpkg, mock_svc):
    mock_dpkg.return_value = False
    mock_svc.return_value = {"unit": "autofs.service", "enabled": "disabled", "active": "inactive"}

    entry = _check_service("autofs", "2.1.1", ["autofs"], ["autofs.service"])
    assert entry["cis_rule"] == "2.1.1"
    assert entry["any_package_installed"] is False
    assert entry["any_unit_active"] is False


@mock.patch("collectors.services_collector._systemctl_state")
@mock.patch("collectors.services_collector._dpkg_installed")
def test_check_service_installed(mock_dpkg, mock_svc):
    mock_dpkg.return_value = True
    mock_svc.return_value = {"unit": "nginx.service", "enabled": "enabled", "active": "active"}

    entry = _check_service("web_server", "2.1.6", ["nginx"], ["nginx.service"])
    assert entry["any_package_installed"] is True
    assert entry["any_unit_active"] is True


@mock.patch("collectors.services_collector._systemctl_state")
@mock.patch("collectors.services_collector._run_cmd")
@mock.patch("collectors.services_collector._read_file")
@mock.patch("collectors.services_collector._dpkg_installed")
def test_collect_mta_postfix(mock_dpkg, mock_rf, mock_run, mock_svc):
    mock_dpkg.side_effect = lambda pkg: pkg == "postfix"
    mock_run.return_value = ("inet_interfaces = loopback-only\n", "", 0)
    mock_svc.return_value = {"unit": "postfix", "enabled": "enabled", "active": "active"}

    res = _collect_mta()
    assert res["mta_detected"] == "postfix"
    assert res["postfix_inet_interfaces"] == "inet_interfaces = loopback-only"


@mock.patch("collectors.services_collector._run_cmd")
def test_collect_listening_sockets(mock_run):
    mock_run.return_value = (
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        "tcp   LISTEN 0     128   0.0.0.0:22       0.0.0.0:*       users:((\"sshd\",pid=1234,fd=3))\n",
        "",
        0,
    )
    sockets = _collect_listening_sockets()
    assert len(sockets) == 1
    assert sockets[0]["protocol"] == "tcp"


@mock.patch("collectors.services_collector._systemctl_state")
@mock.patch("collectors.services_collector._dpkg_installed")
@mock.patch("collectors.services_collector._run_cmd")
def test_check_x_window_server(mock_run, mock_dpkg, mock_svc):
    mock_dpkg.return_value = False
    mock_run.return_value = ("", "", 1)  # pgrep returns nonzero when none found
    mock_svc.return_value = {"unit": "xdm", "enabled": "not-found", "active": "inactive"}

    entry = _check_x_window_server()
    assert entry["cis_rule"] == "2.1.23"
    assert entry["any_package_installed"] is False
    assert entry["xorg_process_running"] is False


@mock.patch("collectors.services_collector._check_x_window_server")
@mock.patch("collectors.services_collector._collect_mta")
@mock.patch("collectors.services_collector._collect_listening_sockets")
@mock.patch("collectors.services_collector._check_service")
@mock.patch("collectors.services_collector._dpkg_installed")
def test_collect_services_top_level(mock_dpkg, mock_svc, mock_sockets, mock_mta, mock_xwin):
    mock_dpkg.return_value = False
    mock_svc.return_value = {
        "cis_rule": "2.1.1", "service_name": "autofs",
        "packages_status": [], "any_package_installed": False,
        "units_status": [], "any_unit_active": False,
    }
    mock_sockets.return_value = []
    mock_mta.return_value = {"cis_rule": "2.1.2", "service_name": "mail_transfer_agent", "mta_detected": "none"}
    mock_xwin.return_value = {"cis_rule": "2.1.23", "service_name": "x_window_server"}

    res = collect_services()
    assert "services" in res
    svc = res["services"]
    assert "server_services" in svc
    assert "client_services" in svc
    assert "listening_sockets_raw" in svc

    json_str = json.dumps(res)
    assert "server_services" in json_str
    assert "client_services" in json_str
