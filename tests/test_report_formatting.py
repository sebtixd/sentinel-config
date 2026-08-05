"""
test_report_formatting.py
==========================
Unit tests for tools/report.py report formatting and newline spacing functions.
"""

from __future__ import annotations

import pytest
from tools.report import format_report_spacing, parse_compliance_stats


def test_format_report_spacing_empty():
    assert format_report_spacing("") == ""
    assert format_report_spacing(None) == None


def test_format_report_spacing_headers_and_rules():
    unformatted = (
        "## Section 3 – Network Configuration\n"
        "### Rule 3.1.1: IPv6 Status\n"
        "- **Status**: INFORMATIONAL\n"
        "- **Evidence**: inet6 count = 6\n"
        "### Rule 3.1.2: Wireless Interfaces\n"
        "- **Status**: PASS\n"
        "- **Evidence**: wlan0 not active\n"
        "## Section 5.3 – PAM\n"
        "### Rule 5.3.1.1: libpam-runtime\n"
        "- **Status**: PASS\n"
    )

    formatted = format_report_spacing(unformatted)

    # Verify spacing before section headers and rules
    assert "\n\n## Section 5.3 – PAM" in formatted
    assert "\n\n### Rule 3.1.2: Wireless Interfaces" in formatted
    assert "\n\n### Rule 5.3.1.1: libpam-runtime" in formatted


def test_format_report_spacing_collapses_excessive_newlines():
    dense_with_extra_breaks = (
        "## Section 1\n\n\n\n\n"
        "### Rule 1.1\n\n\n"
        "- Status: PASS\n"
    )
    formatted = format_report_spacing(dense_with_extra_breaks)
    assert "\n\n\n" not in formatted


def test_parse_compliance_stats_with_pam_and_network():
    report_text = (
        "## Section 3 – Network Configuration\n"
        "Rule 3.1.2\n"
        "Status: PASS\n"
        "Rule 3.1.3\n"
        "Status: FAIL\n"
        "## Section 5.3 – Pluggable Authentication Modules (PAM)\n"
        "Rule 5.3.1.1\n"
        "Status: PASS\n"
    )
    stats = parse_compliance_stats(report_text)
    assert stats["overall"]["PASS"] == 2
    assert stats["overall"]["FAIL"] == 1
    assert "Network Configuration" in stats["sections"]
    assert "Pluggable Authentication Modules (PAM)" in stats["sections"]
