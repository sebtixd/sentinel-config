"""
test_rule_filtering.py
======================
Unit tests for CIS rule parsing, shorthand expansion, rule validation, collector mapping,
LLM report filtering, and main CLI argument handling.
"""

import sys
import pytest
from unittest.mock import patch, MagicMock
from tools.rule_registry import (
    RULE_REGISTRY,
    parse_and_validate_rules,
    get_required_collectors,
    format_rule_list,
    filter_report_by_rules,
)


def test_single_rule_id():
    """Test parsing a single concrete rule ID."""
    result = parse_and_validate_rules("5.1.20")
    assert result == ["5.1.20"]

    result = parse_and_validate_rules(["5.4.1.1"])
    assert result == ["5.4.1.1"]


def test_comma_separated_rule_ids():
    """Test parsing a comma-separated list of rule IDs."""
    result = parse_and_validate_rules("5.1.20, 5.4.1.1, 7.1.5")
    assert result == ["5.1.20", "5.4.1.1", "7.1.5"]


def test_parent_section_shorthand():
    """Test expanding parent section shorthands like '5.1' or '6.2'."""
    result_5_1 = parse_and_validate_rules("5.1")
    assert "5.1.1" in result_5_1
    assert "5.1.20" in result_5_1
    assert "5.1.24" in result_5_1
    # Check that non 5.1 rules are not included
    assert "5.2.1" not in result_5_1
    assert "5.4.1.1" not in result_5_1

    result_6_2 = parse_and_validate_rules("6.2")
    assert "6.2.1.1.1" in result_6_2
    assert "6.2.3.1" in result_6_2
    assert "6.2.4.1" in result_6_2


def test_invalid_rule_id():
    """Test that an invalid or unknown rule ID raises a clear ValueError."""
    with pytest.raises(ValueError) as excinfo:
        parse_and_validate_rules("99.99")
    assert "Invalid CIS rule ID" in str(excinfo.value)
    assert "99.99" in str(excinfo.value)
    assert "--list-rules" in str(excinfo.value)

    # Test invalid rule ID with suggestion
    with pytest.raises(ValueError) as excinfo2:
        parse_and_validate_rules("5.1.999")
    assert "5.1.999" in str(excinfo2.value)


def test_no_argument_full_run_regression():
    """Test that empty or None rule input returns empty list (full run fallback)."""
    assert parse_and_validate_rules("") == []
    assert parse_and_validate_rules([]) == []


def test_get_required_collectors():
    """Test collector key mapping for requested rule IDs."""
    rules = parse_and_validate_rules("5.1.20, 4.1.1, 1.1.1.1")
    collectors = get_required_collectors(rules)
    assert collectors == {"ssh", "ufw", "filesystem"}


def test_format_rule_list():
    """Test output formatting for --list-rules."""
    output = format_rule_list()
    assert "Implemented CIS Benchmark Rules:" in output
    assert "5.1.20" in output
    assert "PermitRootLogin" in output or "ssh" in output


def test_filter_report_by_rules():
    """Test filtering LLM report markdown to only keep requested rules."""
    raw_report = """# CIS BENCHMARK COMPLIANCE REPORT

## Section 5.1 – SSH Server Configuration
### Rule 5.1.1: Ensure access to /etc/ssh/sshd_config is configured
- Status: PASS
- Evidence: mode 0600

### Rule 5.1.20: Ensure sshd PermitRootLogin is disabled
- Status: FAIL
- Evidence: PermitRootLogin yes

## Section 5.4 – User Accounts
### Rule 5.4.1.1: Ensure password expiration is configured
- Status: PASS
- Evidence: PASS_MAX_DAYS 90
"""
    filtered = filter_report_by_rules(raw_report, ["5.1.20"])
    assert "5.1.20" in filtered
    assert "PermitRootLogin" in filtered
    assert "5.1.1" not in filtered
    assert "5.4.1.1" not in filtered


def test_main_cli_args_parsing():
    """Test CLI argument parsing in main.py for --rules and --list-rules."""
    from main import main

    # Test --list-rules exits with code 0
    with patch.object(sys, "argv", ["main.py", "--list-rules"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0

    # Test invalid --rules exits with code 1
    with patch.object(sys, "argv", ["main.py", "user", "host", "--rules", "999.999"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
