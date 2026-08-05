"""
test_api.py
===========
Unit and integration tests for report_parser.py and FastAPI api.py endpoints.
"""

import json
import os
import pytest
from fastapi.testclient import TestClient

from api import app, RUNS_DIR
from tools.report_parser import parse_markdown_report, compute_summary_stats

client = TestClient(app)


def test_parse_markdown_report():
    """Test parsing markdown report into structured rules — dash bullet style."""
    raw_md = """# CIS BENCHMARK COMPLIANCE REPORT

### Rule 5.1.20: Ensure sshd PermitRootLogin is disabled
- **Status**: FAIL
- **Evidence**: PermitRootLogin yes
- **Recommendation**: Set PermitRootLogin no in /etc/ssh/sshd_config

### Rule 5.4.1.1: Ensure password expiration is 365 days or less
- **Status**: PASS
- **Evidence**: PASS_MAX_DAYS 90
- **Recommendation**: None
"""
    rules = parse_markdown_report(raw_md)
    assert len(rules) == 2

    r1 = rules[0]
    assert r1["rule_id"] == "5.1.20"
    assert r1["section"] == "5.1"
    assert r1["section_num"] == "5"
    assert r1["status"] == "FAIL"
    assert "PermitRootLogin yes" in r1["evidence"]
    assert "Set PermitRootLogin no" in r1["recommendation"]

    r2 = rules[1]
    assert r2["rule_id"] == "5.4.1.1"
    assert r2["status"] == "PASS"


def test_parse_markdown_report_asterisk_bullets():
    """Test parsing markdown with asterisk bullets — this is Gemini's actual output format."""
    raw_md = """## Section 5.1 – SSH Server Configuration

### Rule 5.1.20: Ensure sshd PermitRootLogin is disabled
  * **Status**: FAIL
  * **Evidence**: PermitRootLogin yes in /etc/ssh/sshd_config
  * **Recommendation**: Set `PermitRootLogin no` in /etc/ssh/sshd_config and restart sshd.

### Rule 5.4.1.1: Ensure password expiration is configured
  * **Status**: PASS
  * **Evidence**: PASS_MAX_DAYS 90 is configured in /etc/login.defs
  * **Recommendation**: None
"""
    rules = parse_markdown_report(raw_md)
    assert len(rules) == 2

    r1 = rules[0]
    assert r1["rule_id"] == "5.1.20"
    assert r1["status"] == "FAIL"
    assert "PermitRootLogin yes" in r1["evidence"]

    r2 = rules[1]
    assert r2["rule_id"] == "5.4.1.1"
    assert r2["status"] == "PASS"


def test_compute_summary_stats():
    """Test computing overall compliance posture and section breakdowns."""
    rules = [
        {"rule_id": "1.1.1.1", "section_num": "1", "status": "PASS"},
        {"rule_id": "1.1.1.2", "section_num": "1", "status": "FAIL"},
        {"rule_id": "5.1.20", "section_num": "5", "status": "PASS"},
        {"rule_id": "5.4.1.1", "section_num": "5", "status": "PASS"},
    ]
    stats = compute_summary_stats(rules)
    assert stats["total_checked"] == 4
    assert stats["pass_count"] == 3
    assert stats["fail_count"] == 1
    assert stats["compliance_pct"] == 75.0
    assert stats["sections"]["1"]["total"] == 2
    assert stats["sections"]["1"]["pass"] == 1
    assert stats["sections"]["5"]["total"] == 2
    assert stats["sections"]["5"]["pass"] == 2


def test_api_get_rules():
    """Test GET /api/rules endpoint."""
    response = client.get("/api/rules")
    assert response.status_code == 200
    data = response.json()
    assert "rules" in data
    assert len(data["rules"]) > 0
    rule_ids = [r["rule_id"] for r in data["rules"]]
    assert "5.1.20" in rule_ids


def test_api_get_runs():
    """Test GET /api/audit/runs endpoint."""
    response = client.get("/api/audit/runs")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_api_trigger_audit_invalid_rules():
    """Test POST /api/audit/run with invalid rules argument."""
    payload = {
        "hostname": "127.0.0.1",
        "username": "root",
        "rules": "999.999"
    }
    response = client.post("/api/audit/run", json=payload)
    assert response.status_code == 400
    assert "Invalid CIS rule ID" in response.json()["detail"]


def test_api_run_lifecycle_and_compare(tmp_path):
    """Test loading run data and comparing two mock audit runs."""
    run_1_data = {
        "run_id": "test_run_1",
        "status": "completed",
        "created_at": "2026-07-29T10:00:00",
        "hostname": "test-host",
        "target_os": "linux",
        "structured_rules": [
            {"rule_id": "5.1.20", "title": "PermitRootLogin", "status": "FAIL", "evidence": "yes"},
            {"rule_id": "5.4.1.1", "title": "Password Expiration", "status": "PASS", "evidence": "90"},
        ],
        "summary": {"compliance_pct": 50.0}
    }
    run_2_data = {
        "run_id": "test_run_2",
        "status": "completed",
        "created_at": "2026-07-29T11:00:00",
        "hostname": "test-host",
        "target_os": "linux",
        "structured_rules": [
            {"rule_id": "5.1.20", "title": "PermitRootLogin", "status": "PASS", "evidence": "no"},
            {"rule_id": "5.4.1.1", "title": "Password Expiration", "status": "PASS", "evidence": "90"},
        ],
        "summary": {"compliance_pct": 100.0}
    }

    with open(os.path.join(RUNS_DIR, "test_run_1.json"), "w", encoding="utf-8") as f:
        json.dump(run_1_data, f)
    with open(os.path.join(RUNS_DIR, "test_run_2.json"), "w", encoding="utf-8") as f:
        json.dump(run_2_data, f)

    # Test GET /api/audit/run/test_run_1
    res1 = client.get("/api/audit/run/test_run_1")
    assert res1.status_code == 200
    assert res1.json()["status"] == "completed"

    # Test GET /api/audit/compare
    res_cmp = client.get("/api/audit/compare?run_id_1=test_run_1&run_id_2=test_run_2")
    assert res_cmp.status_code == 200
    cmp_data = res_cmp.json()
    assert cmp_data["fixed_count"] == 1
    assert cmp_data["regressed_count"] == 0
    assert cmp_data["total_compared"] == 2
    r_5120 = [c for c in cmp_data["comparisons"] if c["rule_id"] == "5.1.20"][0]
    assert r_5120["diff_status"] == "FIXED"

    # Clean up test JSON files
    os.remove(os.path.join(RUNS_DIR, "test_run_1.json"))
    os.remove(os.path.join(RUNS_DIR, "test_run_2.json"))
