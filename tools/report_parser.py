"""
report_parser.py
================
Parses Gemini compliance audit report markdown into structured rule objects
and computes summary statistics and section breakdowns for the web UI/API.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List
from tools.rule_registry import RULE_REGISTRY

SECTION_NAMES = {
    "1": "Initial Setup & Software",
    "2": "Services & Schedulers",
    "3": "Network Configuration",
    "4": "Host Firewall (UFW)",
    "5": "Access, Auth & Privileges",
    "6": "Logging, Auditing & Integrity",
    "7": "File Permissions & Local Users",
}


def parse_markdown_report(report_text: str) -> List[Dict[str, Any]]:
    """
    Parse markdown report text into a structured list of rule objects.

    Returns:
        List[dict]: List of rule dicts:
            {
                "rule_id": str,
                "section": str,
                "section_num": str,
                "title": str,
                "status": str,  # "PASS", "FAIL", "UNKNOWN", "INFORMATIONAL"
                "evidence": str,
                "recommendation": str,
            }
    """
    if not report_text:
        return []

    rules: List[Dict[str, Any]] = []
    
    # Regex to find rule headers like "### Rule 5.1.20: Title" or "### 5.1.20 Title"
    heading_re = re.compile(
        r"^###\s*(?:Rule\s*)?([0-9]+(?:\.[0-9]+)+)\s*[:\-\s]?\s*(.*)$",
        re.MULTILINE | re.IGNORECASE,
    )

    # Split report by rule headings
    matches = list(heading_re.finditer(report_text))
    
    for i, match in enumerate(matches):
        rule_id = match.group(1).strip()
        raw_title = match.group(2).strip()
        
        # Calculate section strings
        parts = rule_id.split(".")
        section_num = parts[0]
        section = f"{parts[0]}.{parts[1]}" if len(parts) > 1 else parts[0]

        # Use canonical title from registry if available, else raw_title
        registry_info = RULE_REGISTRY.get(rule_id)
        title = registry_info[0] if registry_info else raw_title or f"Rule {rule_id}"

        # Determine block text for this rule
        start_idx = match.end()
        end_idx = matches[i + 1].start() if i + 1 < len(matches) else len(report_text)
        block = report_text[start_idx:end_idx].strip()

        # Parse Status, Evidence, Recommendation from block
        # Gemini uses "  * **Status**: PASS" or "- **Status**: PASS" — handle both
        status = "UNKNOWN"
        status_match = re.search(
            r"[\*\-]\s*\*\*Status\*\*\s*:\s*([A-Z][A-Z _/]+)",
            block,
            re.IGNORECASE,
        )
        if status_match:
            raw_status = status_match.group(1).strip().upper().replace("/", " ")
            if "NOT APPLICABLE" in raw_status or "N/A" == raw_status.strip():
                status = "PASS"
            elif "PASS" in raw_status:
                status = "PASS"
            elif "FAIL" in raw_status:
                status = "FAIL"
            elif "INFORMATIONAL" in raw_status or "INFO" in raw_status:
                status = "INFORMATIONAL"
            else:
                status = "UNKNOWN"

        evidence = ""
        evidence_match = re.search(
            r"[\*\-]\s*\*\*Evidence\*\*\s*:\s*(.*?)(?=\n\s*[\*\-]\s*\*\*|\Z)",
            block,
            re.DOTALL | re.IGNORECASE,
        )
        if evidence_match:
            evidence = evidence_match.group(1).strip()

        recommendation = ""
        rec_match = re.search(
            r"[\*\-]\s*\*\*Recommendation\*\*\s*:\s*(.*?)(?=\n\s*[\*\-]\s*\*\*|\n###|\Z)",
            block,
            re.DOTALL | re.IGNORECASE,
        )
        if rec_match:
            recommendation = rec_match.group(1).strip()

        rules.append({
            "rule_id": rule_id,
            "section": section,
            "section_num": section_num,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    return rules


def compute_summary_stats(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute overall posture stats and section breakdown from structured rules.
    """
    total = len(rules)
    pass_cnt = sum(1 for r in rules if r["status"] == "PASS")
    fail_cnt = sum(1 for r in rules if r["status"] == "FAIL")
    info_cnt = sum(1 for r in rules if r["status"] in ("INFORMATIONAL", "INFO"))
    unknown_cnt = total - (pass_cnt + fail_cnt + info_cnt)

    compliance_pct = round((pass_cnt / total * 100), 1) if total > 0 else 0.0

    # Section 1..7 breakdown
    section_stats: Dict[str, Dict[str, Any]] = {}
    for sec_num in range(1, 8):
        s_key = str(sec_num)
        sec_rules = [r for r in rules if r["section_num"] == s_key]
        s_total = len(sec_rules)
        s_pass = sum(1 for r in sec_rules if r["status"] == "PASS")
        s_fail = sum(1 for r in sec_rules if r["status"] == "FAIL")
        s_other = s_total - (s_pass + s_fail)
        s_pct = round((s_pass / s_total * 100), 1) if s_total > 0 else 0.0

        section_stats[s_key] = {
            "name": SECTION_NAMES.get(s_key, f"Section {s_key}"),
            "total": s_total,
            "pass": s_pass,
            "fail": s_fail,
            "other": s_other,
            "compliance_pct": s_pct,
        }

    return {
        "total_checked": total,
        "pass_count": pass_cnt,
        "fail_count": fail_cnt,
        "info_count": info_cnt,
        "unknown_count": unknown_cnt,
        "compliance_pct": compliance_pct,
        "sections": section_stats,
    }
