"""
report.py
=========
PDF export with statistics and charts for SENTINEL audit reports.

Charts are embedded as base64 data URIs in the markdown so that the
markdown-pdf renderer (chromium) can display them without needing file access.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import re
import sys
from collections import defaultdict

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stats extraction
# ---------------------------------------------------------------------------

_SECTION_MAP = {
    "ftp":                    "FTP",
    "telnet":                 "Telnet",
    "ssh":                    "SSH",
    "privilege escalation":   "Privilege Escalation",
    "pam":                    "Pluggable Authentication Modules (PAM)",
    "pluggable":              "Pluggable Authentication Modules (PAM)",
    "network":                "Network Configuration",
    "user accounts":          "User Accounts",
    "firewall":               "Firewall",
    "file permissions":       "File Permissions",
    "suid":                   "File Permissions",
    "system logging":         "System Logging",
    "system auditing":        "System Auditing",
    "integrity checking":     "Integrity Checking",
    "local user":             "Local User and Group Settings",
}

_STATUS_RE = re.compile(
    r"\bstatus\b.*?\b(pass|fail|unknown|passed|failed|informational)\b",
    re.IGNORECASE,
)


def format_report_spacing(report_text: str) -> str:
    """
    Restructure markdown audit report text to ensure optimal newline spacing
    and readability.

    - Inserts blank lines before section headers (##, ###).
    - Adds newline separation between rules (e.g. before 'Rule X.Y' or '- Rule').
    - Cleans up excessive blank lines (collapsing 3+ newlines to 2).
    """
    if not report_text or not report_text.strip():
        return report_text

    lines = report_text.splitlines()
    formatted_lines: list[str] = []

    rule_header_pattern = re.compile(
        r"^(?:#{2,4}\s+|(?:\*\*)?(?:-[ \t]*)?Rule\s+\d+\.|\d+\.\d+(?:\.\d+)?\b)",
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Add empty line before major Markdown headings (##, ###) if not already preceded by one
        if stripped.startswith("#") and formatted_lines and formatted_lines[-1] != "":
            formatted_lines.append("")

        # Add empty line before rule entries if not already preceded by one
        elif rule_header_pattern.match(stripped) and formatted_lines and formatted_lines[-1] != "":
            formatted_lines.append("")

        # Add empty line before horizontal rules (---)
        elif stripped == "---" and formatted_lines and formatted_lines[-1] != "":
            formatted_lines.append("")

        formatted_lines.append(line)

    result = "\n".join(formatted_lines)
    # Collapse 3 or more consecutive newlines down to 2
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip() + "\n"


def parse_compliance_stats(cis_report: str) -> dict:
    """Extract PASS/FAIL/UNKNOWN counts overall and per section."""
    overall: dict[str, int] = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0}
    sections: dict[str, dict] = defaultdict(lambda: {"PASS": 0, "FAIL": 0, "UNKNOWN": 0})
    current_section = "General"

    for line in cis_report.splitlines():
        line_clean = line.strip().lower()
        # 1. Section detection
        found_sec = None
        for key, label in _SECTION_MAP.items():
            if key in line_clean:
                # Check if it looks like a header (starts with #, starts with *, or is very short)
                if line_clean.startswith("#") or line_clean.startswith("*") or len(line_clean) < 40:
                    found_sec = label
                    break
        if found_sec:
            current_section = found_sec

        # 2. Status detection
        stat_m = _STATUS_RE.search(line)
        if stat_m:
            raw_val = stat_m.group(1).upper()
            if raw_val in ("PASSED", "PASS"):
                status = "PASS"
            elif raw_val in ("FAILED", "FAIL"):
                status = "FAIL"
            else:
                status = "UNKNOWN"
            
            overall[status] = overall.get(status, 0) + 1
            sections[current_section][status] = sections[current_section].get(status, 0) + 1

    total = sum(overall.values())
    pass_rate = round(overall["PASS"] / total * 100, 1) if total else 0.0
    return {"overall": overall, "sections": dict(sections), "total": total, "pass_rate": pass_rate}


# ---------------------------------------------------------------------------
# Chart helpers — return base64 PNG strings
# ---------------------------------------------------------------------------

_PALETTE = {
    "PASS":    "#2ECC71",
    "FAIL":    "#E74C3C",
    "UNKNOWN": "#95A5A6",
}


def _fig_to_b64(fig) -> str:
    """Render a matplotlib figure to a base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor="#FAFAFA")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def _b64_img_tag(b64: str, width: str = "480px") -> str:
    """Return a markdown image tag using a data URI."""
    return f'<img src="data:image/png;base64,{b64}" width="{width}" />'


def generate_pie_chart_b64(stats: dict) -> str | None:
    """Return base64 PNG of the overall compliance pie, or None."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    overall = stats["overall"]
    labels, sizes, colors = [], [], []
    for status in ("PASS", "FAIL", "UNKNOWN"):
        count = overall.get(status, 0)
        if count:
            labels.append(f"{status}\n({count})")
            sizes.append(count)
            colors.append(_PALETTE[status])

    if not sizes:
        return None

    fig, ax = plt.subplots(figsize=(5, 4))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct="%1.1f%%", startangle=90,
        textprops={"fontsize": 11},
        wedgeprops={"linewidth": 1.5, "edgecolor": "white"},
    )
    for at in autotexts:
        at.set_fontsize(10)
        at.set_color("white")
        at.set_fontweight("bold")
    ax.set_title("Overall CIS Compliance", fontsize=14, fontweight="bold", pad=15)
    result = _fig_to_b64(fig)
    plt.close(fig)
    return result


def generate_bar_chart_b64(stats: dict) -> str | None:
    """Return base64 PNG of the per-section bar chart, or None."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        return None

    sections = stats["sections"]
    if not sections:
        return None

    names      = list(sections.keys())
    pass_vals  = [sections[s].get("PASS", 0)    for s in names]
    fail_vals  = [sections[s].get("FAIL", 0)    for s in names]
    unk_vals   = [sections[s].get("UNKNOWN", 0) for s in names]

    x = np.arange(len(names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(8, len(names) * 1.5), 5))
    ax.bar(x - width, pass_vals, width, label="PASS",    color=_PALETTE["PASS"],    edgecolor="white")
    ax.bar(x,         fail_vals, width, label="FAIL",    color=_PALETTE["FAIL"],    edgecolor="white")
    ax.bar(x + width, unk_vals,  width, label="UNKNOWN", color=_PALETTE["UNKNOWN"], edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right", fontsize=10)
    ax.set_ylabel("Rule Count", fontsize=11)
    ax.set_title("CIS Compliance by Section", fontsize=14, fontweight="bold", pad=15)
    ax.legend(fontsize=10)
    ax.set_facecolor("#F8F9FA")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

    result = _fig_to_b64(fig)
    plt.close(fig)
    return result


# ---------------------------------------------------------------------------
# Summary page builder
# ---------------------------------------------------------------------------

def build_summary_markdown(stats: dict) -> str:
    overall   = stats["overall"]
    total     = stats["total"]
    pass_rate = stats["pass_rate"]
    sections  = stats["sections"]

    badge = "🟢" if pass_rate >= 80 else ("🟡" if pass_rate >= 50 else "🔴")

    pie_b64 = generate_pie_chart_b64(stats)
    bar_b64 = generate_bar_chart_b64(stats)

    md = f"""# SENTINEL — CIS Benchmark Audit Report

---

## Executive Summary &nbsp; {badge}

| Metric | Value |
|---|---|
| **Total Rules Evaluated** | {total} |
| **✅ Passed** | {overall.get('PASS', 0)} |
| **❌ Failed** | {overall.get('FAIL', 0)} |
| **❓ Unknown** | {overall.get('UNKNOWN', 0)} |
| **Overall Pass Rate** | **{pass_rate}%** |

---

## Compliance Charts

"""
    if pie_b64:
        md += _b64_img_tag(pie_b64, "420px") + "\n\n"
    if bar_b64:
        md += _b64_img_tag(bar_b64, "680px") + "\n\n"

    md += "---\n\n## Per-Section Breakdown\n\n"
    md += "| Section | ✅ PASS | ❌ FAIL | ❓ UNKNOWN | Pass Rate |\n"
    md += "|---|---|---|---|---|\n"
    for sec, counts in sections.items():
        p = counts.get("PASS", 0)
        f = counts.get("FAIL", 0)
        u = counts.get("UNKNOWN", 0)
        tot = p + f + u
        rate = f"{round(p / tot * 100)}%" if tot else "—"
        md += f"| {sec} | {p} | {f} | {u} | {rate} |\n"

    md += "\n---\n\n"
    return md


# ---------------------------------------------------------------------------
# Main export function
# ---------------------------------------------------------------------------

def save_reports_to_pdf(
    data_json: dict,
    cis_report: str = "",
    suid_report: str = "",
    output_dir: str = ".",
    prefix: str = "audit",
) -> None:
    """Render and save PDF audit reports.

    Parameters
    ----------
    data_json:
        The raw collected security profile dictionary.
    cis_report:
        Optional AI-generated CIS compliance report text.
    suid_report:
        Optional AI-generated SUID/SGID triage report text.
    output_dir:
        Directory to write PDF files into.  Created if it doesn't exist.
    prefix:
        Filename prefix, e.g. ``192.168.1.1_20260714_145530``.
        Final filenames will be ``<prefix>_data.pdf`` and ``<prefix>_ai_report.pdf``.
    """
    try:
        from markdown_pdf import MarkdownPdf, Section
    except ImportError:
        log.warning("'markdown-pdf' is not installed. PDF export skipped.")
        return

    os.makedirs(output_dir, exist_ok=True)
    data_path   = os.path.join(output_dir, f"{prefix}_data.pdf")
    report_path = os.path.join(output_dir, f"{prefix}_ai_report.pdf")

    log.info("Exporting reports to PDF…")
    try:
        # Raw data PDF
        pdf_data = MarkdownPdf(toc_level=2)
        md_data = f"# Raw Security Data Profile\n\n```json\n{json.dumps(data_json, indent=2)}\n```"
        pdf_data.add_section(Section(md_data))
        pdf_data.save(data_path)

        # AI Reports PDF
        if cis_report or suid_report:
            stats = parse_compliance_stats(cis_report) if cis_report else None

            ai_report_md = ""
            if stats and stats["total"] > 0:
                log.info("Generating compliance charts…")
                ai_report_md += build_summary_markdown(stats)
            else:
                ai_report_md += "# SENTINEL AI Audit Reports\n\n"

            if cis_report:
                formatted_cis = format_report_spacing(cis_report)
                ai_report_md += f"## CIS Benchmark Compliance Report\n\n{formatted_cis}\n\n---\n\n"
            if suid_report:
                formatted_suid = format_report_spacing(suid_report)
                ai_report_md += f"## SUID/SGID Triage Report\n\n{formatted_suid}\n\n"

            pdf_reports = MarkdownPdf(toc_level=2)
            pdf_reports.add_section(Section(ai_report_md))
            pdf_reports.save(report_path)

        log.info("Successfully wrote %s and %s", data_path, report_path)
    except Exception as e:
        log.error("Failed to write PDF reports: %s", e)
