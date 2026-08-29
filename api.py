"""
api.py
======
FastAPI REST API layer for SENTINEL CIS Benchmark compliance auditing tool.
Provides non-blocking audit execution, status tracking, structured findings retrieval,
run history, run comparison, and static UI file serving.
"""

from __future__ import annotations
import datetime
import json
import logging
import os
import sys
import threading
import uuid
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Imports from SENTINEL core modules
from tools.rule_registry import (
    RULE_REGISTRY,
    format_rule_list,
    get_required_collectors,
    parse_and_validate_rules,
)
from tools.report_parser import compute_summary_stats, parse_markdown_report
from tools.ai_analysis import generate_compliance_report, analyze_suid_sgid
from tools.report import save_reports_to_pdf

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import winrm
    from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
except ImportError:
    winrm = None

try:
    from collectors.collect_ssh import collect_ssh_from_ssh
    from collectors.ssh_bridges import (
        collect_privilege_escalation_from_ssh,
        collect_file_permissions_from_ssh,
        collect_user_accounts_from_ssh,
        collect_ufw_from_ssh,
        collect_auditd_from_ssh,
        collect_filesystem_from_ssh,
        collect_package_management_from_ssh,
        collect_apparmor_from_ssh,
        collect_bootloader_from_ssh,
        collect_process_hardening_from_ssh,
        collect_warning_banners_from_ssh,
        collect_gnome_from_ssh,
        collect_services_from_ssh,
        collect_time_sync_from_ssh,
        collect_job_schedulers_from_ssh,
        collect_network_config_from_ssh,
        collect_pam_from_ssh,
        collect_system_logging_from_ssh,
        collect_integrity_checking_from_ssh,
    )
    from tools.ssh_collector_runner import run_collector_over_ssh
    from tools.secedit_parser import parse_password_policy
except ImportError:
    pass

log = logging.getLogger("sentinel_api")

app = FastAPI(
    title="SENTINEL CIS Compliance API",
    description="REST API for SENTINEL CIS Benchmark security auditing and reporting",
    version="1.0.0",
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RUNS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_runs")
os.makedirs(RUNS_DIR, exist_ok=True)

REPORTS_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_OUTPUT_DIR, exist_ok=True)


class AuditRunRequest(BaseModel):
    hostname: str = Field(..., description="Remote target IP or hostname")
    username: str = Field(..., description="SSH or WinRM username")
    password: Optional[str] = Field(None, description="SSH or WinRM password")
    port: Optional[int] = Field(None, description="SSH/WinRM port (default 22 for Linux, 5985 for Windows)")
    key_filename: Optional[str] = Field(None, description="Path to SSH private key file")
    target_os: str = Field("linux", description="Target OS: 'linux' or 'windows'")
    rules: Optional[str] = Field(None, description="CIS rules filter (e.g. '5.1.20,5.4.1.1' or '5.1')")


def _save_run_data(run_id: str, data: Dict[str, Any]) -> None:
    filepath = os.path.join(RUNS_DIR, f"{run_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _load_run_data(run_id: str) -> Optional[Dict[str, Any]]:
    filepath = os.path.join(RUNS_DIR, f"{run_id}.json")
    if not os.path.isfile(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def _background_run_audit(run_id: str, req: AuditRunRequest) -> None:
    """Worker task executing audit pipeline and storing results."""
    start_time = datetime.datetime.now()
    run_data: Dict[str, Any] = {
        "run_id": run_id,
        "status": "running",
        "created_at": start_time.isoformat(),
        "hostname": req.hostname,
        "username": req.username,
        "target_os": req.target_os,
        "rules_filter": req.rules,
        "progress_message": "Connecting to remote host...",
        "profile": {},
        "cis_report_markdown": "",
        "suid_report_markdown": "",
        "structured_rules": [],
        "summary": {},
        "error": None,
    }
    _save_run_data(run_id, run_data)

    try:
        requested_rules = None
        required_collectors = None
        if req.rules:
            requested_rules = parse_and_validate_rules(req.rules)
            required_collectors = get_required_collectors(requested_rules)

        combined: Dict[str, Any] = {}
        file_perms_data: Dict[str, Any] = {}

        if req.target_os.lower() == "windows":
            if winrm is None:
                raise RuntimeError("pywinrm is not installed")
            port = req.port if req.port is not None else 5985
            endpoint = f"http://{req.hostname}:{port}/wsman"
            session = winrm.Session(endpoint, auth=(req.username, req.password or ""), transport="ntlm")
            
            res_secedit = session.run_ps("secedit /export /cfg C:\\Windows\\Temp\\secedit_out.cfg")
            if res_secedit.status_code != 0:
                raise RuntimeError(f"secedit export failed: {res_secedit.std_err.decode()}")
            res_read = session.run_ps("Get-Content C:\\Windows\\Temp\\secedit_out.cfg")
            secedit_content = res_read.std_out.decode("utf-16", errors="replace")
            session.run_ps("Remove-Item C:\\Windows\\Temp\\secedit_out.cfg -ErrorAction SilentlyContinue")
            
            sec_policy = parse_password_policy(secedit_content)
            res_lockout = session.run_ps("net accounts")
            lockout_out = res_lockout.std_out.decode("utf-8", errors="replace") if res_lockout.status_code == 0 else ""

            combined = {
                "os": "windows",
                "security_policy": sec_policy,
                "net_accounts_raw": lockout_out.strip(),
            }
        else:
            # Linux path
            if paramiko is None:
                raise RuntimeError("paramiko is not installed")
            port = req.port if req.port is not None else 22
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=req.hostname,
                port=port,
                username=req.username,
                password=req.password,
                key_filename=req.key_filename,
                timeout=10,
            )

            try:
                if required_collectors is None:
                    # Full audit
                    run_data["progress_message"] = "Running full collector suite across all Sections 1-7..."
                    _save_run_data(run_id, run_data)

                    combined.update(collect_ssh_from_ssh(ssh, req.hostname, port, req.password or ""))
                    combined["privilege_escalation"] = collect_privilege_escalation_from_ssh(ssh, req.password or "")
                    file_perms_data = collect_file_permissions_from_ssh(ssh, req.password or "")
                    combined["file_permissions"] = file_perms_data
                    combined["user_accounts"] = collect_user_accounts_from_ssh(ssh, req.password or "")
                    combined.update(collect_ufw_from_ssh(ssh, req.password or ""))
                    combined.update(collect_filesystem_from_ssh(ssh, req.password or ""))
                    combined.update(collect_package_management_from_ssh(ssh, req.password or ""))
                    combined.update(collect_apparmor_from_ssh(ssh, req.password or ""))
                    combined.update(collect_bootloader_from_ssh(ssh, req.password or ""))
                    combined.update(collect_process_hardening_from_ssh(ssh, req.password or ""))
                    combined.update(collect_warning_banners_from_ssh(ssh, req.password or ""))
                    combined.update(collect_gnome_from_ssh(ssh, req.password or ""))
                    combined.update(collect_services_from_ssh(ssh, req.password or ""))
                    combined.update(collect_time_sync_from_ssh(ssh, req.password or ""))
                    combined.update(collect_job_schedulers_from_ssh(ssh, req.password or ""))
                    combined.update(collect_network_config_from_ssh(ssh, req.password or ""))
                    combined.update(collect_pam_from_ssh(ssh, req.password or ""))
                    combined.update(collect_system_logging_from_ssh(ssh, req.password or ""))
                    local_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collectors", "auditd_collector.py")
                    combined.update(run_collector_over_ssh(ssh=ssh, script_path=local_script, password=req.password or "", timeout=60, fallback_key="system_auditing"))
                    combined.update(collect_integrity_checking_from_ssh(ssh, req.password or ""))
                else:
                    # Filtered audit
                    run_data["progress_message"] = f"Running selective collectors for rules: {', '.join(requested_rules or [])}"
                    _save_run_data(run_id, run_data)

                    if "ssh" in required_collectors:
                        combined.update(collect_ssh_from_ssh(ssh, req.hostname, port, req.password or ""))
                    if "privilege_escalation" in required_collectors:
                        combined["privilege_escalation"] = collect_privilege_escalation_from_ssh(ssh, req.password or "")
                    if "file_permissions" in required_collectors:
                        file_perms_data = collect_file_permissions_from_ssh(ssh, req.password or "")
                        combined["file_permissions"] = file_perms_data
                    if "user_accounts" in required_collectors:
                        combined["user_accounts"] = collect_user_accounts_from_ssh(ssh, req.password or "")
                    if "ufw" in required_collectors:
                        combined.update(collect_ufw_from_ssh(ssh, req.password or ""))
                    if "filesystem" in required_collectors:
                        combined.update(collect_filesystem_from_ssh(ssh, req.password or ""))
                    if "package_management" in required_collectors:
                        combined.update(collect_package_management_from_ssh(ssh, req.password or ""))
                    if "apparmor" in required_collectors:
                        combined.update(collect_apparmor_from_ssh(ssh, req.password or ""))
                    if "bootloader" in required_collectors:
                        combined.update(collect_bootloader_from_ssh(ssh, req.password or ""))
                    if "process_hardening" in required_collectors:
                        combined.update(collect_process_hardening_from_ssh(ssh, req.password or ""))
                    if "warning_banners" in required_collectors:
                        combined.update(collect_warning_banners_from_ssh(ssh, req.password or ""))
                    if "gnome" in required_collectors:
                        combined.update(collect_gnome_from_ssh(ssh, req.password or ""))
                    if "services" in required_collectors:
                        combined.update(collect_services_from_ssh(ssh, req.password or ""))
                    if "time_sync" in required_collectors:
                        combined.update(collect_time_sync_from_ssh(ssh, req.password or ""))
                    if "job_schedulers" in required_collectors:
                        combined.update(collect_job_schedulers_from_ssh(ssh, req.password or ""))
                    if "network_config" in required_collectors:
                        combined.update(collect_network_config_from_ssh(ssh, req.password or ""))
                    if "pam" in required_collectors:
                        combined.update(collect_pam_from_ssh(ssh, req.password or ""))
                    if "system_logging" in required_collectors:
                        combined.update(collect_system_logging_from_ssh(ssh, req.password or ""))
                    if "auditd" in required_collectors:
                        local_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collectors", "auditd_collector.py")
                        combined.update(run_collector_over_ssh(ssh=ssh, script_path=local_script, password=req.password or "", timeout=60, fallback_key="system_auditing"))
                    if "integrity_checking" in required_collectors:
                        combined.update(collect_integrity_checking_from_ssh(ssh, req.password or ""))
            finally:
                ssh.close()

        run_data["progress_message"] = "Running AI compliance analysis via Gemini..."
        _save_run_data(run_id, run_data)

        # Load CIS rules file
        cis_rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cis_extracted_rules.md")
        if not os.path.isfile(cis_rules_path):
            cis_rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmarks", "rules.md")

        cis_rules_text = open(cis_rules_path, encoding="utf-8").read() if os.path.isfile(cis_rules_path) else ""
        report_markdown = generate_compliance_report(json.dumps(combined, indent=2), cis_rules_text, requested_rules=requested_rules)

        suid_report_markdown = ""
        suid_sgid_section = file_perms_data.get("suid_sgid", {})
        should_run_suid = (requested_rules is None) or any(r == "7.1.13" or r.startswith("7.1") or r.startswith("7.") for r in (requested_rules or []))
        if should_run_suid and suid_sgid_section.get("suid_sgid_files"):
            suid_report_markdown = analyze_suid_sgid(suid_sgid_section)

        # Parse report markdown into structured rules & compute stats
        structured_rules = parse_markdown_report(report_markdown)
        summary = compute_summary_stats(structured_rules)

        # Save PDF reports
        output_prefix = f"{req.hostname}_{run_id}"
        save_reports_to_pdf(combined, cis_report=report_markdown, suid_report=suid_report_markdown,
                            output_dir=REPORTS_OUTPUT_DIR, prefix=output_prefix)

        end_time = datetime.datetime.now()
        duration_sec = round((end_time - start_time).total_seconds(), 2)

        run_data.update({
            "status": "completed",
            "progress_message": "Audit completed successfully.",
            "duration_seconds": duration_sec,
            "profile": combined,
            "cis_report_markdown": report_markdown,
            "suid_report_markdown": suid_report_markdown,
            "structured_rules": structured_rules,
            "summary": summary,
        })
        _save_run_data(run_id, run_data)

    except Exception as exc:
        log.exception("Audit run failed")
        run_data.update({
            "status": "failed",
            "progress_message": "Audit failed.",
            "error": str(exc),
        })
        _save_run_data(run_id, run_data)


@app.post("/api/audit/run", response_model=Dict[str, Any])
def trigger_audit_run(req: AuditRunRequest, background_tasks: BackgroundTasks):
    """Trigger a new remote security audit run."""
    if req.rules:
        try:
            parse_and_validate_rules(req.rules)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{req.hostname}_{ts}_{uuid.uuid4().hex[:4]}"

    background_tasks.add_task(_background_run_audit, run_id, req)
    return {
        "run_id": run_id,
        "status": "running",
        "message": f"Audit triggered for host {req.hostname}",
    }


@app.get("/api/audit/run/{run_id}", response_model=Dict[str, Any])
def get_audit_run(run_id: str):
    """Fetch details, structured findings, and summary of an audit run."""
    run_data = _load_run_data(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail="Audit run not found")

    # Re-parse structured_rules from saved markdown if empty (e.g. runs before regex fix)
    if run_data.get("status") == "completed" and not run_data.get("structured_rules") and run_data.get("cis_report_markdown"):
        structured_rules = parse_markdown_report(run_data["cis_report_markdown"])
        summary = compute_summary_stats(structured_rules)
        run_data["structured_rules"] = structured_rules
        run_data["summary"] = summary
        _save_run_data(run_id, run_data)

    return run_data


@app.get("/api/audit/run/{run_id}/pdf")
def download_audit_pdf(run_id: str):
    """Download the PDF report for a completed audit run."""
    # Find PDF in reports dir matching this run_id
    if not os.path.isdir(REPORTS_OUTPUT_DIR):
        raise HTTPException(status_code=404, detail="No reports directory found")

    matching = [
        f for f in os.listdir(REPORTS_OUTPUT_DIR)
        if run_id in f and f.endswith(".pdf") and "cis" in f.lower()
    ]
    if not matching:
        # Try any pdf containing the run_id
        matching = [f for f in os.listdir(REPORTS_OUTPUT_DIR) if run_id in f and f.endswith(".pdf")]

    if not matching:
        raise HTTPException(status_code=404, detail="PDF report not found for this run. It may still be generating.")

    pdf_path = os.path.join(REPORTS_OUTPUT_DIR, sorted(matching)[0])
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=sorted(matching)[0],
    )


@app.get("/api/audit/runs", response_model=List[Dict[str, Any]])
def list_audit_runs():
    """List historical audit runs sorted by timestamp descending."""
    runs = []
    for fname in os.listdir(RUNS_DIR):
        if fname.endswith(".json"):
            filepath = os.path.join(RUNS_DIR, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    runs.append({
                        "run_id": d.get("run_id"),
                        "status": d.get("status"),
                        "created_at": d.get("created_at"),
                        "hostname": d.get("hostname"),
                        "username": d.get("username"),
                        "target_os": d.get("target_os"),
                        "rules_filter": d.get("rules_filter"),
                        "duration_seconds": d.get("duration_seconds"),
                        "summary": d.get("summary", {}),
                        "error": d.get("error"),
                    })
            except Exception:
                continue

    runs.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return runs


@app.get("/api/audit/compare", response_model=Dict[str, Any])
def compare_audit_runs(run_id_1: str = Query(...), run_id_2: str = Query(...)):
    """Compare findings between two past audit runs."""
    run1 = _load_run_data(run_id_1)
    run2 = _load_run_data(run_id_2)

    if not run1 or not run2:
        raise HTTPException(status_code=404, detail="One or both audit runs not found")

    rules1 = {r["rule_id"]: r for r in run1.get("structured_rules", [])}
    rules2 = {r["rule_id"]: r for r in run2.get("structured_rules", [])}

    all_rule_ids = sorted(list(set(rules1.keys()) | set(rules2.keys())))
    comparisons = []
    fixed_count = 0
    regressed_count = 0

    for rid in all_rule_ids:
        r1 = rules1.get(rid)
        r2 = rules2.get(rid)
        status1 = r1["status"] if r1 else "NOT_CHECKED"
        status2 = r2["status"] if r2 else "NOT_CHECKED"

        diff_status = "UNCHANGED"
        if status1 == "FAIL" and status2 == "PASS":
            diff_status = "FIXED"
            fixed_count += 1
        elif status1 == "PASS" and status2 == "FAIL":
            diff_status = "REGRESSED"
            regressed_count += 1
        elif status1 != status2:
            diff_status = "CHANGED"

        title = (r2 and r2.get("title")) or (r1 and r1.get("title")) or f"Rule {rid}"

        comparisons.append({
            "rule_id": rid,
            "title": title,
            "status_run_1": status1,
            "status_run_2": status2,
            "diff_status": diff_status,
            "evidence_run_1": r1.get("evidence") if r1 else None,
            "evidence_run_2": r2.get("evidence") if r2 else None,
        })

    return {
        "run_id_1": run_id_1,
        "run_id_2": run_id_2,
        "fixed_count": fixed_count,
        "regressed_count": regressed_count,
        "total_compared": len(all_rule_ids),
        "comparisons": comparisons,
    }


@app.get("/api/rules", response_model=Dict[str, Any])
def get_implemented_rules():
    """List all supported CIS benchmark rules."""
    rules_list = []
    for rid, (title, collector) in sorted(RULE_REGISTRY.items(), key=lambda item: [int(x) for x in item[0].split(".") if x.isdigit()]):
        rules_list.append({
            "rule_id": rid,
            "title": title,
            "collector": collector,
            "section": rid.split(".")[0],
        })
    return {"rules": rules_list}


# Mount Web Frontend UI Static Files
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
os.makedirs(WEB_DIR, exist_ok=True)

@app.get("/image.png")
def serve_image():
    img_file = os.path.join(WEB_DIR, "image.png")
    if os.path.isfile(img_file):
        return FileResponse(img_file)
    raise HTTPException(status_code=404, detail="Image not found")


@app.get("/")
def serve_index():
    index_file = os.path.join(WEB_DIR, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(index_file)
    return JSONResponse({"message": "SENTINEL API Running. Frontend index.html not found."})

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
