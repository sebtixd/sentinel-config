"""
main.py
=======
Connects to a remote Linux machine via SSH (default) or a Windows Server 2016
machine via WinRM (--target-os windows), collects system configuration data
remotely, parses it, and produces a structured JSON security profile, then
runs a Gemini-powered CIS benchmark compliance report.
"""

import argparse
import getpass
import json
import logging
import sys
import os

try:
    import paramiko
except ImportError:
    print("Error: 'paramiko' is not installed. Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)

try:
    import winrm
    from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
except ImportError:
    print("Error: 'pywinrm' is not installed. Run: pip install pywinrm", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logging configuration — structured, levelled output to stderr
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("sentinel")

# Collectors
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
except ImportError as exc:
    print(f"Error importing collectors: {exc}", file=sys.stderr)
    sys.exit(1)

# Tools
try:
    from tools.secedit_parser import parse_password_policy
    from tools.ai_analysis import generate_compliance_report, analyze_suid_sgid
    from tools.report import save_reports_to_pdf
    from tools.rule_registry import (
        parse_and_validate_rules,
        get_required_collectors,
        format_rule_list,
    )
except ImportError as exc:
    print(f"Error importing tools: {exc}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if "--list-rules" in sys.argv:
        print(format_rule_list())
        sys.exit(0)

    # -------------------------------------------------------------------------
    # Argument parsing
    # -------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Audit the security configuration of a remote Linux or Windows machine."
    )
    parser.add_argument("username",          nargs="?", default=None, help="SSH/WinRM username")
    parser.add_argument("hostname",          nargs="?", default=None, help="Remote hostname or IP address")
    parser.add_argument("--port",            type=int, default=None,
                         help="Port (default: 22 for SSH, 5985 for WinRM HTTP, 5986 for WinRM HTTPS)")
    parser.add_argument("--password",        default=None,
                         help="SSH/WinRM password (prompted if omitted)")
    parser.add_argument("--key-filename",    default=None,
                         help="Path to SSH private key file (Linux only)")
    parser.add_argument("--target-os",       choices=["linux", "windows"], default="linux",
                         help="Target OS (default: linux)")
    parser.add_argument("--cis-rules",       default=None,
                         help="Path to the CIS extracted rules Markdown file (default: benchmarks/cis_extracted_rules.md)")
    parser.add_argument("--rules", "--rule-ids", default=None,
                         help="Audit specific CIS rule identifier(s), comma-separated (e.g. --rules 5.1.20,5.4.1.1,7.1.5) or parent section (e.g. --rules 5.1)")
    parser.add_argument("--list-rules",      action="store_true",
                         help="List all implemented CIS benchmark rules and exit")
    parser.add_argument("--output-dir",      default=".",
                         help="Directory to write PDF reports into (default: current directory)")
    parser.add_argument("--output-prefix",   default=None,
                         help="Filename prefix for PDF reports (default: hostname_YYYYMMDD_HHMMSS)")
    args = parser.parse_args()

    if args.list_rules:
        print(format_rule_list())
        sys.exit(0)

    if not args.username or not args.hostname:
        parser.error("the following arguments are required: username, hostname")

    # Validate rules if provided
    requested_rules = None
    required_collectors = None
    if args.rules:
        try:
            requested_rules = parse_and_validate_rules(args.rules)
            required_collectors = get_required_collectors(requested_rules)
            log.info("Auditing requested CIS rules: %s", ", ".join(requested_rules))
        except ValueError as err:
            log.error(str(err))
            sys.exit(1)

    # Prompt for password if not specified/key not used
    password = args.password
    if not password and not args.key_filename:
        password = getpass.getpass(prompt=f"[prompt] Enter password for {args.username}: ")

    # Build output prefix (timestamped, hostname-based by default)
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = args.output_prefix or f"{args.hostname}_{ts}"
    os.makedirs(args.output_dir, exist_ok=True)

    # =========================================================================
    # TARGET OS BRANCHING
    # =========================================================================
    if args.target_os == "windows":
        # ---------------------------------------------------------------------
        # WINDOWS PATH
        # ---------------------------------------------------------------------
        winrm_port = args.port if args.port is not None else 5985
        winrm_endpoint = f"http://{args.hostname}:{winrm_port}/wsman"
        log.info("Connecting to Windows host via WinRM at %s…", winrm_endpoint)
        
        try:
            session = winrm.Session(
                winrm_endpoint,
                auth=(args.username, password),
                transport="ntlm",
            )
            
            log.info("Retrieving security policy via secedit…")
            res_secedit = session.run_ps("secedit /export /cfg C:\\Windows\\Temp\\secedit_out.cfg")
            if res_secedit.status_code != 0:
                log.error("secedit export failed: %s", res_secedit.std_err.decode())
                sys.exit(1)
                
            res_read = session.run_ps("Get-Content C:\\Windows\\Temp\\secedit_out.cfg")
            if res_read.status_code != 0:
                log.error("Failed to read secedit export: %s", res_read.std_err.decode())
                sys.exit(1)
                
            secedit_content = res_read.std_out.decode("utf-16", errors="replace")
            
            session.run_ps("Remove-Item C:\\Windows\\Temp\\secedit_out.cfg -ErrorAction SilentlyContinue")
            
        except WinRMTransportError as exc:
            log.error("WinRM Transport error: %s", exc)
            sys.exit(1)
        except WinRMOperationTimeoutError as exc:
            log.error("WinRM operation timed out: %s", exc)
            sys.exit(1)
        except Exception as exc:
            log.error("Connection error: %s", exc)
            sys.exit(1)

        log.info("Parsing local security policy…")
        sec_policy = parse_password_policy(secedit_content)

        log.info("Collecting additional system info…")
        res_lockout = session.run_ps("net accounts")
        lockout_out = res_lockout.std_out.decode("utf-8", errors="replace") if res_lockout.status_code == 0 else ""

        combined = {
            "os": "windows",
            "security_policy": sec_policy,
            "net_accounts_raw": lockout_out.strip(),
        }
        
        print(json.dumps(combined, indent=2))

        cis_rules_path = args.cis_rules or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "benchmarks", "rules.md"
        )
        report = ""
        if os.path.isfile(cis_rules_path):
            log.info("Running CIS compliance audit using %s…", cis_rules_path)
            cis_rules_text = open(cis_rules_path, encoding="utf-8").read()
            report = generate_compliance_report(json.dumps(combined, indent=2), cis_rules_text, requested_rules=requested_rules)
            log.info("\n" + "=" * 70 + "\n  CIS BENCHMARK COMPLIANCE REPORT\n" + "=" * 70)
            print(report, file=sys.stderr)
        else:
            log.warning("CIS rules file not found at: %s", cis_rules_path)
            log.warning("Skipping compliance audit. Use --cis-rules to specify the path.")
            
        save_reports_to_pdf(combined, cis_report=report,
                            output_dir=args.output_dir, prefix=output_prefix)
        return

    # =========================================================================
    # LINUX PATH  (--target-os linux, the default)
    # =========================================================================
    # Establish SSH connection
    # -------------------------------------------------------------------------
    ssh_port = args.port if args.port is not None else 22
    ssh = paramiko.SSHClient()

    # Security warning: AutoAddPolicy trusts new host keys on first connection
    # without verification. For production use, configure known_hosts and use
    # RejectPolicy, or pin the expected host key fingerprint.
    log.warning(
        "SSH host key policy is set to AutoAddPolicy (Trust On First Use). "
        "Ensure you trust the host %s before proceeding, or configure known_hosts.",
        args.hostname,
    )
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log.info("Connecting to %s@%s:%d…", args.username, args.hostname, ssh_port)
        ssh.connect(
            hostname=args.hostname,
            port=ssh_port,
            username=args.username,
            password=password,
            key_filename=args.key_filename,
            timeout=10,
        )
        log.info("Connection established.")
    except paramiko.AuthenticationException:
        log.error("Authentication failed. Check username / password / key.")
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        combined = {}
        file_perms_data = {}

        if required_collectors is None:
            # Full audit mode — run all collectors across Sections 1 through 7
            log.info("Collecting remote SSH data (CIS 5.1)…")
            combined.update(collect_ssh_from_ssh(ssh, args.hostname, ssh_port, password))

            log.info("Collecting remote privilege escalation data (CIS 5.2)…")
            combined["privilege_escalation"] = collect_privilege_escalation_from_ssh(ssh, password)

            log.info("Collecting remote file permissions data (CIS 7.1)…")
            file_perms_data = collect_file_permissions_from_ssh(ssh, password)
            combined["file_permissions"] = file_perms_data

            log.info("Collecting remote user accounts data (CIS 5.4 / 7.2)…")
            combined["user_accounts"] = collect_user_accounts_from_ssh(ssh, password)

            log.info("Collecting remote firewall data (CIS 4.1)…")
            combined.update(collect_ufw_from_ssh(ssh, password))

            log.info("Collecting remote filesystem data (CIS 1.1)…")
            combined.update(collect_filesystem_from_ssh(ssh, password))

            log.info("Collecting remote package management data (CIS 1.2)…")
            combined.update(collect_package_management_from_ssh(ssh, password))

            log.info("Collecting remote AppArmor data (CIS 1.3)…")
            combined.update(collect_apparmor_from_ssh(ssh, password))

            log.info("Collecting remote bootloader data (CIS 1.4)…")
            combined.update(collect_bootloader_from_ssh(ssh, password))

            log.info("Collecting remote process hardening data (CIS 1.5)…")
            combined.update(collect_process_hardening_from_ssh(ssh, password))

            log.info("Collecting remote warning banners data (CIS 1.6)…")
            combined.update(collect_warning_banners_from_ssh(ssh, password))

            log.info("Collecting remote GNOME data (CIS 1.7)…")
            combined.update(collect_gnome_from_ssh(ssh, password))

            log.info("Collecting remote services data (CIS 2.1 / 2.2)…")
            combined.update(collect_services_from_ssh(ssh, password))

            log.info("Collecting remote time synchronization data (CIS 2.3)…")
            combined.update(collect_time_sync_from_ssh(ssh, password))

            log.info("Collecting remote job schedulers data (CIS 2.4)…")
            combined.update(collect_job_schedulers_from_ssh(ssh, password))

            log.info("Collecting remote network configuration data (CIS 3)…")
            combined.update(collect_network_config_from_ssh(ssh, password))

            log.info("Collecting remote PAM data (CIS 5.3)…")
            combined.update(collect_pam_from_ssh(ssh, password))

            log.info("Collecting remote system logging data (CIS 6.1)…")
            combined.update(collect_system_logging_from_ssh(ssh, password))

            log.info("Collecting remote system auditing data (CIS 6.2)…")
            local_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collectors", "auditd_collector.py")
            combined.update(run_collector_over_ssh(ssh=ssh, script_path=local_script, password=password, timeout=60, fallback_key="system_auditing"))

            log.info("Collecting remote integrity checking data (CIS 6.3)…")
            combined.update(collect_integrity_checking_from_ssh(ssh, password))
        else:
            # Filtered audit mode — run only required collectors
            if "ssh" in required_collectors:
                log.info("Collecting remote SSH data…")
                combined.update(collect_ssh_from_ssh(ssh, args.hostname, ssh_port, password))

            if "privilege_escalation" in required_collectors:
                log.info("Collecting remote privilege escalation data…")
                combined["privilege_escalation"] = collect_privilege_escalation_from_ssh(ssh, password)

            if "file_permissions" in required_collectors:
                log.info("Collecting remote file permissions data (CIS 7.1)…")
                file_perms_data = collect_file_permissions_from_ssh(ssh, password)
                combined["file_permissions"] = file_perms_data

            if "user_accounts" in required_collectors:
                log.info("Collecting remote user accounts data (CIS 5.4 / 7.2)…")
                combined["user_accounts"] = collect_user_accounts_from_ssh(ssh, password)

            if "ufw" in required_collectors:
                log.info("Collecting remote firewall data (CIS 4.1)…")
                combined.update(collect_ufw_from_ssh(ssh, password))

            if "filesystem" in required_collectors:
                log.info("Collecting remote filesystem data (CIS 1.1)…")
                combined.update(collect_filesystem_from_ssh(ssh, password))

            if "package_management" in required_collectors:
                log.info("Collecting remote package management data (CIS 1.2)…")
                combined.update(collect_package_management_from_ssh(ssh, password))

            if "apparmor" in required_collectors:
                log.info("Collecting remote AppArmor data (CIS 1.3)…")
                combined.update(collect_apparmor_from_ssh(ssh, password))

            if "bootloader" in required_collectors:
                log.info("Collecting remote bootloader data (CIS 1.4)…")
                combined.update(collect_bootloader_from_ssh(ssh, password))

            if "process_hardening" in required_collectors:
                log.info("Collecting remote process hardening data (CIS 1.5)…")
                combined.update(collect_process_hardening_from_ssh(ssh, password))

            if "warning_banners" in required_collectors:
                log.info("Collecting remote warning banners data (CIS 1.6)…")
                combined.update(collect_warning_banners_from_ssh(ssh, password))

            if "gnome" in required_collectors:
                log.info("Collecting remote GNOME data (CIS 1.7)…")
                combined.update(collect_gnome_from_ssh(ssh, password))

            if "services" in required_collectors:
                log.info("Collecting remote services data (CIS 2.1 / 2.2)…")
                combined.update(collect_services_from_ssh(ssh, password))

            if "time_sync" in required_collectors:
                log.info("Collecting remote time synchronization data (CIS 2.3)…")
                combined.update(collect_time_sync_from_ssh(ssh, password))

            if "job_schedulers" in required_collectors:
                log.info("Collecting remote job schedulers data (CIS 2.4)…")
                combined.update(collect_job_schedulers_from_ssh(ssh, password))

            if "network_config" in required_collectors:
                log.info("Collecting remote network configuration data (CIS 3)…")
                combined.update(collect_network_config_from_ssh(ssh, password))

            if "pam" in required_collectors:
                log.info("Collecting remote PAM data (CIS 5.3)…")
                combined.update(collect_pam_from_ssh(ssh, password))

            if "system_logging" in required_collectors:
                log.info("Collecting remote system logging data (CIS 6.1)…")
                combined.update(collect_system_logging_from_ssh(ssh, password))

            if "auditd" in required_collectors:
                log.info("Collecting remote system auditing data (CIS 6.2)…")
                local_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collectors", "auditd_collector.py")
                combined.update(run_collector_over_ssh(ssh=ssh, script_path=local_script, password=password, timeout=60, fallback_key="system_auditing"))

            if "integrity_checking" in required_collectors:
                log.info("Collecting remote integrity checking data (CIS 6.3)…")
                combined.update(collect_integrity_checking_from_ssh(ssh, password))

    finally:
        ssh.close()
        log.info("SSH connection closed.")

    # Merge all profiles into one JSON document
    print(json.dumps(combined, indent=2))

    # -------------------------------------------------------------------------
    # Step 8 – AI compliance audit against CIS benchmarks
    # -------------------------------------------------------------------------
    cis_rules_path = args.cis_rules or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "cis_extracted_rules.md"
    )
    report = ""
    if os.path.isfile(cis_rules_path):
        log.info("Running CIS compliance audit using %s…", cis_rules_path)
        cis_rules_text = open(cis_rules_path, encoding="utf-8").read()
        report = generate_compliance_report(json.dumps(combined, indent=2), cis_rules_text, requested_rules=requested_rules)
        log.info("\n" + "=" * 70 + "\n  CIS BENCHMARK COMPLIANCE REPORT\n" + "=" * 70)
        print(report, file=sys.stderr)
    else:
        log.warning("CIS rules file not found at: %s", cis_rules_path)
        log.warning("Skipping compliance audit. Use --cis-rules to specify the path.")

    suid_sgid_section = file_perms_data.get("suid_sgid", {})
    suid_report = ""
    should_run_suid = (requested_rules is None) or any(r == "7.1.13" or r.startswith("7.1") or r.startswith("7.") for r in requested_rules)
    if should_run_suid and suid_sgid_section.get("suid_sgid_files"):
        log.info("Running SUID/SGID triage analysis (CIS 7.1.13)…")
        suid_report = analyze_suid_sgid(suid_sgid_section)
        log.info("\n" + "=" * 70 + "\n  SUID/SGID TRIAGE REPORT\n" + "=" * 70)
        print(suid_report, file=sys.stderr)
    elif should_run_suid:
        log.info("No SUID/SGID files collected — skipping triage.")

    save_reports_to_pdf(combined, cis_report=report, suid_report=suid_report,
                        output_dir=args.output_dir, prefix=output_prefix)


if __name__ == "__main__":
    main()

