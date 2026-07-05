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
import sys
import time

try:
    import paramiko
except ImportError:
    print("Error: 'paramiko' is not installed. Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)

# Import parse_ftp_data directly so we don't need a subprocess pipe.
# ftp_parser.py must be in the same directory.
try:
    from tools.ftp_parser import parse_ftp_data
except ImportError:
    print("Error: 'ftp_parser.py' not found in tools/.", file=sys.stderr)
    sys.exit(1)

try:
    from tools.telnet_parser import parse_telnet_data
except ImportError:
    print("Error: 'telnet_parser.py' not found in tools/.", file=sys.stderr)
    sys.exit(1)

try:
    from tools.ssh_audit_parser import build_security_profile as parse_ssh_data
except ImportError:
    print("Error: 'ssh_audit_parser.py' not found in tools/.", file=sys.stderr)
    sys.exit(1)

try:
    import winrm
    from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
except ImportError:
    print("Error: 'pywinrm' is not installed. Run: pip install pywinrm", file=sys.stderr)
    sys.exit(1)

try:
    from tools.secedit_parser import parse_password_policy
except ImportError:
    print("Error: 'secedit_parser.py' not found in tools/.", file=sys.stderr)
    sys.exit(1)

import os
from dotenv import load_dotenv
load_dotenv()  # load .env into os.environ before reading keys

from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types
_raw_keys = [
    os.environ.get("GEMINI-API-KEY"),
    os.environ.get("GEMINI-API-KEY2"),
    os.environ.get("GEMINI-API-KEY3"),
]
CLIENTS = [genai.Client(api_key=k) for k in _raw_keys if k]
if not CLIENTS:
    raise RuntimeError("No GEMINI API keys found in .env")

MODELS = ["gemini-2.5-flash", "gemini-2.0-flash"]

def generate_with_retry(max_retries=3, **kwargs):
    """Rotate through API keys, then model fallbacks, on 503/429 errors."""
    for model in MODELS:
        for key_idx, api_client in enumerate(CLIENTS):
            for attempt in range(max_retries):
                try:
                    return api_client.models.generate_content(model=model, **kwargs)
                except (genai_errors.ServerError, genai_errors.ClientError) as e:
                    # Safely get status code
                    s_code = getattr(e, 'status_code', None) or getattr(e, 'code', None)
                    
                    # 503 = Service Unavailable, 429 = Rate Limit
                    is_transient = s_code in (503, 429)
                    if not is_transient:
                        raise
                    
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        reason = "unavailable" if s_code == 503 else "rate-limited"
                        print(f"[retry] Key {key_idx + 1}/{len(CLIENTS)}, model={model} {reason} (attempt {attempt + 1}/{max_retries}). Retrying in {wait}s...")
                        time.sleep(wait)
                    else:
                        print(f"[rotate] Key {key_idx + 1} exhausted ({s_code}) for {model}, trying next key...")
                        break  # move to next key
        print(f"[fallback] All keys exhausted for {model}, switching model...")
    raise RuntimeError("All API keys and models exhausted. Please try again later.")


def generate_compliance_report(profile_json: str, cis_rules: str) -> str:
    """Send the security profile + CIS rules to Gemini for compliance analysis."""
    prompt = f"""You are a security compliance auditor.

Below are the CIS Ubuntu 24.04 LTS Benchmark rules for FTP, Telnet, and SSH:

--- CIS RULES ---
{cis_rules}
--- END CIS RULES ---

Below is the security profile collected from the remote machine (JSON):

--- SECURITY PROFILE ---
{profile_json}
--- END SECURITY PROFILE ---

For each CIS rule listed above, determine whether the machine's configuration PASSES or FAILS.
Output a structured compliance report with:
- Rule ID and title
- Status: PASS / FAIL / UNKNOWN (if data is insufficient to determine)
- Evidence: the relevant value(s) from the profile that justify the verdict
- Recommendation: what to fix if the status is FAIL

Be concise but precise. Group results by FTP, Telnet, and SSH sections."""

    response = generate_with_retry(
        contents=prompt,
        config=genai_types.GenerateContentConfig(temperature=0.1),
    )
    return response.text




def remote_run(ssh: paramiko.SSHClient, cmd: str, timeout: int = 10) -> str:
    """Execute a command on the remote machine and return its stdout."""
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def remote_run_sudo(ssh: paramiko.SSHClient, cmd: str, password: str = "", timeout: int = 10) -> str:
    """Execute a command on the remote machine via sudo -S and return its stdout."""
    if not password:
        sudo_cmd = f"sudo -n {cmd}"
    else:
        sudo_cmd = f"sudo -S {cmd}"
    try:
        stdin, stdout, stderr = ssh.exec_command(sudo_cmd, timeout=timeout)
        if password:
            stdin.write(password + "\n")
            stdin.flush()
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def main() -> None:
    # -------------------------------------------------------------------------
    # Argument parsing
    # -------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Audit the security configuration of a remote Linux or Windows machine."
    )
    parser.add_argument("username",          help="SSH/WinRM username")
    parser.add_argument("hostname",          help="Remote hostname or IP address")
    parser.add_argument("--port",            type=int, default=None,
                        help="Port (default: 22 for SSH, 5985 for WinRM HTTP, 5986 for WinRM HTTPS)")
    parser.add_argument("--password",        default=None,
                        help="SSH/WinRM password (prompted if omitted)")
    parser.add_argument("--key-filename",    default=None,
                        help="Path to SSH private key file (Linux only)")
    parser.add_argument("--cis-rules",       default=None,
                        help="Path to CIS benchmark rules markdown file "
                             "(default: cis_extracted_rules.md for Linux, "
                             "password-policy.md for Windows)")
    parser.add_argument("--target-os",       choices=["linux", "windows"], default="linux",
                        help="Target OS to audit (default: linux)")
    args = parser.parse_args()

    # Prompt for password securely if neither a password nor a key was given
    password = args.password
    if not args.key_filename and not password:
        prompt_label = "WinRM" if args.target_os == "windows" else "SSH"
        password = getpass.getpass(
            f"{prompt_label} password for {args.username}@{args.hostname}: "
        )

    # =========================================================================
    # WINDOWS PATH  (--target-os windows)
    # =========================================================================
    if args.target_os == "windows":
        win_port = args.port if args.port is not None else 5985
        win_endpoint = f"http://{args.hostname}:{win_port}/wsman"
        print(f"[*] Connecting to {args.username}@{args.hostname} via WinRM…", file=sys.stderr)
        try:
            win_session = winrm.Session(win_endpoint, auth=(args.username, password), transport="ntlm")
        except (WinRMTransportError, WinRMOperationTimeoutError) as exc:
            print(f"[-] WinRM connection error: {exc}", file=sys.stderr)
            sys.exit(1)
        print("[+] WinRM session established.", file=sys.stderr)

        # -- secedit export --
        temp_file = r"C:\Windows\Temp\sentinel_secpol.cfg"
        print("[*] Running secedit export…", file=sys.stderr)
        try:
            r = win_session.run_cmd("secedit", ["/export", "/cfg", temp_file, "/quiet"])
        except (WinRMTransportError, WinRMOperationTimeoutError) as exc:
            print(f"[-] WinRM error during secedit export: {exc}", file=sys.stderr)
            sys.exit(1)
        if r.status_code != 0:
            print(f"[-] secedit export failed (exit {r.status_code}): {r.std_err.decode('utf-8', errors='replace')}",
                  file=sys.stderr)
            sys.exit(1)

        # -- read the exported file --
        print("[*] Reading back secedit output…", file=sys.stderr)
        try:
            r = win_session.run_cmd("type", [temp_file])
        except (WinRMTransportError, WinRMOperationTimeoutError) as exc:
            print(f"[-] WinRM error reading secedit output: {exc}", file=sys.stderr)
            sys.exit(1)
        if r.status_code != 0:
            print(f"[-] Failed to read secedit file (exit {r.status_code})", file=sys.stderr)
            sys.exit(1)
        try:
            secedit_raw = r.std_out.decode("utf-8")
        except UnicodeDecodeError:
            secedit_raw = r.std_out.decode("cp1252", errors="replace")

        # -- cleanup: ignore failures --
        try:
            win_session.run_cmd("del", [temp_file])
        except Exception:
            print("[warn] Cleanup of remote temp file failed — continuing.", file=sys.stderr)
        print("[+] Password policy data collected.", file=sys.stderr)

        # -- parse and merge --
        password_policy_data = parse_password_policy(secedit_raw)
        combined = {"password_policy": password_policy_data}
        print(json.dumps(combined, indent=2))

        # -- CIS compliance report --
        cis_rules_path = args.cis_rules or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "password-policy.md"
        )
        if os.path.isfile(cis_rules_path):
            print(f"\n[*] Running CIS compliance audit using {cis_rules_path}…", file=sys.stderr)
            cis_rules_text = open(cis_rules_path, encoding="utf-8").read()
            report = generate_compliance_report(json.dumps(combined, indent=2), cis_rules_text)
            print("\n" + "=" * 70, file=sys.stderr)
            print("  CIS BENCHMARK COMPLIANCE REPORT", file=sys.stderr)
            print("=" * 70 + "\n", file=sys.stderr)
            print(report, file=sys.stderr)
        else:
            print(f"[warn] CIS rules file not found at: {cis_rules_path}", file=sys.stderr)
            print("[warn] Skipping compliance audit. Use --cis-rules to specify the path.", file=sys.stderr)
        return

    # =========================================================================
    # LINUX PATH  (--target-os linux, the default)
    # =========================================================================
    # Establish SSH connection
    # -------------------------------------------------------------------------
    ssh_port = args.port if args.port is not None else 22
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[*] Connecting to {args.username}@{args.hostname}:{ssh_port}…", file=sys.stderr)
        ssh.connect(
            hostname=args.hostname,
            port=ssh_port,
            username=args.username,
            password=password,
            key_filename=args.key_filename,
            timeout=10,
        )
        print("[+] Connection established.", file=sys.stderr)
    except paramiko.AuthenticationException:
        print("[-] Authentication failed. Check username / password / key.", file=sys.stderr)
        sys.exit(1)
    except paramiko.SSHException as exc:
        print(f"[-] SSH error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[-] Connection error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        # -------------------------------------------------------------------------
        # Step 1 – Check if an FTP service is installed on the remote machine
        # -------------------------------------------------------------------------
        print("[*] Checking for FTP service on remote…", file=sys.stderr)
        svc_check = remote_run(
            ssh,
            "systemctl list-unit-files 2>/dev/null | grep -E '^(vsftpd|proftpd|pure-ftpd)\\.service' || "
            "dpkg -l 2>/dev/null | awk '/^ii/ && /(vsftpd|proftpd|pure-ftpd)/' || "
            "rpm -qa 2>/dev/null | grep -E '^(vsftpd|proftpd|pure-ftpd)'"
        )
        if not svc_check.strip():
            print("[-] No FTP service (vsftpd/proftpd/pure-ftpd) found on the remote machine.",
                  file=sys.stderr)
            sys.exit(1)
        print("[+] FTP service detected.", file=sys.stderr)

        # -------------------------------------------------------------------------
        # Step 2 – Collect all data remotely (mirrors what ftp_parser.py CLI does)
        # -------------------------------------------------------------------------
        print("[*] Collecting remote FTP data…", file=sys.stderr)

        # systemctl status for any FTP service
        systemctl_out = ""
        for svc in ("vsftpd", "proftpd", "pure-ftpd"):
            out = remote_run(ssh, f"systemctl status {svc} 2>/dev/null")
            if out.strip():
                systemctl_out = out
                break

        # Network sockets
        network_out = remote_run(ssh, "ss -tulpn 2>/dev/null")
        if not network_out.strip():
            network_out = remote_run(ssh, "netstat -tulpn 2>/dev/null")

        # Configuration file
        config_out = remote_run(ssh, "cat /etc/vsftpd.conf 2>/dev/null")
        if not config_out.strip():
            config_out = remote_run(ssh, "cat /etc/proftpd/proftpd.conf 2>/dev/null")
        if not config_out.strip():
            config_out = remote_run(ssh, "cat /etc/pure-ftpd.conf 2>/dev/null")

        # Firewall rules (requires sudo on the remote machine)
        fw_out = remote_run_sudo(ssh, "ufw status verbose 2>/dev/null", password)
        if not fw_out.strip():
            fw_out = remote_run_sudo(ssh, "iptables -L -n 2>/dev/null", password)
        if not fw_out.strip():
            fw_out = remote_run_sudo(ssh, "firewall-cmd --list-all 2>/dev/null", password)

        # Active connections
        activity_out = remote_run(ssh, "ss -tnp 2>/dev/null")

        # CIS 2.1.20 – TFTP server check
        tftp_pkg_out = remote_run(ssh, "dpkg -l 'tftpd*' 'atftpd' 'tftp-hpa' 2>/dev/null")
        if not tftp_pkg_out.strip():
            tftp_pkg_out = remote_run(ssh, "rpm -qa 2>/dev/null | grep -iE 'tftp'")
        tftp_systemctl_out = ""
        for svc in ("tftpd-hpa", "atftpd", "tftp"):
            out = remote_run(ssh, f"systemctl status {svc} 2>/dev/null")
            if out.strip():
                tftp_systemctl_out = out
                break

        # CIS 2.2.6 – FTP client check
        ftp_client_out = remote_run(ssh, "dpkg -l 'ftp' 'lftp' 'ncftp' 'curl' 2>/dev/null | grep '^ii'")
        if not ftp_client_out.strip():
            ftp_client_out = remote_run(ssh, "rpm -qa 2>/dev/null | grep -iE '^ftp-|^lftp|^ncftp'")

        # -------------------------------------------------------------------------
        # Step 3 – Collect Telnet data remotely
        # -------------------------------------------------------------------------
        print("[*] Collecting remote Telnet data…", file=sys.stderr)

        # systemctl: try telnet, telnetd, then telnet.socket
        telnet_systemctl_out = ""
        for unit in ("telnet", "telnetd", "telnet.socket"):
            out = remote_run(ssh, f"systemctl status {unit} 2>/dev/null")
            if out.strip():
                telnet_systemctl_out = out
                break

        # Package manager
        telnet_pkg_out = remote_run(ssh, "dpkg -l 'telnet*' 2>/dev/null")
        if not telnet_pkg_out.strip():
            telnet_pkg_out = remote_run(ssh, "rpm -q telnet telnetd 2>/dev/null")

        # CIS 2.2.4 – Telnet client check (separate from server packages)
        telnet_client_out = remote_run(ssh, "dpkg -l 'telnet' 2>/dev/null | grep '^ii'")
        if not telnet_client_out.strip():
            telnet_client_out = remote_run(ssh, "rpm -q telnet 2>/dev/null")

        # Network sockets — reuse the same ss output from FTP (same command)
        telnet_network_out = network_out

        # inetd / xinetd config files
        inetd_out   = remote_run(ssh, "cat /etc/inetd.conf 2>/dev/null")
        xinetd_out  = remote_run(ssh, "cat /etc/xinetd.d/telnet 2>/dev/null")

        # Check if inetd daemon itself is running (openbsd-inetd on Ubuntu/Debian)
        inetd_systemctl_out = ""
        for inetd_unit in ("openbsd-inetd", "inetd"):
            out = remote_run(ssh, f"systemctl status {inetd_unit} 2>/dev/null")
            if out.strip():
                inetd_systemctl_out = out
                break

        # Firewall — reuse fw_out from FTP collection
        telnet_fw_out = fw_out

        # Active sessions
        sessions_out = remote_run(ssh, "who 2>/dev/null")
        if not sessions_out.strip():
            sessions_out = remote_run(ssh, "w 2>/dev/null")

        # -------------------------------------------------------------------------
        # Step 4 – Collect SSH data
        # -------------------------------------------------------------------------
        print("[*] Collecting remote SSH data (sshd -T)…", file=sys.stderr)
        _sshd_attempts = [
            "/usr/sbin/sshd -T",
            "sshd -T",
            "cat /etc/ssh/sshd_config",
        ]
        sshd_out = ""
        for _cmd in _sshd_attempts:
            sshd_out = remote_run_sudo(ssh, _cmd, password)
            if sshd_out.strip():
                if "cat /etc/ssh/sshd_config" in _cmd:
                    dropin = remote_run_sudo(ssh, "cat /etc/ssh/sshd_config.d/*.conf", password)
                    if dropin.strip():
                        sshd_out += "\n" + dropin
                break

        # CIS 5.1.1/5.1.2/5.1.3 – File permission checks for SSH config and host keys
        print("[*] Collecting SSH file permissions…", file=sys.stderr)
        ssh_config_perms = remote_run_sudo(
            ssh, "stat -c '%a %U %G %n' /etc/ssh/sshd_config", password
        )
        ssh_privkey_perms = remote_run_sudo(
            ssh, "stat -c '%a %U %G %n' /etc/ssh/ssh_host_*_key", password
        )
        ssh_pubkey_perms = remote_run_sudo(
            ssh, "stat -c '%a %U %G %n' /etc/ssh/ssh_host_*_key.pub", password
        )

    finally:
        ssh.close()
        print("[*] SSH connection closed.", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 5 – Run local ssh-audit against the remote host
    # -------------------------------------------------------------------------
    print(f"[*] Running local ssh-audit against {args.hostname}:{ssh_port}…", file=sys.stderr)
    ssh_audit_out = ""
    try:
        import subprocess
        _audit_res = subprocess.run(
            ["ssh-audit", "-n", "-p", str(ssh_port), args.hostname],
            capture_output=True, text=True, timeout=30,
        )
        ssh_audit_out = _audit_res.stdout
    except Exception as e:
        print(f"[warn] ssh-audit failed: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 6 – Parse and print all profiles merged in a single JSON object
    # -------------------------------------------------------------------------
    ftp_profile = parse_ftp_data(
        systemctl_raw=systemctl_out,
        network_raw=network_out,
        config_raw=config_out,
        firewall_raw=fw_out,
        activity_raw=activity_out,
    )
    # Embed TFTP and FTP-client data directly so AI can evaluate CIS 2.1.20 and 2.2.6
    ftp_profile.setdefault("ftp", {})
    ftp_profile["ftp"]["tftp_server_packages"] = tftp_pkg_out.strip() or "not installed"
    ftp_profile["ftp"]["tftp_service_status"]  = tftp_systemctl_out.strip() or "not running"
    ftp_profile["ftp"]["ftp_client_packages"]  = ftp_client_out.strip() or "not installed"

    telnet_profile = parse_telnet_data(
        systemctl_raw=telnet_systemctl_out,
        package_raw=telnet_pkg_out,
        network_raw=telnet_network_out,
        inetd_raw=inetd_out,
        xinetd_raw=xinetd_out,
        firewall_raw=telnet_fw_out,
        sessions_raw=sessions_out,
        inetd_systemctl_raw=inetd_systemctl_out,
    )
    # Embed telnet-client data so AI can evaluate CIS 2.2.4
    telnet_profile.setdefault("telnet", {})
    telnet_profile["telnet"]["telnet_client_packages"] = telnet_client_out.strip() or "not installed"

    ssh_profile = parse_ssh_data(
        sshd_output=sshd_out,
        ssh_audit_output=ssh_audit_out,
    )
    # Embed SSH file permission data so AI can evaluate CIS 5.1.1/5.1.2/5.1.3
    ssh_profile.setdefault("ssh", {})
    ssh_profile["ssh"]["sshd_config_permissions"]  = ssh_config_perms.strip() or "unknown"
    ssh_profile["ssh"]["ssh_privkey_permissions"]  = ssh_privkey_perms.strip() or "unknown"
    ssh_profile["ssh"]["ssh_pubkey_permissions"]   = ssh_pubkey_perms.strip() or "unknown"

    # Merge all profiles into one JSON document
    combined = {**ftp_profile, **telnet_profile, **ssh_profile}
    print(json.dumps(combined, indent=2))

    # -------------------------------------------------------------------------
    # Step 7 – AI compliance audit against CIS benchmarks
    # -------------------------------------------------------------------------
    cis_rules_path = args.cis_rules or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "cis_extracted_rules.md"
    )  # Windows default already handled in the windows branch above
    if os.path.isfile(cis_rules_path):
        print(f"\n[*] Running CIS compliance audit using {cis_rules_path}…", file=sys.stderr)
        cis_rules_text = open(cis_rules_path, encoding="utf-8").read()
        report = generate_compliance_report(json.dumps(combined, indent=2), cis_rules_text)
        print("\n" + "=" * 70, file=sys.stderr)
        print("  CIS BENCHMARK COMPLIANCE REPORT", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)
        print(report, file=sys.stderr)
    else:
        print(f"[warn] CIS rules file not found at: {cis_rules_path}", file=sys.stderr)
        print("[warn] Skipping compliance audit. Use --cis-rules to specify the path.", file=sys.stderr)


if __name__ == "__main__":
    main()
