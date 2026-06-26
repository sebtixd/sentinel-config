"""
main.py
=======
Connects to a remote Linux machine via SSH, collects FTP-related
system data remotely, then uses ftp_parser to produce a structured
JSON security profile of the remote FTP configuration.
"""

import argparse
import getpass
import json
import sys

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


def remote_run(ssh: paramiko.SSHClient, cmd: str, timeout: int = 10) -> str:
    """Execute a command on the remote machine and return its stdout."""
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def main() -> None:
    # -------------------------------------------------------------------------
    # Argument parsing
    # -------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Audit the FTP security configuration of a remote Linux machine."
    )
    parser.add_argument("username",          help="SSH username")
    parser.add_argument("hostname",          help="Remote hostname or IP address")
    parser.add_argument("--port",            type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--password",        default=None,
                        help="SSH password (prompted if omitted)")
    parser.add_argument("--key-filename",    default=None,
                        help="Path to SSH private key file")
    args = parser.parse_args()

    # Prompt for password securely if neither a password nor a key was given
    password = args.password
    if not args.key_filename and not password:
        password = getpass.getpass(
            f"SSH password for {args.username}@{args.hostname}: "
        )

    # -------------------------------------------------------------------------
    # Establish SSH connection
    # -------------------------------------------------------------------------
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[*] Connecting to {args.username}@{args.hostname}:{args.port}…", file=sys.stderr)
        ssh.connect(
            hostname=args.hostname,
            port=args.port,
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
        fw_out = remote_run(ssh, "sudo -n ufw status verbose 2>/dev/null")
        if not fw_out.strip():
            fw_out = remote_run(ssh, "sudo -n iptables -L -n 2>/dev/null")
        if not fw_out.strip():
            fw_out = remote_run(ssh, "sudo -n firewall-cmd --list-all 2>/dev/null")

        # Active connections
        activity_out = remote_run(ssh, "ss -tnp 2>/dev/null")

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
        # sshd -T requires root or for the user to be able to read sshd_config
        sshd_out = remote_run(ssh, "sudo -n sshd -T 2>/dev/null")
        if not sshd_out.strip():
            sshd_out = remote_run(ssh, "sshd -T 2>/dev/null")

    finally:
        ssh.close()
        print("[*] SSH connection closed.", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 5 – Run local ssh-audit against the remote host
    # -------------------------------------------------------------------------
    print(f"[*] Running local ssh-audit against {args.hostname}:{args.port}…", file=sys.stderr)
    try:
        import subprocess
        # We run ssh-audit locally because it's a network scanner
        # and might not be installed on the remote target.
        audit_res = subprocess.run(
            ["ssh-audit", "-p", str(args.port), args.hostname],
            capture_output=True,
            text=True,
            timeout=30
        )
        ssh_audit_out = audit_res.stdout
    except Exception as e:
        print(f"[warn] ssh-audit failed: {e}", file=sys.stderr)
        ssh_audit_out = ""

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

    ssh_profile = parse_ssh_data(
        sshd_output=sshd_out,
        ssh_audit_output=ssh_audit_out,
    )

    # Merge all profiles into one JSON document
    combined = {**ftp_profile, **telnet_profile, **ssh_profile}
    print(json.dumps(combined, indent=2))


if __name__ == "__main__":
    main()
