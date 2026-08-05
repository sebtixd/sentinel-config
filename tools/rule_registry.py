"""
rule_registry.py
================
Central registry of implemented CIS Ubuntu Benchmark rules in SENTINEL.
Provides rule parsing, shorthand section expansion, validation, collector mapping,
and report filtering logic.
"""

from __future__ import annotations
import difflib
import re
from typing import Dict, List, Set, Tuple

# Mapping of implemented Rule ID -> (Title, Collector Key)
# Collector keys:
# 'ssh', 'privilege_escalation', 'file_permissions', 'user_accounts', 'ufw',
# 'filesystem', 'package_management', 'apparmor', 'bootloader', 'process_hardening',
# 'warning_banners', 'gnome', 'services', 'time_sync', 'job_schedulers',
# 'network_config', 'pam', 'system_logging', 'auditd', 'integrity_checking'

RULE_REGISTRY: Dict[str, Tuple[str, str]] = {
    # Section 1.1 - Filesystem Kernel Modules & Partitions
    "1.1.1.1": ("Ensure mounting of cramfs filesystems is disabled", "filesystem"),
    "1.1.1.2": ("Ensure mounting of freevxfs filesystems is disabled", "filesystem"),
    "1.1.1.3": ("Ensure mounting of hfs filesystems is disabled", "filesystem"),
    "1.1.1.4": ("Ensure mounting of hfsplus filesystems is disabled", "filesystem"),
    "1.1.1.5": ("Ensure mounting of jffs2 filesystems is disabled", "filesystem"),
    "1.1.1.6": ("Ensure mounting of overlay filesystems is disabled", "filesystem"),
    "1.1.1.7": ("Ensure mounting of squashfs filesystems is disabled", "filesystem"),
    "1.1.1.8": ("Ensure mounting of udf filesystems is disabled", "filesystem"),
    "1.1.1.9": ("Ensure mounting of firewire-core filesystems is disabled", "filesystem"),
    "1.1.1.10": ("Ensure mounting of usb-storage filesystems is disabled", "filesystem"),
    "1.1.1.11": ("Ensure unused filesystems are kernel modules", "filesystem"),
    "1.1.2.1.1": ("Ensure /tmp is a separate partition", "filesystem"),
    "1.1.2.1.2": ("Ensure nodev option set on /tmp partition", "filesystem"),
    "1.1.2.1.3": ("Ensure nosuid option set on /tmp partition", "filesystem"),
    "1.1.2.1.4": ("Ensure noexec option set on /tmp partition", "filesystem"),
    "1.1.2.2.1": ("Ensure /dev/shm is a separate partition", "filesystem"),
    "1.1.2.2.2": ("Ensure nodev option set on /dev/shm partition", "filesystem"),
    "1.1.2.2.3": ("Ensure nosuid option set on /dev/shm partition", "filesystem"),
    "1.1.2.2.4": ("Ensure noexec option set on /dev/shm partition", "filesystem"),
    "1.1.2.3.1": ("Ensure /home is a separate partition", "filesystem"),
    "1.1.2.3.2": ("Ensure nodev option set on /home partition", "filesystem"),
    "1.1.2.3.3": ("Ensure nosuid option set on /home partition", "filesystem"),
    "1.1.2.4.1": ("Ensure /var is a separate partition", "filesystem"),
    "1.1.2.4.2": ("Ensure nodev option set on /var partition", "filesystem"),
    "1.1.2.4.3": ("Ensure nosuid option set on /var partition", "filesystem"),
    "1.1.2.5.1": ("Ensure /var/tmp is a separate partition", "filesystem"),
    "1.1.2.5.2": ("Ensure nodev option set on /var/tmp partition", "filesystem"),
    "1.1.2.5.3": ("Ensure nosuid option set on /var/tmp partition", "filesystem"),
    "1.1.2.5.4": ("Ensure noexec option set on /var/tmp partition", "filesystem"),
    "1.1.2.6.1": ("Ensure /var/log is a separate partition", "filesystem"),
    "1.1.2.6.2": ("Ensure nodev option set on /var/log partition", "filesystem"),
    "1.1.2.6.3": ("Ensure nosuid option set on /var/log partition", "filesystem"),
    "1.1.2.6.4": ("Ensure noexec option set on /var/log partition", "filesystem"),
    "1.1.2.7.1": ("Ensure /var/log/audit is a separate partition", "filesystem"),
    "1.1.2.7.2": ("Ensure nodev option set on /var/log/audit partition", "filesystem"),
    "1.1.2.7.3": ("Ensure nosuid option set on /var/log/audit partition", "filesystem"),
    "1.1.2.7.4": ("Ensure noexec option set on /var/log/audit partition", "filesystem"),

    # Section 1.2 - Package Management
    "1.2.1.1": ("Ensure package repositories are configured", "package_management"),
    "1.2.1.2": ("Ensure GPG keys are configured", "package_management"),
    "1.2.1.3": ("Ensure GPG key file permissions", "package_management"),
    "1.2.1.4": ("Ensure /etc/apt/trusted.gpg.d permissions", "package_management"),
    "1.2.1.5": ("Ensure /etc/apt/auth.conf.d dir permissions", "package_management"),
    "1.2.1.6": ("Ensure auth.conf.d files permissions", "package_management"),
    "1.2.1.7": ("Ensure /usr/share/keyrings dir permissions", "package_management"),
    "1.2.1.8": ("Ensure /etc/apt/sources.list.d dir permissions", "package_management"),
    "1.2.1.9": ("Ensure sources.list.d files permissions", "package_management"),
    "1.2.2.1": ("Ensure package updates are installed", "package_management"),

    # Section 1.3 - AppArmor
    "1.3.1.1": ("Ensure AppArmor packages are installed", "apparmor"),
    "1.3.1.2": ("Ensure AppArmor is enabled in bootloader", "apparmor"),
    "1.3.1.3": ("Ensure all AppArmor profiles are enforcing", "apparmor"),
    "1.3.1.4": ("Ensure unprivileged unconfined restriction", "apparmor"),

    # Section 1.4 - Bootloader
    "1.4.1": ("Ensure bootloader password is set", "bootloader"),
    "1.4.2": ("Ensure bootloader config permissions", "bootloader"),

    # Section 1.5 - Process Hardening
    "1.5.1": ("Ensure fs.protected_hardlinks is enabled", "process_hardening"),
    "1.5.2": ("Ensure fs.protected_symlinks is enabled", "process_hardening"),
    "1.5.3": ("Ensure kernel.yama.ptrace_scope is enabled", "process_hardening"),
    "1.5.4": ("Ensure fs.suid_dumpable is disabled", "process_hardening"),
    "1.5.5": ("Ensure kernel.dmesg_restrict is enabled", "process_hardening"),
    "1.5.6": ("Ensure prelink is not installed", "process_hardening"),
    "1.5.7": ("Ensure Automatic Error Reporting (Apport) is disabled", "process_hardening"),
    "1.5.8": ("Ensure kernel.kptr_restrict is enabled", "process_hardening"),
    "1.5.9": ("Ensure kernel.randomize_va_space is enabled", "process_hardening"),
    "1.5.10": ("Ensure core dumps are restricted", "process_hardening"),
    "1.5.11": ("Ensure systemd-coredump ProcessSizeMax is configured", "process_hardening"),
    "1.5.12": ("Ensure systemd-coredump Storage is configured", "process_hardening"),

    # Section 1.6 - Warning Banners
    "1.6.1": ("Ensure /etc/motd is configured", "warning_banners"),
    "1.6.2": ("Ensure /etc/issue is configured", "warning_banners"),
    "1.6.3": ("Ensure /etc/issue.net is configured", "warning_banners"),
    "1.6.4": ("Ensure pam_motd is configured", "warning_banners"),
    "1.6.5": ("Ensure sshd warning Banner is configured", "ssh"),
    "1.6.6": ("Ensure access to /etc/motd is configured", "warning_banners"),
    "1.6.7": ("Ensure access to /etc/issue is configured", "warning_banners"),
    "1.6.8": ("Ensure access to /etc/issue.net is configured", "warning_banners"),
    "1.6.9": ("Ensure access to pam_motd files is configured", "warning_banners"),
    "1.6.10": ("Ensure access to sshd warning banner is configured", "ssh"),

    # Section 1.7 - GNOME Display Manager
    "1.7.1": ("Ensure GDM login banner is configured", "gnome"),
    "1.7.2": ("Ensure GDM disable-user-list is enabled", "gnome"),
    "1.7.3": ("Ensure GDM screen lock is configured", "gnome"),
    "1.7.4": ("Ensure GDM automounting is disabled", "gnome"),
    "1.7.5": ("Ensure GDM autorun-never is enabled", "gnome"),
    "1.7.6": ("Ensure XDMCP is disabled", "gnome"),
    "1.7.7": ("Ensure Xwayland is configured", "gnome"),

    # Section 2.1 & 2.2 - Services (Server & Client)
    "2.1.1": ("Ensure autofs services are not in use", "services"),
    "2.1.2": ("Ensure MTA is configured for local-only mode", "services"),
    "2.1.3": ("Ensure avahi services are not in use", "services"),
    "2.1.4": ("Ensure only approved services are listening", "services"),
    "2.1.5": ("Ensure dhcp server services are not in use", "services"),
    "2.1.6": ("Ensure web server services are not in use", "services"),
    "2.1.7": ("Ensure dns server services are not in use", "services"),
    "2.1.8": ("Ensure ftp server services are not in use", "services"),
    "2.1.9": ("Ensure dnsmasq services are not in use", "services"),
    "2.1.10": ("Ensure ldap server services are not in use", "services"),
    "2.1.11": ("Ensure imap/pop3 server services are not in use", "services"),
    "2.1.12": ("Ensure nfs server services are not in use", "services"),
    "2.1.13": ("Ensure nis server services are not in use", "services"),
    "2.1.14": ("Ensure cups print server services are not in use", "services"),
    "2.1.15": ("Ensure rpcbind services are not in use", "services"),
    "2.1.16": ("Ensure rsync daemon services are not in use", "services"),
    "2.1.17": ("Ensure samba services are not in use", "services"),
    "2.1.18": ("Ensure snmpd services are not in use", "services"),
    "2.1.19": ("Ensure telnet server services are not in use", "services"),
    "2.1.20": ("Ensure tftp server services are not in use", "services"),
    "2.1.21": ("Ensure squid proxy services are not in use", "services"),
    "2.1.22": ("Ensure xinetd services are not in use", "services"),
    "2.1.23": ("Ensure X window server services are not in use", "services"),
    "2.2.1": ("Ensure nis client is not installed", "services"),
    "2.2.2": ("Ensure rsh client is not installed", "services"),
    "2.2.3": ("Ensure talk client is not installed", "services"),
    "2.2.4": ("Ensure telnet client is not installed", "services"),
    "2.2.5": ("Ensure ldap-utils is not installed", "services"),
    "2.2.6": ("Ensure ftp client is not installed", "services"),

    # Section 2.3 - Time Synchronization
    "2.3.1.1": ("Ensure single time sync daemon is in use", "time_sync"),
    "2.3.2.1": ("Ensure systemd-timesyncd timeserver is configured", "time_sync"),
    "2.3.2.2": ("Ensure systemd-timesyncd is enabled and active", "time_sync"),
    "2.3.3.1": ("Ensure chrony timeserver is configured", "time_sync"),
    "2.3.3.2": ("Ensure chrony process user is configured", "time_sync"),
    "2.3.3.3": ("Ensure chrony is enabled and active", "time_sync"),

    # Section 2.4 - Job Schedulers
    "2.4.1.1": ("Ensure cron daemon is enabled and active", "job_schedulers"),
    "2.4.1.2": ("Ensure access to /etc/crontab is configured", "job_schedulers"),
    "2.4.1.3": ("Ensure access to /etc/cron.hourly is configured", "job_schedulers"),
    "2.4.1.4": ("Ensure access to /etc/cron.daily is configured", "job_schedulers"),
    "2.4.1.5": ("Ensure access to /etc/cron.weekly is configured", "job_schedulers"),
    "2.4.1.6": ("Ensure access to /etc/cron.monthly is configured", "job_schedulers"),
    "2.4.1.7": ("Ensure access to /etc/cron.yearly is configured", "job_schedulers"),
    "2.4.1.8": ("Ensure access to /etc/cron.d is configured", "job_schedulers"),
    "2.4.1.9": ("Ensure access to crontab mechanism is restricted", "job_schedulers"),
    "2.4.2.1": ("Ensure access to at configured", "job_schedulers"),

    # Section 3 - Network Configuration
    "3.1.1": ("Ensure IPv6 status is identified", "network_config"),
    "3.1.2": ("Ensure wireless interfaces are not available", "network_config"),
    "3.1.3": ("Ensure Bluetooth services are not in use", "network_config"),
    "3.2.1": ("Ensure mounting of atm kernel module is disabled", "network_config"),
    "3.2.2": ("Ensure mounting of can kernel module is disabled", "network_config"),
    "3.2.3": ("Ensure mounting of dccp kernel module is disabled", "network_config"),
    "3.2.4": ("Ensure mounting of rds kernel module is disabled", "network_config"),
    "3.2.5": ("Ensure mounting of sctp kernel module is disabled", "network_config"),
    "3.2.6": ("Ensure mounting of tipc kernel module is disabled", "network_config"),
    "3.3.1": ("Ensure IPv4 kernel parameters are configured", "network_config"),
    "3.3.1.1": ("Ensure IP forwarding is disabled", "network_config"),
    "3.3.1.2": ("Ensure packet redirect sending is disabled", "network_config"),
    "3.3.1.3": ("Ensure bogus ICMP responses are ignored", "network_config"),
    "3.3.1.4": ("Ensure broadcast ICMP requests are ignored", "network_config"),
    "3.3.1.5": ("Ensure ICMP redirects are not accepted", "network_config"),
    "3.3.1.6": ("Ensure secure ICMP redirects are not accepted", "network_config"),
    "3.3.1.7": ("Ensure Reverse Path Filtering is enabled", "network_config"),
    "3.3.1.8": ("Ensure source routed packets are not accepted", "network_config"),
    "3.3.1.9": ("Ensure suspicious packets are logged", "network_config"),
    "3.3.1.10": ("Ensure TCP SYN Cookies is enabled", "network_config"),
    "3.3.2": ("Ensure IPv6 kernel parameters are configured", "network_config"),
    "3.3.2.1": ("Ensure IPv6 router advertisements are not accepted", "network_config"),
    "3.3.2.2": ("Ensure IPv6 redirects are not accepted", "network_config"),
    "3.3.2.3": ("Ensure IPv6 IP forwarding is disabled", "network_config"),

    # Section 4.1 - Uncomplicated Firewall (UFW)
    "4.1.1": ("Ensure ufw is installed", "ufw"),
    "4.1.2": ("Ensure ufw service is configured", "ufw"),
    "4.1.3": ("Ensure ufw incoming default is configured", "ufw"),
    "4.1.4": ("Ensure ufw outgoing default is configured", "ufw"),
    "4.1.5": ("Ensure ufw routed default is configured", "ufw"),

    # Section 5.1 - SSH Server Configuration
    "5.1.1": ("Ensure access to /etc/ssh/sshd_config is configured", "ssh"),
    "5.1.2": ("Ensure access to SSH private host key files is configured", "ssh"),
    "5.1.3": ("Ensure access to SSH public host key files is configured", "ssh"),
    "5.1.4": ("Ensure sshd access is configured", "ssh"),
    "5.1.5": ("Ensure sshd Banner is configured", "ssh"),
    "5.1.6": ("Ensure sshd Ciphers are configured", "ssh"),
    "5.1.7": ("Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured", "ssh"),
    "5.1.8": ("Ensure sshd DisableForwarding is enabled", "ssh"),
    "5.1.9": ("Ensure sshd GSSAPIAuthentication is disabled", "ssh"),
    "5.1.10": ("Ensure sshd HostbasedAuthentication is disabled", "ssh"),
    "5.1.11": ("Ensure sshd IgnoreRhosts is enabled", "ssh"),
    "5.1.12": ("Ensure sshd KexAlgorithms is configured", "ssh"),
    "5.1.13": ("Ensure sshd LoginGraceTime is configured", "ssh"),
    "5.1.14": ("Ensure sshd LogLevel is configured", "ssh"),
    "5.1.15": ("Ensure sshd MACs are configured", "ssh"),
    "5.1.16": ("Ensure sshd MaxAuthTries is configured", "ssh"),
    "5.1.17": ("Ensure sshd MaxStartups is configured", "ssh"),
    "5.1.18": ("Ensure sshd MaxSessions is configured", "ssh"),
    "5.1.19": ("Ensure sshd PermitEmptyPasswords is disabled", "ssh"),
    "5.1.20": ("Ensure sshd PermitRootLogin is disabled", "ssh"),
    "5.1.21": ("Ensure sshd PermitUserEnvironment is disabled", "ssh"),
    "5.1.22": ("Ensure sshd UsePAM is enabled", "ssh"),
    "5.1.23": ("Ensure sshd post-quantum cryptography key exchange algorithms are configured", "ssh"),
    "5.1.24": ("Ensure sshd ListenAddress is configured", "ssh"),

    # Section 5.2 - Privilege Escalation
    "5.2.1": ("Ensure sudo is installed", "privilege_escalation"),
    "5.2.2": ("Ensure sudo commands use pty", "privilege_escalation"),
    "5.2.3": ("Ensure sudo log file exists", "privilege_escalation"),
    "5.2.4": ("Ensure users must provide password for escalation", "privilege_escalation"),
    "5.2.5": ("Ensure re-authentication for privilege escalation is not disabled globally", "privilege_escalation"),
    "5.2.6": ("Ensure sudo timestamp_timeout is configured", "privilege_escalation"),
    "5.2.7": ("Ensure access to the su command is restricted", "privilege_escalation"),

    # Section 5.3 - PAM
    "5.3.1.1": ("Ensure libpam-runtime package is installed", "pam"),
    "5.3.1.2": ("Ensure libpam-modules package is installed", "pam"),
    "5.3.1.3": ("Ensure libpam-pwquality package is installed", "pam"),
    "5.3.1.4": ("Ensure cracklib-runtime package is installed", "pam"),
    "5.3.2.1": ("Ensure pam_unix profile is enabled", "pam"),
    "5.3.2.2": ("Ensure pam_faillock profile is enabled", "pam"),
    "5.3.2.3": ("Ensure pam_pwquality profile is enabled", "pam"),
    "5.3.2.4": ("Ensure pam_pwhistory profile is enabled", "pam"),
    "5.3.3.1.1": ("Ensure pam_faillock deny is configured", "pam"),
    "5.3.3.1.2": ("Ensure pam_faillock unlock_time is configured", "pam"),
    "5.3.3.1.3": ("Ensure pam_faillock even_deny_root is configured", "pam"),
    "5.3.3.2.1": ("Ensure pam_pwquality difok is configured", "pam"),
    "5.3.3.2.2": ("Ensure pam_pwquality minlen is configured", "pam"),
    "5.3.3.2.3": ("Ensure pam_pwquality complexity options are configured", "pam"),
    "5.3.3.2.4": ("Ensure pam_pwquality maxrepeat is configured", "pam"),
    "5.3.3.2.5": ("Ensure pam_pwquality maxsequence is configured", "pam"),
    "5.3.3.2.6": ("Ensure pam_pwquality dictcheck is enabled", "pam"),
    "5.3.3.2.7": ("Ensure pam_pwquality enforcing is enabled", "pam"),
    "5.3.3.2.8": ("Ensure pam_pwquality enforce_for_root is enabled", "pam"),
    "5.3.3.3.1": ("Ensure pam_pwhistory remember is configured", "pam"),
    "5.3.3.3.2": ("Ensure pam_pwhistory enforce_for_root is enabled", "pam"),
    "5.3.3.3.3": ("Ensure pam_pwhistory use_authtok is enabled", "pam"),
    "5.3.3.4.1": ("Ensure pam_unix nullok is absent", "pam"),
    "5.3.3.4.2": ("Ensure pam_unix remember is absent", "pam"),
    "5.3.3.4.3": ("Ensure pam_unix strong password hashing algorithm is used", "pam"),
    "5.3.3.4.4": ("Ensure pam_unix use_authtok is present", "pam"),

    # Section 5.4 - User Accounts
    "5.4.1.1": ("Ensure password expiration is configured", "user_accounts"),
    "5.4.1.2": ("Ensure minimum password days is configured", "user_accounts"),
    "5.4.1.3": ("Ensure password expiration warning days is configured", "user_accounts"),
    "5.4.1.4": ("Ensure strong password hashing algorithm is configured", "user_accounts"),
    "5.4.1.5": ("Ensure inactive password lock is configured", "user_accounts"),
    "5.4.1.6": ("Ensure all users last password change date is in the past", "user_accounts"),
    "5.4.2.1": ("Ensure root is the only UID 0 account", "user_accounts"),
    "5.4.2.2": ("Ensure root is the only GID 0 account", "user_accounts"),
    "5.4.2.3": ("Ensure group root is the only GID 0 group", "user_accounts"),
    "5.4.2.4": ("Ensure root account access is controlled", "user_accounts"),
    "5.4.2.5": ("Ensure root path integrity", "user_accounts"),
    "5.4.2.6": ("Ensure root user umask is configured", "user_accounts"),
    "5.4.2.7": ("Ensure system accounts do not have a valid login shell", "user_accounts"),
    "5.4.2.8": ("Ensure accounts without a valid login shell are locked", "user_accounts"),
    "5.4.3.1": ("Ensure nologin is not listed in /etc/shells", "user_accounts"),
    "5.4.3.2": ("Ensure default user shell timeout is configured", "user_accounts"),
    "5.4.3.3": ("Ensure default user umask is configured", "user_accounts"),

    # Section 6.1 - System Logging
    "6.1.1.1.1": ("Ensure systemd-journald service is enabled and active", "system_logging"),
    "6.1.1.1.2": ("Ensure systemd-journal-remote service is not in use", "system_logging"),
    "6.1.1.1.3": ("Ensure journald is configured to send logs to rsyslog", "system_logging"),
    "6.1.1.1.4": ("Ensure journald log file access is configured", "system_logging"),
    "6.1.1.1.5": ("Ensure journald log file rotation is configured", "system_logging"),
    "6.1.1.1.6": ("Ensure journald Storage is configured", "system_logging"),
    "6.1.1.1.7": ("Ensure journald Compress is configured", "system_logging"),
    "6.1.2.1": ("Ensure rsyslog is installed", "system_logging"),
    "6.1.2.2": ("Ensure rsyslog service is enabled and active", "system_logging"),
    "6.1.2.3": ("Ensure rsyslog default file permissions are configured", "system_logging"),
    "6.1.2.4": ("Ensure rsyslog logging is configured", "system_logging"),
    "6.1.2.5": ("Ensure rsyslog is configured to send logs to a remote log host", "system_logging"),
    "6.1.2.6": ("Ensure rsyslog is not configured to receive logs from a remote client", "system_logging"),
    "6.1.2.7": ("Ensure logrotate is configured", "system_logging"),
    "6.1.2.8": ("Ensure rsyslog-gnutls is installed", "system_logging"),
    "6.1.2.9": ("Ensure rsyslog is configured to use gtls for forwarding", "system_logging"),
    "6.1.2.10": ("Ensure rsyslog CA certificates are configured", "system_logging"),
    "6.1.3.1": ("Ensure access to all logfiles has been configured", "system_logging"),

    # Section 6.2 - System Auditing (auditd)
    "6.2.1.1.1": ("Ensure auditd is installed", "auditd"),
    "6.2.1.1.2": ("Ensure auditd service is enabled and active", "auditd"),
    "6.2.1.1.3": ("Ensure auditing for processes prior to auditd is enabled", "auditd"),
    "6.2.1.1.4": ("Ensure audit_backlog_limit is sufficient", "auditd"),
    "6.2.1.2.1": ("Ensure audit log storage size is configured", "auditd"),
    "6.2.1.2.2": ("Ensure audit logs are not automatically deleted", "auditd"),
    "6.2.1.2.3": ("Ensure system is disabled when audit logs are full", "auditd"),
    "6.2.1.2.4": ("Ensure system warns when audit logs are low on space", "auditd"),
    "6.2.3.1": ("Ensure auditd rules cover sudoers", "auditd"),
    "6.2.3.2": ("Ensure auditd rules cover identity", "auditd"),
    "6.2.3.3": ("Ensure auditd rules cover network environment", "auditd"),
    "6.2.3.4": ("Ensure auditd rules cover logins/sessions", "auditd"),
    "6.2.3.5": ("Ensure auditd rules cover time changes", "auditd"),
    "6.2.3.6": ("Ensure auditd rules cover MAC policy", "auditd"),
    "6.2.3.7": ("Ensure auditd rules cover access/permissions modifications", "auditd"),
    "6.2.3.8": ("Ensure auditd rules configuration is immutable", "auditd"),
    "6.2.4.1": ("Ensure audit log file permissions are strictly constrained", "auditd"),
    "6.2.4.2": ("Ensure audit tool file permissions are strictly constrained", "auditd"),

    # Section 6.3 - Integrity Checking (AIDE)
    "6.3.1": ("Ensure AIDE is installed", "integrity_checking"),
    "6.3.2": ("Ensure filesystem integrity is regularly checked", "integrity_checking"),
    "6.3.3": ("Ensure cryptographic mechanisms protect tools", "integrity_checking"),

    # Section 7.1 - File Permissions
    "7.1.1": ("Ensure access to /etc/passwd is configured", "file_permissions"),
    "7.1.2": ("Ensure access to /etc/passwd- is configured", "file_permissions"),
    "7.1.3": ("Ensure access to /etc/group is configured", "file_permissions"),
    "7.1.4": ("Ensure access to /etc/group- is configured", "file_permissions"),
    "7.1.5": ("Ensure access to /etc/shadow is configured", "file_permissions"),
    "7.1.6": ("Ensure access to /etc/shadow- is configured", "file_permissions"),
    "7.1.7": ("Ensure access to /etc/gshadow is configured", "file_permissions"),
    "7.1.8": ("Ensure access to /etc/gshadow- is configured", "file_permissions"),
    "7.1.9": ("Ensure access to /etc/shells is configured", "file_permissions"),
    "7.1.10": ("Ensure access to /etc/security/opasswd is configured", "file_permissions"),
    "7.1.11": ("Ensure world writable files and directories are secured", "file_permissions"),
    "7.1.12": ("Ensure no files or directories without owner/group exist", "file_permissions"),
    "7.1.13": ("Ensure SUID and SGID files are reviewed", "file_permissions"),

    # Section 7.2 - Local User and Group Settings
    "7.2.1": ("Ensure accounts in /etc/passwd use shadowed passwords", "user_accounts"),
    "7.2.2": ("Ensure /etc/shadow password fields are not empty", "user_accounts"),
    "7.2.3": ("Ensure all groups in /etc/passwd exist in /etc/group", "user_accounts"),
    "7.2.4": ("Ensure shadow group is empty", "user_accounts"),
    "7.2.5": ("Ensure no duplicate UIDs exist", "user_accounts"),
    "7.2.6": ("Ensure no duplicate GIDs exist", "user_accounts"),
    "7.2.7": ("Ensure no duplicate user names exist", "user_accounts"),
    "7.2.8": ("Ensure no duplicate group names exist", "user_accounts"),
    "7.2.9": ("Ensure local interactive user home directories are configured", "user_accounts"),
    "7.2.10": ("Ensure local interactive user dot files access is configured", "user_accounts"),
}


def matches_rule(rule_id: str, pattern: str) -> bool:
    """
    Check if a concrete rule ID matches a pattern.
    Exact match: '5.1.20' == '5.1.20'
    Prefix/Section match: '5.1.20' matches '5.1' or '5'
    """
    return rule_id == pattern or rule_id.startswith(pattern + ".")


def parse_and_validate_rules(rules_input: str | List[str]) -> List[str]:
    """
    Parse a comma-separated rules string or list of rule patterns,
    expand shorthands (e.g. '5.1' -> all '5.1.x' rules), and validate
    against implemented rules.

    Returns:
        List[str]: Sorted list of unique matched concrete rule IDs.

    Raises:
        ValueError: If any provided rule ID or pattern is unrecognized.
    """
    if isinstance(rules_input, str):
        patterns = [p.strip() for p in rules_input.split(",") if p.strip()]
    else:
        patterns = [p.strip() for p in rules_input if p.strip()]

    if not patterns:
        return []

    matched_rules: Set[str] = set()
    invalid_patterns: List[str] = []

    all_rule_ids = list(RULE_REGISTRY.keys())

    for pat in patterns:
        matches = [rid for rid in all_rule_ids if matches_rule(rid, pat)]
        if not matches:
            invalid_patterns.append(pat)
        else:
            matched_rules.update(matches)

    if invalid_patterns:
        err_msgs = []
        for inv in invalid_patterns:
            close = difflib.get_close_matches(inv, all_rule_ids, n=3, cutoff=0.4)
            if close:
                err_msgs.append(f"'{inv}' (did you mean: {', '.join(close)}?)")
            else:
                err_msgs.append(f"'{inv}'")
        
        joined_err = "; ".join(err_msgs)
        raise ValueError(
            f"Invalid CIS rule ID(s): {joined_err}. "
            f"Not a recognized rule ID. Run with --list-rules to list all supported CIS rule IDs."
        )

    # Sort matching rules numerically/hierarchically
    def rule_sort_key(rid: str) -> tuple[int, ...]:
        return tuple(int(part) for part in rid.split(".") if part.isdigit())

    return sorted(list(matched_rules), key=rule_sort_key)


def get_required_collectors(matched_rule_ids: List[str]) -> Set[str]:
    """
    Given a list of matched concrete rule IDs, return the set of collector keys
    required to gather data for these rules.
    """
    required: Set[str] = set()
    for rid in matched_rule_ids:
        if rid in RULE_REGISTRY:
            collector_key = RULE_REGISTRY[rid][1]
            required.add(collector_key)
    return required


def format_rule_list() -> str:
    """Format all implemented CIS rules for --list-rules CLI output."""
    lines = ["Implemented CIS Benchmark Rules:", "=" * 50]
    for rid, (title, collector) in sorted(RULE_REGISTRY.items(), key=lambda item: [int(x) for x in item[0].split(".") if x.isdigit()]):
        lines.append(f"  - {rid:<12} : {title} [{collector}]")
    return "\n".join(lines)


def filter_report_by_rules(report_text: str, requested_rules: List[str]) -> str:
    """
    Post-process LLM generated report to ensure only requested rule IDs
    are present in the output.
    """
    if not requested_rules or not report_text:
        return report_text

    requested_set = set(requested_rules)
    
    # Split report by H3 headings (### Rule ...) or ### 1.1.1.1 ...
    # We parse sections starting with ###
    lines = report_text.splitlines()
    filtered_lines: List[str] = []
    current_rule_included = True
    header_buffer: List[str] = []
    
    rule_heading_re = re.compile(r"^###\s*(?:Rule\s*)?([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE)

    for line in lines:
        match = rule_heading_re.match(line)
        if match:
            rule_id = match.group(1)
            # Check if this rule ID or any parent matches requested set
            current_rule_included = rule_id in requested_set
            if current_rule_included:
                if header_buffer:
                    filtered_lines.extend(header_buffer)
                    header_buffer = []
                filtered_lines.append(line)
        else:
            if line.startswith("# ") or line.startswith("## "):
                # Header lines are kept buffered until a matching rule is found in that section
                header_buffer.append(line)
            elif current_rule_included:
                filtered_lines.append(line)

    return "\n".join(filtered_lines).strip()
