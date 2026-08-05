"""
ai_analysis.py
==============
Gemini API execution and retry logic for auditing CIS benchmarks and triaging SUID/SGID.

Client initialisation is deferred until the first API call so that importing
this module never fails due to missing environment variables.
"""

from __future__ import annotations

import logging
import os
import time
import json
from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

load_dotenv()  # load .env into os.environ before reading keys

log = logging.getLogger(__name__)

MODELS = ["gemini-2.5-flash", "gemini-2.0-flash"]

# Clients are built lazily on first use (see _get_clients below).
_clients: list | None = None


def _get_clients() -> list:
    """Return (and lazily build) the list of Gemini API clients.

    Raises RuntimeError if no API keys are found — only when an actual AI
    call is made, not at module import time.
    """
    global _clients
    if _clients is not None:
        return _clients
    _raw_keys = [
        os.environ.get("GEMINI-API-KEY"),
        os.environ.get("GEMINI-API-KEY2"),
        os.environ.get("GEMINI-API-KEY3"),
    ]
    _clients = [genai.Client(api_key=k) for k in _raw_keys if k]
    if not _clients:
        raise RuntimeError(
            "No GEMINI API keys found. Set GEMINI-API-KEY (and optionally "
            "GEMINI-API-KEY2, GEMINI-API-KEY3) in your .env file."
        )
    return _clients


def generate_with_retry(max_retries=3, **kwargs):
    """Rotate through API keys, then model fallbacks, on 503/429 errors."""
    clients = _get_clients()
    for model in MODELS:
        for key_idx, api_client in enumerate(clients):
            for attempt in range(max_retries):
                try:
                    return api_client.models.generate_content(model=model, **kwargs)
                except (genai_errors.ServerError, genai_errors.ClientError) as e:
                    s_code = getattr(e, "status_code", None) or getattr(e, "code", None)
                    is_transient = s_code in (503, 429)
                    if not is_transient:
                        raise
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        reason = "unavailable" if s_code == 503 else "rate-limited"
                        log.warning(
                            "Key %d/%d, model=%s %s (attempt %d/%d). Retrying in %ds…",
                            key_idx + 1, len(clients), model, reason,
                            attempt + 1, max_retries, wait,
                        )
                        time.sleep(wait)
                    else:
                        log.warning(
                            "Key %d exhausted (%s) for %s, trying next key…",
                            key_idx + 1, s_code, model,
                        )
                        break
        log.warning("All keys exhausted for %s, switching model…", model)
    raise RuntimeError("All API keys and models exhausted. Please try again later.")



from tools.rule_registry import filter_report_by_rules


def generate_compliance_report(profile_json: str, cis_rules: str, requested_rules: list[str] | None = None) -> str:
    """Send the security profile + CIS rules to Gemini for compliance analysis."""
    filter_instruction = ""
    if requested_rules:
        filter_instruction = (
            "\n\nCRITICAL FILTER INSTRUCTION:\n"
            f"You MUST ONLY evaluate and output compliance reports for the following requested CIS Rule IDs: {', '.join(requested_rules)}.\n"
            "Do NOT output report sections, placeholders, or verdicts for any rule IDs not in this list."
        )

    prompt = f"""You are a security compliance auditor.{filter_instruction}

Below are the CIS Ubuntu 24.04 LTS Benchmark rules for Filesystem Kernel Modules & Partitions (Section 1.1),
Package Management (Section 1.2), Network Configuration (Section 3), Firewall (Section 4.1),
PAM (Section 5.3), User Accounts (Section 5.4), System Logging (Section 6.1), System Auditing (Section 6.2),
Integrity Checking (Section 6.3), File Permissions (Section 7.1), and Local User/Group Settings (Section 7.2):

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
- Status: PASS / FAIL / UNKNOWN / INFORMATIONAL
- Evidence: the relevant value(s) from the profile that justify the verdict
- Recommendation: what to fix if the status is FAIL

=== SECTION 1.1 – FILESYSTEM KERNEL MODULES & PARTITIONS ===
All Section 1.1 data is in the `filesystem` object.

** 1.1.1 Filesystem Kernel Modules **
Use `filesystem.filesystem_kernel_modules` (list of objects).
Modules: cramfs (1.1.1.1), freevxfs (1.1.1.2), hfs (1.1.1.3), hfsplus (1.1.1.4), jffs2 (1.1.1.5),
overlay (1.1.1.6), squashfs (1.1.1.7), udf (1.1.1.8), firewire-core (1.1.1.9), usb-storage (1.1.1.10).
For each module, PASS requires ALL of:
  1. `currently_loaded` is false.
  2. `modprobe_config_lines` contains at least one line matching `install <module> /bin/false` or `install <module> /bin/true`.
  3. `modprobe_config_lines` contains at least one line matching `blacklist <module>`.
FAIL if loaded OR missing disable/blacklist lines.
- 1.1.1.11 (Manual) Unused filesystems: Output INFORMATIONAL summarizing raw `filesystem.lsmod_raw` list; no PASS/FAIL.

** 1.1.2 Filesystem Partitions **
Use `filesystem.filesystem_partitions` (list of objects for /tmp, /dev/shm, /home, /var, /var/tmp, /var/log, /var/log/audit).
- 1.1.2.1.1–1.1.2.1.4 (/tmp): PASS partition if `is_separate_partition` is true OR `fstype` == "tmpfs". PASS nodev, nosuid, noexec if in `mount_options_list`.
- 1.1.2.2.1–1.1.2.2.4 (/dev/shm): PASS partition if `is_separate_partition` is true OR `fstype` == "tmpfs". PASS nodev, nosuid, noexec if in `mount_options_list`.
- 1.1.2.3.1–1.1.2.3.3 (/home): PASS partition if `is_separate_partition` is true. PASS nodev, nosuid if in `mount_options_list`.
- 1.1.2.4.1–1.1.2.4.3 (/var): PASS partition if `is_separate_partition` is true. PASS nodev, nosuid if in `mount_options_list`.
- 1.1.2.5.1–1.1.2.5.4 (/var/tmp): PASS partition if `is_separate_partition` is true. PASS nodev, nosuid, noexec if in `mount_options_list`.
- 1.1.2.6.1–1.1.2.6.4 (/var/log): PASS partition if `is_separate_partition` is true. PASS nodev, nosuid, noexec if in `mount_options_list`.
- 1.1.2.7.1–1.1.2.7.4 (/var/log/audit): PASS partition if `is_separate_partition` is true. PASS nodev, nosuid, noexec if in `mount_options_list`.
=== END SECTION 1.1 ===

=== SECTION 1.2 – PACKAGE MANAGEMENT ===
All Section 1.2 data is in the `package_management` object.

** 1.2.1 Package Repositories **
- 1.2.1.1 (Manual) Signed-By option: Output INFORMATIONAL summarizing `sources_files` and `matching_signed_by_lines`.
- 1.2.1.2 Weak dependencies: PASS if `weak_deps_config_lines` contains `APT::Install-Recommends "false";` or `APT::Install-Suggests "false";` (or `0`).
- 1.2.1.3 GPG key files access: PASS if `gpg_key_files_stat` entries have mode_octal ≤ 0o644 and owner="root", group="root".
- 1.2.1.4 /etc/apt/trusted.gpg.d dir: PASS if `trusted_gpg_d_stat.mode_octal` ≤ 0o755 and owner/group="root".
- 1.2.1.5 /etc/apt/auth.conf.d dir: PASS if `auth_conf_d_stat.exists` is false OR mode_octal ≤ 0o700 and owner/group="root".
- 1.2.1.6 files in auth.conf.d: PASS if all entries in `auth_conf_d_files_stat` have mode_octal ≤ 0o600 and owner/group="root".
- 1.2.1.7 /usr/share/keyrings dir: PASS if `keyrings_dir_stat.mode_octal` ≤ 0o755 and owner/group="root".
- 1.2.1.8 /etc/apt/sources.list.d dir: PASS if `sources_list_d_stat.mode_octal` ≤ 0o755 and owner/group="root".
- 1.2.1.9 files in sources.list.d: PASS if all entries in `sources_list_d_files_stat` have mode_octal ≤ 0o644 and owner/group="root".

** 1.2.2 Package Updates **
- 1.2.2.1 (Manual) Package updates installed: Output INFORMATIONAL summarizing `upgradable_package_count`, `apt_cache_error`, and `unattended_upgrades` service status.
=== END SECTION 1.2 ===

=== SECTION 1.3 – APPARMOR ===
All Section 1.3 data is in the `apparmor` object.
- 1.3.1.1 AppArmor packages installed: PASS if `packages.apparmor_installed` is true AND `packages.apparmor_utils_installed` is true.
- 1.3.1.2 AppArmor enabled: PASS if `sysfs_enabled_value` == "Y", `service_enabled` == "enabled", `service_active` == "active", and GRUB has `apparmor=1 security=apparmor`.
- 1.3.1.3 All AppArmor profiles enforcing: Analyze `aa_status.raw_output`. PASS if 0 profiles are in complain mode and 0 unconfined processes; FAIL otherwise.
- 1.3.1.4 apparmor_restrict_unprivileged_unconfined: PASS if `runtime_value` == "1" and `persisted_value` == "1".
=== END SECTION 1.3 ===

=== SECTION 1.4 – BOOTLOADER ===
All Section 1.4 data is in the `bootloader` object.
- 1.4.1 Bootloader password: PASS if `has_superusers` is true and `has_password` is true.
- 1.4.2 Bootloader permissions: PASS if `grub_cfg_permissions` entries have mode_octal ≤ 0o400 (or 0o600) and owner="root", group="root".
=== END SECTION 1.4 ===

=== SECTION 1.5 – PROCESS HARDENING ===
All Section 1.5 data is in the `process_hardening` object.
- 1.5.1 fs.protected_hardlinks: PASS if runtime == 1 and persisted == 1.
- 1.5.2 fs.protected_symlinks: PASS if runtime == 1 and persisted == 1.
- 1.5.3 kernel.yama.ptrace_scope: PASS if runtime == 1 (or 2/3) and persisted is set.
- 1.5.4 fs.suid_dumpable: PASS if runtime == 0 and persisted == 0.
- 1.5.5 kernel.dmesg_restrict: PASS if runtime == 1 and persisted == 1.
- 1.5.6 Prelink not installed: PASS if `prelink_installed` is false.
- 1.5.7 Apport disabled: PASS if `apport_installed` is false OR `service_enabled` == "disabled"/`service_active` == "inactive" OR `etc_default_setting` == "enabled=0".
- 1.5.8 kernel.kptr_restrict: PASS if runtime == 2 (or 1) and persisted == 2.
- 1.5.9 kernel.randomize_va_space: PASS if runtime == 2 and persisted == 2.
- 1.5.10 Core dumps restricted: PASS if `ulimit_soft_core` == "0" and `limits_conf_lines` has `hard core 0`.
- 1.5.11 systemd-coredump ProcessSizeMax: PASS if `systemd_coredump_process_size_max` contains `ProcessSizeMax=0`.
- 1.5.12 systemd-coredump Storage: PASS if `systemd_coredump_storage` contains `Storage=none`.
=== END SECTION 1.5 ===

=== SECTION 1.6 – WARNING BANNERS ===
All Section 1.6 data is in the `warning_banners` object.
(Note: 1.6.5 and 1.6.10 sshd banner rules are evaluated under SSH section 5.1).
- 1.6.1 /etc/motd configured: PASS if `motd.content` does not contain OS/kernel release information.
- 1.6.2 /etc/issue configured: PASS if `issue.content` contains a compliant banner and no OS/kernel flags (\v \r \m \s).
- 1.6.3 /etc/issue.net configured: PASS if `issue_net.content` contains a compliant banner and no OS/kernel flags.
- 1.6.4 pam_motd configured: Analyze `pam_motd` references and `update-motd.d` files; PASS if dynamic motd scripts are disabled/reviewed.
- 1.6.6 access to /etc/motd: PASS if mode_octal ≤ 0o644 and owner="root", group="root".
- 1.6.7 access to /etc/issue: PASS if mode_octal ≤ 0o644 and owner="root", group="root".
- 1.6.8 access to /etc/issue.net: PASS if mode_octal ≤ 0o644 and owner="root", group="root".
- 1.6.9 access to pam_motd files: PASS if mode_octal ≤ 0o644 (or 0o755 for update-motd.d scripts) and owner="root", group="root".
=== END SECTION 1.6 ===

=== SECTION 1.7 – GNOME DISPLAY MANAGER ===
All Section 1.7 data is in the `gnome` object.
- If `gdm_installed` is false: Output **PASS** for all 1.7.x rules with Evidence "GDM is not installed — rule not applicable to this server profile." and Recommendation "None."
- If `gdm_installed` is true:
  - 1.7.1 GDM login banner: PASS if `dconf_settings` has `banner-message-enable=true` and non-empty `banner-message-text`.
  - 1.7.2 disable-user-list: PASS if `dconf_settings` has `disable-user-list=true`.
  - 1.7.3 GDM screen lock: PASS if `lock-enabled=true` and `lock-delay` ≤ 900, with entries in `dconf_locks`.
  - 1.7.4 GDM automount: PASS if `automount=false` and `automount-open=false`, with entries in `dconf_locks`.
  - 1.7.5 GDM autorun-never: PASS if `autorun-never=true`, with entry in `dconf_locks`.
  - 1.7.6 XDMCP disabled: PASS if `gdm3_custom_conf_content` does NOT contain `Enable=true` under `[xdmcp]`.
  - 1.7.7 Xwayland configured: PASS if `WaylandEnable` or `DisableXwayland` is set properly under `[daemon]` or `[security]`.
=== END SECTION 1.7 ===

=== SECTION 2 – SERVICES ===
All Section 2 data is in the `services` object.
Use `services.server_services` (list) for 2.1 and `services.client_services` (list) for 2.2.
Each entry has: `cis_rule`, `service_name`, `packages_status` (list of {{package, installed}}), `any_package_installed`, `units_status` (list of {{unit, enabled, active}}), `any_unit_active`.

** 2.1 Server Services — all should NOT be in use **
PASS for each rule if `any_package_installed` is false AND `any_unit_active` is false.
FAIL if any package is installed OR any unit is active/enabled.
Rules: 2.1.1 (autofs), 2.1.3 (avahi), 2.1.5 (dhcp), 2.1.6 (web server), 2.1.7 (dns/bind9),
2.1.8 (ftp server), 2.1.9 (dnsmasq), 2.1.10 (ldap/slapd), 2.1.11 (imap/pop3),
2.1.12 (nfs server), 2.1.13 (nis/ypserv), 2.1.14 (cups print), 2.1.15 (rpcbind),
2.1.16 (rsync daemon), 2.1.17 (samba/smbd), 2.1.18 (snmpd), 2.1.19 (telnet server),
2.1.20 (tftp server), 2.1.21 (squid proxy), 2.1.22 (xinetd), 2.1.23 (X window server –
also check `xorg_process_running` separately from installed; FAIL if either is true).

** 2.1.2 Mail Transfer Agent local-only mode **
Use the entry where `cis_rule == "2.1.2"`. Check `mta_detected` to determine which MTA applies.
- postfix: PASS if `postfix_inet_interfaces` value is "loopback-only".
- exim4: PASS if `exim4_local_interfaces` value restricts to localhost.
- none: PASS (no MTA installed).

** 2.1.4 Only approved services listening (Manual) **
Use `services.listening_sockets_raw`. Output INFORMATIONAL listing all listening sockets.
Cross-reference with other 2.1.x results to flag any unexpected active services.

** 2.2 Client Services — all packages should NOT be installed **
Use `services.client_services`. PASS if `any_package_installed` is false.
FAIL if any client package is installed.
Rules: 2.2.1 (nis/ypbind), 2.2.2 (rsh-client), 2.2.3 (talk), 2.2.4 (telnet client),
2.2.5 (ldap-utils), 2.2.6 (ftp client).

** 2.3 Time Synchronization **
All Section 2.3 data is in the `time_sync` object (`time_sync_general`, `systemd_timesyncd`, `chrony`).
- 2.3.1.1 Single time sync daemon in use: PASS if `time_sync_general.active_daemon_count == 1`. FAIL if 0 or >1 daemons active.
- 2.3.2.1 systemd-timesyncd timeserver configured: PASS if `systemd_timesyncd.has_ntp_configured` is true (non-commented `NTP=` or `FallbackNTP=` present). (Not applicable if chrony is the active daemon).
- 2.3.2.2 systemd-timesyncd enabled and running: PASS if service enabled is "enabled" AND active is "active".
- 2.3.3.1 chrony timeserver configured: PASS if `chrony.has_servers_configured` is true (`server` or `pool` lines present). (Not applicable if systemd-timesyncd is active).
- 2.3.3.2 chrony process user: PASS if `process_user` == "_chrony" OR `config_user_directive` contains "user _chrony" OR `unit_user` contains "_chrony".
- 2.3.3.3 chrony enabled and running: PASS if service enabled is "enabled" AND active is "active".

** 2.4 Job Schedulers **
All Section 2.4 data is in the `job_schedulers` object (`cron`, `at`).
- 2.4.1.1 cron daemon enabled and active: PASS if `cron.cron_installed` is true, service enabled is "enabled", active is "active".
- 2.4.1.2 access to /etc/crontab: PASS if `exists` is true, `owner` == "root", `group` == "root", `mode_octal` is 0600 (or 0640).
- 2.4.1.3 through 2.4.1.8 access to /etc/cron.hourly, .daily, .weekly, .monthly, .yearly, .d: PASS if `exists` is true, `owner` == "root", `group` == "root", `mode_octal` is 0700 (or 0750/0700).
- 2.4.1.9 access to crontab mechanism: PASS if `/var/spool/cron/crontabs` spool directory `owner` == "root", `group` is "crontab" or "root", `mode_octal` is 1730 or 0700/0755; and `crontab_binary_stat` owner is "root".
- 2.4.2.1 access to at configured: PASS if `at_allow_stat.exists` is true with owner "root" (or "daemon"), group "root" (or "daemon"), mode <= 0640 AND `at_deny_stat.exists` is false (or empty). (Not applicable if package `at` is not installed).
=== END SECTION 2 ===

=== SECTION 3 – NETWORK CONFIGURATION ===

All Section 3 data is in the `network_config` object.

** 3.1 Network Devices **
Use `network_config.network_devices`.

- 3.1.1 (Manual/Informational) IPv6 status identified:
  Report the collected facts from `ipv6_status` — do NOT assign PASS/FAIL.
  Instead output "INFORMATIONAL" and summarise:
    * `sysfs_disable_value` ("1" = disabled, "0" = enabled, null = N/A)
    * `grub_ipv6_disable_flag` (true = ipv6.disable=1 in kernel cmdline)
    * `inet6_address_count` (> 0 means IPv6 is active on at least one interface)

- 3.1.2 Ensure wireless interfaces are not available:
  PASS if ALL of the following hold:
    * `wireless_interfaces.wireless_devices_ip_link` is empty []
    * `wireless_interfaces.wireless_devices_nmcli` is empty [] (or nmcli not available)
    * `wireless_interfaces.loaded_wireless_kernel_modules` is empty []
  FAIL if `any_wireless_found` is True.

- 3.1.3 Ensure Bluetooth services are not in use:
  PASS if `bluetooth.bluez_installed` is False
       OR (`bluetooth.bluetooth_service_enabled` is "disabled"
           AND `bluetooth.bluetooth_service_active` is "inactive").
  FAIL if bluez is installed AND (service enabled OR active).

** 3.2 Network Kernel Modules **
Use `network_config.kernel_modules`. Modules: atm, can, dccp, rds, sctp, tipc.
For each module, PASS requires ALL of:
  1. `currently_loaded` is false.
  2. `modprobe_config_lines` contains at least one line matching
     `install <module> /bin/false` or `install <module> /bin/true`.
  3. `modprobe_config_lines` contains at least one line matching `blacklist <module>`.
FAIL if the module is loaded OR missing any of the required disable/blacklist lines.

** 3.3.1 IPv4 Kernel Parameters **
Use `network_config.sysctl_ipv4`. For each key, PASS requires BOTH:
  * `runtime_value` equals the expected value (live kernel)
  * `persisted_value` equals the expected value (config file)
If `runtime_value` is null, report UNKNOWN with a note that the key is not
available on this kernel. If `persisted_value` is null, the parameter is NOT
persisted — report FAIL with a recommendation to add it to /etc/sysctl.d/.

Expected values (CIS Level 1 / Level 2):
  net.ipv4.ip_forward                       = "0"
  net.ipv4.conf.all.forwarding              = "0"
  net.ipv4.conf.default.forwarding          = "0"
  net.ipv4.conf.all.send_redirects          = "0"
  net.ipv4.conf.default.send_redirects      = "0"
  net.ipv4.icmp_ignore_bogus_error_responses= "1"
  net.ipv4.icmp_echo_ignore_broadcasts      = "1"
  net.ipv4.conf.all.accept_redirects        = "0"
  net.ipv4.conf.default.accept_redirects    = "0"
  net.ipv4.conf.all.secure_redirects        = "0"
  net.ipv4.conf.default.secure_redirects    = "0"
  net.ipv4.conf.all.rp_filter               = "1" (or "2" — both are compliant)
  net.ipv4.conf.default.rp_filter           = "1" (or "2" — both are compliant)
  net.ipv4.conf.all.accept_source_route     = "0"
  net.ipv4.conf.default.accept_source_route = "0"
  net.ipv4.conf.all.log_martians            = "1"
  net.ipv4.conf.default.log_martians        = "1"
  net.ipv4.tcp_syncookies                   = "1"

** 3.3.2 IPv6 Kernel Parameters **
Use `network_config.sysctl_ipv6`. Same runtime + persisted pass criteria as 3.3.1.
Note: if IPv6 is disabled at the kernel level (sysfs_disable_value="1" or
ipv6.disable=1 in GRUB), these keys may not exist — report UNKNOWN/N/A gracefully.

Expected values:
  net.ipv6.conf.all.forwarding              = "0"
  net.ipv6.conf.default.forwarding          = "0"
  net.ipv6.conf.all.accept_redirects        = "0"
  net.ipv6.conf.default.accept_redirects    = "0"
  net.ipv6.conf.all.accept_source_route     = "0"
  net.ipv6.conf.default.accept_source_route = "0"
  net.ipv6.conf.all.accept_ra               = "0"
  net.ipv6.conf.default.accept_ra           = "0"
=== END SECTION 3 ===

=== SECTION 5.3 – PLUGGABLE AUTHENTICATION MODULES (PAM) ===
All Section 5.3 data is in the `pam` object.
IMPORTANT: For arguments that can come from BOTH a .conf file AND inline pam.d arguments,
CIS requires the argument be present. Use the conf file value when set; fall back to the
inline pam.d argument. Both are supplied in the data — note which source you used.

** 5.3.1 PAM Software Packages **
Use `pam.pam_packages` (list). Each entry: {{package, installed, installed_version, candidate_version, candidate_version_error}}.
- 5.3.1.1 libpam-runtime: PASS if installed=true AND installed_version == candidate_version (or candidate_version_error is set — flag for manual review).
- 5.3.1.2 libpam-modules: same logic.
- 5.3.1.3 libpam-pwquality: same logic.
- 5.3.1.4 cracklib-runtime: same logic.
For any package with candidate_version_error, output UNKNOWN and note that APT cache was unavailable.

** 5.3.2 pam-auth-update Profiles **
Use `pam.pam_profiles_raw.module_lines`. The data has per-module line lists across all four
common-* files. A module is "enabled" if it has at least one non-comment, non-disabled
(not preceded by "#" or labelled "[success=N skip..]") active-type line.
- 5.3.2.1 pam_unix enabled: module_lines["pam_unix.so"] is non-empty with an active line.
- 5.3.2.2 pam_faillock enabled: module_lines["pam_faillock.so"] is non-empty.
- 5.3.2.3 pam_pwquality enabled: module_lines["pam_pwquality.so"] is non-empty.
- 5.3.2.4 pam_pwhistory enabled: module_lines["pam_pwhistory.so"] is non-empty.

** 5.3.3.1 pam_faillock arguments **
Use `pam.pam_faillock`. Settings may be in `faillock_conf_settings` (from /etc/security/faillock.conf)
OR `faillock_inline_pam_settings` (from pam.d lines). Use conf file value preferentially.
- 5.3.3.1.1 deny <= 5: PASS if deny ≤ 5 (e.g. "deny = 5"). CIS wants accounts locked after 5 failed attempts.
- 5.3.3.1.2 unlock_time >= 900: PASS if unlock_time ≥ 900 seconds (15 minutes). A value of "0" = never unlock (also compliant).
- 5.3.3.1.3 even_deny_root / root_unlock_time: PASS if even_deny_root is present AND root_unlock_time ≥ 60.

** 5.3.3.2 pam_pwquality arguments **
Use `pam.pam_pwquality`. Settings from `pwquality_conf_settings` (preferred) or `pwquality_inline_pam_settings`.
- 5.3.3.2.1 difok >= 2: PASS if difok ≥ 2.
- 5.3.3.2.2 minlen >= 14: PASS if minlen ≥ 14.
- 5.3.3.2.3 (Manual) Password complexity (dcredit, ucredit, lcredit, ocredit): output INFORMATIONAL with raw values; no PASS/FAIL.
- 5.3.3.2.4 maxrepeat <= 3: PASS if maxrepeat is set and ≤ 3 (0 = disabled = FAIL).
- 5.3.3.2.5 maxsequence <= 3: PASS if maxsequence is set and ≤ 3 (0 = disabled = FAIL).
- 5.3.3.2.6 dictcheck = 1: PASS if dictcheck is not 0 (default 1 = enabled).
- 5.3.3.2.7 enforcing = 1: PASS if enforcing is not 0 (default 1 = enforce).
- 5.3.3.2.8 enforce_for_root present: PASS if enforce_for_root is set in conf or inline args.

** 5.3.3.3 pam_pwhistory arguments **
Use `pam.pam_pwhistory.pwhistory_inline_pam_settings`.
- 5.3.3.3.1 remember >= 24: PASS if remember ≥ 24.
- 5.3.3.3.2 enforce_for_root present: PASS if enforce_for_root token is present in pam_pwhistory lines.
- 5.3.3.3.3 use_authtok present: PASS if use_authtok token is present in pam_pwhistory lines.

** 5.3.3.4 pam_unix arguments **
Use `pam.pam_unix.pam_unix_flag_presence`.
- 5.3.3.4.1 nullok absent: PASS if nullok is null/not present in any pam_unix line.
- 5.3.3.4.2 remember absent: PASS if remember is null/not present (CIS says pam_unix should NOT include remember; use pam_pwhistory for that).
- 5.3.3.4.3 Strong hashing: PASS if yescrypt or sha512 is present. FAIL if md5, blowfish, or no hashing option is found.
- 5.3.3.4.4 use_authtok present (in password stack): PASS if use_authtok is present in a pam_unix line from common-password.
=== END SECTION 5.3 ===

For Section 7.2.x (Local User and Group Settings), use the `user_accounts.local_users_and_groups_evidence` block. If arrays like `duplicate_uids`, `orphan_gids_in_passwd`, `home_directory_issues`, etc., are empty, assume PASS.
For Section 6.1.x (System Logging), use the `system_logging` object in the profile.

=== SECTION 6.2 – SYSTEM AUDITING (auditd) ===
All Section 6.2 data is in the `system_auditing` object.

CRITICAL RULE — READ FIRST:
- If `system_auditing.auditd_installed` is false OR the `system_auditing` object contains only errors (e.g. `"errors": [{...}]`), then ALL rules 6.2.1.1 through 6.2.4.10 MUST be evaluated as **FAIL** (NOT UNKNOWN).
  Evidence: "auditd package is not installed on the system."
  Recommendation: "Install auditd: `sudo apt install auditd`. Then configure and enable the service."
  Do NOT output UNKNOWN for any 6.2.x rule in this case.

Only if `system_auditing.auditd_installed` is true, evaluate each rule individually:

** 6.2.1 Configure auditd Service **
- 6.2.1.1 auditd installed/active: PASS if `auditd_installed` is true and `auditd_service.enabled` == "enabled" and `auditd_service.active` == "active".
- 6.2.1.2 auditd enabled at boot: PASS if `auditd_service.enabled` == "enabled".
- 6.2.1.3 audit=1 in GRUB: Use `bootloader.grub_cmdline` or the raw kernel cmdline data; PASS if `audit=1` is present. If bootloader data is missing, FAIL.
- 6.2.1.4 audit_backlog_limit set: Use `auditd_conf`; PASS if `backlog_wait_time` or `audit_backlog_limit` is configured ≥ 8192.

** 6.2.2 Configure Data Retention **
Use `system_auditing.auditd_conf`:
- 6.2.2.1 max_log_file: PASS if configured to a non-zero value (CIS recommends ≥ 8).
- 6.2.2.2 max_log_file_action: PASS if value is "keep_logs".
- 6.2.2.3 disk_full_action: PASS if value is "halt" or "single".
- 6.2.2.4 space_left_action: PASS if value is "SYSLOG", "EMAIL", "EXEC", "SINGLE", or "HALT".

** 6.2.3 Configure Rules **
Use `system_auditing.audit_rules_raw`. Cross-reference these expected raw patterns:
- **sudoers**: `-w /etc/sudoers -p wa -k scope`, `-w /etc/sudoers.d/ -p wa -k scope`
- **identity**: `-w /etc/group -p wa -k identity`, `-w /etc/passwd -p wa -k identity`, `-w /etc/gshadow -p wa -k identity`, `-w /etc/shadow -p wa -k identity`, `-w /etc/security/opasswd -p wa -k identity`
- **network environments**: `-w /etc/issue -p wa -k system-locale`, `-w /etc/issue.net -p wa -k system-locale`, `-w /etc/hosts -p wa -k system-locale`
- **logins/sessions**: `-w /var/log/faillog -p wa -k logins`, `-w /var/log/lastlog -p wa -k logins`, `-w /var/run/utmp -p wa -k session`, `-w /var/log/wtmp -p wa -k logins`, `-w /var/log/btmp -p wa -k logins`
- **time changes**: `-S adjtimex -S settimeofday -S clock_settime` alongside `-w /etc/localtime -p wa -k time-change`
- **MAC policy**: `-w /etc/apparmor/ -p wa -k MAC-policy`, `-w /etc/apparmor.d/ -p wa -k MAC-policy`
- **access / permissions modifications**: `creat`, `open`, `openat`, `truncate`, `ftruncate`, `chmod`, `fchmod`, `setxattr`, `removexattr` for `auid>=1000` (`exit=-EACCES` and `exit=-EPERM` where applicable).
- **immutability**: `-e 2` indicates the rules are locked.

** 6.2.4 Configure auditd File Permissions **
Use `system_auditing.audit_file_permissions`:
- 6.2.4.1–6.2.4.4: Audit log directory/files owner, group, mode.
- 6.2.4.5–6.2.4.7: Audit config files mode, owner, group.
- 6.2.4.8–6.2.4.10: Audit tool binaries permissions.
=== END SECTION 6.2 ===

=== SECTION 6.3 – INTEGRITY CHECKING (AIDE) ===
All Section 6.3 data is in the `aide_integrity_checking` object.

CRITICAL RULE — READ FIRST:
- If `aide_integrity_checking.aide_installed` is false OR the object contains only errors, then ALL rules 6.3.1 through 6.3.3 MUST be evaluated as **FAIL** (NOT UNKNOWN).
  Evidence: "AIDE package is not installed on the system."
  Recommendation: "Install AIDE: `sudo apt install aide aide-common`. Run `aideinit` to create the initial database."
  Do NOT output UNKNOWN for any 6.3.x rule in this case.

Only if `aide_integrity_checking.aide_installed` is true, evaluate individually:
- 6.3.1 Ensure AIDE is installed: PASS.
- 6.3.2 Ensure filesystem integrity is regularly checked: PASS if cron logs, user crons, or systemd checks are active/enabled and configured properly in `scheduled_checking`.
- 6.3.3 Ensure cryptographic mechanisms protect tools: PASS if `audit_tools_integrity_tracked.matching_aide_config_lines` properly capture audit tool paths with secure hashing (e.g., `p+i+n+u+g+s+b+acl+xattrs+sha512`).
=== END SECTION 6.3 ===

FORMATTING & LAYOUT INSTRUCTIONS:
- Use clean Markdown with clear spacing.
- Group results under H2 section headings (`## FTP Services`, `## Section 3 – Network Configuration`, `## Section 5.3 – Pluggable Authentication Modules (PAM)`, etc.).
- Format each rule with an H3 heading: `### Rule <ID>: <Rule Title>`
- Under each rule, provide details as bullet points:
  * **Status**: PASS | FAIL | UNKNOWN | INFORMATIONAL
  * **Evidence**: <evidence summary from profile>
  * **Recommendation**: <remediation steps if FAIL/UNKNOWN, or "None" if PASS>
- Ensure there is a blank line (`\\n\\n`) between each rule entry and between sections for maximum visual clarity.
- Be concise but precise."""

    response = generate_with_retry(
        contents=prompt,
        config=genai_types.GenerateContentConfig(temperature=0.1),
    )
    if requested_rules:
        return filter_report_by_rules(response.text, requested_rules)
    return response.text




def analyze_suid_sgid(suid_sgid_data: dict) -> str:
    """
    Send the collected SUID/SGID file list to Gemini for expert triage.

    Only unexpected, suspicious, or review-worthy files are reported;
    well-known legitimate system binaries are silently skipped.

    Returns:
        str: A JSON-formatted string matching the findings schema.
    """
    data_json = json.dumps(suid_sgid_data, indent=2)
    prompt = f"""You are a Linux security auditor specialized in CIS Benchmarks.

Analyze the provided SUID/SGID files found on the system.

Your goal is NOT to list all SUID/SGID files. Many system binaries legitimately
require SUID/SGID permissions (for example /usr/bin/passwd, /usr/bin/su,
/usr/bin/chsh, etc.).

Only report SUID/SGID files that are unexpected, suspicious, or require
administrator review.

For each suspicious file, analyze:
- File path
- Owner UID and username
- Group GID and group name
- Permission mode (octal)
- Whether it has SUID, SGID, or both
- Package ownership (if available)
- Reason why it is suspicious
- Potential security impact
- Recommended action

Consider a SUID/SGID file suspicious if:
- It is owned by a non-root user but has SUID/SGID enabled.
- It exists in unusual locations such as /tmp, /var/tmp, /home, /opt (unless
  expected), or user-writable directories.
- It is not part of a trusted system package.
- It belongs to an unknown or removed package.
- It is a custom binary or script with elevated privileges.
- The permissions are overly permissive (for example world-writable SUID/SGID).
- The binary is obsolete, unused, or unnecessary.
- The file has unexpected ownership or permissions compared to normal Linux
  installations.

Do NOT report common legitimate system binaries unless they have abnormal
properties.

Examples of normally expected files:
- /usr/bin/passwd
- /usr/bin/su
- /usr/bin/chsh
- /usr/bin/chfn
- /usr/bin/sudo (if installed)

Output only findings that require attention.

Format the output as JSON:

{{
  "findings": [
    {{
      "path": "",
      "owner": "",
      "group": "",
      "mode": "",
      "suid": true,
      "sgid": false,
      "risk": "low|medium|high|critical",
      "reason": "",
      "recommendation": ""
    }}
  ],
  "summary": {{
    "total_checked": 0,
    "suspicious_found": 0
  }}
}}

If no suspicious SUID/SGID files are found, return:

{{
  "findings": [],
  "summary": {{
    "suspicious_found": 0,
    "message": "No unexpected SUID/SGID files detected."
  }}
}}

Return ONLY the JSON — no markdown fences, no explanatory text.

--- SUID/SGID DATA ---
{data_json}
--- END SUID/SGID DATA ---"""

    response = generate_with_retry(
        contents=prompt,
        config=genai_types.GenerateContentConfig(temperature=0.1),
    )
    return response.text
