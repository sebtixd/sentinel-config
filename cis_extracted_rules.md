# CIS Benchmark Extracted Rules

Extracted from **CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.0.pdf** (starting page 974), filtering on topics: `ssh, ftp`.

## SSH Rules
- **1.6.5** Ensure sshd warning Banner is configured (Automated) (Page 979)
- **1.6.10** Ensure access to sshd warning banner is configured (Automated) (Page 979)
- **4.2.1** in 1.0.0 5/28/2026 2.0.0 MOVED RECOMMENDATION: 5.1.17 - Ensure sshd MaxStartups is configured moved from 5.1.18 in 1.0.0 5/28/2026 2.0.0 MOVED RECOMMENDATION: 5.1.18 - Ensure sshd MaxSessions is configured moved from 5.1.17 in 1.0.0 5/28/2026 2.0.0 MOVED SECTION: 6.1.1 - Configure journald moved from 6.1.2 in 1.0.0 5/28/2026 2.0.0 MOVED SECTION: 6.1.1.1 - Configure journald moved from 6.1.2 in 1.0.0 5/28/2026 2.0.0 MOVED RECOMMENDATION: 6.1.1.1.2 - Ensure systemd-journal-remote service is not in use moved from 6.1.2.1.4 in 1.0.0 (Page 1073)
- **5.1** Configure SSH Server (Page 985)
- **5.1.1** Ensure access to /etc/ssh/sshd_config is configured (Automated) (Page 985)
- **5.1.2** Ensure access to SSH private host key files is configured (Automated) (Page 985)
- **5.1.3** Ensure access to SSH public host key files is configured (Automated) (Page 985)
- **5.1.4** Ensure sshd access is configured (Automated) (Page 986)
- **5.1.5** Ensure sshd Banner is configured (Automated) (Page 986)
- **5.1.6** Ensure sshd Ciphers are configured (Automated) (Page 986)
- **5.1.7** Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured (Automated) (Page 986)
- **5.1.8** Ensure sshd DisableForwarding is enabled (Automated) (Page 986)
- **5.1.9** Ensure sshd GSSAPIAuthentication is disabled (Automated) (Page 986)
- **5.1.10** Ensure sshd HostbasedAuthentication is disabled (Automated) (Page 986)
- **5.1.11** Ensure sshd IgnoreRhosts is enabled (Automated) (Page 986)
- **5.1.12** Ensure sshd KexAlgorithms is configured (Automated) (Page 986)
- **5.1.13** Ensure sshd LoginGraceTime is configured (Automated) (Page 986)
- **5.1.14** Ensure sshd LogLevel is configured (Automated) (Page 986)
- **5.1.15** Ensure sshd MACs are configured (Automated) (Page 986)
- **5.1.16** Ensure sshd MaxAuthTries is configured (Automated) (Page 986)
- **5.1.17** Ensure sshd MaxStartups is configured (Automated) (Page 986)
- **5.1.18** Ensure sshd MaxSessions is configured (Automated) (Page 986)
- **5.1.19** Ensure sshd PermitEmptyPasswords is disabled (Automated) (Page 986)
- **5.1.20** Ensure sshd PermitRootLogin is disabled (Automated) (Page 986)
- **5.1.21** Ensure sshd PermitUserEnvironment is disabled (Automated) (Page 986)
- **5.1.22** Ensure sshd UsePAM is enabled (Automated) (Page 986)
- **5.1.23** Ensure sshd post-quantum cryptography key exchange algorithms are configured (Automated) (Page 987)
- **5.1.24** Ensure sshd ListenAddress is configured (Automated) (Page 987)

## FTP Rules
- **2.1.8** Ensure ftp server services are not in use (Automated) (Page 980)
- **2.1.20** Ensure tftp server services are not in use (Automated) (Page 981)
- **2.2.6** Ensure ftp client is not installed (Automated) (Page 981)

