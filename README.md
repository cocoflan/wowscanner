# Wowscanner

**Wowscanner** is a comprehensive, self-contained Linux security scanner for Debian and Ubuntu systems. A single Bash script audits 50+ security domains — from SSH hardening and kernel parameters to full active pentest simulations — and produces colour-coded terminal output, a paginated findings report, a graphical ODT report, an HTML dashboard, a statistics spreadsheet, and an HMAC-signed archive, all in one run.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Commands](#commands)
- [Flags](#flags)
- [Scan Sections](#scan-sections)
- [Output Files](#output-files)
- [Authentication System](#authentication-system)
- [Password Recovery](#password-recovery)
- [Automated Scanning](#automated-scanning)
- [Report Delivery](#report-delivery)
- [Configuration File](#configuration-file)
- [Persistent Data](#persistent-data)
- [Legal Notice](#legal-notice)
- [License](#license)

---

## Features

- **50+ audit sections** covering every major Linux attack surface
- **Active pentest mode** — nmap full service fingerprint, Nikto web scanner, Hydra SSH brute-force simulation, SQLMap injection probe, stress-ng/hping3 resource exhaustion
- **LAN device discovery** — maps the local subnet via arp-scan or nmap ping sweep, produces a JSON host map embedded in the intelligence report
- **Hardware security** — Secure Boot, IOMMU/DMA protection, CPU vulnerability mitigations (Spectre, Meltdown, MDS), TPM detection
- **Multiple report formats** — plain text, paginated findings, ODT (LibreOffice Writer), HTML (any browser), ODS statistics workbook (LibreOffice Calc), intelligence/CVE context ODT
- **HMAC-signed archives** — every output file is hashed (SHA-256 + SHA-512) and bundled in a signed zip; the `verify` command detects tampering or deletion after the fact
- **Regression tracking** — `baseline` snapshots PASS findings; subsequent runs highlight newly introduced failures
- **Scan diff** — `diff` compares two reports: new FAILs, resolved FAILs, new WARNs, resolved WARNs, score delta
- **One-click hardening** — `harden` writes `/etc/sysctl.d/99-wowscanner.conf` with CIS-aligned kernel parameters and applies them live
- **Weekly automation** — `install-timer` creates a systemd timer that runs the scan weekly and logs to `/var/log/wowscanner/`
- **Report delivery** — `--email=addr` sends the archive via msmtp/sendmail; `--webhook=url` POSTs a JSON summary to Slack, Teams, or any HTTP endpoint
- **Passphrase authentication** — AES-256-CBC + PBKDF2-HMAC-SHA256 (200,000 rounds); even root cannot bypass; includes a full built-in recovery workflow
- **ETA prediction** — EWMA-based runtime prediction using historical scan timing; accuracy improves with each run
- **Tab completion** — auto-installed on first run for all commands and flags
- **Config file support** — `/etc/wowscanner/wowscanner.conf` for persistent flag overrides

---

## Requirements

### Core (required)

| Package | Purpose |
|---|---|
| `bash` ≥ 4.4 | Shell runtime |
| `python3` | Built-in crypto, all report generators, findings parser |
| `zip` | Output archive creation |
| `nmap` | Port scanning (sections 7, 16, 16a) |

### Recommended

| Package | Purpose |
|---|---|
| `lynis` | CIS-benchmark audit (section 15) |
| `rkhunter` | Rootkit detection (section 14b) |
| `chkrootkit` | Rootkit detection (section 14b) |
| `arp-scan` | LAN device discovery (section 16a — preferred over nmap fallback) |

### Pentest tools (optional — skip with `--no-pentest`)

| Package | Purpose |
|---|---|
| `nikto` | Web application scanner (section 0b) |
| `hydra` | SSH brute-force simulation (section 0c) |
| `sqlmap` | SQL injection probe (section 0d) |
| `stress-ng` | CPU/memory/IO exhaustion test (section 0e) |
| `hping3` | SYN flood simulation (section 0e) |
| `enum4linux` / `enum4linux-ng` | SMB/Samba enumeration (section 0a) — auto-installed if missing |

Missing pentest tools are auto-installed at runtime where possible (apt, pip3, or git clone). All installations are non-destructive and removable with standard package managers.

---

## Installation

```bash
# Clone
git clone https://github.com/cocoflan/wowscanner.git
cd wowscanner

# Install core dependencies
sudo apt-get install nmap zip python3

# Install recommended tools
sudo apt-get install lynis rkhunter chkrootkit arp-scan

# Install pentest tools (optional)
sudo apt-get install nikto hydra sqlmap stress-ng hping3

# First run — sets passphrase, installs tab-completion, begins scan
sudo bash wowscanner.sh
```

No build step. No pip install. No virtualenv. The script is entirely self-contained.

---

## Quick Start

```bash
# Standard audit — recommended for regular use (~3-6 min)
sudo bash wowscanner.sh --no-pentest

# Full audit including active pentest sections (~8-15 min)
sudo bash wowscanner.sh

# Fastest possible run — skips pentest and slow sub-checks (~2-4 min)
sudo bash wowscanner.sh --fast-only

# See all commands and flags
sudo bash wowscanner.sh --help
```

On **first run**, the script prompts you to set a passphrase. This passphrase is required on every subsequent run. You will be shown a 48-character recovery key — save it somewhere safe.

---

## Usage

```
sudo bash wowscanner.sh [COMMAND] [FLAGS]
bash wowscanner.sh [COMMAND] [FLAGS]   # after passphrase setup + sudoers entry
```

All commands require root. After the first-run passphrase setup, the script optionally writes a sudoers entry so non-root users can invoke it without the `sudo` keyword — the passphrase is still required.

---

## Commands

| Command | Description |
|---|---|
| *(none)* | Run a full security audit |
| `clean` | Delete all `wowscanner_*` output files in the current directory |
| `clean --all` | Also wipe `/var/lib/wowscanner/` persistent data |
| `clean --integrity` | Reset the integrity alert log only |
| `clean --full` | Full factory reset — output files + all persistent data |
| `verify` | Verify HMAC integrity of all archive zips in the current directory |
| `verify --reset-history` | Retire all known archives (use after moving to a new directory) |
| `diff` | Compare FAIL/WARN findings between the two most-recent scan reports |
| `harden` | Apply CIS-aligned kernel hardening to `/etc/sysctl.d/99-wowscanner.conf` |
| `baseline` | Snapshot current PASS findings for future regression tracking |
| `install-timer` | Install a weekly systemd scan timer |
| `remove-timer` | Remove the systemd timer |
| `install-completion` | Manually install bash tab-completion |
| `example-output` | Write example scan output files without running a scan |
| `recover` | Password recovery — back up and remove auth.key (see [Password Recovery](#password-recovery)) |
| `reset-auth` | Change passphrase (requires current passphrase) |
| `reset-auth forgot` | Reset via recovery key when passphrase is forgotten (root only) |
| `reset-auth rk` | Reset using the 48-char recovery key shown at first-run setup |
| `reset-auth --force` | Wipe all auth data — no undo (root only) |

### clean

Before deleting anything, runs an integrity check against all archive zips in the current directory. Files that fail the hash check are kept. Use `clean --all` to also remove persistent port history, score history, and timing databases.

### verify

Checks every `wowscanner_archive_*.zip` in the current directory against its embedded HMAC-signed `INTEGRITY.txt` manifest. Reports:

- HMAC OK / FAIL (manifest authenticity)
- SHA-256 + SHA-512 hash match per file
- File size match (catches truncation)
- Permission changes since archiving
- mtime changes since archiving
- Known archives that have disappeared from disk (possible tampering or deletion)

Results are appended to `/var/lib/wowscanner/integrity_alerts.log`.

### diff

Extracts all FAIL and WARN findings from the two most-recent `.txt` reports in the current directory and shows:

- New FAILs that appeared since the last scan
- FAILs that have been resolved
- New WARNs that appeared since the last scan
- WARNs that have been resolved
- Score delta (e.g. `72% → 81%`)

### harden

Shows a preview of each sysctl parameter that will change, confirms with you, then writes and applies the config. Parameters applied:

- IP forwarding disabled
- ICMP redirect sending/accepting disabled
- Source route acceptance disabled
- Martian packet logging enabled
- TCP SYN cookies enabled
- ICMP broadcast ignore enabled
- Reverse path filtering enabled
- ASLR set to full randomisation (`kernel.randomize_va_space=2`)
- `kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`, `kernel.sysrq=0`
- `fs.suid_dumpable=0`, `kernel.kexec_load_disabled=1`, `kernel.yama.ptrace_scope=1`

To revert: `rm /etc/sysctl.d/99-wowscanner.conf && sysctl --system`

### baseline

Saves all current PASS findings to `/var/lib/wowscanner/findings_last.db`. Subsequent runs compare against this snapshot and flag anything that was previously passing but is now failing — enabling regression detection across updates, configuration changes, and new deployments.

### install-timer

Creates two systemd unit files:

- `/etc/systemd/system/wowscanner.service` — runs `wowscanner.sh --no-pentest --fast-only` as root
- `/etc/systemd/system/wowscanner.timer` — fires weekly with a randomised 1-hour delay to avoid predictable scheduling

Logs are written to `/var/log/wowscanner/wowscanner.log`. Check timer status with `systemctl list-timers wowscanner.timer`. Edit the service file to change scan flags.

---

## Flags

| Flag | Description |
|---|---|
| `--no-pentest` | Skip active pentest sections 0a–0e |
| `--no-lynis` | Skip Lynis CIS-benchmark audit (section 15) |
| `--no-rkhunter` | Skip rkhunter and chkrootkit (section 14b) |
| `--no-hardening` | Skip advanced hardening checks (section 13c) |
| `--no-netcontainer` | Skip network and container checks (section 13d) |
| `--fast-only` | Skip pentest + tighten all timeouts (~2-4 min total) |
| `--quiet` | Suppress INFO lines — show only PASS/FAIL/WARN |
| `--email=addr` | Email the archive after the scan |
| `--webhook=url` | POST a JSON summary to a webhook URL after the scan |

### Environment overrides (set before `sudo`)

| Variable | Default | Description |
|---|---|---|
| `LYNIS_FULL=true` | fast | Run full Lynis audit (~2-5 min vs ~25-50 sec) |
| `RKH_FULL=true` | fast | Run full rkhunter scan |
| `APT_CACHE_MAX_AGE=0` | 86400 | Force `apt-get update` regardless of cache age |

Example:
```bash
LYNIS_FULL=true RKH_FULL=true sudo bash wowscanner.sh --no-pentest
```

---

## Scan Sections

Wowscanner runs 50 sections on each full scan in the order shown. The live progress bar shows completion percentage with an EWMA-based ETA. A per-section timing panel is printed at the end of every scan.

### Pentest sections (0a–0e)

Skipped with `--no-pentest` or `--fast-only`. All tests target **localhost only**.

| Section | Tools | What it does |
|---|---|---|
| **0a. Network & Service Enumeration** | nmap, enum4linux | Full service/OS/banner fingerprint (`-sV -O -A -p- --open`). SMB/Samba enumeration — auto-installs enum4linux-ng via apt, pip3, or git clone if not present. |
| **0b. Web Application Scanner** | nikto | Scans all detected HTTP/HTTPS ports. Reports version disclosure, exposed admin paths, missing security headers, dangerous files. |
| **0c. SSH Brute-force Simulation** | hydra | Tests 10 credential pairs against the SSH port. Confirms lockout triggers correctly (pam_faillock / fail2ban). |
| **0d. SQL Injection Probe** | sqlmap | Tests injectable parameters on all detected HTTP ports. Confirms parameterised queries or WAF protection. |
| **0e. Stress & Resource Exhaustion** | stress-ng, hping3 | 30-second CPU/memory/IO load test. 5-second SYN flood on the loopback. Confirms OOM killer behaviour and SYN cookie protection. |

### Core sections (1–16)

| Section | What it checks |
|---|---|
| **1. System Information** | Hostname, OS, kernel, uptime, CPU count, RAM, disk usage, inode usage, open file handles, virtualisation platform, zombie processes, unexpected read-only mounts, OOM killer policy, core dump limits, root process count |
| **2. System Updates** | Pending package updates, pending security updates specifically, unattended-upgrades installation and service status, APT cache age, kernel EOL status |
| **3. Users & Accounts** | UID-0 accounts, sudo group members, accounts with login shells, last login timestamps, accounts inactive >90 days, authorized\_keys file permissions and duplicate key detection, locked accounts |
| **4. Password Policy** | Empty passwords in `/etc/shadow`, SHA-512 hash enforcement, `/etc/login.defs` PASS\_MAX\_DAYS / PASS\_MIN\_DAYS / PASS\_WARN\_AGE, PAM password complexity configuration |
| **5. SSH Configuration** | Protocol version, PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, Port, MaxAuthTries, AllowUsers/AllowGroups, StrictModes, AllowAgentForwarding, X11Forwarding, ClientAliveInterval, PrintLastLog, Banner |
| **6. Firewall** | UFW status and default policies (input/output/forward), iptables rule count, ip6tables rule count, firewalld status |
| **7. Open Network Ports** | All listening TCP/UDP ports via ss/netstat, bind-address exposure analysis (0.0.0.0 vs 127.0.0.1), flags database and cache services that should never be externally reachable (MySQL, Redis, MongoDB, PostgreSQL, Elasticsearch, Memcached, Kafka, Consul, Erlang EPMD, ZooKeeper) |
| **8. File & Directory Permissions** | `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group` permissions and ownership, SUID/SGID binaries, world-writable files in /etc, pip package audit, npm package audit, chattr +i immutable file check on critical system files |
| **9. Services & Daemons** | All enabled systemd services, services running as root, failed systemd units |
| **10. Logging & Audit** | rsyslog/syslog-ng/journald service status, auditd status, `/var/log/auth.log` existence and recency, log file permissions |
| **11. Kernel & Sysctl Hardening** | ASLR, dmesg\_restrict, kptr\_restrict, sysrq, SUID core dumps, kexec\_load\_disabled, ptrace scope, TCP SYN cookies, IP forwarding, ICMP redirect acceptance, source routing, martian logging, /proc kernel info leak checks |
| **12. Cron & Scheduled Tasks** | /etc/crontab, /etc/cron.d/, cron.hourly/daily/weekly/monthly, all user crontabs, world-writable cron directories and files, at jobs |
| **13. Installed Packages & Integrity** | Installed package count, debsums file integrity verification, pip vulnerable package scan, npm audit |
| **13c. Advanced Hardening** | Fail2ban installation and status, PAM tally lockout configuration, login.defs settings, su restriction to wheel/sudo group, audit rules for privileged commands, /tmp and /var/tmp mount security options |
| **13d. Network & Container** | Docker daemon.json (userns-remap, no-new-privileges, seccomp profile, AppArmor profile), Docker socket permissions (world-readable check), containers running as root |
| **14. AppArmor / SELinux** | AppArmor module load status, enforce/complain profile counts, SELinux enforcement mode |
| **14b. chkrootkit + rkhunter** | chkrootkit scan for known rootkit signatures. rkhunter database update and scan (fast mode by default; full scan with `RKH_FULL=true`). |
| **15. Lynis Security Audit** | Full CIS-benchmark audit via Lynis (fast mode by default; full with `LYNIS_FULL=true`). Displays hardening index and all failed test IDs. Auto-installs Lynis from the CISOfy repository if not present. |
| **16a. LAN Device Discovery** | Scans the local subnet via arp-scan (preferred) or nmap ping sweep, falls back to the ARP cache. Identifies active hosts, MAC addresses, and vendors. Produces a JSON host map used by the ODT intelligence report. |
| **16. Random Port Scan** | nmap stealth scan on randomly selected port ranges, catching services running on non-standard ports. |

### Extended sections (17b–17z)

| Section | What it checks |
|---|---|
| **17b. Failed Login Analysis** | Parses `/var/log/auth.log` or systemd journal for SSH brute-force indicators: repeated failures, invalid usernames, source IP frequency and geolocation, fail2ban status, active bans |
| **17c. Environment Security** | umask value, PATH entries that are world-writable or relative, LD\_PRELOAD and LD\_LIBRARY\_PATH presence, PYTHONPATH, shell startup file permissions (/etc/profile, /etc/bash.bashrc, ~/.bashrc) |
| **17d. USB Device Audit** | USB storage devices currently connected, USB network adapters, loaded USB-related kernel modules (usb-storage, uas, etc.) |
| **17e. World-Writable Deep** | World-writable files in /etc, /usr, /bin, /sbin, /lib; non-root-owned files in /etc; non-standard SUID binaries; shared directories missing sticky bit; unowned files |
| **17f. Certificate & TLS Audit** | SSL/TLS certificate expiry for all detected HTTPS ports, SSH host key types and bit lengths, detection of weak key types (DSA, RSA <2048) |
| **17g. Network Security Extras** | ARP spoofing indicators (duplicate IPs in ARP table), ICMP redirect acceptance, TCP RFC1337 TIME-WAIT assassination protection, `/etc/hosts.allow` and `/etc/hosts.deny` configuration |
| **17h. Auditd Detailed Check** | auditd service state, active audit rule count, log rotation configuration in /etc/audit/auditd.conf |
| **17i. Open Files & Sockets** | Deleted executables still running in memory, unexpected listening ports since last scan, world-writable Unix domain sockets, world-readable sensitive files, file descriptor exhaustion (near ulimit) |
| **17j. Swap & Memory Security** | Swap partition/file encryption status, `vm.overcommit_memory` policy, kptr\_restrict value |
| **17k. PAM & Auth Hardening** | PAM module file integrity (unexpected binary modifications), TOTP/MFA module presence, sudo session logging, su restriction to wheel/sudo group |
| **17l. Filesystem Hardening** | `/tmp` noexec and nosuid mount options, `/dev/shm` restrictions, `/proc` hidepid setting, home directory permissions (no world-readable home dirs) |
| **17m. Container Security** | Docker daemon.json: userns-remap, no-new-privileges, seccomp profile, AppArmor profile. Docker socket world-readability. Containers currently running as root. |
| **17n. Repository Security** | APT repository signing key configuration, `trusted=yes` overrides in sources.list (disable signature verification), third-party repository count, total enabled repository count |
| **17o. Time Sync Security** | NTP/chrony/systemd-timesyncd service status, chrony tracking drift, configured NTP server list |
| **17p. IPv6 Security** | ip6tables rule count, UFW IPv6 policy, IPv6 router advertisement acceptance (`accept_ra`) |
| **17q. SSH Hardening Extras** | Configured ciphers (flags: arcfour, 3des-cbc, blowfish-cbc), MACs (flags MD5 and SHA-1 based), KexAlgorithms (flags diffie-hellman-group1-sha1, group14-sha1), AllowUsers/AllowGroups presence, MaxSessions limit |
| **17r. Core Dump Security** | `kernel.core_pattern`, ulimit -c for root, `fs.suid_dumpable`, systemd coredump storage configuration in `/etc/systemd/coredump.conf` |
| **17s. Systemd Unit Hardening** | Checks running services for sandbox directives: PrivateTmp, ProtectSystem, ProtectHome, NoNewPrivileges, ReadOnlyPaths. Reports failed unit count. |
| **17t. Sudo Configuration** | NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/, wildcard command rules (privilege escalation vectors), PASSWD\_TIMEOUT, sudoers file permissions and ownership |
| **17u. Log Integrity** | Remote syslog forwarding configuration, `/var/log/auth.log` ownership and permissions, logrotate retention period (minimum rotation count) |
| **17v. Compiler & Dev Tools** | gcc, clang, build-essential presence on production systems, debug tools (gdb, strace, ltrace), pip/npm privilege abuse indicators (running as root without isolation) |
| **17b3. Hardware & Firmware** | Secure Boot (mokutil or EFI variable), IOMMU/DMA protection (Intel VT-d via dmesg, AMD-Vi via cmdline), per-vulnerability CPU mitigation status from `/sys/devices/system/cpu/vulnerabilities/` (covers Spectre v1/v2, Meltdown, MDS, TAA, ITLB Multihit, and others), TPM device detection |
| **17b4. GRUB & Boot Security** | GRUB password protection in grub.cfg, dangerous kernel cmdline parameters (debug, single, init= override), `mitigations=off` detection, /boot directory permissions (should be 700/750), grub.cfg permissions (should be 600) |
| **17b5. Web Server Security** | **Nginx:** server\_tokens, weak TLS protocols (SSLv3/TLS1.0/1.1), missing security headers (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy), directory listing (autoindex). **Apache:** ServerTokens, ServerSignature, TraceEnable (XST vulnerability). |
| **17b6. Secrets & Credential Exposure** | World-readable private key files (.pem, .key, id\_rsa, id\_ed25519, .p12, .pfx) under /etc, /home, /root, /var/www, /opt. Credential patterns in .env, wp-config.php, database.yml, secrets.yml, credentials.json. Sensitive command patterns in bash history. Active SSH agent forwarding sockets. |
| **17w. Network Interface Security** | Promiscuous mode on any interface (packet sniffing indicator), ARP cache anomalies (duplicate IPs), unusual packet drop rates |
| **17x. Kernel Module Security** | Dangerous loaded modules (usb-storage, bluetooth, firewire-core, dccp, sctp, rds, tipc, cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf), module signature enforcement (`module.sig_enforce`), blacklist configuration in /etc/modprobe.d/ |
| **17y. MAC Profile Audit** | AppArmor enforce/complain counts, SELinux mode, recent AppArmor denial events from audit log or journald |
| **17z. Network Exposure Summary** | Consolidates all open ports across all sections with risk ratings: CRIT (database/cache services externally exposed), HIGH (admin panels, unencrypted services), MED (web services), LOW (common expected services). Produces a final exposure summary table. |

---

## Output Files

Every scan writes the following files to the **current working directory**:

| File | Format | Description |
|---|---|---|
| `wowscanner_<TS>.txt` | Plain text | Full audit log with ANSI colour codes. Every finding, detail line, subheader, and section banner. |
| `wowscanner_findings_<TS>.txt` | Plain text | Paginated findings report. One page per section showing all FAIL/WARN/PASS/INFO findings. Navigate with `less` (spacebar = next page). |
| `wowscanner_report_<TS>.odt` | LibreOffice Writer | Graphical report with colour-coded section headings (red/amber/green), inline detail lines, SVG score bar chart, and metric summary boxes. |
| `wowscanner_report_<TS>.html` | HTML | Self-contained single-file HTML dashboard. No server required — open in any browser. |
| `wowscanner_stats_<TS>.ods` | LibreOffice Calc | Statistics workbook with score history across runs, per-section timing, and an All Findings sheet. |
| `wowscanner_intel_<TS>.odt` | LibreOffice Writer | Intelligence report including CVE context for detected issues and the LAN device discovery map. |
| `wowscanner_archive_<TS>.zip` | ZIP | HMAC-signed archive of all above files plus an `INTEGRITY.txt` manifest containing SHA-256, SHA-512, file size, mtime, and permissions for every included file. |

### Navigating the findings report

```bash
# Page through with spacebar
less wowscanner_findings_*.txt

# Show only failures with line numbers
grep -n FAIL wowscanner_findings_*.txt

# Show only warnings
grep -n WARN wowscanner_findings_*.txt

# Jump to next section boundary inside less
/^>>>
```

### Verifying archive integrity

```bash
sudo bash wowscanner.sh verify
```

Detects: HMAC tampering, SHA-256/SHA-512 hash mismatches, file size changes, permission changes, mtime changes, and archives that have disappeared from disk since creation.

---

## Authentication System

Wowscanner requires a passphrase on every invocation — including as root. This is by design.

**How it works:**

1. On first run, you choose a passphrase (minimum 10 characters).
2. A 256-bit master key is derived from the passphrase via PBKDF2-HMAC-SHA256 with 200,000 rounds and a random 32-byte salt.
3. The master key encrypts a 16-byte verification token (AES-256-CBC) and wraps a random 256-bit data key.
4. An HMAC-SHA256 covers all stored fields — wrong passphrase and file tampering produce the same rejection response (no oracle).
5. The key file is stored at `/etc/wowscanner/auth.key` with permissions 400, owner root:root.
6. After successful authentication, a one-time session token is generated and passed to the sudo re-exec via environment variable, preventing a double password prompt.
7. A 48-character recovery key (SHA-256 derived from the master key) is shown **once** at first-run setup. Store it somewhere safe — this is the only way to recover access without wiping auth data.

**Lockout:** 3 consecutive wrong passphrases end the session. The failure is logged to `/var/lib/wowscanner/auth_failures.log` with timestamp, username, hostname, and PID.

---

## Password Recovery

Four recovery paths are available depending on what you have.

### You have your passphrase and want to change it

```bash
sudo bash wowscanner.sh reset-auth
```

Prompts for the current passphrase then sets a new one. Scan history and the data key are preserved — all previous archives remain verifiable.

### You forgot your passphrase and have the recovery key

The recovery key is the 48-character hex string displayed once at first-run setup.

```bash
sudo bash wowscanner.sh reset-auth forgot
# or equivalently
sudo bash wowscanner.sh reset-auth rk
```

Enter the 48-character recovery key when prompted. Sets a new passphrase. Scan history preserved.

### You forgot your passphrase and do not have the recovery key

```bash
sudo bash wowscanner.sh recover
```

Backs up `/etc/wowscanner/auth.key` to `/etc/wowscanner/auth.key.bak`, then removes `auth.key`. The next run triggers the first-run setup wizard where you set a new passphrase. Scan history, port data, and score history in `/var/lib/wowscanner/` are all preserved. Note: previous archives will no longer be verifiable with the new passphrase (they were signed with the old data key).

### Full wipe

```bash
sudo bash wowscanner.sh reset-auth --force
```

Removes the auth key and wipes all associated scan data. No undo.

---

## Automated Scanning

### Install a weekly systemd timer

```bash
sudo bash wowscanner.sh install-timer
```

Creates:
- `/etc/systemd/system/wowscanner.service` — runs `wowscanner.sh --no-pentest --fast-only` as root
- `/etc/systemd/system/wowscanner.timer` — fires weekly with a randomised 1-hour delay
- Output directory `/var/log/wowscanner/` with all reports and the archive

Check timer status:
```bash
systemctl list-timers wowscanner.timer
```

View logs:
```bash
tail -f /var/log/wowscanner/wowscanner.log
```

Remove the timer:
```bash
sudo bash wowscanner.sh remove-timer
```

### Manual cron alternative

```cron
0 2 * * 0 cd /var/log/wowscanner && bash /opt/wowscanner/wowscanner.sh --no-pentest --quiet >> cron.log 2>&1
```

---

## Report Delivery

### Webhook (Slack, Teams, or any HTTP endpoint)

```bash
# One-off
sudo bash wowscanner.sh --no-pentest --webhook=https://hooks.slack.com/services/T.../B.../...

# Persistent via config file
echo 'WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...' \
  | sudo tee -a /etc/wowscanner/wowscanner.conf
```

The POST body is a JSON object containing hostname, score percentage, pass/fail/warn counts, and a rating string (GOOD / MODERATE / CRITICAL, based on score thresholds of 80% and 50%).

### Email

```bash
# One-off
sudo bash wowscanner.sh --no-pentest --email=security@example.com

# Persistent via config file
echo 'REPORT_EMAIL=security@example.com' \
  | sudo tee -a /etc/wowscanner/wowscanner.conf
```

Requires one of: `msmtp`, `sendmail`, or `ssmtp`. The archive zip is attached as base64. If the archive exceeds 20 MB, a text summary is sent instead.

---

## Configuration File

Persistent options can be set in `/etc/wowscanner/wowscanner.conf`. The file is sourced before argument parsing, so command-line flags always take precedence.

```bash
# /etc/wowscanner/wowscanner.conf

# Disable pentest sections for all runs
USE_PENTEST=false

# Always run full Lynis
# LYNIS_FULL=true

# Delivery
WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
# REPORT_EMAIL=security@example.com

# Do not refresh APT cache during scan
# APT_CACHE_MAX_AGE=86400
```

---

## Persistent Data

All state is stored in `/var/lib/wowscanner/`:

| File | Description |
|---|---|
| `port_issues.log` | All port findings across every run |
| `port_history.db` | Per-port first-seen and last-seen timestamps |
| `port_scan_log.db` | Per-run scan register — detects ports reappearing after closing |
| `score_history.db` | Score (pass/total/percentage) per run — feeds the ODS statistics workbook |
| `timing_history.db` | Per-section wall-clock times — feeds the EWMA ETA predictor |
| `findings_last.db` | Most-recent PASS findings — used by `baseline` regression tracking |
| `integrity_alerts.log` | Tamper detection log written by `verify` and `clean` |
| `auth_failures.log` | Failed passphrase attempts with timestamp, user, host, PID |
| `remediation_commands.sh` | Auto-generated remediation commands for detected port issues |

Wipe all persistent data:
```bash
sudo bash wowscanner.sh clean --all
```

---

## Legal Notice

Sections 0a–0e perform **active exploitation tests**: full port scanning, web application scanning, credential brute-forcing, SQL injection probing, and network stress testing. These run against **localhost by default**, but the tools involved are real attack tools.

**Only run Wowscanner on systems you own or have explicit written permission to test.**

Running active pentest tools against systems without authorisation may be illegal under computer fraud and abuse laws in your jurisdiction. The authors accept no liability for misuse.

Use `--no-pentest` for routine compliance scanning and reserve the full scan for authorised security assessments.

---

## License

BSD 2-Clause License — see [LICENSE](LICENSE).

Copyright (c) 2026 cocoflan. All rights reserved.
