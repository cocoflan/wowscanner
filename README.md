Wowscanner Security Scanner

Version 1.0.0 · Author: cocoflan · Copyright (c) 2026 cocoflan. All rights reserved.

A comprehensive Debian/Ubuntu security audit script that covers 20+ audit sections, generates graphical ODT/ODS reports, runs rootkit and Lynis scans, maintains a persistent port-issue tracker, and signs every output archive with dual SHA-256/SHA-512 hashes and an HMAC-based integrity manifest.

Table of Contents

Requirements
Quick Start
Commands
Scan Options & Flags
Environment Overrides
Audit Sections
Output Files
Integrity & Security System
Persistent Data
Samba Integration
Typical Runtimes
Example Output
License


Requirements
RequirementNotesOSDebian 10+ or Ubuntu 20.04+ShellBash 4.4+PrivilegesMust run as root (sudo)PythonPython 3.6+ (used for report generation)NetworkRequired for apt updates and optional tool downloads
Auto-installed if missing (via apt or fallback): nmap, lynis, rkhunter, chkrootkit, nikto, hydra, sqlmap, enum4linux/enum4linux-ng, smbclient, hping3, stress-ng, debsums.

Quick Start
bash# Download
wget https://github.com/cocoflan/wowscanner/raw/main/wowscanner.sh
chmod +x wowscanner.sh

# Run a full audit (pentest sections are OFF by default)
sudo bash wowscanner.sh

# Quickest pass (~2-4 minutes)
sudo bash wowscanner.sh --fast-only

# See all commands and options
sudo bash wowscanner.sh --help

Commands
All commands work without running the audit. They exit immediately after completing their task.
(no command) — Run the audit
bashsudo bash wowscanner.sh [OPTIONS]
Runs all 20 audit sections, generates four output files, creates a signed zip archive, and restarts Samba if detected.

verify — Check archive integrity
bashsudo bash wowscanner.sh verify
sudo bash wowscanner.sh --verify
sudo bash wowscanner.sh -v
Checks every wowscanner_archive_*.zip in the current directory:

ZIP CRC — verifies the archive is structurally intact
HMAC-SHA256 — confirms the embedded manifest has not been tampered with
SHA-256 + SHA-512 — dual-hash verification of every file inside the archive
File size — catches truncation before hashing
Permission audit — detects mode/owner changes since archiving
Modification time — flags any write after the archive was created

Files removed with clean are shown as CLEANED (yellow, no alarm). Files missing for any other reason trigger a red alert with a terminal bell.
│  CRC check  : OK — zip is structurally intact
│  HMAC check : OK — manifest authentic and unmodified
│  Files in manifest: 4
│    CLEANED   wowscanner_20260321_183101.txt  ↳ removed with 'clean' — zip copy intact
│    OK        wowscanner_report_20260321_183101.odt  sha256=a3f8c1d2e4b5f6a7...
│    MISSING!  wowscanner_stats_20260321_183101.ods
│              ↳ Not removed by 'clean' — unexpected deletion!
│              ↳ Restore from zip: unzip wowscanner_archive_... wowscanner_stats_...ods
│
│  ═══ Grand Summary ════════════════════════════════════
│  1 OK   1 cleaned (expected absent)   1 MISSING (unexpected)
│  ⚠  INTEGRITY COMPROMISED — see details above!

clean — Delete output files
bashsudo bash wowscanner.sh clean
sudo bash wowscanner.sh clean --all
Deletes all wowscanner_*.txt, *.odt, *.ods, and *.sha256 files from the current directory. Zip archives are always kept — they contain the integrity manifest and serve as the recovery copy.
Before deleting, clean runs a full integrity check against all zips. Each deleted file is logged to the integrity alert log so verify can correctly classify it as expected-absent.
--all also wipes /var/lib/wowscanner/ (port history, issue log, remediation script).

--help / -h / help
bashsudo bash wowscanner.sh --help
Displays full usage information and exits. Does not require root.

Scan Options & Flags
FlagEffect--no-pentestSkip pentest sections 0a–0e (nmap, Nikto, Hydra, SQLMap, stress-ng)--no-lynisSkip Lynis security audit (section 15)--no-rkhunterSkip chkrootkit and rkhunter (section 14b)--fast-onlySkip all pentest sections and enable fast mode for Lynis and rkhunter--quietSuppress informational (INFO) output lines

⚠ Pentest sections are OFF by default. Sections 0a–0e run active exploitation tests (network enumeration, web scanning, brute-force simulation, SQL injection probing, and stress testing). Only enable them on systems you own or have explicit written permission to test.


Environment Overrides
Set these before sudo to control scanner behaviour:
bash# Run full Lynis audit (default: fast mode, ~25-50 sec)
LYNIS_FULL=true sudo bash wowscanner.sh

# Run full rkhunter scan (default: fast mode, ~30-60 sec)
RKH_FULL=true sudo bash wowscanner.sh

# Force apt-get update even if the cache is fresh
APT_CACHE_MAX_AGE=0 sudo bash wowscanner.sh

# Combine overrides
LYNIS_FULL=true RKH_FULL=true sudo bash wowscanner.sh --no-pentest

Audit Sections
Each result line ends with Ω (omega, coloured to match the result type) as a visual end-of-line marker.
  [✔ PASS]  Root account is locked  Ω
  [✘ FAIL]  UFW firewall is INACTIVE  Ω
  [⚠ WARN]  Default SSH port 22 in use  Ω
  [ℹ INFO]  Lynis version: 3.0.9  Ω
  [- SKIP]  Lynis skipped (--no-lynis)  Ω
Pentest Sections (OFF by default)
SectionToolWhat it checks0a Pentest — Network Enumerationnmap, enum4linuxOpen ports, SMB shares, OS fingerprint, null sessions0b Pentest — Web ScannerNiktoHTTP vulnerabilities, misconfigurations, dangerous files0c Pentest — SSH Brute-forceHydraCommon username/password pairs against local SSH0d Pentest — SQL InjectionSQLMapSQL injection on locally listening HTTP services0e Pentest — Stress Teststress-ng, hping3CPU/memory exhaustion, SYN flood resilience
Security Audit Sections (always run)
SectionWhat it checks1 System InformationHostname, OS, kernel, uptime, CPU, RAM, disk2 System UpdatesPending security updates, last apt-get update time3 Users & AccountsEmpty passwords, root lock, UID 0 accounts, no-expiry accounts4 Password PolicyPASS_MAX_DAYS, min length, PAM complexity modules5 SSH ConfigurationPermitRootLogin, PasswordAuthentication, port, empty passwords, protocol6 FirewallUFW status, iptables rules, nftables, firewalld7 Open Network PortsListening services, unexpected ports, dangerous port list8 File & Directory PermissionsWorld-writable files, SUID/SGID binaries, sticky bits9 Services & DaemonsRunning services, suspicious processes, unnecessary daemons10 Logging & Auditsyslog, journald, auditd, auth.log, logrotate11 Kernel Hardeningsysctl: ASLR, SYN cookies, IP forwarding, kptr_restrict12 Cron & Scheduled TasksSystem cron, user crontabs, at jobs, unusual entries13 Packages & IntegrityInstalled packages, debsums integrity check14b Rootkit Scannerschkrootkit, rkhunter (fast or full mode)14 Mandatory Access ControlAppArmor profiles, SELinux status15 Lynis Security AuditFull Lynis run (fast or full mode), hardening index16 Port Scannmap scan, persistent port issue tracker, remediation script17 SummaryScore, PASS/FAIL/WARN counts, per-section breakdown

Output Files
Every scan produces five files in the current directory, all identified by a YYYYMMDD_HHMMSS timestamp:
FileFormatContentswowscanner_<ts>.txtPlain textComplete audit log with all section outputwowscanner_report_<ts>.odtLibreOffice WriterGraphical report with security index, colour-coded findings, section tableswowscanner_stats_<ts>.odsLibreOffice Calc7-sheet workbook with score gauge, bar chart, pie chart, heatmap, severity radar, per-section stats, deep-dive tableswowscanner_intel_<ts>.odtLibreOffice WriterIntelligence report: executive dashboard, CVE landscape (NIST NVD 2020–2025), CISA KEV table, threat intelligence (Trend Micro · Elastic · Mandiant), remediation matrixwowscanner_archive_<ts>.zipZIPAll four files above + INTEGRITY.txt manifest (never deleted by clean)wowscanner_archive_<ts>.sha256TextSHA-256 sidecar, compatible with sha256sum -c
Security Index (embedded in all three ODF files)
Every report opens with a Security Index panel showing:

A semi-circular gauge coloured by score band
A colour legend explaining each rating:

ColourRangeMeaning🔴 Dark red0–20%Critical — Immediate action required🟠 Orange-red21–40%High — Significant risks, address FAILs urgently🟡 Amber41–60%Moderate — Several issues need attention🟢 Dark green61–80%Good — Reasonably hardened, maintain regularly🔵 Blue81–100%Excellent — Well hardened, schedule regular audits

A Findings by Section horizontal bar chart (Excel-style, PASS/FAIL/WARN per section with score %)

ODS Statistics Workbook sheets
SheetContentsOverviewScore gauge, summary counts, ratingPer-SectionPASS/FAIL/WARN/INFO per audit sectionAll IssuesEvery FAIL and WARN with full textFAIL Deep-DiveSeverity, description, fix command, CVE refsWARN Deep-DiveSame as FAIL Deep-DiveChartDataRaw numbers for custom chartingChartsAll 7 SVG charts embedded as inline images

Integrity & Security System
What gets recorded at archive time
Every zip contains INTEGRITY.txt — a signed manifest listing for each file:
# Wowscanner integrity manifest v2
# Generated  : 2026-03-21 18:31:01
# Host       : myserver
# Files      : 4
# Format     : SHA256  SHA512  SIZE  MTIME  MODE  UID  GID  filename
#
a3f8c1d2...  d72e09f1...  8192  1742550000  0o100644  0  0  wowscanner_20260321_183101.txt
...
# HMAC-SHA256: cb43752c705934c3...
The HMAC is computed using a machine-derived key (hostname + /etc/machine-id) so the manifest cannot be forged on a different machine.
Seven layers checked by verify

Zip CRC — archive structural integrity
HMAC-SHA256 — manifest authenticity (detects INTEGRITY.txt tampering)
File size — fast truncation/padding detection
SHA-256 — content integrity
SHA-512 — second independent hash (collision resistance)
Permission audit — mode and owner changes
Modification time — any write after archiving

Passive check on every scan
At the start of every scan, the script checks whether any previously archived zip has disappeared from the current directory. If so it immediately shows a [⚠ WARN] with a terminal bell before the audit begins:
[⚠ WARN]  ARCHIVE MISSING: wowscanner_archive_20260320_080000.zip — gone since last scan!  Ω
[⚠ WARN]  Run:  sudo bash wowscanner.sh verify  — for a full integrity check  Ω
Restoring files from a zip
bash# Restore all files from an archive
unzip wowscanner_archive_20260321_183101.zip -d .

# Restore one specific file
unzip wowscanner_archive_20260321_183101.zip wowscanner_report_20260321_183101.odt

# Verify hashes manually
sha256sum -c wowscanner_archive_20260321_183101.sha256

Persistent Data
Stored in /var/lib/wowscanner/ across all runs:
FileContentsport_issues.logTimestamped log of every port issue foundport_history.dbFirst-seen / last-seen / count per portremediation_commands.shAuto-generated fix commands, one block per portintegrity_alerts.logAll archive events: ARCHIVED, CLEANED, TAMPERED, MISSING, VERIFY_CLEAN
The remediation script is generated with per-service advice:
bashsudo bash /var/lib/wowscanner/remediation_commands.sh
Wipe persistent data with:
bashsudo bash wowscanner.sh clean --all

Samba Integration
If smbd is running, the scanner automatically restarts it at the very end of every scan (after all output files are fully written and closed). This ensures the share directory listing is refreshed immediately and all output files are visible on the network share without a manual restart.
[✔]  smbd.service restarted — share directory is now up to date
All writes to /var/lib/wowscanner/ use atomic temp-file-then-rename operations to prevent Samba from seeing partially written files.

Typical Runtimes
ModeCommandTimeFast (no pentest)--fast-only2–4 minDefault (no pentest)(no flags)3–6 minWith pentest(no flags, pentest enabled)8–15 minFull scannersLYNIS_FULL=true RKH_FULL=true10–20 minEverythingpentest + full scanners20–40 min

Example Output
╔═══════════════════════════════════════════════════════════╗
║  Wowscanner Security Scanner  v1.0.0                      ║
║  Copyright (c) 2026 cocoflan. All rights reserved.        ║
║  2026-03-21 18:31:00 UTC                                  ║
╚═══════════════════════════════════════════════════════════╝

  Flags : --no-lynis | --no-pentest | --no-rkhunter | --quiet | --fast-only
  Mode  : pentest=OFF  lynis=ON  rkhunter=ON

  [✔ PASS]  Root account is locked  Ω
  [✔ PASS]  No accounts with empty passwords  Ω
  [✘ FAIL]  UFW firewall is INACTIVE  Ω
          ↳ ufw enable
  [⚠ WARN]  SSH listening on default port 22  Ω
  [⚠ WARN]  Lynis hardening index: 58/100 — MODERATE  Ω

  ...

╔══════════════════════════════════════════════════════════════╗
  OUTPUT FILES
╚══════════════════════════════════════════════════════════════╝

  Total elapsed time: 4m 12s

  Individual output files:
  • wowscanner_20260321_183101.txt
  • wowscanner_report_20260321_183101.odt
  • wowscanner_stats_20260321_183101.ods
  • wowscanner_intel_20260321_183101.odt

  Archive (all files above in one zip):
  • wowscanner_archive_20260321_183101.zip
  • wowscanner_archive_20260321_183101.sha256

  [✔]  smbd.service restarted — share directory is now up to date

License
Copyright (c) 2026 cocoflan. All rights reserved.
This software is provided for security auditing purposes on systems you own or have explicit written permission to test. The author accepts no liability for damages resulting from the use of this software. Pentest sections must not be run against systems without prior authorisation.