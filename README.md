# Wowscanner

**Wowscanner** is a comprehensive security scanner for Debian/Ubuntu Linux.  
It audits a system across 40+ sections — from SSH hardening and kernel sysctl
settings to full pentest simulations — and produces colour-coded terminal
output, a paginated findings report, an ODT/HTML report, a statistics
spreadsheet, and an HMAC-signed archive, all in a single run.

---

## Requirements

| Dependency | Purpose |
|---|---|
| `bash` ≥ 4.4 | Shell runtime |
| `python3` | Built-in crypto, report generators |
| `nmap` | Port scanning (sections 7, 16) |
| `lynis` | CIS-benchmark audit (section 15) |
| `rkhunter`, `chkrootkit` | Rootkit detection (section 14b) |
| `nikto` | Web application scanner (section 0b) |
| `hydra` | SSH brute-force simulation (section 0c) |
| `sqlmap` | SQL injection probe (section 0d) |
| `stress-ng`, `hping3` | Resource exhaustion test (section 0e) |
| `zip` | Archive creation |

All pentest tools (nikto, hydra, sqlmap, stress-ng, hping3) are **optional**.
Skip them with `--no-pentest` or `--fast-only`.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/cocoflan/wowscanner.git
cd wowscanner

# Install common dependencies (Debian/Ubuntu)
sudo apt-get install nmap lynis rkhunter chkrootkit zip python3

# Optional: pentest tools
sudo apt-get install nikto hydra sqlmap stress-ng hping3

# First run — sets passphrase and installs tab-completion
sudo bash wowscanner.sh
```

---

## Usage

```bash
# Full audit (recommended — skip pentest for routine use)
sudo bash wowscanner.sh --no-pentest

# Full audit including pentest sections
sudo bash wowscanner.sh

# Quickest run (~2-4 min)
sudo bash wowscanner.sh --fast-only

# See all commands and flags
sudo bash wowscanner.sh --help
```

---

## Commands

| Command | Description |
|---|---|
| *(none)* | Run full security audit |
| `clean` | Delete output files in the current directory |
| `clean --all` | Also wipe `/var/lib/wowscanner/` persistent data |
| `verify` | Verify HMAC integrity of all archive zips |
| `diff` | Compare the two most-recent scan reports |
| `harden` | Write `/etc/sysctl.d/99-wowscanner.conf` hardening rules |
| `baseline` | Snapshot current PASS findings for regression tracking |
| `install-timer` | Install a weekly systemd scan timer |
| `recover` | Reset passphrase — backs up `auth.key` and removes it |
| `reset-auth` | Change passphrase (requires current passphrase) |
| `reset-auth forgot` | Reset via recovery key (root only) |

---

## Flags

| Flag | Description |
|---|---|
| `--no-pentest` | Skip pentest sections 0a–0e |
| `--no-lynis` | Skip Lynis audit (section 15) |
| `--no-rkhunter` | Skip rkhunter/chkrootkit (section 14b) |
| `--fast-only` | Skip pentest + all slow sections |
| `--quiet` | Suppress info lines |
| `--email=addr` | Email report after scan |
| `--webhook=url` | POST report JSON to webhook URL |

---

## Output Files

After every scan, the following files are written to the current directory:

| File | Description |
|---|---|
| `wowscanner_<TS>.txt` | Full plain-text audit log |
| `wowscanner_findings_<TS>.txt` | Paginated findings (spacebar to page) |
| `wowscanner_report_<TS>.odt` | Graphical report (LibreOffice Writer) |
| `wowscanner_report_<TS>.html` | Self-contained HTML report |
| `wowscanner_stats_<TS>.ods` | Statistics workbook (LibreOffice Calc) |
| `wowscanner_intel_<TS>.odt` | Intelligence / CVE context report |
| `wowscanner_archive_<TS>.zip` | HMAC-signed archive of all above |

---

## Authentication

Wowscanner uses a passphrase gate (AES-256-CBC + PBKDF2-HMAC-SHA256,
200,000 rounds). Even root cannot bypass it — the passphrase is required
to derive the AES key that decrypts the auth blob.

```bash
# Forgot your passphrase?
sudo bash wowscanner.sh recover          # wipes auth.key, prompts new one on next run

# Change passphrase (needs current passphrase)
sudo bash wowscanner.sh reset-auth

# Reset using the 48-char recovery key shown at first-run setup
sudo bash wowscanner.sh reset-auth forgot
```

---

## Sections (40+)

<details>
<summary>Click to expand full section list</summary>

| # | Section |
|---|---|
| 0a | Pentest — Network & Service Enumeration (nmap, enum4linux) |
| 0b | Pentest — Web Application Scanner (nikto) |
| 0c | Pentest — SSH Brute-force Simulation (hydra) |
| 0d | Pentest — SQL Injection Probe (sqlmap) |
| 0e | Pentest — Stress & Resource Exhaustion (stress-ng, hping3) |
| 1 | System Information |
| 2 | System Updates |
| 3 | Users & Accounts |
| 4 | Password Policy |
| 5 | SSH Configuration |
| 6 | Firewall |
| 7 | Open Network Ports |
| 8 | File & Directory Permissions |
| 9 | Services & Daemons |
| 10 | Logging & Audit |
| 11 | Kernel & Sysctl Hardening |
| 12 | Cron & Scheduled Tasks |
| 13 | Installed Packages & Integrity |
| 14 | AppArmor / SELinux |
| 14b | chkrootkit + rkhunter |
| 15 | Lynis Security Audit |
| 16 | Random Port Scan |
| 17 | Summary |
| 17b | Failed Login Analysis |
| 17c | Environment Security |
| 17d | USB Device Audit |
| 17e | World-Writable Deep |
| 17f | Certificate & TLS Audit |
| 17g | Network Security Extras |
| 17h | Auditd Detailed Check |
| 17i | Open Files & Sockets |
| 17j | Swap & Memory Security |
| 17k | PAM & Auth Hardening |
| 17l | Filesystem Hardening |
| 17m | Container Security |
| 17n | Repository Security |
| 17o | Time Sync Security |
| 17p | IPv6 Security |
| 17q | SSH Hardening Extras |
| 17r | Core Dump Security |
| 17s | Systemd Unit Hardening |
| 17t | Sudo Configuration |
| 17u | Log Integrity |
| 17v | Compiler & Dev Tools |
| 17w | Network Interface Security |
| 17x | Kernel Module Security |
| 17y | MAC Profile Audit |
| 17z | Network Exposure Summary |

</details>

---

## ⚠ Legal Notice

The pentest sections (0a–0e) perform **active exploitation tests** against
the target system. Only run Wowscanner on systems you own or have explicit
written permission to test. The authors accept no liability for misuse.

---

## License

BSD 2-Clause License — see [LICENSE](LICENSE).
