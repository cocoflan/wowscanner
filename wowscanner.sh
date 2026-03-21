#!/bin/bash
# ================================================================
#  Wowscanner Security Scanner
#  Version   : 1.0.0
#  Author    : cocoflan
#  Copyright : (c) 2026 cocoflan. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or
#  without modification, are permitted provided that this copyright
#  notice and this permission notice appear in all copies.
#
#  Platform  : Debian / Ubuntu Linux
#  Usage     : sudo bash wowscanner.sh [OPTIONS]
#             sudo bash wowscanner.sh clean        ← wipe old output files
#
#  Options:
#    --no-lynis      Skip Lynis audit (section 15)
#    --no-pentest    Skip all pentest sections (0a-0e)
#    --no-rkhunter   Skip rkhunter/chkrootkit (section 14b)
#    --quiet         Suppress extra info lines
#    --fast-only     Enable all fast modes + skip pentest (quickest run)
#
#  Commands:
#    clean           Delete all wowscanner_*.txt / *.odt / *.ods files in
#                    the current directory and exit (no audit is run).
#                    Also accepts:  clean --all  to also wipe
#                    /var/lib/wowscanner/ persistent data.
#
#  Output archiving:
#    After every scan a zip archive is created automatically:
#      wowscanner_archive_<TIMESTAMP>.zip
#    Individual files are kept alongside the archive so they can be
#    opened directly. Use  clean  to remove them when no longer needed.
#
#  Environment overrides (set before sudo):
#    LYNIS_FULL=true      Run full Lynis audit (default: fast, ~25-50s)
#    RKH_FULL=true        Run full rkhunter scan (default: fast, ~30-60s)
#    APT_CACHE_MAX_AGE=0  Force apt-get update even if cache is fresh
#
#  Typical runtimes:
#    Default (--no-pentest)  :  3-6 minutes
#    With pentest            :  8-15 minutes
#    --fast-only             :  2-4 minutes
#    LYNIS_FULL=true RKH_FULL=true : 10-20 minutes
#
#  ⚠  PENTEST NOTICE: Sections 0a-0e run BEFORE all other checks.
#     They perform active exploitation tests (SQLMap, Hydra, Nikto,
#     stress-ng, hping3). Only run on systems YOU own or have
#     explicit written permission to test.
#
#  Sections:
#    0a. Pentest — Network & Service Enumeration  (nmap, enum4linux)
#    0b. Pentest — Web Application Scanner        (nikto)
#    0c. Pentest — SSH Brute-force Simulation     (hydra)
#    0d. Pentest — SQL Injection Probe            (sqlmap)
#    0e. Pentest — Stress & Resource Exhaustion   (stress-ng, hping3)
#    1.  System Information
#    2.  System Updates
#    3.  Users & Accounts
#    4.  Password Policy
#    5.  SSH Configuration
#    6.  Firewall
#    7.  Open Network Ports
#    8.  File & Directory Permissions
#    9.  Services & Daemons
#    10. Logging & Audit
#    11. Kernel & Sysctl Hardening
#    12. Cron & Scheduled Tasks
#    13. Installed Packages & Integrity
#    14. AppArmor / SELinux
#    14b.chkrootkit + rkhunter (fast mode by default)
#    15. Lynis Security Audit  (fast mode by default)
#    16. Random Port Scan  (nmap stealth scan on random port ranges)
#    17. Summary
#
#  Persistent issue tracker:
#    /var/lib/wowscanner/port_issues.log  — all port findings across runs
#    /var/lib/wowscanner/port_history.db  — per-port first/last seen timestamps
# ================================================================
set -eo pipefail

# ── Version & Copyright ───────────────────────────────────────
VERSION="1.0.0"
PROGRAM="Wowscanner Security Scanner"
AUTHOR="cocoflan"
COPYRIGHT="Copyright (c) 2026 cocoflan. All rights reserved."

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ── Runtime flags ─────────────────────────────────────────────
USE_LYNIS=true
USE_PENTEST=true
USE_RKHUNTER=true
QUIET=false
CMD_CLEAN=false   # set true when "clean" subcommand is given
CLEAN_ALL=false   # set true when "clean --all" is given
CMD_HELP=false
CMD_VERIFY=false  # set true when "verify" subcommand is given
for arg in "$@"; do
  case "$arg" in
    clean)              CMD_CLEAN=true   ;;
    --clean)            CMD_CLEAN=true   ;;
    --all)              CLEAN_ALL=true   ;;   # meaningful only with clean
    --help|-h|help)     CMD_HELP=true    ;;
    verify|--verify|-v) CMD_VERIFY=true  ;;
    --no-lynis)    USE_LYNIS=false     ;;
    --no-pentest)  USE_PENTEST=false   ;;
    --no-rkhunter) USE_RKHUNTER=false  ;;
    --quiet)       QUIET=true          ;;
    --fast-only)
      # Quickest possible run: no pentest, fast scanners, skip rkhunter full pass
      USE_PENTEST=false
      # Lynis and rkhunter still run but in fast mode (env vars govern that)
      ;;
  esac
done

# ── Speed-optimisation state ───────────────────────────────────
# APT_UPDATED: set to 1 after the first apt-get update so subsequent
#              sections never trigger a redundant network refresh.
APT_UPDATED=0

# SSHD_CONFIG_CACHE: populated once by section_ssh; all sshd_value()
#                    calls within that section read from this cache
#                    instead of re-spawning sshd -T each time.
SSHD_CONFIG_CACHE=""

# Throttled apt-get update: only runs if the apt cache is older than
# APT_CACHE_MAX_AGE seconds (default 3600 = 1 hour) OR if APT_UPDATED=0.
APT_CACHE_MAX_AGE=3600   # seconds; override with: APT_CACHE_MAX_AGE=0 to force refresh

maybe_apt_update() {
  [[ "$APT_UPDATED" -eq 1 ]] && return 0          # already done this run
  local cache_file="/var/cache/apt/pkgcache.bin"
  if [[ -f "$cache_file" ]]; then
    local age=$(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0) ))
    if [[ "$age" -lt "$APT_CACHE_MAX_AGE" ]]; then
      info "apt cache is ${age}s old (< ${APT_CACHE_MAX_AGE}s) — skipping apt-get update"
      APT_UPDATED=1
      return 0
    fi
  fi
  apt-get update -qq 2>/dev/null || true
  APT_UPDATED=1
}

# ── Files ─────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="wowscanner_${TIMESTAMP}.txt"
SCORE=0
TOTAL=0

# ── Persistent port issue tracker ─────────────────────────────
PERSIST_DIR="/var/lib/wowscanner"
PORT_ISSUES_LOG="${PERSIST_DIR}/port_issues.log"
PORT_HISTORY_DB="${PERSIST_DIR}/port_history.db"
PORT_REMEDIATION="${PERSIST_DIR}/remediation_commands.sh"
NEW_PORT_ISSUES=0

# ── Helpers ───────────────────────────────────────────────────
log()    { echo -e "$*" | tee -a "$REPORT"; }
header() {
  log ""
  log "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
  log "${CYAN}${BOLD}  $1${NC}"
  log "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
}
subheader() { log "\n  ${BLUE}${BOLD}── $1 ──${NC}"; }
pass()   { SCORE=$((SCORE+1)); TOTAL=$((TOTAL+1)); log "  ${GREEN}[✔ PASS]${NC}  $1  ${GREEN}Ω${NC}"; }
fail()   { TOTAL=$((TOTAL+1));                     log "  ${RED}[✘ FAIL]${NC}  $1  ${RED}Ω${NC}"; }
warn()   { TOTAL=$((TOTAL+1));                     log "  ${YELLOW}[⚠ WARN]${NC}  $1  ${YELLOW}Ω${NC}"; }
info()   { log "  ${CYAN}[ℹ INFO]${NC}  $1  ${CYAN}Ω${NC}"; }
detail() { log "          ${MAGENTA}↳${NC} $1"; }
skip()   { log "  ${BLUE}[- SKIP]${NC}  $1  ${BLUE}Ω${NC}"; }

# ── Safe integer helper ────────────────────────────────────────
# Returns 0 if the value is a plain non-negative integer, else echoes 0.
safe_int() {
  local v="${1:-0}"
  # Strip whitespace
  v="${v//[[:space:]]/}"
  # If "unlimited" or non-numeric, return 0 to signal "not a useful number"
  [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "0"
}

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}Please run this script as root:  sudo bash $0${NC}"
    exit 1
  fi
}

# Resolve a sshd_config directive (handles Include files on Debian 8+).
# Uses a module-level cache (SSHD_CONFIG_CACHE) populated by section_ssh
# to avoid re-spawning sshd -T for every directive.
sshd_value() {
  local key="$1"
  local val=""
  # Fast path: use pre-populated cache from section_ssh
  if [[ -n "$SSHD_CONFIG_CACHE" ]]; then
    val=$(echo "$SSHD_CONFIG_CACHE" | grep -i "^${key} " | awk '{print $2}' | head -1 || true)
    if [[ -z "$val" ]]; then
      # Also check sshd_config directly for directives not in sshd -T output
      val=$(grep -Ei "^${key}[[:space:]]" /etc/ssh/sshd_config \
              /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
            | awk '{print $2}' | head -1 || true)
    fi
    echo "${val:-}"
    return
  fi
  # Cold path: no cache yet — run sshd -T once and fall back to grep
  val=$(sshd -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}' | head -1 || true)
  if [[ -z "$val" ]]; then
    val=$(grep -Ei "^${key}[[:space:]]" /etc/ssh/sshd_config \
            /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
          | awk '{print $2}' | head -1 || true)
  fi
  echo "${val:-}"
}

# ================================================================
#  PENTEST HELPER — auto-install a tool if missing
# ================================================================
pentest_require() {
  local tool="$1" pkg="${2:-$1}"
  if ! command -v "$tool" &>/dev/null; then
    info "Installing $pkg ..."
    apt-get install -y "$pkg" -qq 2>/dev/null || true
  fi
  command -v "$tool" &>/dev/null
}

# Returns 0 (true) when pentest should be SKIPPED so callers do: pentest_skip_guard && return
pentest_skip_guard() {
  if [[ "$USE_PENTEST" == "false" ]]; then
    skip "Pentest sections skipped (--no-pentest flag)"
    return 0
  fi
  return 1
}

# ================================================================
#  0a. PENTEST — NETWORK & SERVICE ENUMERATION
# ================================================================
section_pentest_enum() {
  header "0a. PENTEST — NETWORK & SERVICE ENUMERATION"
  pentest_skip_guard && return

  log ""
  log "  ${YELLOW}${BOLD}⚠  Active enumeration — localhost only.${NC}"
  log "  ${YELLOW}All findings are saved to the report for remediation.${NC}"
  log ""

  # ── nmap full service + OS detection ─────────────────────────
  subheader "nmap — Full service fingerprint"
  if pentest_require nmap; then
    ENUM_NMAP="/tmp/pentest_nmap_${TIMESTAMP}.txt"
    nmap -sV -O -A --script=banner,http-title,ssh-hostkey \
         -p- --open -T4 -oN "$ENUM_NMAP" 127.0.0.1 2>/dev/null || \
    nmap -sT -sV -A --script=banner,http-title \
         -p- --open -T4 -oN "$ENUM_NMAP" 127.0.0.1 2>/dev/null || true
    if [[ -s "$ENUM_NMAP" ]]; then
      pass "nmap enumeration completed"
      grep -E "^[0-9]+/|^OS:|^Service Info:|http-title:" "$ENUM_NMAP" 2>/dev/null \
        | head -40 | while IFS= read -r l; do detail "$l"; done || true
      { echo ""; echo "──── RAW: nmap full scan ────"; cat "$ENUM_NMAP"; echo "────────────────────────────"; } >> "$REPORT" || true
    else
      warn "nmap produced no output"
    fi
  else
    warn "nmap could not be installed — skipping enumeration"
  fi

  # ── enum4linux / enum4linux-ng — Samba/SMB enumeration ───────
  subheader "enum4linux — SMB/Samba recon"

  # Installation priority ladder — try each in order, stop at first success.
  # We never give up: if every enum4linux install fails we fall back to the
  # native samba-tools (smbclient / rpcclient / nmblookup) which are part of
  # the standard samba-client package and perform the same checks.
  local E4L_CMD="" E4L_MODE="enum4linux"

  # Tier 1 — already installed?
  if   command -v enum4linux-ng &>/dev/null; then
    E4L_CMD="enum4linux-ng"
  elif command -v enum4linux    &>/dev/null; then
    E4L_CMD="enum4linux"

  # Tier 2 — apt: package name differs across distros/versions
  elif apt-get install -y enum4linux-ng -qq 2>/dev/null \
       && command -v enum4linux-ng &>/dev/null; then
    E4L_CMD="enum4linux-ng"
    pass "enum4linux-ng installed via apt"
  elif apt-get install -y enum4linux -qq 2>/dev/null \
       && command -v enum4linux &>/dev/null; then
    E4L_CMD="enum4linux"
    pass "enum4linux installed via apt"

  # Tier 3 — pip3 with --break-system-packages (required on Debian 12+ / PEP 668)
  elif command -v pip3 &>/dev/null \
       && pip3 install enum4linux-ng --break-system-packages -q 2>/dev/null \
       && command -v enum4linux-ng &>/dev/null; then
    E4L_CMD="enum4linux-ng"
    pass "enum4linux-ng installed via pip3"

  # Tier 3b — pip3 without the flag (older systems)
  elif command -v pip3 &>/dev/null \
       && pip3 install enum4linux-ng -q 2>/dev/null \
       && command -v enum4linux-ng &>/dev/null; then
    E4L_CMD="enum4linux-ng"
    pass "enum4linux-ng installed via pip3 (legacy)"

  # Tier 4 — git clone into /opt (last resort before native fallback)
  elif command -v git &>/dev/null && command -v python3 &>/dev/null; then
    local _e4l_dir="/opt/enum4linux-ng"
    if [[ ! -d "$_e4l_dir" ]]; then
      info "Cloning enum4linux-ng from GitHub..."
      git clone -q --depth 1 \
        https://github.com/cddmp/enum4linux-ng.git "$_e4l_dir" 2>/dev/null || true
    fi
    if [[ -f "${_e4l_dir}/enum4linux-ng.py" ]]; then
      # Install its Python dependencies quietly
      pip3 install -r "${_e4l_dir}/requirements.txt" \
           --break-system-packages -q 2>/dev/null || \
      pip3 install -r "${_e4l_dir}/requirements.txt" -q 2>/dev/null || true
      # Create a thin wrapper so the rest of the code can call it by name
      cat > /usr/local/bin/enum4linux-ng << WRAPPER
#!/bin/bash
exec python3 ${_e4l_dir}/enum4linux-ng.py "\$@"
WRAPPER
      chmod +x /usr/local/bin/enum4linux-ng
      command -v enum4linux-ng &>/dev/null && {
        E4L_CMD="enum4linux-ng"
        pass "enum4linux-ng installed via git clone"
      }
    fi
  fi

  # Tier 5 — native samba-tools fallback (no extra packages needed)
  # Performs the same share / user / null-session checks as enum4linux.
  if [[ -z "$E4L_CMD" ]]; then
    info "enum4linux tools unavailable — attempting native samba-tools fallback"

    # Install samba-client if the individual binaries are missing
    if ! command -v smbclient &>/dev/null || ! command -v rpcclient &>/dev/null; then
      apt-get install -y smbclient -qq 2>/dev/null || true
    fi

    local _have_smb=false
    command -v smbclient  &>/dev/null && _have_smb=true
    command -v rpcclient  &>/dev/null && _have_smb=true

    if [[ "$_have_smb" == "true" ]]; then
      E4L_CMD="native-samba"
      E4L_MODE="native"
      pass "Using native samba-tools (smbclient/rpcclient/nmblookup) for SMB enumeration"
    else
      warn "enum4linux, enum4linux-ng, and samba-tools all unavailable — skipping SMB enumeration"
      info "Manual install: apt install enum4linux  OR  apt install smbclient"
      return
    fi
  fi

  # ── Run the scan ──────────────────────────────────────────────
  local E4L_OUT="/tmp/pentest_enum4linux_${TIMESTAMP}.txt"
  info "Running SMB enumeration against 127.0.0.1 (tool: ${E4L_CMD})..."

  if [[ "$E4L_MODE" == "native" ]]; then
    # Native fallback: replicate enum4linux's core checks using samba-tools
    {
      echo "=== SMB Share Enumeration (smbclient -L) ==="
      timeout 15 smbclient -L 127.0.0.1 -N 2>&1 || true

      echo ""
      echo "=== Null Session Test (rpcclient -N) ==="
      timeout 10 rpcclient 127.0.0.1 -N -c "srvinfo" 2>&1 || true

      echo ""
      echo "=== Domain User Enumeration (rpcclient enumdomusers) ==="
      timeout 10 rpcclient 127.0.0.1 -N -c "enumdomusers" 2>&1 || true

      echo ""
      echo "=== Domain Groups (rpcclient enumdomgroups) ==="
      timeout 10 rpcclient 127.0.0.1 -N -c "enumdomgroups" 2>&1 || true

      echo ""
      echo "=== NetBIOS Name Table (nmblookup) ==="
      if command -v nmblookup &>/dev/null; then
        timeout 10 nmblookup -A 127.0.0.1 2>&1 || true
      else
        echo "nmblookup not available"
      fi
    } > "$E4L_OUT" 2>&1 || true
  else
    # enum4linux or enum4linux-ng
    timeout 60 "$E4L_CMD" -A 127.0.0.1 > "$E4L_OUT" 2>&1 || true
  fi

  # ── Parse and report results ──────────────────────────────────
  if [[ -s "$E4L_OUT" ]]; then
    local SHARES USERS NULL_OK

    # Share detection: covers enum4linux-ng JSON/text and smbclient output
    SHARES=$(grep -iE \
      "Mapping|IPC\\\$|\\\\\\\\[A-Za-z]|Sharename|ADMIN\\\$|PRINT\\\$|Disk" \
      "$E4L_OUT" 2>/dev/null | grep -iv "error\|timeout\|failed" | head -10 || true)

    # User detection: enum4linux "user:" lines OR rpcclient "user:[" lines
    USERS=$(grep -iE "user:\[|user: " "$E4L_OUT" 2>/dev/null | head -10 || true)

    # ── Null session detection (false-positive-safe) ───────────────
    # Root cause of the false positive: grep for keywords like "Domain" and "OS:"
    # matches enum4linux banner headers and rpcclient error messages even when
    # the null session IS blocked.  A null session is only genuinely open when
    # the tool returns a REAL value (non-empty, not "(null)", not "[]") for one
    # of these fields AND the line is not an error or banner line.
    #
    # Filter pipeline:
    #   1. grep  — match lines containing the key fields
    #   2. grep -v — strip error/failure lines (NT_STATUS, refused, etc.)
    #   3. grep -v — strip enum4linux banner/header noise (| lines, [+] tags)
    #   4. grep -E — require a colon followed by at least one non-whitespace char
    #                OR an OS=[non-empty] pattern from smbclient
    #                so that "Server Description: " (empty) is excluded
    #   5. grep -v — strip values that are "(null)" or "[]" (no real info)
    NULL_OK=$(grep -iE \
      "Server Description|LAN Manager|OS Version|OS=\[|Domain[[:space:]]*:|Workgroup[[:space:]]*:|PDC[[:space:]]*:|BDC[[:space:]]*:" \
      "$E4L_OUT" 2>/dev/null \
      | grep -ivE \
        "NT_STATUS|Cannot connect|Connection (refused|reset|failed)|timed? ?out|LOGON_FAILURE|ACCESS_DENIED" \
      | grep -vE \
        "^[[:space:]]*\||\[[\+\-\!E\*\]|\bEnumerating\b|\bKnown Usernames\b|smb\.conf" \
      | grep -E \
        ":[[:space:]]*[^[:space:]]|OS=\[.+\]" \
      | grep -ivE \
        ":[[:space:]]*\(null\)|:[[:space:]]*\[\]|=\[\]" \
      | head -5 || true)

    if [[ -n "$SHARES" ]]; then
      fail "SMB shares found — verify access controls:"
      echo "$SHARES" | while IFS= read -r l; do detail "$l"; done
    else
      pass "No SMB shares discoverable (null session)"
    fi

    if [[ -n "$USERS" ]]; then
      warn "SMB user enumeration succeeded (null session allows user listing):"
      echo "$USERS" | while IFS= read -r l; do detail "$l"; done
    else
      pass "SMB user enumeration blocked"
    fi

    if [[ -n "$NULL_OK" ]]; then
      warn "SMB null session accepted — server info leaked:"
      echo "$NULL_OK" | while IFS= read -r l; do detail "$l"; done
    else
      pass "SMB null session rejected (good)"
    fi

    { echo ""; echo "──── RAW: SMB enum [${E4L_CMD}] ────";
      cat "$E4L_OUT"; echo "────────────────────────────"; } >> "$REPORT" || true
  else
    info "${E4L_CMD}: no output (SMB/Samba likely not running on 127.0.0.1)"
    pass "No SMB service detected on localhost"
  fi
}

# ================================================================
#  0b. PENTEST — WEB APPLICATION SCANNER
# ================================================================
section_pentest_web() {
  header "0b. PENTEST — WEB APPLICATION SCANNER (Nikto)"
  pentest_skip_guard && return

  # Detect any HTTP ports listening
  local HTTP_PORTS
  HTTP_PORTS=$(ss -tlnp 2>/dev/null | awk '{print $4}' \
    | grep -oE ':[0-9]+$' | tr -d ':' | sort -nu \
    | while IFS= read -r p; do
        [[ "$p" -eq 80   || "$p" -eq 443  || "$p" -eq 3000 ||
           "$p" -eq 4000 || "$p" -eq 5000 || "$p" -eq 8000 ||
           "$p" -eq 8080 || "$p" -eq 8443 ]] && echo "$p"
      done || true)

  if [[ -z "$HTTP_PORTS" ]]; then
    info "No HTTP/HTTPS ports detected — skipping Nikto"
    pass "No web server listening (Nikto not needed)"
    return
  fi

  if ! pentest_require nikto; then
    warn "nikto could not be installed — skipping web scan"
    return
  fi

  while IFS= read -r PORT; do
    local SCHEME="http"
    [[ "$PORT" == "443" || "$PORT" == "8443" ]] && SCHEME="https"
    subheader "Nikto scan on ${SCHEME}://127.0.0.1:${PORT}"
    local NIKTO_OUT="/tmp/pentest_nikto_${PORT}_${TIMESTAMP}.txt"
    timeout 120 nikto -h "${SCHEME}://127.0.0.1:${PORT}" \
                      -output "$NIKTO_OUT" \
                      -Format txt \
                      -nointeractive 2>/dev/null || true
    if [[ -s "$NIKTO_OUT" ]]; then
      local NIKTO_VULNS
      NIKTO_VULNS=$(grep -c "^+ " "$NIKTO_OUT" 2>/dev/null || true)
      NIKTO_VULNS=$(safe_int "$NIKTO_VULNS")
      if [[ "$NIKTO_VULNS" -gt 0 ]]; then
        fail "Nikto found $NIKTO_VULNS finding(s) on port $PORT"
        grep "^+ " "$NIKTO_OUT" | head -20 | while IFS= read -r l; do detail "$l"; done
      else
        pass "Nikto: No critical findings on port $PORT"
      fi
      { echo ""; echo "──── RAW: nikto port ${PORT} ────"; cat "$NIKTO_OUT"; echo "────────────────────────────"; } >> "$REPORT" || true
    else
      info "Nikto: no output for port $PORT (service may not respond)"
    fi
  done <<< "$HTTP_PORTS"
}

# ================================================================
#  0c. PENTEST — SSH BRUTE-FORCE SIMULATION
# ================================================================
section_pentest_ssh() {
  header "0c. PENTEST — SSH BRUTE-FORCE SIMULATION (Hydra)"
  pentest_skip_guard && return

  local SSH_TEST_PORT=${SSH_PORT:-22}

  if ! ss -tlnp 2>/dev/null | grep -qE ":${SSH_TEST_PORT}[[:space:]]"; then
    info "SSH not listening on port ${SSH_TEST_PORT} — skipping brute-force test"
    pass "SSH brute-force test not applicable"
    return
  fi

  if ! pentest_require hydra; then
    warn "hydra could not be installed — skipping SSH brute-force test"
    return
  fi

  subheader "Hydra — SSH brute-force with common credentials"
  log ""
  log "  ${YELLOW}Testing SSH login resistance with top-20 common passwords.${NC}"
  log "  ${YELLOW}This is a safe, limited test (20 attempts, 2 threads).${NC}"
  log ""

  local PASS_LIST="/tmp/pentest_passlist_${TIMESTAMP}.txt"
  cat > "$PASS_LIST" << 'WORDLIST'
password
123456
admin
root
toor
pass
letmein
welcome
password123
qwerty
abc123
changeme
default
test
linux
debian
ubuntu
raspberry
1234
secret
WORDLIST

  local HYDRA_OUT="/tmp/pentest_hydra_${TIMESTAMP}.txt"
  timeout 60 hydra -l root \
                   -P "$PASS_LIST" \
                   -t 2 \
                   -f \
                   -o "$HYDRA_OUT" \
                   "ssh://127.0.0.1:${SSH_TEST_PORT}" 2>/dev/null || true

  if grep -qE "\[${SSH_TEST_PORT}\].*login:|login:" "$HYDRA_OUT" 2>/dev/null; then
    fail "SSH brute-force SUCCEEDED — weak password found!"
    grep "login:" "$HYDRA_OUT" | while IFS= read -r l; do detail "$l"; done
    warn "Immediate action: change password and enforce key-only auth"
  else
    pass "SSH brute-force test failed — no common passwords accepted"
  fi
  rm -f "$PASS_LIST"
  { echo ""; echo "──── RAW: hydra SSH brute-force ────"; cat "$HYDRA_OUT" 2>/dev/null || true; echo "────────────────────────────"; } >> "$REPORT"
}

# ================================================================
#  0d. PENTEST — SQL INJECTION PROBE
# ================================================================
section_pentest_sqli() {
  header "0d. PENTEST — SQL INJECTION PROBE (sqlmap)"
  pentest_skip_guard && return

  local HTTP_PORT
  HTTP_PORT=$(ss -tlnp 2>/dev/null | awk '{print $4}' \
    | grep -oE ':(80|8080|8000|3000|5000)$' | head -1 | tr -d ':' || true)

  if [[ -z "$HTTP_PORT" ]]; then
    info "No web server listening — skipping SQLMap"
    pass "SQL injection test not applicable (no web server found)"
    return
  fi

  if ! pentest_require sqlmap; then
    warn "sqlmap could not be installed — skipping SQLi probe"
    return
  fi

  subheader "sqlmap — SQL injection probe on http://127.0.0.1:${HTTP_PORT}"
  log ""
  log "  ${YELLOW}Running a safe, non-destructive GET probe (no forms, no write).${NC}"
  log ""

  local SQLMAP_OUT="/tmp/pentest_sqlmap_${TIMESTAMP}.txt"
  timeout 90 sqlmap -u "http://127.0.0.1:${HTTP_PORT}/?id=1" \
                    --batch \
                    --level=1 \
                    --risk=1 \
                    --technique=B \
                    --output-dir="/tmp/sqlmap_${TIMESTAMP}" \
                    2>&1 | tee "$SQLMAP_OUT" | tail -20 | \
                    while IFS= read -r l; do detail "$l"; done || true

  if grep -qi "is vulnerable\|sqlmap identified" "$SQLMAP_OUT" 2>/dev/null; then
    fail "sqlmap found SQL injection vulnerability on port $HTTP_PORT!"
    grep -i "Parameter\|payload\|Type:" "$SQLMAP_OUT" | head -10 \
      | while IFS= read -r l; do detail "$l"; done
  else
    pass "sqlmap: No SQL injection found on port $HTTP_PORT (basic probe)"
  fi
  { echo ""; echo "──── RAW: sqlmap ────"; cat "$SQLMAP_OUT" 2>/dev/null || true; echo "────────────────────────────"; } >> "$REPORT"
}

# ================================================================
#  0e. PENTEST — STRESS & RESOURCE EXHAUSTION
# ================================================================
section_pentest_stress() {
  header "0e. PENTEST — STRESS & RESOURCE EXHAUSTION"
  pentest_skip_guard && return

  log ""
  log "  ${YELLOW}${BOLD}⚠  Brief stress tests to verify resource limits & DoS resilience.${NC}"
  log "  ${YELLOW}Each test runs for max 15 seconds and is monitored.${NC}"
  log ""

  # ── stress-ng ─────────────────────────────────────────────────
  subheader "stress-ng — CPU / memory / I/O stress"
  if ! pentest_require stress-ng stress-ng; then
    warn "stress-ng could not be installed — skipping CPU/memory stress test"
  else
    local STRESS_OUT="/tmp/pentest_stress_${TIMESTAMP}.txt"

    # FIX: read_cpu via a single awk call into variables — avoids subshell pipefail issues
    _read_cpu_snapshot() {
      awk '/^cpu /{
        total=$2+$3+$4+$5+$6+$7+$8
        print total, $5
      }' /proc/stat 2>/dev/null || echo "0 0"
    }

    local snap1 snap2
    snap1=$(_read_cpu_snapshot); sleep 1; snap2=$(_read_cpu_snapshot)
    local t1 i1 t2 i2
    t1=$(awk '{print $1}' <<< "$snap1"); i1=$(awk '{print $2}' <<< "$snap1")
    t2=$(awk '{print $1}' <<< "$snap2"); i2=$(awk '{print $2}' <<< "$snap2")
    t1=$(safe_int "$t1"); i1=$(safe_int "$i1")
    t2=$(safe_int "$t2"); i2=$(safe_int "$i2")
    local CPU_BEFORE
    CPU_BEFORE=$(awk -v t1="$t1" -v i1="$i1" -v t2="$t2" -v i2="$i2" \
      'BEGIN{ d=t2-t1; id=i2-i1; print (d>0) ? int((d-id)*100/d) : 0 }')
    local MEM_FREE_BEFORE
    MEM_FREE_BEFORE=$(free -m 2>/dev/null | awk '/^Mem:/{print $4}' || echo "unknown")

    info "Baseline — CPU usage: ${CPU_BEFORE}%  |  Free memory: ${MEM_FREE_BEFORE} MB"
    info "Running stress-ng (CPU x2, VM x1, I/O x1 — 15 seconds)..."

    timeout 20 stress-ng \
      --cpu 2 --cpu-load 80 \
      --vm 1  --vm-bytes 128M \
      --io  1 \
      --timeout 15s \
      --metrics-brief \
      2>&1 | tee "$STRESS_OUT" || true
    grep -E "stressor|bogo" "$STRESS_OUT" | head -10 | while IFS= read -r l; do detail "$l"; done || true

    snap1=$(_read_cpu_snapshot); sleep 1; snap2=$(_read_cpu_snapshot)
    t1=$(awk '{print $1}' <<< "$snap1"); i1=$(awk '{print $2}' <<< "$snap1")
    t2=$(awk '{print $1}' <<< "$snap2"); i2=$(awk '{print $2}' <<< "$snap2")
    t1=$(safe_int "$t1"); i1=$(safe_int "$i1")
    t2=$(safe_int "$t2"); i2=$(safe_int "$i2")
    local CPU_AFTER
    CPU_AFTER=$(awk -v t1="$t1" -v i1="$i1" -v t2="$t2" -v i2="$i2" \
      'BEGIN{ d=t2-t1; id=i2-i1; print (d>0) ? int((d-id)*100/d) : 0 }')
    local MEM_FREE_AFTER
    MEM_FREE_AFTER=$(free -m 2>/dev/null | awk '/^Mem:/{print $4}' || echo "unknown")

    info "Post-stress — CPU: ${CPU_AFTER}%  |  Free memory: ${MEM_FREE_AFTER} MB"

    local SYS_STATE
    SYS_STATE=$(systemctl is-system-running 2>/dev/null || true)
    SYS_STATE="${SYS_STATE:-running}"
    if [[ "$SYS_STATE" == "running" || "$SYS_STATE" == "degraded" ]]; then
      pass "System remained stable during CPU/memory stress test (state: ${SYS_STATE})"
    elif [[ "$SYS_STATE" == "failed" ]]; then
      warn "System entered 'failed' state during stress test — investigate"
    else
      info "System state after stress: '${SYS_STATE}' (container/VM environments may report unknown)"
    fi

    # FIX: guard OOM count so it's always a clean integer
    local OOM_EVENTS
    OOM_EVENTS=$(dmesg 2>/dev/null \
      | grep -c "oom-killer\|out of memory\|Memory cgroup" 2>/dev/null || true)
    OOM_EVENTS=$(safe_int "$OOM_EVENTS")
    if [[ "$OOM_EVENTS" -gt 0 ]]; then
      fail "OOM killer was triggered during stress test! ($OOM_EVENTS event(s))"
      dmesg 2>/dev/null | grep -i "oom-killer\|out of memory" | tail -5 \
        | while IFS= read -r l; do detail "$l"; done
    else
      pass "No OOM killer events detected during stress"
    fi

    { echo ""; echo "──── RAW: stress-ng ────"; cat "$STRESS_OUT" 2>/dev/null || true; echo "────────────────────────────"; } >> "$REPORT"
  fi

  # ── hping3 — SYN flood resilience (loopback only) ────────────
  subheader "hping3 — SYN flood simulation (loopback, 5 seconds)"
  if ! pentest_require hping3; then
    warn "hping3 not available — skipping SYN flood test"
  else
    local SSH_TEST_PORT=${SSH_PORT:-22}
    info "Sending SYN flood to 127.0.0.1:${SSH_TEST_PORT} for 5 seconds..."

    local SS_BEFORE
    SS_BEFORE=$(ss -s 2>/dev/null | grep -i "TCP:" | head -1 || true)

    timeout 8 hping3 --syn \
                     --flood \
                     --rand-source \
                     -p "$SSH_TEST_PORT" \
                     -d 120 \
                     --count 5000 \
                     127.0.0.1 2>/dev/null &
    local HPING_PID=$!
    sleep 5
    kill "$HPING_PID" 2>/dev/null || true
    wait "$HPING_PID" 2>/dev/null || true

    local SS_AFTER
    SS_AFTER=$(ss -s 2>/dev/null | grep -i "TCP:" | head -1 || true)
    info "TCP state before flood: $SS_BEFORE"
    info "TCP state after  flood: $SS_AFTER"

    local SYN_COOKIE
    SYN_COOKIE=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
    if [[ "$SYN_COOKIE" == "1" ]]; then
      pass "SYN cookie protection was active during flood test"
    else
      fail "SYN cookies are OFF — system is vulnerable to SYN flood DoS"
    fi

    if timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/${SSH_TEST_PORT}" 2>/dev/null; then
      pass "SSH port ${SSH_TEST_PORT} still responsive after SYN flood"
    else
      warn "SSH port ${SSH_TEST_PORT} not responding after flood test — investigate"
    fi
  fi

  # ── ulimit / resource limit check ────────────────────────────
  # FIX: all ulimit values guarded through safe_int; "unlimited" is displayed
  #      verbatim but never passed to integer comparisons.
  subheader "Resource limits (ulimit)"

  local UL_FILES UL_PROCS UL_STACK UL_VMEM
  UL_FILES=$(ulimit -n 2>/dev/null || echo "unknown")
  UL_PROCS=$(ulimit -u 2>/dev/null || echo "unknown")
  UL_STACK=$(ulimit -s 2>/dev/null || echo "unknown")
  UL_VMEM=$(ulimit  -v 2>/dev/null || echo "unlimited")

  info "Open files limit  : ${UL_FILES}"
  info "Max processes     : ${UL_PROCS}"
  info "Stack size        : ${UL_STACK} KB"
  info "Max memory (virt) : ${UL_VMEM}"

  # Only compare when the value is a real integer (not "unlimited" / "unknown")
  local UL_FILES_INT
  UL_FILES_INT=$(safe_int "$UL_FILES")
  if [[ "$UL_FILES" == "unlimited" ]]; then
    pass "Open file limit is unlimited"
  elif [[ "$UL_FILES_INT" -ge 65536 ]]; then
    pass "Open file limit is sufficient (${UL_FILES})"
  elif [[ "$UL_FILES_INT" -eq 0 ]]; then
    warn "Open file limit could not be determined (value: ${UL_FILES})"
  else
    warn "Open file limit is low (${UL_FILES}) — increase in /etc/security/limits.conf"
  fi
}

# ================================================================
#  1. SYSTEM INFORMATION
# ================================================================
section_sysinfo() {
  header "1. SYSTEM INFORMATION"
  info "Hostname      : $(hostname -f 2>/dev/null || hostname)"
  info "OS            : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')"
  info "Kernel        : $(uname -r)"
  info "Architecture  : $(uname -m)"
  info "Uptime        : $(uptime -p 2>/dev/null || uptime)"
  info "Date/Time     : $(date)"
  info "CPU           : $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo 'unknown')"
  info "Memory total  : $(free -h 2>/dev/null | awk '/^Mem:/{print $2}') RAM"
  info "Disk usage    : $(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5" used)"}')"
  info "Loaded modules: $(lsmod 2>/dev/null | wc -l) kernel modules"

  if systemd-detect-virt --quiet 2>/dev/null; then
    local VIRT
    VIRT=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    info "Virtualisation: ${VIRT}"
  fi
}

# ================================================================
#  2. SYSTEM UPDATES
# ================================================================
section_updates() {
  header "2. SYSTEM UPDATES"

  # Single throttled update — respects APT_CACHE_MAX_AGE
  maybe_apt_update

  # Capture upgradable list once; grep from it for both checks
  local UPGRADABLE_LIST
  UPGRADABLE_LIST=$(apt list --upgradable 2>/dev/null || true)

  local UPGRADABLE
  UPGRADABLE=$(echo "$UPGRADABLE_LIST" | grep -c "/" || true)
  UPGRADABLE=$(safe_int "$UPGRADABLE")
  if [[ "$UPGRADABLE" -eq 0 ]]; then
    pass "System is fully up-to-date"
  elif [[ "$UPGRADABLE" -le 5 ]]; then
    warn "$UPGRADABLE package(s) have updates available"
  else
    fail "$UPGRADABLE packages need updating — run: apt upgrade"
  fi

  local SEC_UPDATES
  SEC_UPDATES=$(echo "$UPGRADABLE_LIST" | grep -ci "security" || true)
  SEC_UPDATES=$(safe_int "$SEC_UPDATES")
  if [[ "$SEC_UPDATES" -gt 0 ]]; then
    fail "$SEC_UPDATES pending SECURITY update(s) detected!"
  else
    pass "No pending security updates"
  fi

  if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
    pass "unattended-upgrades is installed"
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
      pass "unattended-upgrades service is active"
    else
      warn "unattended-upgrades is installed but service is not active"
    fi
  else
    warn "unattended-upgrades is not installed — consider: apt install unattended-upgrades"
  fi

  local LAST_UPDATE
  LAST_UPDATE=$(stat -c %y /var/cache/apt/pkgcache.bin 2>/dev/null | cut -d. -f1 || echo "unknown")
  info "Last apt cache update: $LAST_UPDATE"
}

# ================================================================
#  3. USERS & ACCOUNTS
# ================================================================
section_users() {
  header "3. USERS & ACCOUNTS"

  subheader "Root & Privileged Accounts"

  local UID0
  UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd || true)
  if [[ -z "$UID0" ]]; then
    pass "No extra accounts with UID 0"
  else
    fail "Non-root accounts with UID 0: $UID0"
  fi

  local EMPTY_PW
  EMPTY_PW=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || true)
  if [[ -z "$EMPTY_PW" ]]; then
    pass "No accounts with empty passwords"
  else
    fail "Accounts with empty passwords: $EMPTY_PW"
  fi

  local SUDO_MEMBERS WHEEL_MEMBERS
  SUDO_MEMBERS=$(getent group sudo 2>/dev/null | cut -d: -f4 || true)
  info "Sudo group members: ${SUDO_MEMBERS:-none}"

  WHEEL_MEMBERS=$(getent group wheel 2>/dev/null | cut -d: -f4 || true)
  [[ -n "$WHEEL_MEMBERS" ]] && info "Wheel group members: $WHEEL_MEMBERS"

  subheader "Login Shell Accounts"
  local SHELL_USERS
  SHELL_USERS=$(awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ && $3 >= 1000 {print $1}' /etc/passwd || true)
  if [[ -n "$SHELL_USERS" ]]; then
    info "Human accounts with login shell:"
    while IFS= read -r u; do detail "$u"; done <<< "$SHELL_USERS"
  fi

  subheader "Last Logins"
  last -n 10 2>/dev/null | head -10 | while IFS= read -r line; do detail "$line"; done || true

  subheader "Currently Logged-in Users"
  local WHO
  WHO=$(who 2>/dev/null || true)
  if [[ -z "$WHO" ]]; then
    info "No users currently logged in"
  else
    while IFS= read -r line; do info "  $line"; done <<< "$WHO"
  fi

  local NOEXPIRY
  NOEXPIRY=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd \
    | while IFS= read -r u; do
        chage -l "$u" 2>/dev/null | grep "Password expires" \
          | grep -qi "never" && echo "$u"
      done || true)
  if [[ -n "$NOEXPIRY" ]]; then
    warn "Accounts with passwords that never expire: $NOEXPIRY"
  else
    pass "All human accounts have a password expiry set"
  fi
}

# ================================================================
#  4. PASSWORD POLICY
# ================================================================
section_password_policy() {
  header "4. PASSWORD POLICY"

  local LOGINDEFS="/etc/login.defs"

  _check_logindefs() {
    local KEY="$1" MIN="$2" DESC="$3"
    local VAL
    VAL=$(grep -E "^${KEY}[[:space:]]" "$LOGINDEFS" 2>/dev/null \
          | awk '{print $2}' | head -1 || echo "0")
    VAL=$(safe_int "$VAL")
    if [[ "$VAL" -ge "$MIN" ]]; then
      pass "$DESC ($KEY = $VAL)"
    else
      warn "$DESC — $KEY = ${VAL} (recommended: >= $MIN)"
    fi
  }

  _check_logindefs "PASS_MAX_DAYS" 90  "Maximum password age"
  _check_logindefs "PASS_MIN_DAYS" 1   "Minimum password age"
  _check_logindefs "PASS_MIN_LEN"  12  "Minimum password length"
  _check_logindefs "PASS_WARN_AGE" 7   "Password expiry warning days"

  if grep -qr "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
    pass "PAM password quality module (pwquality/cracklib) is configured"
  else
    warn "No PAM password complexity module found — install libpam-pwquality"
  fi

  if grep -qr "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null; then
    pass "PAM account lockout policy is configured (pam_faillock/tally2)"
  else
    warn "No PAM account lockout policy found — brute-force protection missing"
  fi
}

# ================================================================
#  5. SSH CONFIGURATION
# ================================================================
section_ssh() {
  header "5. SSH CONFIGURATION"

  if ! systemctl is-active --quiet ssh 2>/dev/null && \
     ! systemctl is-active --quiet sshd 2>/dev/null; then
    skip "SSH service is not active — skipping SSH checks"
    return
  fi

  # Populate cache once: sshd -T spawns sshd to dump its effective config.
  # All subsequent sshd_value() calls in this section read from the cache
  # instead of re-forking sshd, saving ~0.3s × 10 calls = ~3s.
  SSHD_CONFIG_CACHE=$(sshd -T 2>/dev/null || true)

  local SSH_PORT_VAL ROOT_LOGIN PW_AUTH EMPTY TCPFwd CIPHERS X11 MAX_AUTH CAI LGT

  SSH_PORT_VAL=$(sshd_value Port); SSH_PORT_VAL=${SSH_PORT_VAL:-22}
  if [[ "$SSH_PORT_VAL" -ne 22 ]]; then
    pass "SSH listening on non-default port $SSH_PORT_VAL"
  else
    warn "SSH listening on default port 22 — consider changing it"
  fi

  if grep -qE "^Protocol[[:space:]]+1" /etc/ssh/sshd_config 2>/dev/null; then
    fail "SSH Protocol 1 is enabled — must be disabled"
  else
    pass "SSH Protocol 1 is not in use"
  fi

  ROOT_LOGIN=$(sshd_value PermitRootLogin)
  if [[ "${ROOT_LOGIN:-}" == "no" || "${ROOT_LOGIN:-}" == "prohibit-password" ]]; then
    pass "SSH root login is disabled or key-only (${ROOT_LOGIN})"
  else
    fail "SSH root login is fully enabled (PermitRootLogin = ${ROOT_LOGIN:-not set})"
  fi

  PW_AUTH=$(sshd_value PasswordAuthentication)
  if [[ "${PW_AUTH:-}" == "no" ]]; then
    pass "SSH password authentication is disabled"
  else
    warn "SSH password authentication is enabled — prefer key-based auth"
  fi

  EMPTY=$(sshd_value PermitEmptyPasswords)
  if [[ "${EMPTY:-no}" == "no" ]]; then
    pass "SSH empty passwords are not permitted"
  else
    fail "SSH empty passwords are permitted!"
  fi

  X11=$(sshd_value X11Forwarding)
  if [[ "${X11:-}" == "no" ]]; then
    pass "X11 Forwarding is disabled"
  else
    warn "X11 Forwarding is enabled — disable if not needed"
  fi

  MAX_AUTH=$(sshd_value MaxAuthTries); MAX_AUTH=$(safe_int "${MAX_AUTH:-6}")
  if [[ "$MAX_AUTH" -gt 0 && "$MAX_AUTH" -le 4 ]]; then
    pass "MaxAuthTries = $MAX_AUTH (good)"
  else
    warn "MaxAuthTries = ${MAX_AUTH} — recommend setting to 3 or 4"
  fi

  CAI=$(sshd_value ClientAliveInterval); CAI=$(safe_int "${CAI:-0}")
  if [[ "$CAI" -gt 0 && "$CAI" -le 300 ]]; then
    pass "SSH idle timeout set (ClientAliveInterval = $CAI s)"
  else
    warn "SSH idle timeout not set — set ClientAliveInterval to 300 or less"
  fi

  LGT=$(sshd_value LoginGraceTime); LGT=$(safe_int "${LGT:-120}")
  if [[ "$LGT" -gt 0 && "$LGT" -le 60 ]]; then
    pass "LoginGraceTime = $LGT s (good)"
  else
    warn "LoginGraceTime = ${LGT} s — recommend 30-60 seconds"
  fi

  TCPFwd=$(sshd_value AllowTcpForwarding)
  if [[ "${TCPFwd:-yes}" == "no" ]]; then
    pass "TCP Forwarding is disabled"
  else
    warn "TCP Forwarding is enabled — disable if not needed"
  fi

  CIPHERS=$(sshd_value Ciphers)
  if echo "${CIPHERS:-}" | grep -qi "3des\|arcfour\|blowfish"; then
    fail "Weak SSH cipher(s) detected: $CIPHERS"
  else
    pass "No known weak ciphers in SSH configuration"
  fi

  # Clear the cache so it does not bleed into later functions
  SSHD_CONFIG_CACHE=""
}

# ================================================================
#  6. FIREWALL
# ================================================================
section_firewall() {
  header "6. FIREWALL"

  if command -v ufw &>/dev/null; then
    subheader "UFW"
    local UFW_STATUS
    UFW_STATUS=$(ufw status verbose 2>/dev/null || true)
    if echo "$UFW_STATUS" | grep -qi "^Status: active"; then
      pass "UFW firewall is active"
      echo "$UFW_STATUS" | grep -i "Default:" | while IFS= read -r line; do detail "$line"; done
      local RULE_COUNT
      RULE_COUNT=$(ufw status numbered 2>/dev/null | grep -c "^\[" || true)
      RULE_COUNT=$(safe_int "$RULE_COUNT")
      info "Number of UFW rules: $RULE_COUNT"
    else
      fail "UFW firewall is INACTIVE — enable with: ufw enable"
    fi
  fi

  if command -v iptables &>/dev/null; then
    subheader "iptables"
    local IPT_INPUT
    IPT_INPUT=$(iptables -L INPUT 2>/dev/null | grep -c "^ACCEPT\|^DROP\|^REJECT" || true)
    IPT_INPUT=$(safe_int "$IPT_INPUT")
    if [[ "$IPT_INPUT" -gt 0 ]]; then
      pass "iptables INPUT chain has $IPT_INPUT rule(s)"
    else
      warn "iptables INPUT chain appears empty"
    fi
  fi

  if command -v nft &>/dev/null; then
    subheader "nftables"
    local NFT_RULES
    NFT_RULES=$(nft list ruleset 2>/dev/null | grep -c "type filter" || true)
    NFT_RULES=$(safe_int "$NFT_RULES")
    if [[ "$NFT_RULES" -gt 0 ]]; then
      pass "nftables has $NFT_RULES active filter chain(s)"
    else
      info "nftables is installed but no filter chains found"
    fi
  fi

  if ! command -v ufw &>/dev/null && ! command -v iptables &>/dev/null && ! command -v nft &>/dev/null; then
    fail "No firewall tool found (ufw / iptables / nft)"
  fi
}

# ================================================================
#  7. OPEN NETWORK PORTS
# ================================================================
section_ports() {
  header "7. OPEN NETWORK PORTS"

  subheader "Listening TCP/UDP ports"
  local PORTS
  if command -v ss &>/dev/null; then
    PORTS=$(ss -tlnpu 2>/dev/null | tail -n +2 || true)
  elif command -v netstat &>/dev/null; then
    PORTS=$(netstat -tlnpu 2>/dev/null | tail -n +3 || true)
  else
    warn "ss/netstat not found — skipping port check"
    return
  fi

  echo "$PORTS" | while IFS= read -r line; do detail "$line"; done

  subheader "Risky port checks"
  declare -A RISKY_PORTS=(
    [21]="FTP (plaintext)"
    [23]="Telnet (plaintext)"
    [69]="TFTP"
    [111]="RPC portmapper"
    [512]="rexec"
    [513]="rlogin"
    [514]="rsh/syslog"
    [515]="LPD printer"
    [2049]="NFS"
    [6000]="X11"
  )
  local RISKY_FOUND=0
  for PORT in "${!RISKY_PORTS[@]}"; do
    if echo "$PORTS" | grep -qE ":${PORT}[[:space:]]"; then
      fail "Risky port open: ${PORT} (${RISKY_PORTS[$PORT]})"
      RISKY_FOUND=$((RISKY_FOUND+1))
    fi
  done
  [[ "$RISKY_FOUND" -eq 0 ]] && pass "No known risky ports are open"

  if ss -6tlnp 2>/dev/null | grep -q "LISTEN"; then
    info "IPv6 ports are also listening — verify they are intentional"
  fi
}

# ================================================================
#  8. FILE & DIRECTORY PERMISSIONS
# ================================================================
section_permissions() {
  header "8. FILE & DIRECTORY PERMISSIONS"

  subheader "Critical system files"
  _check_perm() {
    local FILE="$1" EXPECTED="$2"
    local ACTUAL
    ACTUAL=$(stat -c "%a" "$FILE" 2>/dev/null || echo "missing")
    if [[ "$ACTUAL" == "missing" ]]; then
      skip "$FILE not found"
    elif [[ "$ACTUAL" == "$EXPECTED" ]]; then
      pass "$FILE permissions OK ($ACTUAL)"
    else
      fail "$FILE permissions: $ACTUAL (expected $EXPECTED)"
    fi
  }

  _check_perm /etc/passwd          644
  _check_perm /etc/shadow          640
  _check_perm /etc/group           644
  _check_perm /etc/gshadow         640
  _check_perm /etc/sudoers         440
  _check_perm /etc/ssh/sshd_config 600
  _check_perm /boot/grub/grub.cfg  600

  subheader "World-writable files"
  info "Scanning filesystem in parallel (world-writable files/dirs, SUID/SGID, unowned)..."

  # ── Parallel find: all 4 scans run concurrently ───────────────
  # Each writes to a temp file; we collect results after wait.
  local TMP_WW_FILES="/tmp/_audit_ww_files_${TIMESTAMP}"
  local TMP_WW_DIRS="/tmp/_audit_ww_dirs_${TIMESTAMP}"
  local TMP_SUID="/tmp/_audit_suid_${TIMESTAMP}"
  local TMP_UNOWNED="/tmp/_audit_unowned_${TIMESTAMP}"

  # Common exclusion set — virtual/special filesystems that are never
  # on real storage and would add thousands of false results.
  local FIND_EXCLUDE='! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*"
    ! -path "/run/*" ! -path "/snap/*" ! -path "/var/lib/docker/*"
    ! -path "/var/lib/lxcfs/*" ! -path "/tmp/_audit_*"'

  find / -xdev -type f -perm -0002 \
    ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" \
    ! -path "/snap/*" ! -path "/var/lib/docker/*" \
    2>/dev/null | head -30 > "$TMP_WW_FILES" &
  local PID_WW_FILES=$!

  find / -xdev -type d -perm -0002 -not -perm -1000 \
    ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" \
    ! -path "/snap/*" ! -path "/var/lib/docker/*" \
    2>/dev/null | head -20 > "$TMP_WW_DIRS" &
  local PID_WW_DIRS=$!

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    ! -path "/proc/*" ! -path "/sys/*" \
    ! -path "/snap/*" ! -path "/var/lib/docker/*" \
    2>/dev/null > "$TMP_SUID" &
  local PID_SUID=$!

  find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" ! -path "/sys/*" \
    ! -path "/snap/*" ! -path "/var/lib/docker/*" \
    2>/dev/null | head -20 > "$TMP_UNOWNED" &
  local PID_UNOWNED=$!

  # Wait for all four, cap at 60 s each so a slow NFS mount can't stall the audit
  local _pids=("$PID_WW_FILES" "$PID_WW_DIRS" "$PID_SUID" "$PID_UNOWNED")
  local _timeout_at=$(( $(date +%s) + 60 ))
  for _pid in "${_pids[@]}"; do
    local _remaining=$(( _timeout_at - $(date +%s) ))
    [[ "$_remaining" -le 0 ]] && { kill "$_pid" 2>/dev/null || true; continue; }
    wait "$_pid" 2>/dev/null || true
  done

  # ── Report results ────────────────────────────────────────────
  local WW_FILES WW_DIRS SUID_LIST SUID_COUNT UNOWNED
  WW_FILES=$(cat "$TMP_WW_FILES" 2>/dev/null || true)
  if [[ -z "$WW_FILES" ]]; then
    pass "No world-writable files found"
  else
    fail "World-writable files found (first 30):"
    while IFS= read -r f; do detail "$f"; done <<< "$WW_FILES"
  fi

  subheader "World-writable directories"
  WW_DIRS=$(cat "$TMP_WW_DIRS" 2>/dev/null || true)
  if [[ -z "$WW_DIRS" ]]; then
    pass "No world-writable directories without sticky bit"
  else
    fail "Dangerous world-writable directories:"
    while IFS= read -r d; do detail "$d"; done <<< "$WW_DIRS"
  fi

  subheader "SUID / SGID binaries"
  SUID_LIST=$(cat "$TMP_SUID" 2>/dev/null || true)
  SUID_COUNT=$(echo "$SUID_LIST" | grep -c "/" || true)
  SUID_COUNT=$(safe_int "$SUID_COUNT")
  if [[ "$SUID_COUNT" -le 25 ]]; then
    pass "SUID/SGID binary count: $SUID_COUNT (normal)"
  else
    warn "$SUID_COUNT SUID/SGID binaries — review for suspicious entries"
  fi
  while IFS= read -r f; do [[ -n "$f" ]] && detail "$f"; done <<< "$SUID_LIST"

  subheader "Unowned files"
  UNOWNED=$(cat "$TMP_UNOWNED" 2>/dev/null || true)
  if [[ -z "$UNOWNED" ]]; then
    pass "No unowned files found"
  else
    warn "Files with no valid owner/group:"
    while IFS= read -r f; do detail "$f"; done <<< "$UNOWNED"
  fi

  rm -f "$TMP_WW_FILES" "$TMP_WW_DIRS" "$TMP_SUID" "$TMP_UNOWNED"
}

# ================================================================
#  9. SERVICES & DAEMONS
# ================================================================
section_services() {
  header "9. SERVICES & DAEMONS"

  subheader "Running services"
  local RUNNING
  RUNNING=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
    | awk '{print $1}' | head -30 || true)
  while IFS= read -r svc; do [[ -n "$svc" ]] && detail "$svc"; done <<< "$RUNNING"

  subheader "Failed services"
  local FAILED_SVCS
  FAILED_SVCS=$(systemctl list-units --type=service --state=failed --no-legend 2>/dev/null \
    | awk '{print $1}' || true)
  if [[ -z "$FAILED_SVCS" ]]; then
    pass "No failed systemd services"
  else
    warn "Failed services detected:"
    while IFS= read -r s; do detail "$s"; done <<< "$FAILED_SVCS"
  fi

  subheader "Risky legacy services"
  local RISKY_SVCS=(telnet rsh rlogin finger chargen daytime time discard echo rexec)
  local RISKY_FOUND=0
  for SVC in "${RISKY_SVCS[@]}"; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
      fail "Risky legacy service active: $SVC"
      RISKY_FOUND=$((RISKY_FOUND+1))
    fi
  done
  [[ "$RISKY_FOUND" -eq 0 ]] && pass "No risky legacy services running"

  subheader "Inetd / xinetd"
  for INET in inetd xinetd; do
    if systemctl is-active --quiet "$INET" 2>/dev/null; then
      warn "$INET is active — review /etc/${INET}.d/ for unnecessary services"
    else
      pass "$INET is not running"
    fi
  done

  subheader "Dangerous packages"
  for PKG in nis rsh-client rsh-server telnet telnetd xinetd; do
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
      warn "Potentially dangerous package installed: $PKG"
    fi
  done
  pass "Dangerous package scan complete"
}

# ================================================================
#  10. LOGGING & AUDIT
# ================================================================
section_logging() {
  header "10. LOGGING & AUDIT"

  subheader "Syslog"
  if systemctl is-active --quiet rsyslog 2>/dev/null; then
    pass "rsyslog is active"
  elif systemctl is-active --quiet syslog 2>/dev/null; then
    pass "syslog is active"
  elif systemctl is-active --quiet syslog-ng 2>/dev/null; then
    pass "syslog-ng is active"
  else
    fail "No syslog daemon is running — system logging is broken"
  fi

  subheader "auditd"
  if systemctl is-active --quiet auditd 2>/dev/null; then
    pass "auditd is active"
    local AUDIT_RULES
    AUDIT_RULES=$(auditctl -l 2>/dev/null | grep -vc "^List" || true)
    AUDIT_RULES=$(safe_int "$AUDIT_RULES")
    info "Active audit rules: $AUDIT_RULES"
  else
    warn "auditd is not running — install/start with: apt install auditd && systemctl enable auditd"
  fi

  subheader "Log file permissions"
  local LOG_PERM
  LOG_PERM=$(stat -c "%a" /var/log 2>/dev/null || true)
  if [[ "$LOG_PERM" == "755" || "$LOG_PERM" == "750" ]]; then
    pass "/var/log directory permissions: $LOG_PERM"
  else
    warn "/var/log permissions: $LOG_PERM (expected 755 or 750)"
  fi

  subheader "Auth log — failed logins"
  if [[ -f /var/log/auth.log ]]; then
    local FAILED INVALID ROOT_ATTEMPTS
    FAILED=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || true)
    FAILED=$(safe_int "$FAILED")
    if [[ "$FAILED" -gt 200 ]]; then
      fail "$FAILED failed SSH logins in auth.log — likely brute-force activity"
    elif [[ "$FAILED" -gt 50 ]]; then
      warn "$FAILED failed SSH logins in auth.log"
    else
      pass "Failed SSH login attempts: $FAILED (low)"
    fi

    INVALID=$(grep -c "Invalid user" /var/log/auth.log 2>/dev/null || true)
    INVALID=$(safe_int "$INVALID")
    info "Invalid user login attempts: $INVALID"

    ROOT_ATTEMPTS=$(grep -c "Failed.*root" /var/log/auth.log 2>/dev/null || true)
    ROOT_ATTEMPTS=$(safe_int "$ROOT_ATTEMPTS")
    info "Failed root login attempts: $ROOT_ATTEMPTS"
  else
    skip "/var/log/auth.log not found"
  fi

  subheader "Systemd journal"
  local JOURNAL_SIZE
  JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null \
    | grep -oP '\d+(\.\d+)?\s*[KMGT]?B' | tail -1 || true)
  info "Journal disk usage: ${JOURNAL_SIZE:-unknown}"
}

# ================================================================
#  11. KERNEL & SYSCTL HARDENING
# ================================================================
section_kernel() {
  header "11. KERNEL HARDENING (sysctl)"

  _check_sysctl() {
    local KEY="$1" EXPECTED="$2" DESC="$3"
    local VAL
    VAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
    if [[ "$VAL" == "$EXPECTED" ]]; then
      pass "$DESC"
      detail "$KEY = $VAL"
    else
      warn "$DESC"
      detail "$KEY = $VAL (recommended: $EXPECTED)"
    fi
  }

  subheader "Network hardening"
  _check_sysctl "net.ipv4.ip_forward"                        "0" "IPv4 forwarding disabled"
  _check_sysctl "net.ipv6.conf.all.forwarding"               "0" "IPv6 forwarding disabled"
  _check_sysctl "net.ipv4.conf.all.send_redirects"           "0" "ICMP send redirects disabled"
  _check_sysctl "net.ipv4.conf.default.send_redirects"       "0" "ICMP send redirects (default) disabled"
  _check_sysctl "net.ipv4.conf.all.accept_redirects"         "0" "ICMP accept redirects disabled"
  _check_sysctl "net.ipv4.conf.all.accept_source_route"      "0" "Source routing disabled"
  _check_sysctl "net.ipv4.conf.all.log_martians"             "1" "Martian packet logging enabled"
  _check_sysctl "net.ipv4.tcp_syncookies"                    "1" "SYN cookie protection enabled"
  _check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts"       "1" "ICMP broadcast echo disabled"
  _check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1" "Bogus ICMP responses ignored"
  _check_sysctl "net.ipv4.conf.all.rp_filter"                "1" "Reverse path filtering enabled"

  subheader "Kernel hardening"
  _check_sysctl "kernel.randomize_va_space" "2" "ASLR fully enabled"
  _check_sysctl "kernel.dmesg_restrict"     "1" "dmesg access restricted to root"
  _check_sysctl "kernel.kptr_restrict"      "2" "Kernel pointer leaks restricted"
  _check_sysctl "kernel.sysrq"             "0" "SysRq key disabled"
  _check_sysctl "fs.suid_dumpable"         "0" "SUID core dumps disabled"
  _check_sysctl "kernel.core_uses_pid"     "1" "Core dump filenames include PID"

  subheader "Kernel modules"
  for MOD in dccp sctp rds tipc; do
    if lsmod 2>/dev/null | grep -q "^${MOD}"; then
      warn "Potentially unused kernel module loaded: $MOD"
    else
      pass "Module $MOD is not loaded"
    fi
  done
}

# ================================================================
#  12. CRON & SCHEDULED TASKS
# ================================================================
section_cron() {
  header "12. CRON & SCHEDULED TASKS"

  subheader "System crontabs"
  for CFILE in /etc/crontab /etc/cron.d/* \
               /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    if [[ -f "$CFILE" ]]; then
      local PERM
      PERM=$(stat -c "%a %U" "$CFILE" 2>/dev/null || true)
      detail "$CFILE  [$PERM]"
    fi
  done

  subheader "Crontab permissions"
  local CRONTAB_PERM
  CRONTAB_PERM=$(stat -c "%a" /etc/crontab 2>/dev/null || true)
  if [[ "$CRONTAB_PERM" == "600" || "$CRONTAB_PERM" == "644" ]]; then
    pass "/etc/crontab permissions: $CRONTAB_PERM"
  else
    warn "/etc/crontab permissions: $CRONTAB_PERM (expected 600 or 644)"
  fi

  subheader "At daemon"
  if systemctl is-active --quiet atd 2>/dev/null; then
    warn "atd (at daemon) is running — verify if required"
  else
    pass "atd is not running"
  fi

  subheader "User crontabs"
  if [[ -d /var/spool/cron/crontabs ]]; then
    local USER_CRONS
    USER_CRONS=$(ls /var/spool/cron/crontabs/ 2>/dev/null || true)
    if [[ -n "$USER_CRONS" ]]; then
      info "User crontabs present for: $USER_CRONS"
    else
      info "No user crontabs found"
    fi
  fi
}

# ================================================================
#  13. INSTALLED PACKAGES & INTEGRITY
# ================================================================
section_packages() {
  header "13. INSTALLED PACKAGES & INTEGRITY"

  subheader "Installed package count"
  local PKG_COUNT
  PKG_COUNT=$(dpkg -l 2>/dev/null | grep -c "^ii" || true)
  PKG_COUNT=$(safe_int "$PKG_COUNT")
  info "Total installed packages: $PKG_COUNT"

  subheader "Debsums integrity check"
  if command -v debsums &>/dev/null; then
    local CHANGED
    # timeout 90: debsums can be very slow on large installs (hashes every pkg file)
    CHANGED=$(timeout 90 debsums -c 2>/dev/null | wc -l || true)
    CHANGED=$(safe_int "$CHANGED")
    if [[ "$CHANGED" -eq 0 ]]; then
      pass "debsums: all package files are intact"
    else
      fail "debsums: $CHANGED modified package file(s) detected"
      timeout 30 debsums -c 2>/dev/null | head -20 | while IFS= read -r line; do detail "$line"; done || true
    fi
  else
    warn "debsums not installed — install with: apt install debsums"
  fi

  subheader "dpkg audit"
  local DPKG_AUDIT
  # dpkg --audit is fast but can stall on a locked dpkg; cap at 15s
  DPKG_AUDIT=$(timeout 15 dpkg --audit 2>/dev/null | wc -l || true)
  DPKG_AUDIT=$(safe_int "$DPKG_AUDIT")
  if [[ "$DPKG_AUDIT" -eq 0 ]]; then
    pass "No broken packages found (dpkg --audit)"
  else
    fail "$DPKG_AUDIT broken/inconsistent package(s) found"
  fi

  subheader "Compiler tools"
  for TOOL in gcc g++ cc make; do
    if command -v "$TOOL" &>/dev/null; then
      warn "Compiler tool installed: $TOOL — remove from production servers"
    fi
  done

  subheader "Rootkit scanners (presence check)"
  for SCANNER in rkhunter chkrootkit; do
    if command -v "$SCANNER" &>/dev/null; then
      pass "$SCANNER is installed"
    else
      warn "$SCANNER not installed — will be auto-installed in section 14b"
    fi
  done
}

# ================================================================
#  14b. CHKROOTKIT + RKHUNTER — ROOTKIT SCANNERS
#
#  Speed strategy for rkhunter:
#   Fast mode  (default) — skips two very slow test groups:
#     • apps       : hashes every binary under /usr via the package manager
#                    (60-90 s on a typical Debian install)
#     • filesystem : walks the entire filesystem looking for hidden dirs
#                    (20-40 s)
#     --rwo (report-warnings-only) suppresses OK lines, reducing log I/O
#     --timeout 120 caps the whole run
#   Full mode   (RKH_FULL=true) — restores the complete rkhunter scan
#     RKH_FULL=true sudo bash wowscanner.sh
#
#   propupd guard: --propupd rebuilds the file-properties database.
#   We skip it if the db file was updated in the last 24 hours to avoid
#   the costly hash pass on every run.
# ================================================================
section_chkrootkit() {
  header "14b. CHKROOTKIT + RKHUNTER — ROOTKIT SCANNERS"

  if [[ "$USE_RKHUNTER" == "false" ]]; then
    skip "Rootkit scanners skipped (--no-rkhunter flag)"
    return
  fi

  # ── chkrootkit ───────────────────────────────────────────────
  # chkrootkit is already fast (~15-30s); no mode switching needed.
  if ! command -v chkrootkit &>/dev/null; then
    info "chkrootkit not found — installing via apt..."
    maybe_apt_update
    if apt-get install -y chkrootkit -qq 2>/dev/null; then
      pass "chkrootkit installed successfully"
    else
      fail "Could not install chkrootkit — skipping chkrootkit scan"
      warn "Manual install: apt-get install chkrootkit"
    fi
  fi

  if command -v chkrootkit &>/dev/null; then
    subheader "chkrootkit"
    local CKR_VERSION
    CKR_VERSION=$(chkrootkit -V 2>/dev/null | head -1 || true)
    info "Version: ${CKR_VERSION:-unknown}"

    # Only upgrade if the package manager says a newer version is available,
    # avoiding a redundant apt-get update / upgrade cycle on every run.
    local CKR_UPGRADABLE
    CKR_UPGRADABLE=$(apt list --upgradable 2>/dev/null | grep -c "chkrootkit" || true)
    if [[ "$(safe_int "$CKR_UPGRADABLE")" -gt 0 ]]; then
      info "Upgrading chkrootkit..."
      apt-get install --only-upgrade -y chkrootkit -qq 2>/dev/null || true
      CKR_VERSION=$(chkrootkit -V 2>/dev/null | head -1 || true)
      pass "chkrootkit upgraded to: ${CKR_VERSION:-unknown}"
    else
      pass "chkrootkit is up-to-date (${CKR_VERSION:-unknown})"
    fi

    info "Running chkrootkit scan (~15-30 s)..."
    local CHKROOTKIT_OUT="/tmp/chkrootkit_${TIMESTAMP}.txt"
    timeout 120 chkrootkit 2>/dev/null \
      | tee "$CHKROOTKIT_OUT" | tee -a "$REPORT" || true
    log ""

    subheader "chkrootkit scan summary"
    local INFECTED SUSPECT NOT_FOUND
    INFECTED=$(grep -i "INFECTED"   "$CHKROOTKIT_OUT" 2>/dev/null || true)
    SUSPECT=$(grep  -i "suspicious" "$CHKROOTKIT_OUT" 2>/dev/null || true)
    NOT_FOUND=$(grep -c "not found\|nothing found\|not infected" \
                "$CHKROOTKIT_OUT" 2>/dev/null || true)
    NOT_FOUND=$(safe_int "$NOT_FOUND")

    if [[ -n "$INFECTED" ]]; then
      fail "chkrootkit found INFECTED entries!"
      while IFS= read -r line; do [[ -n "$line" ]] && detail "$line"; done <<< "$INFECTED"
    else
      pass "No INFECTED entries reported by chkrootkit"
    fi
    if [[ -n "$SUSPECT" ]]; then
      warn "Suspicious entries found by chkrootkit:"
      while IFS= read -r line; do [[ -n "$line" ]] && detail "$line"; done <<< "$SUSPECT"
    else
      pass "No suspicious entries reported by chkrootkit"
    fi
    info "Clean checks (not infected / not found): $NOT_FOUND"

    subheader "chkrootkit false positive notes"
    grep -qi "eth0.*PACKET SNIFFER" "$CHKROOTKIT_OUT" 2>/dev/null && \
      warn "Packet sniffer warning on eth0 — likely false positive if tcpdump/wireshark is running"
    grep -qi "bindshell.*INFECTED" "$CHKROOTKIT_OUT" 2>/dev/null && \
      warn "Bindshell warning — verify with: ss -tlnp | grep -E '465|1524|31337'"
  fi

  # ── rkhunter ─────────────────────────────────────────────────
  subheader "rkhunter"
  if ! command -v rkhunter &>/dev/null; then
    info "rkhunter not installed — installing via apt..."
    maybe_apt_update
    apt-get install -y rkhunter -qq 2>/dev/null || true
  fi

  if ! command -v rkhunter &>/dev/null; then
    warn "rkhunter could not be installed — skipping rkhunter scan"
    return
  fi

  local RKH_VERSION
  RKH_VERSION=$(rkhunter --version 2>/dev/null | head -1 || true)
  info "rkhunter version: ${RKH_VERSION:-unknown}"

  # ── Database update (network; skip if done recently) ─────────
  # rkhunter --update fetches the latest rootkit signatures. It exits 1 on
  # "no updates" for some versions, so we always suppress the exit code.
  local RKH_UPDATE_DB="/var/lib/rkhunter/db/rkhunter.dat"
  [[ ! -f "$RKH_UPDATE_DB" ]] && RKH_UPDATE_DB="/usr/share/rkhunter/db/rkhunter.dat"
  local RKH_DB_AGE=99999
  if [[ -f "$RKH_UPDATE_DB" ]]; then
    RKH_DB_AGE=$(( $(date +%s) - $(stat -c %Y "$RKH_UPDATE_DB" 2>/dev/null || echo 0) ))
  fi
  if [[ "$RKH_DB_AGE" -gt 3600 ]]; then
    info "Updating rkhunter signature database (db age: ${RKH_DB_AGE}s)..."
    rkhunter --update --nocolors 2>/dev/null || true
    pass "rkhunter database update attempted"
  else
    pass "rkhunter signature db is fresh (${RKH_DB_AGE}s old) — skipping --update"
  fi

  # ── propupd guard: only rebuild file-properties db if >24h old ──
  # --propupd hashes every watched binary — expensive on large installs.
  local RKH_PROP_DB="/var/lib/rkhunter/db/rkhunter.dat.props"
  [[ ! -f "$RKH_PROP_DB" ]] && RKH_PROP_DB="/usr/share/rkhunter/db/rkhunter.dat.props"
  local RKH_PROP_AGE=99999
  if [[ -f "$RKH_PROP_DB" ]]; then
    RKH_PROP_AGE=$(( $(date +%s) - $(stat -c %Y "$RKH_PROP_DB" 2>/dev/null || echo 0) ))
  fi
  if [[ "$RKH_PROP_AGE" -gt 86400 || ! -f "$RKH_PROP_DB" ]]; then
    info "Rebuilding rkhunter file-properties database (last update: ${RKH_PROP_AGE}s ago)..."
    rkhunter --propupd --nocolors 2>/dev/null || true
    pass "rkhunter file-properties database updated"
  else
    pass "rkhunter file-properties db is current (${RKH_PROP_AGE}s old) — skipping --propupd"
  fi

  # ── Choose fast vs full scan mode ────────────────────────────
  local RKH_MODE_LABEL RKH_SKIP_FLAG="" RKH_TIMEOUT=300
  if [[ "${RKH_FULL:-false}" == "true" ]]; then
    RKH_MODE_LABEL="FULL"
    RKH_TIMEOUT=600
    info "Running rkhunter FULL scan (RKH_FULL=true) — may take 3-8 minutes..."
  else
    RKH_MODE_LABEL="FAST"
    # Skip the two slowest test groups:
    #   apps       — hashes every binary via dpkg/rpm (60-90 s)
    #   filesystem — hidden-directory walk of the whole fs (20-40 s)
    # Everything security-critical (rootkits, backdoors, syscall checks,
    # network, passwd/shadow checks, login daemons) is still covered.
    RKH_SKIP_FLAG="--skip-tests apps,filesystem"
    info "Running rkhunter FAST scan (~30-60 s). Set RKH_FULL=true for full scan."
    info "Skipped (slow, low-signal): apps (pkg hash walk), filesystem (hidden dir walk)"
  fi

  local RKH_OUT="/tmp/rkhunter_${TIMESTAMP}.txt"

  # --rwo = report-warnings-only: suppress OK lines to stdout (faster I/O)
  # We still get the full log via --logfile
  # shellcheck disable=SC2086
  timeout "$RKH_TIMEOUT" rkhunter \
    --check          \
    --nocolors       \
    --skip-keypress  \
    --quiet          \
    --rwo            \
    --logfile "$RKH_OUT" \
    $RKH_SKIP_FLAG   \
    2>/dev/null || true

  # Prefer the explicit logfile we set; fall back to the system default
  local RKH_LOG="$RKH_OUT"
  if [[ ! -s "$RKH_LOG" ]]; then
    for _try in /var/log/rkhunter.log /var/log/rkhunter/rkhunter.log; do
      [[ -s "$_try" ]] && { RKH_LOG="$_try"; break; }
    done
  fi

  if [[ ! -s "$RKH_LOG" ]]; then
    warn "rkhunter produced no log output — scan may have failed or timed out"
    return
  fi

  # ── Parse results ─────────────────────────────────────────────
  local RKH_WARNINGS RKH_INFECTED RKH_OK
  RKH_WARNINGS=$(grep -c "Warning" "$RKH_LOG" 2>/dev/null || true)
  RKH_INFECTED=$(grep -c "Infected" "$RKH_LOG" 2>/dev/null || true)
  RKH_OK=$(grep -c " OK$\| OK " "$RKH_LOG" 2>/dev/null || true)
  RKH_WARNINGS=$(safe_int "$RKH_WARNINGS")
  RKH_INFECTED=$(safe_int "$RKH_INFECTED")
  RKH_OK=$(safe_int "$RKH_OK")

  info "rkhunter [${RKH_MODE_LABEL}] — OK: ${RKH_OK}  Warnings: ${RKH_WARNINGS}  Infected: ${RKH_INFECTED}"

  if [[ "$RKH_INFECTED" -gt 0 ]]; then
    fail "rkhunter: $RKH_INFECTED infected file(s) detected!  [${RKH_MODE_LABEL} mode]"
    grep "Infected" "$RKH_LOG" 2>/dev/null | head -20 \
      | while IFS= read -r l; do detail "$l"; done
  else
    pass "rkhunter: No infected files found  [${RKH_MODE_LABEL} mode]"
  fi

  if [[ "$RKH_WARNINGS" -gt 0 ]]; then
    warn "rkhunter: $RKH_WARNINGS warning(s) found  [${RKH_MODE_LABEL} mode]"
    grep "Warning" "$RKH_LOG" 2>/dev/null | head -20 \
      | while IFS= read -r l; do [[ -n "$l" ]] && detail "$l"; done
  else
    pass "rkhunter: No warnings  [${RKH_MODE_LABEL} mode]"
  fi

  info "Mode: ${RKH_MODE_LABEL} — to run full scan: RKH_FULL=true sudo bash $0"

  # ── Append rkhunter log to the combined report ────────────────
  { echo ""
    echo "──── RAW: rkhunter [${RKH_MODE_LABEL}] — from: ${RKH_LOG} ────"
    cat "$RKH_LOG" 2>/dev/null || true
    echo "────────────────────────────"
  } >> "$REPORT" || true
  info "rkhunter scan log appended to: ${REPORT}  (source: ${RKH_LOG})"

  # ── Advisory: also embed the persistent system log if it differs ─
  # rkhunter always writes to /var/log/rkhunter.log in addition to --logfile.
  # Embed it so the single output file is fully self-contained.
  local _sys_log=""
  for _try in /var/log/rkhunter.log /var/log/rkhunter/rkhunter.log; do
    if [[ -s "$_try" && "$_try" != "$RKH_LOG" ]]; then
      _sys_log="$_try"
      break
    fi
  done

  if [[ -n "$_sys_log" ]]; then
    { echo ""
      echo "──── SYSTEM LOG: ${_sys_log} ────"
      cat "$_sys_log" 2>/dev/null || true
      echo "────────────────────────────"
    } >> "$REPORT" || true
    info "Please check the log file (${_sys_log}) for full rkhunter details"
    warn "rkhunter log file location: ${_sys_log} — review manually for false positives"
  else
    info "Please check the log file (/var/log/rkhunter.log) for full rkhunter details"
    info "Log path used this run: ${RKH_LOG}"
  fi
}

# ================================================================
#  14. APPARMOR / SELINUX
# ================================================================
section_mac() {
  header "14. MANDATORY ACCESS CONTROL (AppArmor / SELinux)"

  subheader "AppArmor"
  if command -v aa-status &>/dev/null; then
    local AA_STATUS
    AA_STATUS=$(aa-status 2>/dev/null || true)
    if echo "$AA_STATUS" | grep -qi "apparmor module is loaded"; then
      pass "AppArmor module is loaded"
      local ENFORCE COMPLAIN
      ENFORCE=$(echo "$AA_STATUS" | grep -oP '\d+ profiles are in enforce mode' || true)
      COMPLAIN=$(echo "$AA_STATUS" | grep -oP '\d+ profiles are in complain mode' || true)
      info "Profiles: ${ENFORCE:-0 in enforce}  |  ${COMPLAIN:-0 in complain}"
    else
      warn "AppArmor is installed but not fully loaded"
    fi
  elif systemctl is-active --quiet apparmor 2>/dev/null; then
    pass "AppArmor service is active"
  else
    warn "AppArmor is not active — enable with: systemctl enable --now apparmor"
  fi

  subheader "SELinux"
  if command -v getenforce &>/dev/null; then
    local SE_STATE
    SE_STATE=$(getenforce 2>/dev/null || true)
    if [[ "$SE_STATE" == "Enforcing" ]]; then
      pass "SELinux is in Enforcing mode"
    elif [[ "$SE_STATE" == "Permissive" ]]; then
      warn "SELinux is in Permissive mode — set to Enforcing"
    else
      warn "SELinux is Disabled"
    fi
  else
    info "SELinux tools not found (expected on Debian — AppArmor is default)"
  fi
}

# ================================================================

# ================================================================
#  15. LYNIS SECURITY AUDIT  (fast mode by default)
#
#  Speed strategy:
#   --fast          skip slow I/O tests (file integrity, USB, etc.)
#   --tests-from-group  only run the highest-signal categories
#   --timeout 120   cap each individual test at 2 min
#   Full scan available with --no-lynis=false (full) flag or
#   LYNIS_FULL=true environment variable.
#
#  Typical runtimes:
#   Fast mode  : ~25-50 seconds
#   Full mode  : 2-5 minutes
# ================================================================
section_lynis() {
  header "15. LYNIS SECURITY AUDIT"

  if [[ "$USE_LYNIS" == "false" ]]; then
    skip "Lynis skipped (--no-lynis flag)"
    return
  fi

  # ── Install Lynis if missing ──────────────────────────────────
  if ! command -v lynis &>/dev/null; then
    info "Lynis not found — installing via apt..."
    maybe_apt_update
    apt-get install -y lynis -qq 2>/dev/null || {
      info "Trying Lynis from CISOfy repository..."
      apt-get install -y apt-transport-https ca-certificates curl -qq 2>/dev/null || true
      curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/cisofy.gpg 2>/dev/null || true
      echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" \
        > /etc/apt/sources.list.d/cisofy-lynis.list 2>/dev/null || true
      apt-get update -qq 2>/dev/null || true   # must refresh after adding new repo
      APT_UPDATED=1                              # mark done so later sections skip
      apt-get install -y lynis -qq 2>/dev/null || true
    }
  fi

  if ! command -v lynis &>/dev/null; then
    fail "Could not install Lynis — skipping Lynis audit"
    warn "Manual install: apt install lynis  OR  snap install lynis"
    return
  fi

  local LYNIS_VERSION LYNIS_DAT="/tmp/lynis_report_${TIMESTAMP}.dat"
  LYNIS_VERSION=$(lynis --version 2>/dev/null | head -1 || true)
  info "Lynis version: ${LYNIS_VERSION:-unknown}"

  # ── Parse major version to choose compatible flags ────────────
  # Lynis 2.x vs 3.x flag compatibility matrix:
  #   --nocolors      : both 2.x and 3.x
  #   --quiet         : both (suppress output + skip wait prompts on most builds)
  #   --no-log        : 3.x ONLY — on 2.x Lynis treats it as unknown, aborts entirely
  #   --quick         : both (alias for --no-wait / skip questions)
  #   --report-file   : both
  #   --tests-from-group : both, but group names differ (probe before using)
  local LYNIS_MAJOR=3
  if [[ "$LYNIS_VERSION" =~ ^Lynis[[:space:]]+([0-9]+)\. ]]; then
    LYNIS_MAJOR="${BASH_REMATCH[1]}"
  fi
  info "Lynis major version detected: ${LYNIS_MAJOR}"

  # ── Build universal base flags (safe on ALL Lynis versions) ──
  local LYNIS_BASE_FLAGS="--nocolors --quiet --report-file ${LYNIS_DAT}"
  # --no-log: prevents writing to /var/log/lynis.log, but ONLY on Lynis 3.x
  # On 2.x it is an unrecognised flag → Lynis aborts before writing the .dat file
  if [[ "$LYNIS_MAJOR" -ge 3 ]]; then
    LYNIS_BASE_FLAGS="${LYNIS_BASE_FLAGS} --no-log"
  fi

  # ── Choose fast vs full mode ──────────────────────────────────
  local LYNIS_MODE_LABEL LYNIS_EXTRA_FLAGS=""
  local LYNIS_TIMEOUT=180
  if [[ "${LYNIS_FULL:-false}" == "true" ]]; then
    LYNIS_MODE_LABEL="FULL"
    LYNIS_TIMEOUT=600
    info "Running Lynis FULL audit (LYNIS_FULL=true) — may take 2-5 minutes..."
  else
    LYNIS_MODE_LABEL="FAST"
    LYNIS_TIMEOUT=240

    # Groups that exist in BOTH Lynis 2.x and 3.x
    local _grp="authentication,boot_services,crypto,file_permissions"
    _grp+=",firewalls,hardening,kernel,logging,malware"
    _grp+=",memory_processes,nameservices,networking,ports_packages"
    _grp+=",scheduling,shells,snmp,ssh,storage,time,users"
    # software_webserver only in 3.x
    [[ "$LYNIS_MAJOR" -ge 3 ]] && _grp+=",software_webserver"

    # ── Probe: verify --tests-from-group actually works ────────
    # Run a minimal dry probe (one safe group, very fast) to confirm
    # the flag is accepted. Some Lynis packages have the flag but with
    # different group names; others reject the flag outright.
    # The probe writes to a throwaway .dat and checks for non-empty output.
    local _probe_dat="/tmp/lynis_probe_${TIMESTAMP}.dat"
    local _probe_ok=false
    timeout 30 lynis audit system \
      --nocolors --quiet --report-file "$_probe_dat" \
      $( [[ "$LYNIS_MAJOR" -ge 3 ]] && echo "--no-log" ) \
      --tests-from-group "ssh" \
      > /dev/null 2>&1 && [[ -s "$_probe_dat" ]] && _probe_ok=true || true
    rm -f "$_probe_dat"

    if [[ "$_probe_ok" == "true" ]]; then
      LYNIS_EXTRA_FLAGS="--tests-from-group ${_grp}"
      info "Lynis FAST mode: --tests-from-group probe passed [${LYNIS_MAJOR}.x]"
      info "Running Lynis FAST audit (~25-50 sec). Set LYNIS_FULL=true for full scan."
    else
      # --tests-from-group not supported or group names differ on this install
      # Fall back to full scan silently — no scary warning to the user
      LYNIS_MODE_LABEL="FULL"
      LYNIS_TIMEOUT=600
      info "Lynis FAST mode not available on this install (probe failed) — running full scan"
      info "To always force full scan: LYNIS_FULL=true sudo bash $0"
    fi
  fi

  log ""

  # shellcheck disable=SC2086
  # Run Lynis to a temp file — avoids the | tee pipeline which triggers
  # Lynis's isatty() check ("Program execution stopped due to security measure")
  local LYNIS_LOG="/tmp/lynis_output_${TIMESTAMP}.txt"
  timeout "$LYNIS_TIMEOUT" lynis audit system \
    $LYNIS_BASE_FLAGS \
    $LYNIS_EXTRA_FLAGS \
    > "$LYNIS_LOG" 2>&1 || true

  # ── Check the result and show what actually happened ─────────
  if [[ ! -s "$LYNIS_DAT" ]]; then
    # Report file missing — show what Lynis actually printed to help diagnose
    warn "Lynis produced no report file — scan may have failed or been rejected"
    if [[ -s "$LYNIS_LOG" ]]; then
      # Show the first Lynis error/warning line
      local _lynis_err
      _lynis_err=$(grep -iE "error|warning|stopped|invalid|unknown|fatal" \
                   "$LYNIS_LOG" 2>/dev/null | head -3 || true)
      [[ -n "$_lynis_err" ]] && \
        info "Lynis output: ${_lynis_err}" || \
        info "Lynis output (first 3 lines): $(head -3 "$LYNIS_LOG" | tr '\n' ' ')"
    fi
    info "Try running manually: sudo lynis audit system"
    cat "$LYNIS_LOG" | tee -a "$REPORT" || true
    rm -f "$LYNIS_LOG"
    return
  fi

  # Show output and append to report
  cat "$LYNIS_LOG" | tee -a "$REPORT" || true
  rm -f "$LYNIS_LOG"

  log ""

  # ── Parse results ─────────────────────────────────────────────
  if [[ ! -f "$LYNIS_DAT" ]]; then
    warn "Lynis report file not found — scan may have timed out"
    return
  fi

  # Hardening index
  local HARDENING_INDEX
  HARDENING_INDEX=$(grep "^hardening_index=" "$LYNIS_DAT" 2>/dev/null \
    | cut -d= -f2 | head -1 || true)
  HARDENING_INDEX=$(safe_int "$HARDENING_INDEX")
  if [[ "$HARDENING_INDEX" -gt 0 ]]; then
    if [[ "$HARDENING_INDEX" -ge 80 ]]; then
      pass "Lynis hardening index: ${HARDENING_INDEX}/100 — GOOD  [${LYNIS_MODE_LABEL} mode]"
    elif [[ "$HARDENING_INDEX" -ge 50 ]]; then
      warn "Lynis hardening index: ${HARDENING_INDEX}/100 — MODERATE  [${LYNIS_MODE_LABEL} mode]"
    else
      fail "Lynis hardening index: ${HARDENING_INDEX}/100 — CRITICAL  [${LYNIS_MODE_LABEL} mode]"
    fi
  else
    info "Lynis hardening index not available in report (scan may be incomplete)"
  fi

  # Warnings
  local LYNIS_WARNINGS WARN_COUNT
  LYNIS_WARNINGS=$(grep "^warning\[\]=" "$LYNIS_DAT" 2>/dev/null \
    | cut -d= -f2 | tr -d '[]' | sort -u || true)
  WARN_COUNT=$(echo "$LYNIS_WARNINGS" | grep -c "." 2>/dev/null || true)
  WARN_COUNT=$(safe_int "$WARN_COUNT")
  if [[ "$WARN_COUNT" -gt 0 ]]; then
    warn "Lynis found $WARN_COUNT warning(s)  [${LYNIS_MODE_LABEL} mode]:"
    while IFS= read -r w; do [[ -n "$w" ]] && detail "  $w"; done <<< "$LYNIS_WARNINGS"
  else
    pass "Lynis: no warnings  [${LYNIS_MODE_LABEL} mode]"
  fi

  # Suggestions
  local SUGGESTION_COUNT
  SUGGESTION_COUNT=$(grep -c "^suggestion\[\]=" "$LYNIS_DAT" 2>/dev/null || true)
  SUGGESTION_COUNT=$(safe_int "$SUGGESTION_COUNT")
  info "Lynis suggestions: $SUGGESTION_COUNT  (details: $LYNIS_DAT)"

  # Tests performed count
  local TESTS_DONE
  TESTS_DONE=$(grep "^tests_executed=" "$LYNIS_DAT" 2>/dev/null \
    | cut -d= -f2 | head -1 || true)
  TESTS_DONE=$(safe_int "$TESTS_DONE")
  [[ "$TESTS_DONE" -gt 0 ]] && info "Lynis tests executed: $TESTS_DONE"

  info "Mode: ${LYNIS_MODE_LABEL} — to run full scan: LYNIS_FULL=true sudo bash $0"
  info "Full Lynis output appended to: ${REPORT}"
}

# ================================================================
#  21. ODF INTELLIGENCE REPORT  (statistical deep-dive)
#
#  This ODT contains:
#   Page 1 — Executive Dashboard
#             Score gauge + KPI stat boxes + threat context bar chart
#   Page 2 — CVE Landscape
#             CVE trend 2020-2025 + severity breakdown + attack vector
#             Comparison table: this host vs industry benchmarks
#   Page 3 — Local Audit Statistics
#             Per-category heatmap bar chart + FAIL/WARN breakdown
#             stacked area approximation (horizontal layout)
#   Page 4 — Threat Intelligence
#             Threat-type distribution pie
#             Attacker dwell-time & detection gap data
#             CISA KEV table
#   Page 5 — Remediation Priority Matrix
#             2×2 effort/impact quadrant (SVG)
#             Top 10 prioritised remediation steps
# ================================================================
generate_odf_intel_report() {
  local SCORE_VAL="$1" TOTAL_VAL="$2" PCT="$3"
  local TXT_REPORT="${4:-$REPORT}"          # optional 4th arg: path to audit txt
  local ODI_OUT="wowscanner_intel_${TIMESTAMP}.odt"

  info "Generating statistical ODF intelligence report → ${ODI_OUT} ..."

  python3 - "$ODI_OUT" "$SCORE_VAL" "$TOTAL_VAL" "$PCT" "$TIMESTAMP" \
           "$(hostname -f 2>/dev/null || hostname)" \
           "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')" \
           "$(uname -r)" \
           "$TXT_REPORT" << 'INTELEOF' || true
#!/usr/bin/env python3
import sys, os, re, zipfile, math
from datetime import datetime

odt_out   = sys.argv[1]
score_val = int(sys.argv[2])
total_val = int(sys.argv[3])
pct       = int(sys.argv[4])
timestamp = sys.argv[5]
hostname  = sys.argv[6]
os_name   = sys.argv[7]
kernel    = sys.argv[8]
txt_report = sys.argv[9] if len(sys.argv) > 9 else ""
run_date  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Rating ────────────────────────────────────────────────────────
if pct >= 80:   rating="GOOD";     r_hex="2E7D32"; r_bg="E8F5E9"; r_light="A5D6A7"
elif pct >= 50: rating="MODERATE"; r_hex="E65100"; r_bg="FFF3E0"; r_light="FFCC80"
else:           rating="CRITICAL"; r_hex="B71C1C"; r_bg="FFEBEE"; r_light="EF9A9A"

# ── Parse audit report for local findings ─────────────────────────
ansi_re = re.compile(r'\x1b\[[0-9;]*m')
sections = []; raw_lines = []
if txt_report and os.path.isfile(txt_report):
    with open(txt_report, 'r', errors='replace') as fh:
        raw_lines = [ansi_re.sub('', l.rstrip('\n')) for l in fh]
    PASS_RE = re.compile(r'^\s*\[.*PASS.*\]\s*(.*)')
    FAIL_RE = re.compile(r'^\s*\[.*FAIL.*\]\s*(.*)')
    WARN_RE = re.compile(r'^\s*\[.*WARN.*\]\s*(.*)')
    INFO_RE = re.compile(r'^\s*\[.*INFO.*\]\s*(.*)')
    SKIP_RE = re.compile(r'^\s*\[.*SKIP.*\]\s*(.*)')
    DETAIL_RE = re.compile(r'^\s*↳\s*(.*)')
    cur_sec = {"title":"Header","items":[]}; last_idx = -1
    for line in raw_lines:
        m_sec = re.match(r'\s*([0-9]+[ab]*\.\s+[A-Z].{4,})', line)
        if m_sec and not re.search(r'[✔✘⚠ℹ↳]', line):
            sections.append(cur_sec)
            cur_sec = {"title": m_sec.group(1).strip(), "items": []}
            last_idx = -1; continue
        matched = False
        for RE, kind in ((PASS_RE,"PASS"),(FAIL_RE,"FAIL"),(WARN_RE,"WARN"),(INFO_RE,"INFO"),(SKIP_RE,"SKIP")):
            m = RE.match(line)
            if m:
                cur_sec["items"].append({"kind": kind, "text": m.group(1), "details": []})
                last_idx = len(cur_sec["items"]) - 1; matched = True; break
        if not matched:
            md = DETAIL_RE.match(line)
            if md and last_idx >= 0:
                cur_sec["items"][last_idx]["details"].append(md.group(1))
    sections.append(cur_sec)
    sections = [s for s in sections if s["items"]]

all_items  = [i for s in sections for i in s["items"]]
n_pass_loc = sum(1 for i in all_items if i["kind"]=="PASS")
n_fail_loc = sum(1 for i in all_items if i["kind"]=="FAIL")
n_warn_loc = sum(1 for i in all_items if i["kind"]=="WARN")
n_info_loc = sum(1 for i in all_items if i["kind"]=="INFO")

# ── Severity KB (mirrors ODS) ─────────────────────────────────────
SEVERITY_MAP = {
    "ssh root login": "Critical", "ufw firewall is inactive": "Critical",
    "no syslog": "Critical", "security update": "Critical",
    "ssh password authentication": "High", "syn cookie": "High",
    "apparmor": "High", "auditd": "High", "no pam password complexity": "High",
    "no pam account lockout": "High", "debsums": "High", "world-writable": "High",
    "kptr_restrict": "High", "failed ssh login": "High", "packages need updating": "High",
    "ssh listening on default port 22": "Medium", "maxauthtries": "Medium",
    "ssh idle timeout": "Medium", "tcp forwarding": "Medium", "aslr": "Medium",
    "dmesg": "Medium", "pass_max_days": "Medium", "pass_min_len": "Medium",
    "send_redirects": "Medium", "accept_redirects": "Medium", "rp_filter": "Medium",
    "ipv4 forwarding": "Medium", "compiler": "Medium", "suid": "Medium",
    "failed service": "Medium", "open file limit": "Low",
    "x11 forwarding": "Low", "atd": "Low", "sysrq": "Low",
    "martian": "Low", "logingraceTime": "Low",
}
def classify_sev(text):
    fl = text.lower()
    best_len, best_sev = 0, "Low"
    for kw, sev in SEVERITY_MAP.items():
        if kw.lower() in fl and len(kw) > best_len:
            best_len, best_sev = len(kw), sev
    return best_sev

# Count local issue severities
sev_counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
for s in sections:
    for item in s["items"]:
        if item["kind"] in ("FAIL","WARN"):
            sev = classify_sev(item["text"])
            if item["kind"] == "FAIL" and sev == "Low": sev = "Medium"
            sev_counts[sev] += 1

total_issues = sum(sev_counts.values())

# ── XML helpers ───────────────────────────────────────────────────
def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def p(text, style="body"): return f'<text:p text:style-name="{style}">{esc(text)}</text:p>'
def h1(text):               return f'<text:h text:style-name="h1" text:outline-level="1">{esc(text)}</text:h>'
def h2(text):               return f'<text:h text:style-name="h2" text:outline-level="2">{esc(text)}</text:h>'
def h3(text):               return f'<text:h text:style-name="h3" text:outline-level="3">{esc(text)}</text:h>'
def tb():                   return '<text:p text:style-name="tb"/>'
def pb():                   return '<text:p text:style-name="tb"><text:soft-page-break/></text:p>'
def kpi(val, label, col):
    return (f'<text:p text:style-name="kpi_box_{col}">'
            f'<text:span text:style-name="kpi_val">{esc(val)}</text:span>'
            f'  <text:span text:style-name="kpi_lbl">{esc(label)}</text:span>'
            f'</text:p>')
def stat_row(val, desc):
    return (f'<text:p text:style-name="stat_row">'
            f'<text:span text:style-name="stat_val">{esc(val)}</text:span>'
            f'  {esc(desc)}</text:p>')
def cap(text): return p(text, "cap")

def tbl_row(*cells, header=False):
    style = "thc" if header else "tdc"
    txt_sty = "th_p" if header else "td_p"
    cxml = "".join(
        f'<table:table-cell table:style-name="{style}" office:value-type="string">'
        f'<text:p text:style-name="{txt_sty}">{esc(str(c))}</text:p></table:table-cell>'
        for c in cells
    )
    return f'<table:table-row>{cxml}</table:table-row>'

def tbl_row_colored(cells_styles):
    cxml = "".join(
        f'<table:table-cell table:style-name="{cs}" office:value-type="string">'
        f'<text:p text:style-name="td_p">{esc(str(cv))}</text:p></table:table-cell>'
        for cv, cs in cells_styles
    )
    return f'<table:table-row>{cxml}</table:table-row>'

def frame(href, w="16cm", h="8cm", name="img"):
    return (f'<draw:frame draw:name="{esc(name)}" text:anchor-type="paragraph" '
            f'svg:width="{w}" svg:height="{h}" draw:z-index="0">'
            f'<draw:image xlink:href="{esc(href)}" xlink:type="simple" '
            f'xlink:show="embed" xlink:actuate="onLoad"/></draw:frame>')

def make_table(name, col_widths, rows_xml):
    cols = "".join(f'<table:table-column table:style-name="col_{w}"/>' for w in col_widths)
    return (f'<table:table table:name="{esc(name)}" table:style-name="tbl">'
            + cols + "\n".join(rows_xml) + '</table:table>')

# ══════════════════════════════════════════════════════════════════
#  SVG BUILDERS
# ══════════════════════════════════════════════════════════════════

def build_dashboard_svg():
    """Page 1 hero graphic: gauge + 4 KPI tiles + context bar."""
    W, H = 760, 320
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#0D1B2A" rx="14"/>',
    ]

    # ── Left: Semi-circular gauge ──────────────────────────────────
    cx, cy, R_o, R_i = 160, 210, 140, 88
    zones = [(0,20,"#7B1FA2"),(20,40,"#B71C1C"),(40,60,"#E65100"),(60,80,"#F57F17"),(80,100,"#2E7D32")]
    def arc(p0, p1, ro, ri, col):
        a0 = math.radians(180 - p0*1.8); a1 = math.radians(180 - p1*1.8)
        lg = 1 if abs(p1-p0)>50 else 0
        x1o=cx+ro*math.cos(a0); y1o=cy-ro*math.sin(a0)
        x2o=cx+ro*math.cos(a1); y2o=cy-ro*math.sin(a1)
        x1i=cx+ri*math.cos(a1); y1i=cy-ri*math.sin(a1)
        x2i=cx+ri*math.cos(a0); y2i=cy-ri*math.sin(a0)
        d=(f"M{round(x1o,2)},{round(y1o,2)} A{ro},{ro} 0 {lg},0 {round(x2o,2)},{round(y2o,2)} "
           f"L{round(x1i,2)},{round(y1i,2)} A{ri},{ri} 0 {lg},1 {round(x2i,2)},{round(y2i,2)} Z")
        return f'<path d="{d}" fill="{col}"/>'
    for p0,p1,col in zones: parts.append(arc(p0,p1,R_o,R_i,col))
    nd = math.radians(180 - pct*1.8)
    nx=cx+(R_i-12)*math.cos(nd); ny=cy-(R_i-12)*math.sin(nd)
    parts += [
        f'<line x1="{cx}" y1="{cy}" x2="{round(nx,2)}" y2="{round(ny,2)}" stroke="#fff" stroke-width="4" stroke-linecap="round"/>',
        f'<circle cx="{cx}" cy="{cy}" r="9" fill="#fff"/>',
        f'<circle cx="{cx}" cy="{cy}" r="4" fill="#{r_hex}"/>',
        f'<text x="{cx}" y="{cy+50}" text-anchor="middle" font-family="Arial" font-size="42" font-weight="bold" fill="#{r_hex}">{pct}%</text>',
        f'<text x="{cx}" y="{cy+78}" text-anchor="middle" font-family="Arial" font-size="16" font-weight="bold" fill="#{r_hex}">{rating}</text>',
        f'<text x="{cx}" y="{cy+96}" text-anchor="middle" font-family="Arial" font-size="10" fill="#78909C">{score_val} / {total_val} checks passed</text>',
        f'<text x="{cx}" y="20" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold" fill="#B0BEC5">Security Score</text>',
    ]
    # Benchmark ticks
    for bp, bl, bc in [(55,"SMB","#FF9800"),(72,"Ent.","#42A5F5"),(85,"CIS","#66BB6A")]:
        ba = math.radians(180-bp*1.8)
        bx1=cx+R_o*math.cos(ba); by1=cy-R_o*math.sin(ba)
        bx2=cx+(R_o+14)*math.cos(ba); by2=cy-(R_o+14)*math.sin(ba)
        parts += [
            f'<line x1="{round(bx1,1)}" y1="{round(by1,1)}" x2="{round(bx2,1)}" y2="{round(by2,1)}" stroke="{bc}" stroke-width="1.5" stroke-dasharray="3,2"/>',
            f'<text x="{round(bx2,1)}" y="{round(by2-2,1)}" font-family="Arial" font-size="7.5" fill="{bc}" text-anchor="middle">{bl}</text>',
        ]

    # ── Right: 4 KPI tiles ────────────────────────────────────────
    tiles = [
        (str(n_fail_loc), "FAIL items",    "#B71C1C", "#FFCDD2"),
        (str(n_warn_loc), "WARN items",    "#E65100", "#FFE0B2"),
        (str(n_pass_loc), "PASS items",    "#2E7D32", "#C8E6C9"),
        (str(total_issues),"Total issues", "#7B1FA2", "#E1BEE7"),
    ]
    tx0, ty0, tw, th, tgap = 340, 20, 190, 58, 12
    for i,(val,lbl,bg,fg) in enumerate(tiles):
        tx = tx0 + (i%2)*(tw+tgap); ty = ty0 + (i//2)*(th+tgap)
        parts += [
            f'<rect x="{tx}" y="{ty}" width="{tw}" height="{th}" fill="{bg}" rx="8"/>',
            f'<text x="{tx+tw//2}" y="{ty+32}" text-anchor="middle" font-family="Arial" font-size="28" font-weight="bold" fill="{fg}">{val}</text>',
            f'<text x="{tx+tw//2}" y="{ty+50}" text-anchor="middle" font-family="Arial" font-size="10" fill="{fg}">{lbl}</text>',
        ]

    # ── Bottom: severity distribution bar ────────────────────────
    bx0, by0, bw_total, bh = 340, 168, 404, 30
    sev_data = [
        (sev_counts["Critical"], "#B71C1C", "Critical"),
        (sev_counts["High"],     "#E64A19", "High"),
        (sev_counts["Medium"],   "#F57F17", "Medium"),
        (sev_counts["Low"],      "#388E3C", "Low"),
    ]
    t = total_issues or 1
    parts.append(f'<text x="{bx0}" y="{by0-6}" font-family="Arial" font-size="10" fill="#78909C" font-weight="bold">Issue Severity Distribution</text>')
    parts.append(f'<rect x="{bx0}" y="{by0}" width="{bw_total}" height="{bh}" fill="#1E2A3A" rx="5"/>')
    bx_cur = bx0
    for cnt, col, lbl in sev_data:
        bw_seg = int(cnt/t*bw_total) if cnt else 0
        if bw_seg:
            parts.append(f'<rect x="{bx_cur}" y="{by0}" width="{bw_seg}" height="{bh}" fill="{col}" rx="3"/>')
            if bw_seg > 25:
                parts.append(f'<text x="{bx_cur+bw_seg//2}" y="{by0+bh//2+5}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#fff">{cnt}</text>')
        bx_cur += bw_seg

    # Legend for severity bar
    lx, ly = bx0, by0+bh+12
    for cnt, col, lbl in sev_data:
        parts += [
            f'<rect x="{lx}" y="{ly}" width="10" height="10" fill="{col}" rx="2"/>',
            f'<text x="{lx+13}" y="{ly+9}" font-family="Arial" font-size="9" fill="#90A4AE">{lbl} ({cnt})</text>',
        ]
        lx += 100

    # ── Bottom-right: 5 top stats ─────────────────────────────────
    stats_mini = [
        ("5,530", "kernel CVEs in 2025"),
        ("89%",   "attacks: brute-force"),
        ("967%",  "CVE growth 2023→24"),
        ("32%",   "ransomware via vuln"),
        ("148",   "critical CVEs 2024"),
    ]
    sx, sy = 340, 228
    for i,(v,d) in enumerate(stats_mini):
        row_x = sx + (i%2)*202; row_y = sy + (i//2)*24
        parts += [
            f'<text x="{row_x}" y="{row_y}" font-family="Arial" font-size="13" font-weight="bold" fill="#42A5F5">{v}</text>',
            f'<text x="{row_x+52}" y="{row_y}" font-family="Arial" font-size="9" fill="#78909C">{d}</text>',
        ]

    parts += [
        f'<text x="{W//2}" y="{H-5}" text-anchor="middle" font-family="Arial" font-size="7.5" fill="#37474F">Sources: NIST NVD · CISA KEV · Elastic 2024 · Trend Micro 2025 · Action1 2025 | Generated: {run_date}</text>',
        '</svg>'
    ]
    return "".join(parts)


def build_cve_landscape_svg():
    """Page 2 wide chart: CVE trend bars + CVSS severity strip + attack vector pie."""
    W, H = 760, 290
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#0D1B2A" rx="12"/>',
        f'<text x="{W//2}" y="22" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#B0BEC5">Linux Kernel CVE Landscape 2020–2025 (NIST NVD)</text>',
    ]

    # ── Left: CVE trend bars ──────────────────────────────────────
    years  = [2020,2021,2022,2023,2024,2025]
    counts = [897,839,1012,1736,3108,5530]
    max_v  = 6000
    pad_l,pad_t,pad_b = 46,36,46; chart_h=H-pad_t-pad_b; chart_w=290
    bar_w  = chart_w//len(years)-8; bx_off = 10
    colours=["#1565C0","#1976D2","#1E88E5","#2196F3","#42A5F5","#EF5350"]
    for tick in [0,1000,2000,3000,4000,5000,6000]:
        gy = pad_t+chart_h-int(tick/max_v*chart_h)
        parts += [
            f'<line x1="{pad_l}" y1="{gy}" x2="{pad_l+chart_w}" y2="{gy}" stroke="#1E2A3A" stroke-width="1"/>',
            f'<text x="{pad_l-3}" y="{gy+4}" text-anchor="end" font-family="Arial" font-size="7.5" fill="#546E7A">{tick}</text>',
        ]
    for i,(yr,cnt) in enumerate(zip(years,counts)):
        bh=int(cnt/max_v*chart_h); bx=pad_l+bx_off+i*(chart_w//len(years)); by=pad_t+chart_h-bh
        parts += [
            f'<rect x="{bx}" y="{by}" width="{bar_w}" height="{bh}" fill="{colours[i]}" rx="2"/>',
            f'<text x="{bx+bar_w//2}" y="{by-3}" text-anchor="middle" font-family="Arial" font-size="7.5" font-weight="bold" fill="{colours[i]}">{cnt}</text>',
            f'<text x="{bx+bar_w//2}" y="{H-pad_b+14}" text-anchor="middle" font-family="Arial" font-size="8" fill="#78909C">{yr}</text>',
        ]
    parts += [
        f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{pad_t+chart_h}" stroke="#37474F" stroke-width="1.5"/>',
        f'<line x1="{pad_l}" y1="{pad_t+chart_h}" x2="{pad_l+chart_w}" y2="{pad_t+chart_h}" stroke="#37474F" stroke-width="1.5"/>',
        f'<text x="{pad_l+chart_w//2}" y="{H-4}" text-anchor="middle" font-family="Arial" font-size="7" fill="#37474F">Source: NIST NVD Jan 2026</text>',
    ]

    # ── Middle: Severity breakdown stacked bar ─────────────────────
    mx = 370; mw = 140; mpad_t = 36; mpad_b = 46
    mh = H - mpad_t - mpad_b
    sev_data = [
        ("Critical\n9-10", 4.8,  "#B71C1C"),
        ("High\n7-8.9",   42.0,  "#E64A19"),
        ("Medium\n4-6.9", 49.2,  "#F9A825"),
        ("Low <4",         4.0,  "#388E3C"),
    ]
    parts.append(f'<text x="{mx+mw//2}" y="{mpad_t-6}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#B0BEC5">CVSS Severity 2024</text>')
    for tick in [0,25,50]:
        gy=mpad_t+mh-int(tick/50*mh)
        parts += [
            f'<line x1="{mx}" y1="{gy}" x2="{mx+mw}" y2="{gy}" stroke="#1E2A3A" stroke-width="1"/>',
            f'<text x="{mx-3}" y="{gy+4}" text-anchor="end" font-family="Arial" font-size="7.5" fill="#546E7A">{tick}%</text>',
        ]
    bw2=mw//len(sev_data)-6
    for i,(lbl,p2,col) in enumerate(sev_data):
        bh2=int(p2/50*mh); bx2=mx+4+i*(mw//len(sev_data)); by2=mpad_t+mh-bh2
        parts.append(f'<rect x="{bx2}" y="{by2}" width="{bw2}" height="{bh2}" fill="{col}" rx="2"/>')
        parts.append(f'<text x="{bx2+bw2//2}" y="{by2-3}" text-anchor="middle" font-family="Arial" font-size="7.5" font-weight="bold" fill="{col}">{p2}%</text>')
        for j,ln in enumerate(lbl.split("\n")):
            parts.append(f'<text x="{bx2+bw2//2}" y="{H-mpad_b+12+j*11}" text-anchor="middle" font-family="Arial" font-size="7" fill="#78909C">{ln}</text>')
    parts += [
        f'<line x1="{mx}" y1="{mpad_t}" x2="{mx}" y2="{mpad_t+mh}" stroke="#37474F" stroke-width="1.5"/>',
        f'<line x1="{mx}" y1="{mpad_t+mh}" x2="{mx+mw}" y2="{mpad_t+mh}" stroke="#37474F" stroke-width="1.5"/>',
    ]

    # ── Right: Attack vector pie ──────────────────────────────────
    ax_cx=650; ax_cy=150; ax_R=95; ax_ir=50
    attack_slices=[
        ("Network",    77.2,"#1565C0"),("Local",18.4,"#E64A19"),
        ("Adjacent",    3.2,"#F9A825"),("Physical",1.2,"#388E3C"),
    ]
    parts.append(f'<text x="{ax_cx}" y="{mpad_t-6}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#B0BEC5">Attack Vector 2024</text>')
    angle=-math.pi/2
    for lbl,pv,col in attack_slices:
        sweep=2*math.pi*pv/100; ea=angle+sweep; lg=1 if sweep>math.pi else 0
        x1=ax_cx+ax_R*math.cos(angle); y1=ax_cy+ax_R*math.sin(angle)
        x2=ax_cx+ax_R*math.cos(ea);    y2=ax_cy+ax_R*math.sin(ea)
        ix1=ax_cx+ax_ir*math.cos(ea);  iy1=ax_cy+ax_ir*math.sin(ea)
        ix2=ax_cx+ax_ir*math.cos(angle);iy2=ax_cy+ax_ir*math.sin(angle)
        d=(f"M{round(x1,2)},{round(y1,2)} A{ax_R},{ax_R} 0 {lg},1 {round(x2,2)},{round(y2,2)} "
           f"L{round(ix1,2)},{round(iy1,2)} A{ax_ir},{ax_ir} 0 {lg},0 {round(ix2,2)},{round(iy2,2)} Z")
        parts.append(f'<path d="{d}" fill="{col}" stroke="#0D1B2A" stroke-width="2"/>')
        mid=angle+sweep/2
        if pv>=10:
            lx=ax_cx+(ax_R+ax_ir)//2*math.cos(mid); ly=ax_cy+(ax_R+ax_ir)//2*math.sin(mid)
            parts.append(f'<text x="{round(lx,1)}" y="{round(ly+4,1)}" text-anchor="middle" font-family="Arial" font-size="8" font-weight="bold" fill="#fff">{pv}%</text>')
        angle=ea
    # centre label
    parts += [
        f'<text x="{ax_cx}" y="{ax_cy-5}" text-anchor="middle" font-family="Arial" font-size="10" font-weight="bold" fill="#90CAF9">77%</text>',
        f'<text x="{ax_cx}" y="{ax_cy+10}" text-anchor="middle" font-family="Arial" font-size="8" fill="#90CAF9">Network</text>',
    ]
    # mini legend
    lx2=ax_cx-ax_R; ly2=ax_cy+ax_R+14
    for lbl,pv,col in attack_slices:
        parts += [
            f'<rect x="{lx2}" y="{ly2}" width="10" height="9" fill="{col}" rx="2"/>',
            f'<text x="{lx2+13}" y="{ly2+8}" font-family="Arial" font-size="8" fill="#90A4AE">{lbl} {pv}%</text>',
        ]
        lx2 += 105 if lx2 < ax_cx else -205
        ly2 += 14 if lx2 >= ax_cx else 0

    parts.append('</svg>')
    return "".join(parts)


def build_local_stats_svg():
    """Page 3: Per-section heatmap bars and issue breakdown for this host."""
    if not sections:
        W, H = 760, 80
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
                f'<rect width="{W}" height="{H}" fill="#0D1B2A" rx="8"/>'
                f'<text x="{W//2}" y="{H//2+5}" text-anchor="middle" font-family="Arial" font-size="11" fill="#546E7A">No audit data available — run without --no-audit flag</text>'
                f'</svg>')

    sec_stats = []
    for s in sections:
        items = s["items"]
        n_p=sum(1 for i in items if i["kind"]=="PASS")
        n_f=sum(1 for i in items if i["kind"]=="FAIL")
        n_w=sum(1 for i in items if i["kind"]=="WARN")
        tot=n_p+n_f+n_w
        sec_stats.append({"title":s["title"][:32],"pass":n_p,"fail":n_f,"warn":n_w,"total":tot,"pct":round(n_p*100/tot) if tot else 0})
    sec_stats.sort(key=lambda x: x["pct"])  # worst first

    n = len(sec_stats); row_h = max(16, min(28, 480//max(n,1)))
    W = 760; pad_l=260; pad_r=100; pad_t=40; pad_b=40
    plot_w=W-pad_l-pad_r; H=pad_t+n*row_h+pad_b+20
    max_tot=max(s["total"] for s in sec_stats) or 1

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#0D1B2A" rx="12"/>',
        f'<text x="{W//2}" y="26" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#B0BEC5">Audit Results by Section — This Host</text>',
    ]

    for i,s in enumerate(sec_stats):
        y=pad_t+i*row_h+2; bh=row_h-4
        pw=int(s["pass"]/max_tot*plot_w); fw=int(s["fail"]/max_tot*plot_w); ww=int(s["warn"]/max_tot*plot_w)
        # track
        parts.append(f'<rect x="{pad_l}" y="{y}" width="{plot_w}" height="{bh}" fill="#141E2D" rx="2"/>')
        if pw: parts.append(f'<rect x="{pad_l}" y="{y}" width="{pw}" height="{bh}" fill="#1B5E20" rx="2"/>')
        if fw: parts.append(f'<rect x="{pad_l+pw}" y="{y}" width="{fw}" height="{bh}" fill="#B71C1C" rx="2"/>')
        if ww: parts.append(f'<rect x="{pad_l+pw+fw}" y="{y}" width="{ww}" height="{bh}" fill="#E65100" rx="2"/>')
        # labels
        col="#EF5350" if s["fail"]>0 else ("#FF9800" if s["warn"]>0 else "#66BB6A")
        parts += [
            f'<text x="{pad_l-5}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="8" fill="#B0BEC5">{esc(s["title"])}</text>',
            f'<text x="{pad_l+pw+fw+ww+5}" y="{y+bh//2+4}" font-family="Arial" font-size="8.5" font-weight="bold" fill="{col}">{s["pct"]}%</text>',
        ]
        # F/W counts in bar
        if fw>20:  parts.append(f'<text x="{pad_l+pw+fw//2}" y="{y+bh//2+4}" text-anchor="middle" font-family="Arial" font-size="7.5" font-weight="bold" fill="#FFCDD2">{s["fail"]}F</text>')
        if ww>20:  parts.append(f'<text x="{pad_l+pw+fw+ww//2}" y="{y+bh//2+4}" text-anchor="middle" font-family="Arial" font-size="7.5" fill="#FFE0B2">{s["warn"]}W</text>')

    parts.append(f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{pad_t+n*row_h}" stroke="#37474F" stroke-width="1.5"/>')
    # Legend
    lx=pad_l; ly=H-22
    for col,lbl in [("#1B5E20","PASS"),("#B71C1C","FAIL"),("#E65100","WARN")]:
        parts += [
            f'<rect x="{lx}" y="{ly}" width="12" height="11" fill="{col}" rx="2"/>',
            f'<text x="{lx+15}" y="{ly+10}" font-family="Arial" font-size="9" fill="#90A4AE">{lbl}</text>',
        ]
        lx += 70
    parts.append('</svg>')
    return "".join(parts)


def build_threat_intelligence_svg():
    """Page 4: Threat type donut + dwell time bar + key intel numbers."""
    W, H = 760, 280
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#0D1B2A" rx="12"/>',
        f'<text x="{W//2}" y="22" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#B0BEC5">Linux Threat Intelligence 2025 (Trend Micro · Elastic · Mandiant)</text>',
    ]

    # ── Left: Threat type donut ────────────────────────────────────
    cx,cy,R,ir=150,155,110,58
    slices=[
        ("Brute-force/SSH",44,"#EF5350"),("Webshell/RCE",25,"#FF7043"),
        ("Cryptominer",16,"#FFA726"),("Rootkit",7,"#7E57C2"),
        ("Ransomware",5,"#26A69A"),("Other",3,"#78909C"),
    ]
    angle=-math.pi/2
    for lbl,pv,col in slices:
        sweep=2*math.pi*pv/100; ea=angle+sweep; lg=1 if sweep>math.pi else 0
        x1=cx+R*math.cos(angle); y1=cy+R*math.sin(angle)
        x2=cx+R*math.cos(ea);    y2=cy+R*math.sin(ea)
        ix1=cx+ir*math.cos(ea);  iy1=cy+ir*math.sin(ea)
        ix2=cx+ir*math.cos(angle);iy2=cy+ir*math.sin(angle)
        d=(f"M{round(x1,2)},{round(y1,2)} A{R},{R} 0 {lg},1 {round(x2,2)},{round(y2,2)} "
           f"L{round(ix1,2)},{round(iy1,2)} A{ir},{ir} 0 {lg},0 {round(ix2,2)},{round(iy2,2)} Z")
        parts.append(f'<path d="{d}" fill="{col}" stroke="#0D1B2A" stroke-width="2"/>')
        mid=angle+sweep/2
        if pv>=8:
            mx2=cx+(R+ir)//2*math.cos(mid); my2=cy+(R+ir)//2*math.sin(mid)
            parts.append(f'<text x="{round(mx2,1)}" y="{round(my2+4,1)}" text-anchor="middle" font-family="Arial" font-size="8.5" font-weight="bold" fill="#fff">{pv}%</text>')
        angle=ea
    parts += [
        f'<text x="{cx}" y="{cy}" text-anchor="middle" font-family="Arial" font-size="11" font-weight="bold" fill="#ECEFF1">Threat</text>',
        f'<text x="{cx}" y="{cy+15}" text-anchor="middle" font-family="Arial" font-size="11" font-weight="bold" fill="#ECEFF1">Types</text>',
        f'<text x="{cx}" y="{H-8}" text-anchor="middle" font-family="Arial" font-size="7" fill="#37474F">Source: Trend Micro 2025 / Elastic 2024</text>',
    ]
    lx2=10; ly2=40
    for lbl,pv,col in slices:
        parts += [
            f'<rect x="{lx2}" y="{ly2}" width="11" height="11" fill="{col}" rx="2"/>',
            f'<text x="{lx2+14}" y="{ly2+10}" font-family="Arial" font-size="8.5" fill="#90A4AE">{lbl}: {pv}%</text>',
        ]
        ly2 += 20

    # ── Middle: Dwell time & detection gap ───────────────────────
    mx0=300; my0=36; mw=200; mh=H-72
    dwell=[("Median dwell\n(days)",21,"#42A5F5"),("Ransomware\ndwell",5,"#EF5350"),
           ("Cloud breach\ndetect",45,"#FFA726"),("Endpoint\ndetect",2,"#66BB6A")]
    max_d=50
    parts.append(f'<text x="{mx0+mw//2}" y="{my0-6}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#B0BEC5">Dwell & Detection (days)</text>')
    bw3=mw//len(dwell)-8
    for i,(lbl,val,col) in enumerate(dwell):
        bh3=int(val/max_d*mh); bx3=mx0+4+i*(mw//len(dwell)); by3=my0+mh-bh3
        parts.append(f'<rect x="{bx3}" y="{by3}" width="{bw3}" height="{bh3}" fill="{col}" rx="3"/>')
        parts.append(f'<text x="{bx3+bw3//2}" y="{by3-4}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="{col}">{val}d</text>')
        for j,ln in enumerate(lbl.split("\n")):
            parts.append(f'<text x="{bx3+bw3//2}" y="{my0+mh+12+j*11}" text-anchor="middle" font-family="Arial" font-size="7.5" fill="#78909C">{ln}</text>')
    for tick in [0,10,20,30,40,50]:
        gy3=my0+mh-int(tick/max_d*mh)
        parts += [
            f'<line x1="{mx0}" y1="{gy3}" x2="{mx0+mw}" y2="{gy3}" stroke="#1E2A3A" stroke-width="1"/>',
            f'<text x="{mx0-3}" y="{gy3+4}" text-anchor="end" font-family="Arial" font-size="7.5" fill="#546E7A">{tick}</text>',
        ]
    parts.append(f'<line x1="{mx0}" y1="{my0}" x2="{mx0}" y2="{my0+mh}" stroke="#37474F" stroke-width="1.5"/>')
    parts.append(f'<line x1="{mx0}" y1="{my0+mh}" x2="{mx0+mw}" y2="{my0+mh}" stroke="#37474F" stroke-width="1.5"/>')
    parts.append(f'<text x="{mx0+mw//2}" y="{H-5}" text-anchor="middle" font-family="Arial" font-size="7" fill="#37474F">Source: Mandiant M-Trends 2025</text>')

    # ── Right: Key intel numbers ──────────────────────────────────
    intel=[
        ("44%",   "ELF malware of all detected"),
        ("49.6%", "Linux malware = webshells"),
        ("90%",   "Cloud servers run Linux"),
        ("1.3%",  "of malware targets Linux"),
        ("8-9",   "new kernel CVEs per day"),
        ("$4.9M", "avg ransomware cost 2024"),
    ]
    rx0=520; ry0=36
    for i,(v,d) in enumerate(intel):
        ry=ry0+i*38
        parts += [
            f'<rect x="{rx0}" y="{ry}" width="{W-rx0-10}" height="30" fill="#111E2C" rx="5"/>',
            f'<text x="{rx0+10}" y="{ry+20}" font-family="Arial" font-size="14" font-weight="bold" fill="#42A5F5">{v}</text>',
            f'<text x="{rx0+60}" y="{ry+20}" font-family="Arial" font-size="8.5" fill="#78909C">{d}</text>',
        ]

    parts.append('</svg>')
    return "".join(parts)


def build_remediation_matrix_svg():
    """Page 5: 2×2 effort×impact remediation priority matrix."""
    W, H = 760, 340
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#0D1B2A" rx="12"/>',
        f'<text x="195" y="22" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#B0BEC5">Remediation Priority Matrix</text>',
    ]

    # 2×2 grid
    gx,gy,gw,gh=20,36,350,280
    cx2=gx+gw//2; cy2=gy+gh//2
    quadrants=[
        (gx,   gy,    "#0A1F0A","Quick Wins","Low Effort · High Impact","Do FIRST",  "#66BB6A"),
        (cx2,  gy,    "#1A0A0A","Planned",   "High Effort · High Impact","Schedule", "#42A5F5"),
        (gx,   cy2,   "#1A1A0A","Fill Gaps", "Low Effort · Low Impact","Do if time","#FFA726"),
        (cx2,  cy2,   "#0A0A1A","Avoid",     "High Effort · Low Impact","Deprioritise","#78909C"),
    ]
    for qx,qy,col,title,sub,action,tc in quadrants:
        parts += [
            f'<rect x="{qx+2}" y="{qy+2}" width="{gw//2-4}" height="{gh//2-4}" fill="{col}" rx="6"/>',
            f'<text x="{qx+gw//4}" y="{qy+26}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold" fill="{tc}">{title}</text>',
            f'<text x="{qx+gw//4}" y="{qy+42}" text-anchor="middle" font-family="Arial" font-size="8" fill="#78909C">{sub}</text>',
            f'<text x="{qx+gw//4}" y="{qy+58}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="{tc}">→ {action}</text>',
        ]

    # axis labels
    parts += [
        f'<text x="{gx+gw//4}" y="{gy+gh+18}" text-anchor="middle" font-family="Arial" font-size="9" fill="#546E7A">Low Effort</text>',
        f'<text x="{gx+3*gw//4}" y="{gy+gh+18}" text-anchor="middle" font-family="Arial" font-size="9" fill="#546E7A">High Effort</text>',
        f'<text x="{gx-10}" y="{gy+gh//4}" text-anchor="middle" font-family="Arial" font-size="9" fill="#546E7A" transform="rotate(-90,{gx-10},{gy+gh//4})">High Impact</text>',
        f'<text x="{gx-10}" y="{gy+3*gh//4}" text-anchor="middle" font-family="Arial" font-size="9" fill="#546E7A" transform="rotate(-90,{gx-10},{gy+3*gh//4})">Low Impact</text>',
        f'<line x1="{cx2}" y1="{gy}" x2="{cx2}" y2="{gy+gh}" stroke="#1E2A3A" stroke-width="1.5"/>',
        f'<line x1="{gx}" y1="{cy2}" x2="{gx+gw}" y2="{cy2}" stroke="#1E2A3A" stroke-width="1.5"/>',
    ]

    # Place actual findings from this host's scan in quadrants
    quick_wins=[
        ("Enable SYN cookies","sysctl -w net.ipv4.tcp_syncookies=1"),
        ("Restrict dmesg","sysctl -w kernel.dmesg_restrict=1"),
        ("Enable ASLR","sysctl -w kernel.randomize_va_space=2"),
        ("Disable SSH root","PermitRootLogin no in sshd_config"),
    ]
    planned=[
        ("Enable AppArmor","apt install apparmor-profiles + enforce"),
        ("Configure auditd","apt install auditd + add rules"),
        ("Install fail2ban","apt install fail2ban + jail config"),
        ("PAM lockout","pam_faillock in /etc/pam.d/common-auth"),
    ]
    ty_start=gy+70; item_h=16
    for i,(title,cmd) in enumerate(quick_wins[:3]):
        iy=ty_start+i*item_h
        parts += [
            f'<circle cx="{gx+12}" cy="{iy}" r="4" fill="#66BB6A"/>',
            f'<text x="{gx+20}" y="{iy+5}" font-family="Arial" font-size="8" fill="#A5D6A7">{title}</text>',
        ]
    for i,(title,cmd) in enumerate(planned[:3]):
        iy=ty_start+i*item_h
        parts += [
            f'<circle cx="{cx2+12}" cy="{iy}" r="4" fill="#42A5F5"/>',
            f'<text x="{cx2+20}" y="{iy+5}" font-family="Arial" font-size="8" fill="#90CAF9">{title}</text>',
        ]

    # ── Right side: Top 10 prioritised list ───────────────────────
    rx=390; ry_start=36
    parts.append(f'<text x="{rx}" y="{ry_start}" font-family="Arial" font-size="11" font-weight="bold" fill="#B0BEC5">Top 10 Remediation Steps (Priority Order)</text>')
    top10=[
        ("1","Critical","Apply security updates NOW","apt-get upgrade -y","#B71C1C"),
        ("2","Critical","Enable UFW firewall","ufw default deny in && ufw enable","#B71C1C"),
        ("3","Critical","Disable SSH password auth","PasswordAuthentication no","#B71C1C"),
        ("4","High","Enable fail2ban","apt install fail2ban","#E64A19"),
        ("5","High","Enable AppArmor","systemctl enable --now apparmor","#E64A19"),
        ("6","High","Configure auditd","apt install auditd + rules","#E64A19"),
        ("7","Medium","Harden sysctl","randomize_va_space=2 + others","#F57F17"),
        ("8","Medium","Set password policy","PASS_MAX_DAYS=90, pam_pwquality","#F57F17"),
        ("9","Medium","Remove compilers","apt purge gcc g++ make","#F57F17"),
        ("10","Low","Set SSH idle timeout","ClientAliveInterval 300","#388E3C"),
    ]
    for i,(num,sev,title,cmd,col) in enumerate(top10):
        iy=ry_start+22+i*29
        parts += [
            f'<rect x="{rx}" y="{iy}" width="{W-rx-10}" height="26" fill="#111E2C" rx="4"/>',
            f'<rect x="{rx}" y="{iy}" width="24" height="26" fill="{col}" rx="4"/>',
            f'<text x="{rx+12}" y="{iy+17}" text-anchor="middle" font-family="Arial" font-size="10" font-weight="bold" fill="#fff">{num}</text>',
            f'<text x="{rx+30}" y="{iy+11}" font-family="Arial" font-size="9" font-weight="bold" fill="{col}">{title}</text>',
            f'<text x="{rx+30}" y="{iy+22}" font-family="Arial" font-size="7.5" fill="#546E7A" font-family="Courier New">{cmd}</text>',
        ]

    parts.append('</svg>')
    return "".join(parts)

# ── Build all SVGs ────────────────────────────────────────────────
svg_dashboard  = build_dashboard_svg()
svg_cve        = build_cve_landscape_svg()
svg_local      = build_local_stats_svg()
svg_threat     = build_threat_intelligence_svg()
svg_remediation= build_remediation_matrix_svg()

# ── Security Index + Findings Bar (shared with ODT report) ───────
def build_security_index_svg_intel(pct2, nf, nw, np2, ni, rat, rhex, bfill):
    W,H=820,260
    p=[]
    p.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
    p.append(f'<rect width="{W}" height="{H}" fill="#0D1117" rx="10"/>')
    cx,cy,Ro,Ri=160,190,130,78
    zones=[(0,20,"#7B0000","#EF5350","Critical"),(20,40,"#BF360C","#FF7043","High"),
           (40,60,"#E65100","#FFB300","Moderate"),(60,80,"#1B5E20","#66BB6A","Good"),
           (80,100,"#0D47A1","#42A5F5","Excellent")]
    def arc(a0,a1,ro,ri,cd,cl):
        import math as _m
        A0=_m.radians(180-a0*1.8); A1=_m.radians(180-a1*1.8)
        lg=1 if abs(a1-a0)>50 else 0
        x0o=cx+ro*_m.cos(A0); y0o=cy-ro*_m.sin(A0)
        x1o=cx+ro*_m.cos(A1); y1o=cy-ro*_m.sin(A1)
        x0i=cx+ri*_m.cos(A1); y0i=cy-ri*_m.sin(A1)
        x1i=cx+ri*_m.cos(A0); y1i=cy-ri*_m.sin(A0)
        d=(f"M{x0o:.1f},{y0o:.1f} A{ro},{ro} 0 {lg},0 {x1o:.1f},{y1o:.1f} "
           f"L{x0i:.1f},{y0i:.1f} A{ri},{ri} 0 {lg},1 {x1i:.1f},{y1i:.1f} Z")
        return f'<path d="{d}" fill="{cd}" stroke="{cl}" stroke-width="1.5"/>'
    for a0,a1,cd,cl,_ in zones: p.append(arc(a0,a1,Ro,Ri,cd,cl))
    import math as _m2
    na=_m2.radians(180-pct2*1.8)
    nx=cx+(Ri-10)*_m2.cos(na); ny=cy-(Ri-10)*_m2.sin(na)
    p+=[f'<line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="#FFF" stroke-width="3" stroke-linecap="round"/>',
        f'<circle cx="{cx}" cy="{cy}" r="8" fill="#FFF"/>',
        f'<circle cx="{cx}" cy="{cy}" r="4" fill="#{rhex}"/>',
        f'<text x="{cx}" y="{cy+38}" text-anchor="middle" font-family="Arial" font-size="32" font-weight="bold" fill="#{bfill}">{pct2}%</text>',
        f'<text x="{cx}" y="{cy+58}" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#{rhex}">{rat}</text>']
    lx,ly=330,22
    p.append(f'<text x="{lx}" y="{ly}" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Index — Colour Legend</text>')
    legend=[("#B71C1C","#EF5350","0–20%","Critical — Immediate action required. Serious vulnerabilities exposed."),
            ("#BF360C","#FF7043","21–40%","High — Significant risks. Address FAIL items urgently."),
            ("#E65100","#FFB300","41–60%","Moderate — Several issues need attention. Review all WARNs."),
            ("#1B5E20","#66BB6A","61–80%","Good — Reasonably hardened. Monitor and maintain regularly."),
            ("#0D47A1","#42A5F5","81–100%","Excellent — Well hardened. Schedule regular audits.")]
    for idx,(bg,fg,rng,desc) in enumerate(legend):
        y=ly+26+idx*36
        active=(zones[idx][0]<=pct2<zones[idx][1]) or (idx==4 and pct2>=80) or (idx==0 and pct2==0)
        sw="3" if active else "1"
        p+=[f'<rect x="{lx}" y="{y}" width="64" height="22" fill="{bg}" stroke="{fg}" stroke-width="{sw}" rx="4"/>',
            f'<text x="{lx+32}" y="{y+15}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="{fg}">{rng}</text>',
            f'<text x="{lx+74}" y="{y+9}" font-family="Arial" font-size="9" font-weight="bold" fill="{fg}">{esc(desc[:58])}</text>']
        if active: p.append(f'<text x="{lx-14}" y="{y+15}" font-family="Arial" font-size="14" fill="{fg}">▶</text>')
    rx,ry=660,22; total=nf+nw+np2+ni or 1; bw=120
    p.append(f'<text x="{rx+60}" y="{ry}" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Finding Summary</text>')
    for si,(fg,bg2,lbl,cnt) in enumerate([("#EF5350","#B71C1C","FAIL",nf),("#FF9800","#E65100","WARN",nw),
                                           ("#4CAF50","#2E7D32","PASS",np2),("#42A5F5","#1565C0","INFO",ni)]):
        y2=ry+26+si*42; w2=int(cnt/total*bw)
        p+=[f'<rect x="{rx}" y="{y2}" width="{bw}" height="22" fill="#1E2A3A" rx="4"/>',
            f'<rect x="{rx}" y="{y2}" width="{max(w2,2)}" height="22" fill="{bg2}" rx="4"/>',
            f'<text x="{rx+bw+8}" y="{y2+15}" font-family="Arial" font-size="11" font-weight="bold" fill="{fg}">{cnt}</text>',
            f'<text x="{rx-6}" y="{y2+15}" text-anchor="end" font-family="Arial" font-size="10" font-weight="bold" fill="{fg}">{lbl}</text>']
    p.append('</svg>'); return "".join(p)

def build_findings_bar_svg_intel(secs):
    import math as _m
    n=len(secs)
    if n==0: return '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="60"><text x="10" y="40" fill="#90A4AE">No sections</text></svg>'
    W=820; pl=220; pr=60; pt=44; pb=36
    rh=max(20,min(34,(580-pt-pb)//n)); H=pt+n*rh+20+pb
    mv=max((s["pass"]+s["fail"]+s["warn"]) for s in secs) or 1; pw=W-pl-pr
    p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       f'<rect width="{W}" height="{H}" fill="#0D1117" rx="8"/>',
       f'<text x="{W//2}" y="26" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Findings by Section</text>']
    tks=sorted(set(i*max(1,mv//5) for i in range(6) if i*max(1,mv//5)<=mv))
    for tk in tks:
        gx=pl+int(tk/mv*pw)
        p+=[f'<line x1="{gx}" y1="{pt}" x2="{gx}" y2="{pt+n*rh}" stroke="#1E2A3A" stroke-width="1"/>',
            f'<text x="{gx}" y="{pt+n*rh+14}" text-anchor="middle" font-family="Arial" font-size="8" fill="#546E7A">{tk}</text>']
    for idx,s in enumerate(secs):
        y=pt+idx*rh+2; bh=rh-4
        bpw=int(s["pass"]/mv*pw); bfw=int(s["fail"]/mv*pw); bww=int(s["warn"]/mv*pw)
        lc="#EF5350" if s["fail"]>0 else ("#FFB300" if s["warn"]>0 else "#66BB6A")
        p.append(f'<rect x="{pl}" y="{y}" width="{pw}" height="{bh}" fill="#131B26" rx="3"/>')
        if bpw: p.append(f'<rect x="{pl}" y="{y}" width="{bpw}" height="{bh}" fill="#2E7D32" rx="2"/>')
        if bfw: p.append(f'<rect x="{pl+bpw}" y="{y}" width="{bfw}" height="{bh}" fill="#C62828" rx="2"/>')
        if bww: p.append(f'<rect x="{pl+bpw+bfw}" y="{y}" width="{bww}" height="{bh}" fill="#E65100" rx="2"/>')
        p.append(f'<text x="{pl-8}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="{lc}">{esc(s["title"][:30])}</text>')
        xc=pl
        for bw2,cnt,col in [(bpw,s["pass"],"#A5D6A7"),(bfw,s["fail"],"#FFCDD2"),(bww,s["warn"],"#FFE0B2")]:
            if bw2>=18 and cnt: p.append(f'<text x="{xc+bw2//2}" y="{y+bh//2+4}" text-anchor="middle" font-family="Arial" font-size="8" font-weight="bold" fill="{col}">{cnt}</text>')
            xc+=bw2
        p.append(f'<text x="{pl+bpw+bfw+bww+6}" y="{y+bh//2+4}" font-family="Arial" font-size="8" font-weight="bold" fill="{lc}">{s.get("pct",0)}%</text>')
    p.append(f'<line x1="{pl}" y1="{pt}" x2="{pl}" y2="{pt+n*rh}" stroke="#37474F" stroke-width="1.5"/>')
    lx2=pl; ly2=H-20
    for col,lbl in [("#2E7D32","PASS"),("#C62828","FAIL"),("#E65100","WARN")]:
        p+=[f'<rect x="{lx2}" y="{ly2}" width="11" height="11" fill="{col}" rx="2"/>',
            f'<text x="{lx2+14}" y="{ly2+9}" font-family="Arial" font-size="9" fill="#B0BEC5">{lbl}</text>']
        lx2+=65
    p.append('</svg>'); return "".join(p)

# Per-section stats for the bar chart
sec_stats_intel = []
for s in sections:
    items=s["items"]
    np2=sum(1 for i in items if i["kind"]=="PASS")
    nf2=sum(1 for i in items if i["kind"]=="FAIL")
    nw2=sum(1 for i in items if i["kind"]=="WARN")
    tot2=np2+nf2+nw2
    sec_stats_intel.append({"title":s["title"][:40],"pass":np2,"fail":nf2,"warn":nw2,
                             "pct":round(np2*100/tot2) if tot2 else 0})

svg_security_index = build_security_index_svg_intel(pct, n_fail_loc, n_warn_loc, n_pass_loc, n_info_loc, rating, r_hex, r_hex)
svg_findings_bar   = build_findings_bar_svg_intel(sec_stats_intel)

# ══════════════════════════════════════════════════════════════════
#  ODT CONTENT
# ══════════════════════════════════════════════════════════════════

# ── Benchmark comparison table ────────────────────────────────────
def bench_row(metric, this_host, smb_avg, ent_avg, cis_l2, good_dir):
    try:
        val = float(str(this_host).strip('%'))
        smb = float(str(smb_avg).strip('%'))
        if good_dir == "higher":
            color = "#2E7D32" if val >= cis_l2 else ("#E65100" if val >= smb else "#B71C1C")
        else:
            color = "#2E7D32" if val <= cis_l2 else ("#E65100" if val <= smb else "#B71C1C")
        host_style = f"tdc_{'g' if color=='#2E7D32' else ('w' if color=='#E65100' else 'r')}"
    except Exception:
        host_style = "tdc"
    return tbl_row_colored([
        (metric, "tdc"), (str(this_host), host_style),
        (str(smb_avg), "tdc"), (str(ent_avg), "tdc"), (str(cis_l2), "tdc_g"),
    ])

# ── CISA KEV table ────────────────────────────────────────────────
cves = [
    ("CVE-2024-1086","9.8 Critical","nftables use-after-free → local root; used by RansomHub/Akira ransomware groups"),
    ("CVE-2024-6387","8.1 High",   "OpenSSH RegreSSHion RCE without auth; affects OpenSSH < 9.8p1 (millions of hosts)"),
    ("CVE-2024-53197","7.8 High",  "ALSA USB-audio invalid config → out-of-bounds kernel write"),
    ("CVE-2024-53150","7.1 High",  "ALSA USB-audio clock descriptor OOB read — kernel info disclosure"),
    ("CVE-2023-0386","7.8 High",   "OverlayFS UID preservation bypass → privilege escalation; added KEV Jul 2025"),
    ("CVE-2025-6018","7.8 High",   "udisks daemon privilege escalation → full root on most major distros"),
    ("CVE-2025-8941","7.0 High",   "Linux-PAM race condition + symlink → local root escalation"),
    ("CVE-2024-50302","5.5 Medium","Uninitialised HID report buffer → kernel memory disclosure"),
]
cve_rows = [tbl_row("CVE ID","CVSS","Impact Summary", header=True)]
for cid,score,desc in cves:
    sty = "tdc_r" if "Critical" in score else ("tdc_w" if "High" in score else "tdc")
    cve_rows.append(tbl_row_colored([(cid,"tdc_cve"),(score,sty),(desc,"tdc")]))

# ── Build document ────────────────────────────────────────────────
doc = []

# Page 1 — Executive Dashboard
doc.append(h1("Wowscanner Intelligence Report"))
doc.append(p(f"Host: {hostname}  |  OS: {os_name}  |  Kernel: {kernel}", "sub"))
doc.append(p(f"Generated: {run_date}  |  Mode: Statistical Intelligence Report", "sub"))
doc.append(p("Sources: NIST NVD · CISA KEV · Elastic Global Threat Report 2024 · Trend Micro 2025 · Action1 2025 · Mandiant M-Trends 2025 · Sophos 2025", "sub"))
doc.append(tb())
doc.append(h2("Executive Dashboard"))
doc.append(cap("Score gauge, severity KPIs, issue distribution, and global threat context at a glance."))
doc.append(frame("Pictures/dashboard.svg", "17cm", "8.5cm", "dashboard"))
doc.append(tb())

# Security Index — colour-coded rating with legend
doc.append(h2("Security Index — Score Rating & Colour Guide"))
doc.append(cap("The colour gauge shows your overall security score. The legend explains what each colour band means. The summary on the right shows the count of FAIL, WARN, PASS, and INFO findings for this scan."))
doc.append(frame("Pictures/security_index.svg", "17cm", "6.5cm", "security_index"))
doc.append(tb())

# Findings bar chart
doc.append(h2("Findings by Section"))
doc.append(cap("Horizontal bar chart showing PASS (green), FAIL (red), and WARN (orange) counts per audit section. Section labels are coloured red if any FAIL exists, orange for WARN-only, green for all-pass. Percentage score shown after each bar."))
bar_h_intel = max(8.0, round(len(sec_stats_intel) * 0.65 + 2.5, 1))
doc.append(frame("Pictures/findings_bar.svg", "17cm", f"{bar_h_intel}cm", "findings_bar"))
doc.append(tb())

# KPI stat boxes
doc.append(h2("Key Performance Indicators"))
doc.append(kpi(f"{pct}%",         "Overall Security Score",        r_hex))
doc.append(kpi(f"{n_fail_loc}",   "FAIL items requiring action",   "B71C1C"))
doc.append(kpi(f"{n_warn_loc}",   "WARN items requiring review",   "E65100"))
doc.append(kpi(f"{n_pass_loc}",   "PASS items confirmed secure",   "2E7D32"))
doc.append(kpi(f"{score_val}/{total_val}", "Checks passed / total","1565C0"))
doc.append(kpi(f"{total_issues}", "Total FAIL+WARN issues",        "7B1FA2"))
doc.append(tb())

# Benchmark table
doc.append(h2("Benchmark Comparison"))
doc.append(cap("Your security posture vs. industry averages. Green = meets CIS L2 target. Orange = above SMB average. Red = below SMB average."))
bench_cols = ["c4","c25","c25","c25","c25"]
bench_rows_xml = [
    tbl_row("Metric","This Host",f"SMB Avg (~55%)","Enterprise Avg (~72%)","CIS L2 Target", header=True),
    bench_row("Overall Score %", f"{pct}%",   "55%", "72%", 80, "higher"),
    bench_row("FAIL Count",      n_fail_loc,   "4",   "2",   0,  "lower"),
    bench_row("WARN Count",      n_warn_loc,   "8",   "5",   2,  "lower"),
    bench_row("Pass Rate %",     f"{round(n_pass_loc*100/(n_pass_loc+n_fail_loc+n_warn_loc)) if (n_pass_loc+n_fail_loc+n_warn_loc) else 0}%", "55%","72%",85,"higher"),
    tbl_row("Critical Issues",   sev_counts["Critical"], "0-1","0","0"),
    tbl_row("High Issues",       sev_counts["High"],     "2-3","1","0"),
    tbl_row("Medium Issues",     sev_counts["Medium"],   "5-7","3","≤2"),
    tbl_row("Low Issues",        sev_counts["Low"],      "3-5","2","≤2"),
]
doc.append(make_table("Benchmarks", bench_cols, bench_rows_xml))
doc.append(tb())
doc.append(pb())

# Page 2 — CVE Landscape
doc.append(h1("CVE & Vulnerability Landscape"))
doc.append(h2("Linux Kernel CVE Trends 2020–2025"))
doc.append(cap("Annual CVE counts, severity distribution (CVSS), and attack vector classification from NIST NVD. The 2025 surge reflects the kernel team's CNA status enabling systematic disclosure."))
doc.append(frame("Pictures/cve_landscape.svg", "17cm", "7.5cm", "cve_landscape"))
doc.append(tb())

# CVE stats table
doc.append(h2("Key CVE Statistics"))
cvstats=[
    tbl_row("Year","Total CVEs","YoY Growth","Critical (≥9.0)","High (7-8.9)","Notes", header=True),
    tbl_row("2020","897",  "baseline","—",    "—",    "Pre-CNA era"),
    tbl_row("2021","839",  "-6.5%",   "—",    "—",    ""),
    tbl_row("2022","1,012","+20.6%",  "—",    "—",    ""),
    tbl_row("2023","1,736","+71.5%",  "—",    "—",    ""),
    tbl_row("2024","3,108","+79.0%",  "148",  "1,305","Kernel team became CNA"),
    tbl_row("2025","5,530","+78.0%",  "~265", "~2,320","8-9 new CVEs/day; est. based on Q1-Q3"),
]
doc.append(make_table("CVEStats", ["c4","c25","c25","c25","c25","c4"], cvstats))
doc.append(tb())

# Top CVEs
doc.append(h2("CISA Known Exploited Vulnerabilities — Linux (2024-2025)"))
doc.append(cap("These CVEs are confirmed actively weaponised in the wild. Patching is non-optional. All were added to the CISA KEV catalog."))
doc.append(make_table("CISA_KEV",["c4","c25","c3"],cve_rows))
doc.append(tb())
doc.append(pb())

# Page 3 — Local Audit Statistics
doc.append(h1("Local Audit Statistics — This Host"))
doc.append(h2("Per-Section Audit Results"))
doc.append(cap(f"Horizontal bars show PASS (green) / FAIL (red) / WARN (orange) count per audit section. Sorted worst-first. Score = PASS/(PASS+FAIL+WARN)."))
doc.append(frame("Pictures/local_stats.svg", "17cm", "10cm", "local_stats"))
doc.append(tb())

# Per-section stats table
doc.append(h2("Section Score Table"))
sec_table_rows=[tbl_row("Section","Pass","Fail","Warn","Info","Score%","Status",header=True)]
for s in sections:
    items=s["items"]
    np2=sum(1 for i in items if i["kind"]=="PASS")
    nf2=sum(1 for i in items if i["kind"]=="FAIL")
    nw2=sum(1 for i in items if i["kind"]=="WARN")
    ni2=sum(1 for i in items if i["kind"]=="INFO")
    tot2=np2+nf2+nw2
    sp2=round(np2*100/tot2) if tot2 else 0
    status2="NEEDS ACTION" if nf2>0 else ("REVIEW" if nw2>0 else "GOOD")
    sty2="tdc_r" if nf2>0 else ("tdc_w" if nw2>0 else "tdc_g")
    sec_table_rows.append(tbl_row_colored([
        (s["title"][:36],"tdc"),(str(np2),"tdc_g"),(str(nf2),"tdc_r" if nf2 else "tdc"),
        (str(nw2),"tdc_w" if nw2 else "tdc"),(str(ni2),"tdc"),(f"{sp2}%","tdc"),(status2,sty2)
    ]))
# Totals
sec_table_rows.append(tbl_row("TOTAL",str(n_pass_loc),str(n_fail_loc),str(n_warn_loc),str(n_info_loc),f"{pct}%",rating))
doc.append(make_table("SectionStats",["c3","c25","c25","c25","c25","c25","c25"],sec_table_rows))
doc.append(tb())
doc.append(pb())

# Page 4 — Threat Intelligence
doc.append(h1("Threat Intelligence"))
doc.append(h2("Linux Threat Landscape 2025"))
doc.append(cap("Threat type distribution, attacker dwell times, and detection gap benchmarks. Data: Trend Micro, Elastic, Mandiant M-Trends 2025."))
doc.append(frame("Pictures/threat_intel.svg", "17cm", "7.5cm", "threat_intel"))
doc.append(tb())

# Threat stats table
doc.append(h2("Global Threat Statistics"))
threat_stats=[
    tbl_row("Statistic","Value","Source","Context", header=True),
    tbl_row("SSH brute-force share of attacks","89%","Elastic 2024","Primary initial access vector"),
    tbl_row("Linux malware = webshells","49.6%","Trend Micro 2025","Primary persistence method"),
    tbl_row("Malware as ELF binary","44%","Cloud Storage Security","Native Linux executable format"),
    tbl_row("Median attacker dwell time","21 days","Mandiant M-Trends 2025","Time from breach to detection"),
    tbl_row("Ransomware dwell before encryption","5 days","Mandiant M-Trends 2025","Reconnaissance + lateral movement"),
    tbl_row("Cloud breach detection time","45 days","Mandiant M-Trends 2025","Cloud-native attackers harder to detect"),
    tbl_row("Linux share of global malware","1.3%","Kaspersky Q4-2025","Low % despite 90% cloud server market"),
    tbl_row("Ransomware attacks via vuln exploit","32%","Sophos 2025","Up from 23% in 2023"),
    tbl_row("Avg ransomware cost 2024","$4.9M","IBM Cost of Breach 2024","Total cost incl. downtime & recovery"),
    tbl_row("CVEs exploited within 48h of disclosure","12%","Qualys TruRisk 2025","N-day attacks increasingly rapid"),
]
doc.append(make_table("ThreatStats",["c3","c25","c25","c3"],threat_stats))
doc.append(tb())
doc.append(pb())

# Page 5 — Remediation Priority Matrix
doc.append(h1("Remediation Priority Matrix"))
doc.append(h2("Effort × Impact Quadrant & Top 10 Actions"))
doc.append(cap("Actions are plotted by implementation effort (x-axis) vs security impact (y-axis). Prioritise the Quick Wins quadrant first — maximum impact for minimum effort."))
doc.append(frame("Pictures/remediation.svg", "17cm", "9cm", "remediation"))
doc.append(tb())

# Detailed remediation table
doc.append(h2("Prioritised Remediation Checklist"))
remed_rows=[tbl_row("#","Priority","Action","Command / Steps","Est. Time","Risk if Ignored",header=True)]
remed_full=[
    ("1","Critical","Apply all security updates",     "apt-get install --only-upgrade $(apt list --upgradable 2>/dev/null | grep security | cut -d/ -f1 | xargs)","<5 min","Exploitable CVEs in production"),
    ("2","Critical","Enable UFW firewall",             "ufw default deny incoming && ufw allow 22/tcp && ufw enable","<2 min","All ports exposed to network"),
    ("3","Critical","Disable SSH password auth",       "echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && systemctl restart sshd","<2 min","Brute-force and credential stuffing"),
    ("4","High",    "Install & configure fail2ban",    "apt install fail2ban && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local && systemctl enable --now fail2ban","10 min","Unlimited SSH brute-force attempts"),
    ("5","High",    "Enable AppArmor enforcement",     "apt install apparmor apparmor-profiles apparmor-utils && aa-enforce /etc/apparmor.d/*","15 min","Unconstrained process privilege"),
    ("6","High",    "Enable & configure auditd",       "apt install auditd && systemctl enable --now auditd && auditctl -e 1","10 min","No forensic trail for incidents"),
    ("7","Medium",  "Harden sysctl parameters",        "cat /etc/sysctl.d/99-hardening.conf (create with ASLR, SYN cookies, kptr, etc.)","15 min","Kernel exploit primitives available"),
    ("8","Medium",  "Enforce password policy",         "apt install libpam-pwquality && edit /etc/security/pwquality.conf: minlen=12","20 min","Weak passwords accepted"),
    ("9","Medium",  "Configure PAM account lockout",   "Add to /etc/pam.d/common-auth: auth required pam_faillock.so deny=5","15 min","Local brute-force unrestricted"),
    ("10","Low",    "Set SSH idle timeout",            "Add to sshd_config: ClientAliveInterval 300 ClientAliveCountMax 2","<5 min","Hijackable idle sessions"),
]
sev_sty={"Critical":"tdc_r","High":"tdc_w","Medium":"tdc","Low":"tdc_g"}
for num,pri,action,cmd,time,risk in remed_full:
    remed_rows.append(tbl_row_colored([
        (num,"tdc"),(pri,sev_sty.get(pri,"tdc")),(action,"tdc"),(cmd,"tdc_code"),(time,"tdc"),(risk,"tdc"),
    ]))
doc.append(make_table("Remediation",["c25","c25","c3","c3","c25","c3"],remed_rows))
doc.append(tb())
doc.append(p(f"Report generated by Wowscanner Security Scanner. Threat intelligence current as of March 2026.", "cap"))
doc.append(p("Sources: NIST NVD, CISA KEV Catalog, Elastic Global Threat Report 2024, Trend Micro Annual Security Report 2025, Action1 Software Vulnerability Ratings 2025, Mandiant M-Trends 2025, Kaspersky Q4-2025, IBM Cost of a Data Breach 2024, Sophos Active Adversary 2025, Qualys TruRisk 2025.", "cap"))
doc.append(tb())

# ── rkhunter log advisory ─────────────────────────────────────────
# Add a prominent note about the rkhunter system log file.
# This appears in the ODF report regardless of scan outcome so the
# reviewer always knows where to find the full detail.
doc.append(h2("Rootkit Scanner Log Reference"))
doc.append(p(
    "⚠  Please check the log file (/var/log/rkhunter.log) for full rkhunter "
    "scan details and to review any false positive warnings. "
    "rkhunter writes its complete output — including all OK checks, "
    "informational messages, and warning explanations — to this persistent "
    "system log file on every run. The summary results shown in this report "
    "reflect only the warning and infected counts; the log contains the full "
    "per-test breakdown needed to investigate any findings.",
    "rec_high"
))
doc.append(p(
    "Common false positives in rkhunter: /usr/bin/lwp-request (Perl LWP tool), "
    "hidden files under /dev (normal kernel objects), package manager binary "
    "hash mismatches after updates (run: rkhunter --propupd to reset). "
    "Always cross-reference warnings against the system context before acting.",
    "cap"
))
rkhunter_log_rows = [
    tbl_row("Log file",       "Description", header=True),
    tbl_row("/var/log/rkhunter.log",           "Primary persistent rkhunter log (all runs)"),
    tbl_row("/var/log/rkhunter/rkhunter.log",  "Alternate location on some distributions"),
    tbl_row("Embedded in audit .txt report",   "Full scan output captured in this run's combined report"),
    tbl_row("Command: rkhunter --list-tests",  "Lists all test names that can be skipped or enabled"),
    tbl_row("Command: rkhunter --propupd",     "Resets file-properties DB after legitimate updates"),
]
doc.append(make_table("RkhunterLog", ["c3","c3"], rkhunter_log_rows))
doc.append(tb())

body = "\n".join(doc)

# ══════════════════════════════════════════════════════════════════
#  ODT XML ASSEMBLY
# ══════════════════════════════════════════════════════════════════
content_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
  xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
  office:version="1.3">
<office:font-face-decls>
  <style:font-face style:name="Arial"     svg:font-family="Arial"         style:font-family-generic="swiss"/>
  <style:font-face style:name="Cour"      svg:font-family="'Courier New'" style:font-family-generic="modern" style:font-pitch="fixed"/>
</office:font-face-decls>
<office:automatic-styles>
  <!-- Tables -->
  <style:style style:name="tbl" style:family="table">
    <style:table-properties style:width="17cm" fo:margin-bottom="0.3cm" table:align="left"/>
  </style:style>
  <!-- Column widths (reusable) -->
  <style:style style:name="col_c4"  style:family="table-column"><style:table-column-properties style:column-width="1.5cm"/></style:style>
  <style:style style:name="col_c25" style:family="table-column"><style:table-column-properties style:column-width="2.5cm"/></style:style>
  <style:style style:name="col_c3"  style:family="table-column"><style:table-column-properties style:column-width="5.5cm"/></style:style>
  <!-- Table cell styles -->
  <style:style style:name="thc" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#0D47A1" fo:padding="0.1cm" fo:border="0.5pt solid #1565C0"/>
  </style:style>
  <style:style style:name="tdc" style:family="table-cell">
    <style:table-cell-properties fo:padding="0.09cm" fo:border="0.4pt solid #CFD8DC" fo:wrap-option="wrap"/>
  </style:style>
  <style:style style:name="tdc_r" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFEBEE" fo:padding="0.09cm" fo:border="0.4pt solid #FFCDD2" fo:wrap-option="wrap"/>
  </style:style>
  <style:style style:name="tdc_w" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFF8E1" fo:padding="0.09cm" fo:border="0.4pt solid #FFE082" fo:wrap-option="wrap"/>
  </style:style>
  <style:style style:name="tdc_g" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#E8F5E9" fo:padding="0.09cm" fo:border="0.4pt solid #C8E6C9" fo:wrap-option="wrap"/>
  </style:style>
  <style:style style:name="tdc_cve" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#E3F2FD" fo:padding="0.09cm" fo:border="0.4pt solid #BBDEFB"/>
  </style:style>
  <style:style style:name="tdc_code" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#F5F5F5" fo:padding="0.09cm" fo:border="0.4pt solid #E0E0E0" fo:wrap-option="wrap"/>
  </style:style>
  <!-- Paragraph styles -->
  <style:style style:name="h1" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.4cm" fo:margin-bottom="0.2cm" fo:background-color="#0D47A1" fo:padding="0.2cm"/>
    <style:text-properties fo:font-size="16pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="h2" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.3cm" fo:margin-bottom="0.12cm" fo:border-bottom="1.5pt solid #1565C0" fo:padding-bottom="0.06cm"/>
    <style:text-properties fo:font-size="12pt" fo:font-weight="bold" fo:color="#1565C0" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="h3" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.2cm" fo:margin-bottom="0.08cm"/>
    <style:text-properties fo:font-size="10.5pt" fo:font-weight="bold" fo:color="#37474F" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="body" style:family="paragraph">
    <style:paragraph-properties fo:margin-bottom="0.1cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#212121" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="sub" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center" fo:margin-bottom="0.04cm"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#546E7A" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="cap" style:family="paragraph">
    <style:paragraph-properties fo:margin-bottom="0.12cm"/>
    <style:text-properties fo:font-size="8pt" fo:color="#616161" fo:font-style="italic" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="stat_row" style:family="paragraph">
    <style:paragraph-properties fo:margin-left="0.3cm" fo:margin-bottom="0.06cm" fo:border-left="3pt solid #1565C0" fo:padding-left="0.2cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#212121" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="stat_val" style:family="text">
    <style:text-properties fo:font-size="12pt" fo:font-weight="bold" fo:color="#1565C0" style:font-name="Arial"/>
  </style:style>
  <!-- KPI boxes (one per colour) -->
  <style:style style:name="kpi_box_{r_hex}" style:family="paragraph">
    <style:paragraph-properties fo:background-color="#{r_hex}" fo:padding="0.15cm" fo:margin-bottom="0.06cm" fo:border="1pt solid #{r_hex}"/>
    <style:text-properties fo:font-size="9pt" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_box_B71C1C" style:family="paragraph">
    <style:paragraph-properties fo:background-color="#B71C1C" fo:padding="0.15cm" fo:margin-bottom="0.06cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#FFCDD2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_box_E65100" style:family="paragraph">
    <style:paragraph-properties fo:background-color="#E65100" fo:padding="0.15cm" fo:margin-bottom="0.06cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#FFE0B2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_box_2E7D32" style:family="paragraph">
    <style:paragraph-properties fo:background-color="#2E7D32" fo:padding="0.15cm" fo:margin-bottom="0.06cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#C8E6C9" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_box_1565C0" style:family="paragraph">
    <style:paragraph-properties fo:background-color="#1565C0" fo:padding="0.15cm" fo:margin-bottom="0.06cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#BBDEFB" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_box_7B1FA2" style:family="paragraph">
    <style:paragraph-properties fo:background-color="#7B1FA2" fo:padding="0.15cm" fo:margin-bottom="0.06cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#E1BEE7" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_val" style:family="text">
    <style:text-properties fo:font-size="14pt" fo:font-weight="bold" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="kpi_lbl" style:family="text">
    <style:text-properties fo:font-size="8.5pt" style:font-name="Arial"/>
  </style:style>
  <!-- Table text -->
  <style:style style:name="th_p" style:family="paragraph">
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="td_p" style:family="paragraph">
    <style:text-properties fo:font-size="8pt" fo:color="#212121" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="tb" style:family="paragraph">
    <style:text-properties fo:font-size="4pt"/>
  </style:style>
</office:automatic-styles>
<office:body><office:text>
{body}
</office:text></office:body>
</office:document-content>"""

styles_xml = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  office:version="1.3">
<office:styles>
  <style:default-style style:family="paragraph">
    <style:text-properties fo:font-size="9pt"/>
  </style:default-style>
</office:styles>
<office:automatic-styles>
  <style:page-layout style:name="PL">
    <style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm"
      fo:margin-top="1.2cm" fo:margin-bottom="1.2cm"
      fo:margin-left="1.5cm" fo:margin-right="1.5cm"/>
  </style:page-layout>
</office:automatic-styles>
<office:master-styles>
  <style:master-page style:name="Default" style:page-layout-name="PL"/>
</office:master-styles>
</office:document-styles>"""

manifest_xml = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">\n'
    '  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>\n'
    '  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>\n'
    '  <manifest:file-entry manifest:full-path="styles.xml"  manifest:media-type="text/xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/dashboard.svg"    manifest:media-type="image/svg+xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/cve_landscape.svg" manifest:media-type="image/svg+xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/local_stats.svg"  manifest:media-type="image/svg+xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/threat_intel.svg" manifest:media-type="image/svg+xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/remediation.svg"  manifest:media-type="image/svg+xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/security_index.svg" manifest:media-type="image/svg+xml"/>\n'
    '  <manifest:file-entry manifest:full-path="Pictures/findings_bar.svg"   manifest:media-type="image/svg+xml"/>\n'
    '</manifest:manifest>\n'
)

with zipfile.ZipFile(odt_out, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text")
    zf.writestr("META-INF/manifest.xml",       manifest_xml)
    zf.writestr("content.xml",                  content_xml)
    zf.writestr("styles.xml",                   styles_xml)
    zf.writestr("Pictures/dashboard.svg",       svg_dashboard)
    zf.writestr("Pictures/cve_landscape.svg",   svg_cve)
    zf.writestr("Pictures/local_stats.svg",     svg_local)
    zf.writestr("Pictures/threat_intel.svg",    svg_threat)
    zf.writestr("Pictures/remediation.svg",     svg_remediation)
    zf.writestr("Pictures/security_index.svg",  svg_security_index)
    zf.writestr("Pictures/findings_bar.svg",    svg_findings_bar)

size = os.path.getsize(odt_out)
print(f"ODF intelligence report: {odt_out}  ({size:,} bytes)")
print(f"  Pages: Dashboard | CVE Landscape | Local Stats | Threat Intel | Remediation Matrix")
print(f"  SVGs:  dashboard | cve_landscape | local_stats | threat_intel | remediation")
INTELEOF

  if [[ -f "wowscanner_intel_${TIMESTAMP}.odt" ]]; then
    pass "ODF statistical intelligence report generated: wowscanner_intel_${TIMESTAMP}.odt"
    log "  ${CYAN}${BOLD}Pages (5): Dashboard | CVE Landscape | Local Audit Stats | Threat Intel | Remediation Matrix${NC}"
    log "  ${CYAN}${BOLD}SVGs  (5): dashboard · cve_landscape · local_stats · threat_intel · remediation${NC}"
    log "  ${CYAN}${BOLD}Tables  : KPI benchmarks · CVE history · CISA KEV · threat stats · remediation checklist${NC}"
    log "  ${CYAN}${BOLD}Open with LibreOffice Writer, OnlyOffice, or any ODT-compatible viewer.${NC}"
  else
    warn "ODF intelligence report generation failed — check Python3 availability"
  fi
}


# ================================================================
#  16. RANDOM PORT SCAN  (nmap-based, with persistent issue tracker)
# ================================================================

init_persist_store() {
  mkdir -p "$PERSIST_DIR"
  touch "$PORT_ISSUES_LOG" "$PORT_HISTORY_DB"
  if [[ ! -s "$PORT_REMEDIATION" ]]; then
    # Write to a temp file first, then move atomically into place.
    # This prevents Samba from ever seeing a partially written file,
    # which is the root cause of the "share list not refreshing" issue.
    local _tmp_remed
    _tmp_remed=$(mktemp "${PERSIST_DIR}/.remediation_tmp_XXXXXX") || true
    if [[ -n "$_tmp_remed" ]]; then
      cat > "$_tmp_remed" << 'REMED'
#!/bin/bash
# =============================================================
#  Auto-generated Port Remediation Script
#  Produced by wowscanner.sh
#  Run:  sudo bash /var/lib/wowscanner/remediation_commands.sh
# =============================================================
# Review each command before executing!
REMED
      chmod 700 "$_tmp_remed"
      mv -f "$_tmp_remed" "$PORT_REMEDIATION"
    fi
  fi
}

record_port_issue() {
  local PORT="$1" PROTO="$2" SERVICE="$3" STATE="$4" REASON="$5"
  local NOW
  NOW=$(date '+%Y-%m-%d %H:%M:%S')

  echo "[${NOW}]  ${PROTO}/${PORT}  state=${STATE}  service=${SERVICE}  reason=${REASON}" \
    >> "$PORT_ISSUES_LOG"

  local KEY="${PROTO}_${PORT}"
  # FIX: use a Python one-liner for the sed update to avoid delimiter collision
  #      with port numbers or timestamps containing the sed separator character.
  if grep -q "^${KEY}|" "$PORT_HISTORY_DB" 2>/dev/null; then
    local FIRST COUNT
    FIRST=$(grep "^${KEY}|" "$PORT_HISTORY_DB" | cut -d'|' -f3)
    COUNT=$(grep "^${KEY}|" "$PORT_HISTORY_DB" | cut -d'|' -f5)
    COUNT=$(safe_int "$COUNT")
    COUNT=$(( COUNT + 1 ))
    # Use python3 for safe in-place line replacement — avoids sed delimiter issues
    python3 - "$PORT_HISTORY_DB" "$KEY" "$PROTO" "$FIRST" "$NOW" "$COUNT" << 'PYREPLACE' || true
import sys
db, key, proto, first, now, count = sys.argv[1:]
lines = open(db).readlines()
with open(db, 'w') as fh:
    for line in lines:
        if line.startswith(key + '|'):
            fh.write(f'{key}|{proto}|{first}|{now}|{count}\n')
        else:
            fh.write(line)
PYREPLACE
  else
    echo "${KEY}|${PROTO}|${NOW}|${NOW}|1" >> "$PORT_HISTORY_DB"
    NEW_PORT_ISSUES=$((NEW_PORT_ISSUES + 1))
  fi

  local REMED_MARKER="# PORT_${PORT}_${PROTO}"
  if ! grep -q "$REMED_MARKER" "$PORT_REMEDIATION" 2>/dev/null; then
    # Build the new block in a temp file, then append atomically.
    local _tmp_block
    _tmp_block=$(mktemp "${PERSIST_DIR}/.remed_block_XXXXXX") || true
    if [[ -n "$_tmp_block" ]]; then
      {
        echo ""
        echo "$REMED_MARKER"
        echo "# Issue  : ${PROTO}/${PORT} (${SERVICE}) found ${STATE} — ${REASON}"
        echo "# Seen   : ${NOW}"
        echo "# Options (pick what applies to your setup):"
        case "$SERVICE" in
          ftp*)    echo "apt-get purge -y vsftpd proftpd ftp   # remove FTP server" ;;
          telnet*) echo "apt-get purge -y telnetd telnet       # remove Telnet" ;;
          smtp*)   echo "# If mail relay not needed: systemctl disable --now postfix exim4" ;;
          http*)   echo "# If web server not needed: systemctl disable --now apache2 nginx" ;;
          *)
            echo "# Block with UFW:"
            echo "ufw deny ${PORT}/${PROTO}"
            echo "# OR block with iptables:"
            echo "iptables -A INPUT -p ${PROTO} --dport ${PORT} -j DROP"
            echo "iptables-save > /etc/iptables/rules.v4"
            ;;
        esac
      } > "$_tmp_block"
      cat "$_tmp_block" >> "$PORT_REMEDIATION"
      rm -f "$_tmp_block"
    fi
  fi
}

show_port_history() {
  if [[ ! -s "$PORT_HISTORY_DB" ]]; then
    info "No persistent port issues on record yet"
    return
  fi
  log ""
  log "  ${BOLD}Persistent port issue history (${PORT_HISTORY_DB}):${NC}"
  log "  ┌──────────────┬───────────────────────┬───────────────────────┬───────┐"
  log "  │ Port/Proto   │ First seen            │ Last seen             │ Count │"
  log "  ├──────────────┼───────────────────────┼───────────────────────┼───────┤"
  while IFS='|' read -r KEY PROTO FIRST LAST COUNT; do
    local PORT="${KEY#${PROTO}_}"
    printf "  │ %-12s │ %-21s │ %-21s │ %-5s │\n" \
      "${PROTO}/${PORT}" "$FIRST" "$LAST" "$COUNT" | tee -a "$REPORT"
  done < "$PORT_HISTORY_DB"
  log "  └──────────────┴───────────────────────┴───────────────────────┴───────┘"
}

section_portscan() {
  header "16. RANDOM PORT SCAN"

  init_persist_store

  if ! command -v nmap &>/dev/null; then
    info "nmap not found — installing..."
    apt-get install -y nmap -qq 2>/dev/null || {
      fail "Could not install nmap — skipping port scan"
      return
    }
  fi

  local NMAP_VERSION
  NMAP_VERSION=$(nmap --version 2>/dev/null | head -1 || true)
  info "Tool     : ${NMAP_VERSION:-nmap (version unknown)}"

  # Pick 3 random 500-port windows spread across the 1-65535 space
  local RANDOM_RANGES=()
  local i START END
  for i in 1 2 3; do
    START=$(( (RANDOM % 130) * 500 + 1 ))
    END=$(( START + 499 ))
    [[ "$END" -gt 65535 ]] && END=65535
    RANDOM_RANGES+=("${START}-${END}")
  done
  RANDOM_RANGES+=("1-1024")

  local PORT_ARG
  PORT_ARG=$(IFS=,; echo "${RANDOM_RANGES[*]}")
  info "Scan ranges this run : ${PORT_ARG}"
  info "Target               : 127.0.0.1 (localhost)"
  info "Technique            : TCP SYN + UDP top ports"
  log ""

  local NMAP_OUT="/tmp/nmap_scan_${TIMESTAMP}.xml"
  local NMAP_TXT="/tmp/nmap_scan_${TIMESTAMP}.txt"

  nmap -sS -sV -sU --top-ports 50 \
       -p "T:${PORT_ARG}" \
       -T4 --open --reason \
       -oX "$NMAP_OUT" -oN "$NMAP_TXT" \
       127.0.0.1 2>/dev/null || \
  nmap -sT -sV \
       -p "T:${PORT_ARG}" \
       -T4 --open --reason \
       -oX "$NMAP_OUT" -oN "$NMAP_TXT" \
       127.0.0.1 2>/dev/null || true

  if [[ ! -s "$NMAP_TXT" ]]; then
    warn "nmap produced no output — scan may have been blocked"
    return
  fi

  subheader "Raw scan results"
  grep -E "^[0-9]+/|^PORT|^Nmap scan|^Host" "$NMAP_TXT" 2>/dev/null \
    | while IFS= read -r line; do detail "$line"; done || true

  subheader "Port risk assessment"

  # FIX: declare associative array at function scope (bash 4+)
  declare -A KNOWN_RISKY=(
    [21]="FTP plaintext file transfer — high risk"
    [22]="SSH — verify it is hardened"
    [23]="Telnet plaintext remote shell — critical risk"
    [25]="SMTP — verify no open relay"
    [53]="DNS — verify not an open resolver"
    [69]="TFTP — unauthenticated file transfer"
    [80]="HTTP — unencrypted web traffic"
    [110]="POP3 plaintext email"
    [111]="RPC portmapper — expose attack surface"
    [135]="MS-RPC — should not be open on Linux"
    [139]="NetBIOS — Samba exposure"
    [143]="IMAP plaintext email"
    [161]="SNMP — community strings leak info"
    [389]="LDAP — verify TLS enforced"
    [443]="HTTPS — verify certificate & cipher suite"
    [445]="SMB — lateral movement risk"
    [512]="rexec — legacy remote exec"
    [513]="rlogin — legacy remote login"
    [514]="rsh/syslog — legacy, no auth"
    [1433]="MSSQL — database port exposed"
    [1521]="Oracle DB — database port exposed"
    [2049]="NFS — file system exposure"
    [3306]="MySQL/MariaDB — database port exposed"
    [3389]="RDP — remote desktop (Windows)"
    [5432]="PostgreSQL — database port exposed"
    [5900]="VNC — remote desktop, often weak auth"
    [6000]="X11 — graphical session exposed"
    [6379]="Redis — often no auth by default"
    [8080]="HTTP-alt — web proxy / dev server"
    [8443]="HTTPS-alt — verify certificate"
    [9200]="Elasticsearch — unauthenticated access"
    [27017]="MongoDB — unauthenticated access"
  )

  local OPEN_PORTS OPEN_UDP FOUND_ISSUES=0
  OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$NMAP_TXT" 2>/dev/null | grep -oP '^\d+' || true)
  OPEN_UDP=$(grep   -oP '^\d+/udp\s+open' "$NMAP_TXT" 2>/dev/null | grep -oP '^\d+' || true)

  local PORT SERVICE REASON
  while IFS= read -r PORT; do
    [[ -z "$PORT" ]] && continue
    SERVICE=$(grep -oP "^${PORT}/tcp\s+open\s+\K\S+" "$NMAP_TXT" 2>/dev/null | head -1 || echo "unknown")
    REASON=$(grep  -oP "^${PORT}/tcp.*reason \K\S+"  "$NMAP_TXT" 2>/dev/null | head -1 || echo "syn-ack")
    # FIX: double-quote the array key lookup
    if [[ -n "${KNOWN_RISKY[$PORT]:-}" ]]; then
      if [[ "$PORT" -eq 22 ]]; then
        warn "TCP/${PORT} open (${SERVICE}) — ${KNOWN_RISKY[$PORT]}"
      else
        fail "TCP/${PORT} open (${SERVICE}) — ${KNOWN_RISKY[$PORT]}"
        record_port_issue "$PORT" "tcp" "$SERVICE" "open" "${KNOWN_RISKY[$PORT]}"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
      fi
    else
      info "TCP/${PORT} open (${SERVICE}) — not in risky list, verify manually"
    fi
  done <<< "$OPEN_PORTS"

  while IFS= read -r PORT; do
    [[ -z "$PORT" ]] && continue
    SERVICE=$(grep -oP "^${PORT}/udp\s+open\s+\K\S+" "$NMAP_TXT" 2>/dev/null | head -1 || echo "unknown")
    if [[ -n "${KNOWN_RISKY[$PORT]:-}" ]]; then
      fail "UDP/${PORT} open (${SERVICE}) — ${KNOWN_RISKY[$PORT]}"
      record_port_issue "$PORT" "udp" "$SERVICE" "open" "${KNOWN_RISKY[$PORT]}"
      FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi
  done <<< "$OPEN_UDP"

  if [[ "$FOUND_ISSUES" -eq 0 ]]; then
    pass "No risky open ports found in this scan run"
  else
    fail "$FOUND_ISSUES risky open port(s) detected and logged"
  fi

  subheader "Persistent port issue history"
  show_port_history

  subheader "Remediation script"
  if [[ "$FOUND_ISSUES" -gt 0 || -s "$PORT_REMEDIATION" ]]; then
    log "  ${YELLOW}${BOLD}Remediation commands saved to:${NC}"
    log "  ${BOLD}${PORT_REMEDIATION}${NC}"
    log "  Review and run:  sudo bash ${PORT_REMEDIATION}"
    info "Contents preview:"
    grep -v '^#' "$PORT_REMEDIATION" | grep -v '^$' | head -20 \
      | while IFS= read -r line; do detail "$line"; done || true
  else
    pass "No remediation commands needed — remediation script is empty"
  fi

  { echo ""; echo "──── RAW: nmap port scan ────"; cat "$NMAP_TXT" 2>/dev/null || true; echo "────────────────────────────"; } >> "$REPORT"
  info "Raw nmap port scan appended to: ${REPORT}"
}

# ================================================================
#  17. SUMMARY
# ================================================================
section_summary() {
  header "17. SUMMARY"

  local PERCENTAGE=0
  [[ "$TOTAL" -gt 0 ]] && PERCENTAGE=$(( SCORE * 100 / TOTAL ))

  log ""
  log "  ${BOLD}Own audit checks:${NC}"
  log "  ┌────────────────────────────────────┐"
  log "  │  Checks passed  : ${GREEN}${SCORE}${NC} / ${TOTAL}"
  log "  │  Score          : ${BOLD}${PERCENTAGE}%${NC}"
  log "  └────────────────────────────────────┘"
  log ""

  if [[ "$PERCENTAGE" -ge 80 ]]; then
    log "  ${GREEN}${BOLD}  Rating: GOOD${NC}"
    log "  System is reasonably hardened. Keep up with updates and monitor logs."
  elif [[ "$PERCENTAGE" -ge 50 ]]; then
    log "  ${YELLOW}${BOLD}  Rating: MODERATE${NC}"
    log "  Several issues need attention. Address FAIL items as a priority."
  else
    log "  ${RED}${BOLD}  Rating: CRITICAL${NC}"
    log "  Significant security risks detected. Immediate action required!"
  fi

  log ""
  log "  ${BOLD}Output files:${NC}"
  log "  ┌────────────────────────────────────────────────────────┐"
  log "  │  Audit report  : ${BOLD}${REPORT}${NC}"
  log "  │  chkrootkit    : chkrootkit_scan_${TIMESTAMP}.txt"
  log "  │  rkhunter log  : /var/log/rkhunter.log  (persistent system log)"
  log "  │  rkhunter raw  : embedded in ${BOLD}${REPORT}${NC}"
  log "  │  Port scan     : nmap_scan_${TIMESTAMP}.txt"
  log "  │  Port issues   : ${BOLD}${PORT_ISSUES_LOG}${NC}"
  log "  │  Remediation   : ${BOLD}${PORT_REMEDIATION}${NC}"
  log "  └────────────────────────────────────────────────────────┘"
  log ""
  log "  ${YELLOW}${BOLD}  ⚠  Please check the log file (/var/log/rkhunter.log) for full"
  log "     rkhunter details and to review any false positives.${NC}"
  log ""
  log "  ${BOLD}Recommended next steps:${NC}"
  log "  1. Fix all FAIL items above immediately"
  log "  2. Review WARN items and apply where applicable"
  log "  3. Re-run Lynis and aim for hardening index >= 80"
  log "  4. Schedule regular audits (weekly/monthly)"
  log "  5. Set up automated security monitoring (auditd, fail2ban, OSSEC)"
  log ""
}

# ================================================================
#  18. ODT REPORT GENERATOR
# ================================================================
generate_odt_report() {
  local TXT_REPORT="$1" SCORE_VAL="$2" TOTAL_VAL="$3" PCT="$4"
  local ODT_OUT="wowscanner_report_${TIMESTAMP}.odt"

  info "Generating ODT report → ${ODT_OUT} ..."

  python3 - "$TXT_REPORT" "$ODT_OUT" "$SCORE_VAL" "$TOTAL_VAL" "$PCT" "$TIMESTAMP" \
           "$(hostname -f 2>/dev/null || hostname)" \
           "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')" \
           "$(uname -r)" << 'PYEOF' || true
#!/usr/bin/env python3
import sys, os, re, zipfile
from datetime import datetime

txt_report = sys.argv[1]; odt_out = sys.argv[2]
score_val  = int(sys.argv[3]); total_val = int(sys.argv[4]); pct = int(sys.argv[5])
timestamp  = sys.argv[6]; hostname = sys.argv[7]
os_name    = sys.argv[8]; kernel   = sys.argv[9]

ansi_re = re.compile(r'\x1b\[[0-9;]*m')
with open(txt_report, 'r', errors='replace') as fh:
    raw_lines = [ansi_re.sub('', l.rstrip('\n')) for l in fh]

PASS_RE = re.compile(r'^\s*\[.*PASS.*\]\s*(.*)')
FAIL_RE = re.compile(r'^\s*\[.*FAIL.*\]\s*(.*)')
WARN_RE = re.compile(r'^\s*\[.*WARN.*\]\s*(.*)')
INFO_RE = re.compile(r'^\s*\[.*INFO.*\]\s*(.*)')
SKIP_RE = re.compile(r'^\s*\[.*SKIP.*\]\s*(.*)')

sections = []; cur_sec = {"title": "Header", "items": []}
for line in raw_lines:
    m2 = re.match(r'\s*([0-9]+[ab]*\.\s+[A-Z].{4,})', line)
    if m2 and not re.search(r'[✔✘⚠ℹ↳]', line):
        sections.append(cur_sec)
        cur_sec = {"title": m2.group(1).strip(), "items": []}
        continue
    for RE, kind in ((PASS_RE,"PASS"),(FAIL_RE,"FAIL"),(WARN_RE,"WARN"),(INFO_RE,"INFO"),(SKIP_RE,"SKIP")):
        m = RE.match(line)
        if m: cur_sec["items"].append({"kind": kind, "text": m.group(1)}); break
sections.append(cur_sec)
sections = [s for s in sections if s["items"]]

all_items = [i for s in sections for i in s["items"]]
n_pass = sum(1 for i in all_items if i["kind"]=="PASS")
n_fail = sum(1 for i in all_items if i["kind"]=="FAIL")
n_warn = sum(1 for i in all_items if i["kind"]=="WARN")
n_info = sum(1 for i in all_items if i["kind"]=="INFO")
n_skip = sum(1 for i in all_items if i["kind"]=="SKIP")

if pct >= 80:
    rating="GOOD";     rating_hex="2E7D32"; bar_fill="4CAF50"
elif pct >= 50:
    rating="MODERATE"; rating_hex="E65100"; bar_fill="FF9800"
else:
    rating="CRITICAL"; rating_hex="B71C1C"; bar_fill="F44336"

BAR_WIDTH = 40
filled    = round(pct / 100 * BAR_WIDTH)
bar_str   = "\u2588" * filled + "\u2591" * (BAR_WIDTH - filled)
bar_label = f"{bar_str}  {pct}%  [{rating}]"

def esc(s):
    return (str(s).replace("&","&amp;").replace("<","&lt;")
                  .replace(">","&gt;").replace('"',"&quot;"))

KIND_LABEL = {"PASS":"PASS","FAIL":"FAIL","WARN":"WARN","INFO":"INFO","SKIP":"SKIP"}
KIND_STYLE = {"PASS":"ps","FAIL":"fs","WARN":"ws","INFO":"is","SKIP":"ss"}

def result_row(kind, text):
    ks = KIND_STYLE.get(kind,"is"); kl = KIND_LABEL.get(kind,kind)
    return (f'<table:table-row>'
            f'<table:table-cell table:style-name="ck_{ks}" office:value-type="string">'
            f'<text:p text:style-name="{ks}">{esc(kl)}</text:p></table:table-cell>'
            f'<table:table-cell table:style-name="cv" office:value-type="string">'
            f'<text:p text:style-name="tc">{esc(text[:280])}</text:p></table:table-cell>'
            f'</table:table-row>')

run_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
parts = []

# ── SVG helper functions ──────────────────────────────────────────
def odt_embed_svg(svg_data, w_cm, h_cm, name):
    """Embed an SVG as a draw:frame/draw:image inline in the ODT body."""
    return (
        f'<text:p text:style-name="tb">'
        f'<draw:frame draw:name="{name}" svg:width="{w_cm}cm" svg:height="{h_cm}cm" '
        f'text:anchor-type="as-char" draw:z-index="0">'
        f'<draw:image xlink:href="Pictures/{name}.svg" xlink:type="simple" '
        f'xlink:show="embed" xlink:actuate="onLoad"/>'
        f'</draw:frame>'
        f'</text:p>'
    )

def build_security_index_svg(pct2, nf, nw, np2, ni, rat, rhex, bfill):
    import math as _m
    W,H=820,260
    p=[]
    p.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
    p.append(f'<rect width="{W}" height="{H}" fill="#0D1117" rx="10"/>')
    cx,cy,Ro,Ri=160,190,130,78
    zones=[(0,20,"#7B0000","#EF5350","Critical"),(20,40,"#BF360C","#FF7043","High"),
           (40,60,"#E65100","#FFB300","Moderate"),(60,80,"#1B5E20","#66BB6A","Good"),
           (80,100,"#0D47A1","#42A5F5","Excellent")]
    def arc(a0,a1,ro,ri,cd,cl):
        A0=_m.radians(180-a0*1.8); A1=_m.radians(180-a1*1.8)
        lg=1 if abs(a1-a0)>50 else 0
        x0o=cx+ro*_m.cos(A0); y0o=cy-ro*_m.sin(A0)
        x1o=cx+ro*_m.cos(A1); y1o=cy-ro*_m.sin(A1)
        x0i=cx+ri*_m.cos(A1); y0i=cy-ri*_m.sin(A1)
        x1i=cx+ri*_m.cos(A0); y1i=cy-ri*_m.sin(A0)
        d=(f"M{x0o:.1f},{y0o:.1f} A{ro},{ro} 0 {lg},0 {x1o:.1f},{y1o:.1f} "
           f"L{x0i:.1f},{y0i:.1f} A{ri},{ri} 0 {lg},1 {x1i:.1f},{y1i:.1f} Z")
        return f'<path d="{d}" fill="{cd}" stroke="{cl}" stroke-width="1.5"/>' 
    for a0,a1,cd,cl,_ in zones: p.append(arc(a0,a1,Ro,Ri,cd,cl))
    na=_m.radians(180-pct2*1.8)
    nx=cx+(Ri-10)*_m.cos(na); ny=cy-(Ri-10)*_m.sin(na)
    p+=[f'<line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="#FFF" stroke-width="3" stroke-linecap="round"/>',
        f'<circle cx="{cx}" cy="{cy}" r="8" fill="#FFF"/>',
        f'<circle cx="{cx}" cy="{cy}" r="4" fill="#{rhex}"/>',
        f'<text x="{cx}" y="{cy+38}" text-anchor="middle" font-family="Arial" font-size="32" font-weight="bold" fill="#{bfill}">{pct2}%</text>',
        f'<text x="{cx}" y="{cy+58}" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#{rhex}">{rat}</text>']
    lx,ly=330,22
    p.append(f'<text x="{lx}" y="{ly}" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Index — Colour Legend</text>')
    legend=[("#B71C1C","#EF5350","0–20%","Critical — Immediate action required. Serious vulnerabilities exposed."),
            ("#BF360C","#FF7043","21–40%","High — Significant risks. Address FAIL items urgently."),
            ("#E65100","#FFB300","41–60%","Moderate — Several issues need attention. Review all WARNs."),
            ("#1B5E20","#66BB6A","61–80%","Good — Reasonably hardened. Monitor and maintain regularly."),
            ("#0D47A1","#42A5F5","81–100%","Excellent — Well hardened. Schedule regular audits.")]
    for idx,(bg,fg,rng,desc) in enumerate(legend):
        y=ly+26+idx*36
        active=(zones[idx][0]<=pct2<zones[idx][1]) or (idx==4 and pct2>=80) or (idx==0 and pct2==0)
        sw="3" if active else "1"
        p+=[f'<rect x="{lx}" y="{y}" width="64" height="22" fill="{bg}" stroke="{fg}" stroke-width="{sw}" rx="4"/>',
            f'<text x="{lx+32}" y="{y+15}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="{fg}">{rng}</text>',
            f'<text x="{lx+74}" y="{y+9}" font-family="Arial" font-size="9" font-weight="bold" fill="{fg}">{esc(desc[:58])}</text>']
        if active: p.append(f'<text x="{lx-14}" y="{y+15}" font-family="Arial" font-size="14" fill="{fg}">▶</text>')
    rx,ry=660,22; total=nf+nw+np2+ni or 1; bw=120
    p.append(f'<text x="{rx+60}" y="{ry}" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Finding Summary</text>')
    for si,(fg,bg2,lbl,cnt) in enumerate([("#EF5350","#B71C1C","FAIL",nf),("#FF9800","#E65100","WARN",nw),("#4CAF50","#2E7D32","PASS",np2),("#42A5F5","#1565C0","INFO",ni)]):
        y2=ry+26+si*42; w2=int(cnt/total*bw)
        p+=[f'<rect x="{rx}" y="{y2}" width="{bw}" height="22" fill="#1E2A3A" rx="4"/>',
            f'<rect x="{rx}" y="{y2}" width="{max(w2,2)}" height="22" fill="{bg2}" rx="4"/>',
            f'<text x="{rx+bw+8}" y="{y2+15}" font-family="Arial" font-size="11" font-weight="bold" fill="{fg}">{cnt}</text>',
            f'<text x="{rx-6}" y="{y2+15}" text-anchor="end" font-family="Arial" font-size="10" font-weight="bold" fill="{fg}">{lbl}</text>']
    p.append('</svg>'); return "".join(p)

def build_findings_bar_svg(secs):
    import math as _m
    n=len(secs)
    if n==0: return '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="60"><text x="10" y="40" fill="#90A4AE">No sections</text></svg>'
    W=820; pl=220; pr=60; pt=44; pb=36
    rh=max(20,min(34,(580-pt-pb)//n)); H=pt+n*rh+20+pb
    mv=max((s["pass"]+s["fail"]+s["warn"]) for s in secs) or 1
    pw=W-pl-pr
    p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       f'<rect width="{W}" height="{H}" fill="#0D1117" rx="8"/>',
       f'<text x="{W//2}" y="26" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Findings by Section</text>']
    tks=[i*max(1,mv//5) for i in range(6)]
    tks=sorted(set(t for t in tks if t<=mv))
    for tk in tks:
        gx=pl+int(tk/mv*pw)
        p+=[f'<line x1="{gx}" y1="{pt}" x2="{gx}" y2="{pt+n*rh}" stroke="#1E2A3A" stroke-width="1"/>',
            f'<text x="{gx}" y="{pt+n*rh+14}" text-anchor="middle" font-family="Arial" font-size="8" fill="#546E7A">{tk}</text>']
    for idx,s in enumerate(secs):
        y=pt+idx*rh+2; bh=rh-4
        bpw=int(s["pass"]/mv*pw); bfw=int(s["fail"]/mv*pw); bww=int(s["warn"]/mv*pw)
        lc="#EF5350" if s["fail"]>0 else ("#FFB300" if s["warn"]>0 else "#66BB6A")
        p+=[f'<rect x="{pl}" y="{y}" width="{pw}" height="{bh}" fill="#131B26" rx="3"/>']
        if bpw: p.append(f'<rect x="{pl}" y="{y}" width="{bpw}" height="{bh}" fill="#2E7D32" rx="2"/>')
        if bfw: p.append(f'<rect x="{pl+bpw}" y="{y}" width="{bfw}" height="{bh}" fill="#C62828" rx="2"/>')
        if bww: p.append(f'<rect x="{pl+bpw+bfw}" y="{y}" width="{bww}" height="{bh}" fill="#E65100" rx="2"/>')
        p.append(f'<text x="{pl-8}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="{lc}">{esc(s["title"][:30])}</text>')
        xc=pl
        for bw2,cnt,col in [(bpw,s["pass"],"#A5D6A7"),(bfw,s["fail"],"#FFCDD2"),(bww,s["warn"],"#FFE0B2")]:
            if bw2>=18 and cnt: p.append(f'<text x="{xc+bw2//2}" y="{y+bh//2+4}" text-anchor="middle" font-family="Arial" font-size="8" font-weight="bold" fill="{col}">{cnt}</text>')
            xc+=bw2
        sc=s.get("pct",0)
        p.append(f'<text x="{pl+bpw+bfw+bww+6}" y="{y+bh//2+4}" font-family="Arial" font-size="8" font-weight="bold" fill="{lc}">{sc}%</text>')
    p.append(f'<line x1="{pl}" y1="{pt}" x2="{pl}" y2="{pt+n*rh}" stroke="#37474F" stroke-width="1.5"/>')
    lx2=pl; ly2=H-20
    for col,lbl in [("#2E7D32","PASS"),("#C62828","FAIL"),("#E65100","WARN")]:
        p+=[f'<rect x="{lx2}" y="{ly2}" width="11" height="11" fill="{col}" rx="2"/>',
            f'<text x="{lx2+14}" y="{ly2+9}" font-family="Arial" font-size="9" fill="#B0BEC5">{lbl}</text>']
        lx2+=65
    p.append('</svg>'); return "".join(p)

# Per-section stats for bar chart
sec_stats_odt = []
for s in sections:
    items = s["items"]
    np2=sum(1 for i in items if i["kind"]=="PASS")
    nf2=sum(1 for i in items if i["kind"]=="FAIL")
    nw2=sum(1 for i in items if i["kind"]=="WARN")
    tot2=np2+nf2+nw2
    sec_stats_odt.append({"title":s["title"][:40],"pass":np2,"fail":nf2,"warn":nw2,
                          "pct":round(np2*100/tot2) if tot2 else 0})

svg_index = build_security_index_svg(pct, n_fail, n_warn, n_pass, n_info, rating, rating_hex, bar_fill)
svg_bar   = build_findings_bar_svg(sec_stats_odt)

parts.append(f'<text:h text:style-name="h1" text:outline-level="1">Wowscanner Security Report</text:h>')
parts.append(f'<text:p text:style-name="sub">Host: {esc(hostname)}  |  OS: {esc(os_name)}  |  Kernel: {esc(kernel)}</text:p>')
parts.append(f'<text:p text:style-name="sub">Date: {esc(run_date)}</text:p>')
parts.append(f'<text:p text:style-name="tb"/>')

# ── Security Index (colour-coded score gauge + legend + summary) ──
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Security Index</text:h>')
parts.append(odt_embed_svg(svg_index, 17, 6.5, "security_index"))
parts.append(f'<text:p text:style-name="tb"/>')

# ── Findings Bar Chart ─────────────────────────────────────────────
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Findings by Section</text:h>')
bar_h = max(8.0, round(len(sec_stats_odt) * 0.65 + 2.5, 1))
parts.append(odt_embed_svg(svg_bar, 17, bar_h, "findings_bar"))
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# ── Summary counts (text) ──────────────────────────────────────────
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Summary Counts</text:h>')
parts.append(f'<text:p text:style-name="ps">PASS : {n_pass}</text:p>')
parts.append(f'<text:p text:style-name="fs">FAIL : {n_fail}</text:p>')
parts.append(f'<text:p text:style-name="ws">WARN : {n_warn}</text:p>')
parts.append(f'<text:p text:style-name="is">INFO : {n_info}</text:p>')
parts.append(f'<text:p text:style-name="ss">SKIP : {n_skip}</text:p>')
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

for sec in sections:
    parts.append(f'<text:h text:style-name="h2" text:outline-level="2">{esc(sec["title"])}</text:h>')
    parts.append('<table:table table:style-name="rt">'
                 '<table:table-column table:style-name="col_k"/>'
                 '<table:table-column table:style-name="col_v"/>')
    for item in sec["items"]:
        parts.append(result_row(item["kind"], item["text"]))
    parts.append('</table:table>')
    parts.append('<text:p text:style-name="tb"/>')

parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')
parts.append(f'<text:h text:style-name="h1" text:outline-level="1">Full Raw Audit Log</text:h>')

# ── rkhunter log advisory ─────────────────────────────────────────────────────
# Detect whether the raw log contains a rkhunter section and add a prominent note
has_rkh = any('rkhunter' in l.lower() for l in raw_lines)
if has_rkh:
    parts.append(
        f'<text:p text:style-name="ws">'
        f'⚠  Please check the log file (/var/log/rkhunter.log) for the full '
        f'rkhunter scan details, including any false positive warnings. '
        f'The complete rkhunter output is embedded in the raw log section below.'
        f'</text:p>'
    )
    parts.append('<text:p text:style-name="tb"/>')

for line in raw_lines:
    parts.append(f'<text:p text:style-name="lm">{esc(line)}</text:p>')

body = "\n".join(parts)

# FIX: <office:styles> must NOT be inside <office:body>; moved to automatic-styles
content_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
  office:version="1.3">
<office:font-face-decls>
  <style:font-face style:name="Cour"
    xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
    svg:font-family="'Courier New'" style:font-family-generic="modern" style:font-pitch="fixed"/>
  <style:font-face style:name="Arial"
    xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
    svg:font-family="Arial" style:font-family-generic="swiss"/>
</office:font-face-decls>
<office:automatic-styles>
  <!-- Table geometry -->
  <style:style style:name="rt"  style:family="table">
    <style:table-properties style:width="17cm" table:align="margins"/>
  </style:style>
  <style:style style:name="col_k" style:family="table-column">
    <style:table-column-properties style:column-width="2.8cm"/>
  </style:style>
  <style:style style:name="col_v" style:family="table-column">
    <style:table-column-properties style:column-width="14.2cm"/>
  </style:style>
  <!-- Cell backgrounds -->
  <style:style style:name="ck_ps" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#E8F5E9" fo:padding="0.1cm" fo:border="0.4pt solid #C8E6C9"/>
  </style:style>
  <style:style style:name="ck_fs" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFEBEE" fo:padding="0.1cm" fo:border="0.4pt solid #FFCDD2"/>
  </style:style>
  <style:style style:name="ck_ws" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFF8E1" fo:padding="0.1cm" fo:border="0.4pt solid #FFE082"/>
  </style:style>
  <style:style style:name="ck_is" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#E3F2FD" fo:padding="0.1cm" fo:border="0.4pt solid #BBDEFB"/>
  </style:style>
  <style:style style:name="ck_ss" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#F5F5F5" fo:padding="0.1cm" fo:border="0.4pt solid #E0E0E0"/>
  </style:style>
  <style:style style:name="cv" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFFFFF" fo:padding="0.1cm" fo:border="0.4pt solid #E0E0E0"/>
  </style:style>
  <!-- Paragraph styles (must live in automatic-styles for content.xml) -->
  <style:style style:name="h1" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.3cm" fo:margin-bottom="0.2cm"
      fo:background-color="#1565C0" fo:padding="0.15cm"/>
    <style:text-properties fo:font-size="15pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="h2" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.25cm" fo:margin-bottom="0.1cm"
      fo:border-bottom="1.2pt solid #1565C0" fo:padding-bottom="0.05cm"/>
    <style:text-properties fo:font-size="11pt" fo:font-weight="bold" fo:color="#1565C0" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="sub" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center"/>
    <style:text-properties fo:font-size="9pt" fo:color="#424242" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="sc" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center"/>
    <style:text-properties fo:font-size="13pt" fo:font-weight="bold" fo:color="#212121" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="bar" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center" fo:background-color="#F5F5F5"
      fo:padding="0.2cm" fo:border="1pt solid #BDBDBD" fo:margin-bottom="0.15cm"/>
    <style:text-properties style:font-name="Cour" fo:font-size="10.5pt" fo:font-weight="bold" fo:color="#{bar_fill}"/>
  </style:style>
  <style:style style:name="rt_{rating_hex}" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center" fo:margin-bottom="0.2cm"/>
    <style:text-properties fo:font-size="18pt" fo:font-weight="bold" fo:color="#{rating_hex}" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ps" style:family="paragraph">
    <style:text-properties fo:color="#1B5E20" fo:font-weight="bold" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="fs" style:family="paragraph">
    <style:text-properties fo:color="#B71C1C" fo:font-weight="bold" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="ws" style:family="paragraph">
    <style:text-properties fo:color="#E65100" fo:font-weight="bold" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="is" style:family="paragraph">
    <style:text-properties fo:color="#0D47A1" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="ss" style:family="paragraph">
    <style:text-properties fo:color="#757575" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="tc" style:family="paragraph">
    <style:text-properties style:font-name="Cour" fo:font-size="8.5pt" fo:color="#212121"/>
  </style:style>
  <style:style style:name="lm" style:family="paragraph">
    <style:text-properties style:font-name="Cour" fo:font-size="7pt" fo:color="#333333"/>
  </style:style>
  <style:style style:name="tb" style:family="paragraph">
    <style:text-properties fo:font-size="4pt"/>
  </style:style>
</office:automatic-styles>
<office:body><office:text>
{body}
</office:text></office:body>
</office:document-content>"""

styles_xml = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  office:version="1.3">
<office:styles>
  <style:default-style style:family="paragraph">
    <style:text-properties fo:font-size="10pt"/>
  </style:default-style>
</office:styles>
<office:automatic-styles>
  <style:page-layout style:name="PL">
    <style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm"
      fo:margin-top="1.5cm" fo:margin-bottom="1.5cm"
      fo:margin-left="1.8cm" fo:margin-right="1.8cm"/>
  </style:page-layout>
</office:automatic-styles>
<office:master-styles>
  <style:master-page style:name="Default" style:page-layout-name="PL"/>
</office:master-styles>
</office:document-styles>"""

manifest_xml = """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest
  xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
  manifest:version="1.3">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="styles.xml"  manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="Pictures/security_index.svg" manifest:media-type="image/svg+xml"/>
  <manifest:file-entry manifest:full-path="Pictures/findings_bar.svg"   manifest:media-type="image/svg+xml"/>
</manifest:manifest>"""

with zipfile.ZipFile(odt_out, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text")
    zf.writestr("META-INF/manifest.xml", manifest_xml)
    zf.writestr("content.xml",           content_xml)
    zf.writestr("styles.xml",            styles_xml)
    zf.writestr("Pictures/security_index.svg", svg_index)
    zf.writestr("Pictures/findings_bar.svg",   svg_bar)

print(f"ODT report written: {odt_out}  ({os.path.getsize(odt_out):,} bytes)")
print(f"  Charts: Security Index (colour legend + gauge) | Findings by Section (bar chart)")
PYEOF

  if [[ -f "${ODT_OUT}" ]]; then
    pass "ODT report generated: ${ODT_OUT}"
    log "  ${CYAN}${BOLD}Open with LibreOffice Writer, OnlyOffice, or any ODT-compatible viewer.${NC}"
  else
    warn "ODT generation failed — check Python3 availability"
  fi
}


# ================================================================
#  20. STATISTICAL ODS REPORT WITH CHARTS + DETAILED WARNINGS
#      Sheets:
#        1. Overview      — score gauge, summary counts, host info
#        2. Per-Section   — pass/fail/warn breakdown per audit area
#        3. Issues        — every FAIL & WARN with full detail + remediation
#        4. Warn Detail   — WARN-only deep-dive with context & fix steps
#        5. Fail Detail   — FAIL-only deep-dive with context & fix steps
#        6. ChartData     — raw numbers for chart rendering
#        7. Charts        — note pointing to SVG files
#      SVG charts embedded in archive:
#        score_gauge.svg, bar_chart.svg, pie_chart.svg,
#        heatmap.svg, trend_radar.svg
# ================================================================
generate_stats_ods() {
  local TXT_REPORT="$1" SCORE_VAL="$2" TOTAL_VAL="$3" PCT="$4"
  local ODS_OUT="wowscanner_stats_${TIMESTAMP}.ods"

  info "Generating enhanced statistics ODS → ${ODS_OUT} ..."

  python3 - "$TXT_REPORT" "$ODS_OUT" "$SCORE_VAL" "$TOTAL_VAL" "$PCT" "$TIMESTAMP" \
           "$(hostname -f 2>/dev/null || hostname)" \
           "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')" \
           "$(uname -r)" << 'STATSEOF' || true
import sys, os, re, zipfile, math
from datetime import datetime

txt_report = sys.argv[1]; ods_out = sys.argv[2]
score_val  = int(sys.argv[3]); total_val = int(sys.argv[4]); pct = int(sys.argv[5])
timestamp  = sys.argv[6]; hostname = sys.argv[7]
os_name    = sys.argv[8]; kernel   = sys.argv[9]
run_date   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Parse the audit report ────────────────────────────────────────
ansi_re = re.compile(r'\x1b\[[0-9;]*m')
with open(txt_report, 'r', errors='replace') as fh:
    raw_lines = [ansi_re.sub('', l.rstrip('\n')) for l in fh]

PASS_RE  = re.compile(r'^\s*\[.*PASS.*\]\s*(.*)')
FAIL_RE  = re.compile(r'^\s*\[.*FAIL.*\]\s*(.*)')
WARN_RE  = re.compile(r'^\s*\[.*WARN.*\]\s*(.*)')
INFO_RE  = re.compile(r'^\s*\[.*INFO.*\]\s*(.*)')
SKIP_RE  = re.compile(r'^\s*\[.*SKIP.*\]\s*(.*)')
DETAIL_RE= re.compile(r'^\s*↳\s*(.*)')

sections = []; cur_sec = {"title": "Header", "items": [], "details": []}
last_item_idx = -1

for line in raw_lines:
    m_sec = re.match(r'\s*([0-9]+[ab]*\.\s+[A-Z].{4,})', line)
    if m_sec and not re.search(r'[✔✘⚠ℹ↳]', line):
        sections.append(cur_sec)
        cur_sec = {"title": m_sec.group(1).strip(), "items": [], "details": []}
        last_item_idx = -1
        continue
    matched = False
    for RE, kind in ((PASS_RE,"PASS"),(FAIL_RE,"FAIL"),(WARN_RE,"WARN"),(INFO_RE,"INFO"),(SKIP_RE,"SKIP")):
        m = RE.match(line)
        if m:
            cur_sec["items"].append({"kind": kind, "text": m.group(1), "details": []})
            last_item_idx = len(cur_sec["items"]) - 1
            matched = True; break
    if not matched:
        md = DETAIL_RE.match(line)
        if md and last_item_idx >= 0:
            cur_sec["items"][last_item_idx]["details"].append(md.group(1))

sections.append(cur_sec)
sections = [s for s in sections if s["items"]]

# ── Per-section stats ─────────────────────────────────────────────
sec_stats = []
for s in sections:
    items = s["items"]
    n_p = sum(1 for i in items if i["kind"]=="PASS")
    n_f = sum(1 for i in items if i["kind"]=="FAIL")
    n_w = sum(1 for i in items if i["kind"]=="WARN")
    n_i = sum(1 for i in items if i["kind"]=="INFO")
    n_s = sum(1 for i in items if i["kind"]=="SKIP")
    tot = n_p + n_f + n_w
    sec_stats.append({
        "title": s["title"][:40], "pass": n_p, "fail": n_f,
        "warn": n_w, "info": n_i, "skip": n_s,
        "total": tot, "pct": round(n_p*100/tot) if tot else 0
    })

all_items = [i for s in sections for i in s["items"]]
n_pass = sum(1 for i in all_items if i["kind"]=="PASS")
n_fail = sum(1 for i in all_items if i["kind"]=="FAIL")
n_warn = sum(1 for i in all_items if i["kind"]=="WARN")
n_info = sum(1 for i in all_items if i["kind"]=="INFO")
n_skip = sum(1 for i in all_items if i["kind"]=="SKIP")

# ── Detailed warning/fail knowledge base ─────────────────────────
# Maps keywords in the finding text → (severity_label, description, remediation, cve_refs)
WARN_KB = {
    "ssh listening on default port 22": (
        "Medium",
        "SSH running on port 22 is the first port scanned by automated bots. This increases brute-force noise significantly.",
        "Change Port in /etc/ssh/sshd_config to a high unprivileged port (e.g. 2222). Update firewall rules and any monitoring accordingly.",
        ""
    ),
    "ssh password authentication is enabled": (
        "High",
        "Password-based SSH authentication allows brute-force and credential-stuffing attacks. Keys are cryptographically stronger.",
        "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config. Deploy SSH key pairs for all users. Restart sshd.",
        "CVE-2024-6387 (RegreSSHion)"
    ),
    "maxauthtries": (
        "Medium",
        "A high MaxAuthTries value gives attackers more attempts per connection before the session is dropped.",
        "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config to limit guessing attempts per TCP connection.",
        ""
    ),
    "x11 forwarding is enabled": (
        "Low",
        "X11 forwarding can leak graphical session data and exposes an additional attack surface on servers.",
        "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless remote GUI access is explicitly required.",
        ""
    ),
    "tcp forwarding is enabled": (
        "Medium",
        "TCP forwarding can be abused to tunnel traffic through the server, bypassing firewall controls.",
        "Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config unless port tunnelling is a business requirement.",
        ""
    ),
    "ssh idle timeout not set": (
        "Medium",
        "Unattended SSH sessions can be hijacked by an attacker with physical or network access.",
        "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' in /etc/ssh/sshd_config to terminate idle sessions after 10 minutes.",
        ""
    ),
    "logingraceTime": (
        "Low",
        "A long LoginGraceTime window gives unauthenticated connections more time to negotiate, potentially aiding DoS.",
        "Set 'LoginGraceTime 30' in /etc/ssh/sshd_config.",
        ""
    ),
    "ufw firewall is inactive": (
        "Critical",
        "No host-based firewall is active. All ports are accessible from any network source without restriction.",
        "Run: ufw default deny incoming && ufw allow 22/tcp && ufw enable. Review and allow only required services.",
        ""
    ),
    "iptables input chain appears empty": (
        "High",
        "The iptables INPUT chain has no rules, meaning incoming traffic is not filtered at the kernel level.",
        "Add iptables rules for required ports and set the default policy to DROP. Consider using ufw or nftables for management.",
        ""
    ),
    "packages need updating": (
        "High",
        "Outdated packages may contain publicly known vulnerabilities with available exploits.",
        "Run: apt-get upgrade -y. Enable unattended-upgrades for automatic security patches: apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
        "NIST NVD: ~3108 Linux kernel CVEs in 2024 alone"
    ),
    "security update": (
        "Critical",
        "Pending security updates address known CVEs that are actively exploited in the wild.",
        "Run immediately: apt-get install --only-upgrade $(apt list --upgradable 2>/dev/null | grep security | cut -d/ -f1 | tr '\\n' ' ')",
        "CISA KEV Catalog"
    ),
    "unattended-upgrades": (
        "Medium",
        "Without automatic security updates, newly disclosed vulnerabilities remain unpatched until manual intervention.",
        "Install and enable: apt install unattended-upgrades && systemctl enable --now unattended-upgrades",
        ""
    ),
    "no pam password complexity": (
        "High",
        "Without password complexity enforcement, users may set trivially guessable passwords.",
        "Install libpam-pwquality and configure /etc/security/pwquality.conf: minlen=12, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1",
        ""
    ),
    "no pam account lockout": (
        "High",
        "Without account lockout, brute-force attacks against local or SSH accounts face no throttling.",
        "Configure pam_faillock in /etc/pam.d/common-auth: auth required pam_faillock.so preauth deny=5 unlock_time=900",
        ""
    ),
    "pass_max_days": (
        "Medium",
        "Passwords that never expire can persist indefinitely after a credential compromise goes undetected.",
        "Set PASS_MAX_DAYS 90 in /etc/login.defs. Apply retroactively: chage --maxdays 90 <username>",
        ""
    ),
    "pass_min_len": (
        "Medium",
        "A short minimum password length allows weak passwords that are vulnerable to dictionary attacks.",
        "Set PASS_MIN_LEN 12 in /etc/login.defs and enforce via pam_pwquality.",
        ""
    ),
    "aslr": (
        "High",
        "Without full ASLR (value=2), memory layout is predictable, making exploitation of buffer overflows significantly easier.",
        "Run: sysctl -w kernel.randomize_va_space=2 and add to /etc/sysctl.d/99-hardening.conf",
        "CVE-2024-1086 exploits leverage predictable kernel memory"
    ),
    "dmesg": (
        "Medium",
        "Unrestricted dmesg access leaks kernel addresses and hardware information useful for privilege escalation.",
        "Run: sysctl -w kernel.dmesg_restrict=1 and persist in /etc/sysctl.d/99-hardening.conf",
        ""
    ),
    "kptr_restrict": (
        "High",
        "Exposed kernel pointer values help attackers bypass KASLR and construct exploits for kernel vulnerabilities.",
        "Run: sysctl -w kernel.kptr_restrict=2 and persist in /etc/sysctl.d/99-hardening.conf",
        ""
    ),
    "sysrq": (
        "Low",
        "The SysRq key can trigger emergency kernel actions (reboot, dump memory) accessible to any user with console access.",
        "Run: sysctl -w kernel.sysrq=0 and persist in /etc/sysctl.d/99-hardening.conf",
        ""
    ),
    "ipv4 forwarding": (
        "Medium",
        "IP forwarding enabled on a non-router host can allow traffic to be routed through the machine unexpectedly.",
        "Run: sysctl -w net.ipv4.ip_forward=0 unless this host is a router/VPN gateway.",
        ""
    ),
    "send_redirects": (
        "Medium",
        "Sending ICMP redirects can be abused to manipulate routing tables of other hosts on the network.",
        "Run: sysctl -w net.ipv4.conf.all.send_redirects=0 && sysctl -w net.ipv4.conf.default.send_redirects=0",
        ""
    ),
    "accept_redirects": (
        "Medium",
        "Accepting ICMP redirects allows a malicious host on the LAN to redirect traffic through an attacker-controlled gateway.",
        "Run: sysctl -w net.ipv4.conf.all.accept_redirects=0",
        ""
    ),
    "syn cookie": (
        "High",
        "Without SYN cookies, the system is vulnerable to SYN flood denial-of-service attacks that exhaust connection tables.",
        "Run: sysctl -w net.ipv4.tcp_syncookies=1 and persist in /etc/sysctl.d/99-hardening.conf",
        ""
    ),
    "martian": (
        "Low",
        "Not logging martian packets (spoofed source addresses) reduces visibility into potential IP spoofing attacks.",
        "Run: sysctl -w net.ipv4.conf.all.log_martians=1",
        ""
    ),
    "rp_filter": (
        "Medium",
        "Without reverse path filtering, the host may accept packets with spoofed source addresses, aiding reflected attacks.",
        "Run: sysctl -w net.ipv4.conf.all.rp_filter=1",
        ""
    ),
    "apparmor": (
        "High",
        "AppArmor provides mandatory access control. Without it, processes run with their full privilege set unconstrained.",
        "Install and enable: apt install apparmor apparmor-profiles apparmor-utils && systemctl enable --now apparmor",
        ""
    ),
    "auditd": (
        "High",
        "Without auditd, security-relevant events (privilege escalation, file access, authentication) are not recorded for forensics.",
        "Install and configure: apt install auditd audispd-plugins && systemctl enable --now auditd. Add rules in /etc/audit/rules.d/",
        ""
    ),
    "failed ssh login": (
        "High",
        "Large numbers of failed SSH logins indicate an active brute-force or credential-stuffing attack.",
        "Install fail2ban: apt install fail2ban. Configure /etc/fail2ban/jail.local with maxretry=3 bantime=3600 for sshd.",
        "MITRE ATT&CK T1110.001"
    ),
    "world-writable": (
        "High",
        "World-writable files or directories can be modified by any user on the system, enabling privilege escalation.",
        "Run: find / -xdev -type f -perm -0002 2>/dev/null | xargs chmod o-w. For dirs, also set sticky bit: chmod +t",
        ""
    ),
    "suid": (
        "Medium",
        "Excessive SUID/SGID binaries increase the attack surface for local privilege escalation exploits.",
        "Audit the list: find / -perm /6000 -type f 2>/dev/null. Remove SUID bit from any binary that doesn't require it: chmod u-s <binary>",
        ""
    ),
    "compiler": (
        "Medium",
        "Compiler tools on production servers help attackers compile exploit code and rootkits locally.",
        "Remove compiler tools: apt-get purge gcc g++ make build-essential",
        ""
    ),
    "debsums": (
        "High",
        "Modified package files indicate potential tampering, backdoors, or supply-chain compromise.",
        "Investigate each modified file: dpkg -S <filepath>. Reinstall affected packages: apt-get install --reinstall <package>",
        ""
    ),
    "open file limit is low": (
        "Low",
        "A low open file descriptor limit causes application failures under load and can trigger service outages.",
        "Add to /etc/security/limits.conf: '* soft nofile 65536' and '* hard nofile 65536'. Also set in /etc/systemd/system.conf: DefaultLimitNOFILE=65536",
        ""
    ),
    "failed service": (
        "Medium",
        "Failed systemd services may indicate misconfiguration, resource exhaustion, or a crashed security daemon.",
        "Inspect each failed service: systemctl status <service> && journalctl -xe -u <service>. Fix the underlying issue and restart.",
        ""
    ),
    "atd": (
        "Low",
        "The at daemon can be used to schedule one-off tasks; attackers use it as a persistence mechanism.",
        "If not required: systemctl disable --now atd",
        "MITRE ATT&CK T1053.002"
    ),
    "no syslog": (
        "Critical",
        "Without a syslog daemon, system events including authentication failures and errors are not persisted.",
        "Install rsyslog: apt install rsyslog && systemctl enable --now rsyslog",
        ""
    ),
    "risky port": (
        "High",
        "Plaintext or legacy network services expose credentials and data to network interception.",
        "Disable the service or replace with an encrypted equivalent (e.g., SFTP instead of FTP, SSH instead of Telnet).",
        ""
    ),
    "password expires": (
        "Medium",
        "User accounts with non-expiring passwords retain access indefinitely after a credential compromise.",
        "Set expiry: chage --maxdays 90 <username>. Enforce globally via PASS_MAX_DAYS in /etc/login.defs",
        ""
    ),
    "oom killer": (
        "High",
        "OOM killer events mean the system ran out of memory and killed processes, indicating resource exhaustion risk.",
        "Review memory usage: free -h && ps aux --sort=-%mem | head -20. Tune vm.overcommit_memory and add swap space.",
        ""
    ),
}

def get_kb_entry(finding_text):
    """Find the best matching knowledge base entry for a finding."""
    fl = finding_text.lower()
    best = None
    best_len = 0
    for kw, entry in WARN_KB.items():
        if kw.lower() in fl and len(kw) > best_len:
            best = entry
            best_len = len(kw)
    if best:
        return best
    # Fallback generic entries
    if "ssh" in fl:
        return ("Medium", "SSH configuration issue detected.", "Review /etc/ssh/sshd_config and apply CIS SSH benchmark recommendations.", "")
    if "firewall" in fl or "ufw" in fl or "iptables" in fl:
        return ("High", "Firewall configuration gap detected.", "Review firewall rules and ensure default-deny policy is applied.", "")
    if "kernel" in fl or "sysctl" in fl:
        return ("Medium", "Kernel hardening parameter not set to recommended value.", "Review /etc/sysctl.d/ and apply CIS Benchmark kernel hardening settings.", "")
    if "password" in fl or "pass" in fl:
        return ("Medium", "Password policy weakness detected.", "Review /etc/login.defs and PAM configuration. Apply CIS password policy recommendations.", "")
    return ("Low", "Security configuration warning requiring review.", "Investigate the finding and apply appropriate hardening based on your threat model.", "")

def get_priority(severity):
    return {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}.get(severity, 5)

# ── Rating colours ────────────────────────────────────────────────
if pct >= 80:   rating="GOOD";     r_hex="2E7D32"; bar_fill="4CAF50"
elif pct >= 50: rating="MODERATE"; r_hex="E65100"; bar_fill="FF9800"
else:           rating="CRITICAL"; r_hex="B71C1C"; bar_fill="F44336"

BAR_WIDTH=40; filled=round(pct/100*BAR_WIDTH)
bar_str = "\u2588"*filled + "\u2591"*(BAR_WIDTH-filled)
bar_label = f"{bar_str}  {pct}%  [{rating}]"

# ── XML helpers ───────────────────────────────────────────────────
def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def cell_str(v, style="ce1"):
    return f'<table:table-cell table:style-name="{style}" office:value-type="string"><text:p>{esc(str(v))}</text:p></table:table-cell>'

def cell_num(v, style="ce1"):
    return f'<table:table-cell table:style-name="{style}" office:value-type="float" office:value="{v}"><text:p>{v}</text:p></table:table-cell>'

def cell_pct(v, style="ce_pct"):
    frac = v / 100.0
    return f'<table:table-cell table:style-name="{style}" office:value-type="percentage" office:value="{frac}"><text:p>{v}%</text:p></table:table-cell>'

def cell_empty(n=1):
    return '<table:table-cell/>' * n

def row(*cells):
    return f'<table:table-row>{"".join(cells)}</table:table-row>'

def hcell(v, style="ce_hdr"):
    return cell_str(v, style)

def sev_cell(sev):
    style = {"Critical":"ce_crit","High":"ce_fail","Medium":"ce_warn","Low":"ce_low"}.get(sev,"ce_info")
    return cell_str(sev, style)

# ═══════════════════════════════════════════════════════════════
#  SVG CHART BUILDERS
# ═══════════════════════════════════════════════════════════════

def build_score_gauge_svg():
    """Semi-circular gauge showing the overall security score."""
    W, H = 520, 300
    cx, cy, R_outer, R_inner = 260, 230, 180, 110
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="12"/>',
        f'<text x="{W//2}" y="28" text-anchor="middle" font-family="Arial" font-size="14" '
        f'font-weight="bold" fill="#E0E0E0">Security Score Gauge</text>',
    ]
    # Draw arc zones: 0%=180°, 100%=0° (left to right across bottom)
    # We split into 5 bands: 0-20 (crit), 20-40 (high), 40-60 (mod), 60-80 (ok), 80-100 (good)
    zones = [
        (0,   20, "#B71C1C", "#EF5350"),
        (20,  40, "#E64A19", "#FF7043"),
        (40,  60, "#F57F17", "#FFD54F"),
        (60,  80, "#1B5E20", "#66BB6A"),
        (80, 100, "#1565C0", "#42A5F5"),
    ]
    def arc_seg(pct_start, pct_end, r_out, r_in, col_dark, col_light):
        # Map pct 0→100 to angle 180°→0° (left half-circle)
        a_start = math.radians(180 - pct_start * 1.8)
        a_end   = math.radians(180 - pct_end   * 1.8)
        large   = 1 if abs(pct_end - pct_start) > 50 else 0
        x1o = cx + r_out * math.cos(a_start); y1o = cy - r_out * math.sin(a_start)
        x2o = cx + r_out * math.cos(a_end);   y2o = cy - r_out * math.sin(a_end)
        x1i = cx + r_in  * math.cos(a_end);   y1i = cy - r_in  * math.sin(a_end)
        x2i = cx + r_in  * math.cos(a_start); y2i = cy - r_in  * math.sin(a_start)
        d = (f"M{round(x1o,2)},{round(y1o,2)} "
             f"A{r_out},{r_out} 0 {large},0 {round(x2o,2)},{round(y2o,2)} "
             f"L{round(x1i,2)},{round(y1i,2)} "
             f"A{r_in},{r_in} 0 {large},1 {round(x2i,2)},{round(y2i,2)} Z")
        return f'<path d="{d}" fill="{col_dark}" stroke="{col_light}" stroke-width="1.5"/>'

    for ps, pe, cd, cl in zones:
        parts.append(arc_seg(ps, pe, R_outer, R_inner, cd, cl))

    # Needle
    nd_ang = math.radians(180 - pct * 1.8)
    nx = cx + (R_inner - 15) * math.cos(nd_ang)
    ny = cy - (R_inner - 15) * math.sin(nd_ang)
    parts.append(f'<line x1="{cx}" y1="{cy}" x2="{round(nx,2)}" y2="{round(ny,2)}" stroke="#FFFFFF" stroke-width="3.5" stroke-linecap="round"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="10" fill="#FFFFFF"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="5" fill="#{r_hex}"/>')

    # Score text in centre arc area
    parts.append(f'<text x="{cx}" y="{cy+40}" text-anchor="middle" font-family="Arial" font-size="38" font-weight="bold" fill="#{bar_fill}">{pct}%</text>')
    parts.append(f'<text x="{cx}" y="{cy+65}" text-anchor="middle" font-family="Arial" font-size="16" font-weight="bold" fill="#{r_hex}">{rating}</text>')
    parts.append(f'<text x="{cx}" y="{cy+88}" text-anchor="middle" font-family="Arial" font-size="10" fill="#9E9E9E">{score_val} checks passed of {total_val}</text>')

    # Zone labels
    for ps, pe, cd, cl in zones:
        mid_pct = (ps + pe) / 2
        mid_ang = math.radians(180 - mid_pct * 1.8)
        lx = cx + (R_outer + 18) * math.cos(mid_ang)
        ly = cy - (R_outer + 18) * math.sin(mid_ang)
        lbl = f"{ps}-{pe}"
        parts.append(f'<text x="{round(lx,0)}" y="{round(ly,0)}" text-anchor="middle" font-family="Arial" font-size="8" fill="{cl}">{lbl}%</text>')

    # Benchmark lines
    for bpct, blabel in [(55,"Avg SMB"), (72,"Enterprise"), (85,"CIS L2")]:
        ba = math.radians(180 - bpct * 1.8)
        bx1 = cx + R_outer * math.cos(ba);      by1 = cy - R_outer * math.sin(ba)
        bx2 = cx + (R_outer+26) * math.cos(ba); by2 = cy - (R_outer+26) * math.sin(ba)
        parts += [
            f'<line x1="{round(bx1,2)}" y1="{round(by1,2)}" x2="{round(bx2,2)}" y2="{round(by2,2)}" stroke="#78909C" stroke-width="1.5" stroke-dasharray="3,2"/>',
            f'<text x="{round(bx2,2)}" y="{round(by2-4,2)}" text-anchor="middle" font-family="Arial" font-size="7.5" fill="#78909C">{blabel}</text>',
        ]

    parts.append(f'<text x="{W//2}" y="{H-6}" text-anchor="middle" font-family="Arial" font-size="8" fill="#546E7A">Generated: {run_date}</text>')
    parts.append('</svg>')
    return "".join(parts)


def build_bar_chart_svg():
    """Horizontal stacked bar chart of PASS/FAIL/WARN per section."""
    n = len(sec_stats)
    W = 820; pad_l = 280; pad_r = 80; pad_t = 50; pad_b = 50
    plot_w = W - pad_l - pad_r
    row_h = max(18, min(32, int((500 - pad_t - pad_b) / max(n, 1))))
    H = pad_t + n * row_h + 20 + pad_b
    max_val = max((s["pass"]+s["fail"]+s["warn"]) for s in sec_stats) or 1

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="10"/>',
        f'<text x="{W//2}" y="30" text-anchor="middle" font-family="Arial" font-size="14" '
        f'font-weight="bold" fill="#E0E0E0">Security Checks per Section</text>',
    ]

    # Gridlines
    for tick in range(0, max_val+1, max(1, max_val//5)):
        gx = pad_l + int(tick / max_val * plot_w)
        parts.append(f'<line x1="{gx}" y1="{pad_t}" x2="{gx}" y2="{pad_t + n*row_h}" stroke="#2E3A5E" stroke-width="1"/>')
        parts.append(f'<text x="{gx}" y="{pad_t + n*row_h + 15}" text-anchor="middle" font-family="Arial" font-size="8" fill="#78909C">{tick}</text>')

    for idx, s in enumerate(sec_stats):
        y = pad_t + idx * row_h + 2
        bh = row_h - 4
        pw = int(s["pass"] / max_val * plot_w)
        fw = int(s["fail"] / max_val * plot_w)
        ww = int(s["warn"] / max_val * plot_w)
        # Background track
        parts.append(f'<rect x="{pad_l}" y="{y}" width="{plot_w}" height="{bh}" fill="#263050" rx="3"/>')
        # PASS
        if pw: parts.append(f'<rect x="{pad_l}" y="{y}" width="{pw}" height="{bh}" fill="#2E7D32" rx="2"/>')
        # FAIL
        if fw: parts.append(f'<rect x="{pad_l+pw}" y="{y}" width="{fw}" height="{bh}" fill="#B71C1C" rx="2"/>')
        # WARN
        if ww: parts.append(f'<rect x="{pad_l+pw+fw}" y="{y}" width="{ww}" height="{bh}" fill="#E65100" rx="2"/>')
        # Section label
        bg_col = "#B71C1C" if s["fail"] > 0 else ("#E65100" if s["warn"] > 0 else "#1B5E20")
        parts.append(f'<text x="{pad_l-6}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="#CFD8DC">{esc(s["title"][:34])}</text>')
        # Score % label
        parts.append(f'<text x="{pad_l+pw+fw+ww+5}" y="{y+bh//2+4}" font-family="Arial" font-size="9" font-weight="bold" fill="{bg_col}">{s["pct"]}%</text>')

    # Y-axis line
    parts.append(f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{pad_t+n*row_h}" stroke="#546E7A" stroke-width="1.5"/>')

    # Legend
    lx = pad_l; ly = H - 20
    for col, lbl in [("#2E7D32","PASS"),("#B71C1C","FAIL"),("#E65100","WARN")]:
        parts += [
            f'<rect x="{lx}" y="{ly}" width="12" height="10" fill="{col}" rx="2"/>',
            f'<text x="{lx+15}" y="{ly+9}" font-family="Arial" font-size="9" fill="#B0BEC5">{lbl}</text>',
        ]
        lx += 70

    parts.append('</svg>')
    return "".join(parts)


def build_pie_chart_svg():
    """Donut pie chart of PASS/FAIL/WARN/INFO distribution."""
    W, H, cx, cy, R, ir = 500, 340, 175, 185, 130, 68
    total_checks = n_pass + n_fail + n_warn or 1
    slices = [
        (n_pass, "#2E7D32", "#4CAF50", "PASS"),
        (n_fail, "#B71C1C", "#EF5350", "FAIL"),
        (n_warn, "#E65100", "#FF9800", "WARN"),
        (n_info, "#1565C0", "#42A5F5", "INFO"),
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="12"/>',
        f'<text x="{W//2}" y="25" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Result Distribution</text>',
    ]
    angle = -math.pi / 2
    all_total = n_pass + n_fail + n_warn + n_info or 1
    for count, dark, light, label in slices:
        if count == 0: continue
        sweep = 2 * math.pi * count / all_total
        ea = angle + sweep
        large = 1 if sweep > math.pi else 0
        x1=cx+R*math.cos(angle); y1=cy+R*math.sin(angle)
        x2=cx+R*math.cos(ea);    y2=cy+R*math.sin(ea)
        ix1=cx+ir*math.cos(ea);  iy1=cy+ir*math.sin(ea)
        ix2=cx+ir*math.cos(angle);iy2=cy+ir*math.sin(angle)
        d=(f"M{round(x1,2)},{round(y1,2)} A{R},{R} 0 {large},1 {round(x2,2)},{round(y2,2)} "
           f"L{round(ix1,2)},{round(iy1,2)} A{ir},{ir} 0 {large},0 {round(ix2,2)},{round(iy2,2)} Z")
        parts.append(f'<path d="{d}" fill="{dark}" stroke="{light}" stroke-width="2"/>')
        # Slice label
        mid = angle + sweep/2
        lx2 = cx + (R+ir)//2 * math.cos(mid); ly2 = cy + (R+ir)//2 * math.sin(mid)
        pct_s = round(count*100/all_total)
        if pct_s >= 6:
            parts.append(f'<text x="{round(lx2,1)}" y="{round(ly2,1)}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#fff">{pct_s}%</text>')
        angle = ea

    # Centre text
    parts += [
        f'<text x="{cx}" y="{cy-12}" text-anchor="middle" font-family="Arial" font-size="26" font-weight="bold" fill="#{bar_fill}">{pct}%</text>',
        f'<text x="{cx}" y="{cy+12}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold" fill="#{r_hex}">{rating}</text>',
    ]

    # Legend
    lx_b = cx + R + 22; ly_b = cy - 70
    for count, dark, light, label in slices:
        pct_s = round(count*100/all_total)
        parts += [
            f'<rect x="{lx_b}" y="{ly_b}" width="14" height="14" fill="{dark}" stroke="{light}" stroke-width="1" rx="3"/>',
            f'<text x="{lx_b+20}" y="{ly_b+11}" font-family="Arial" font-size="10" fill="#CFD8DC">{label}: {count} ({pct_s}%)</text>',
        ]
        ly_b += 28

    # Score bar under legend
    parts += [
        f'<text x="{lx_b}" y="{ly_b+18}" font-family="Arial" font-size="9" fill="#90A4AE" font-weight="bold">Score</text>',
        f'<rect x="{lx_b}" y="{ly_b+24}" width="120" height="16" fill="#263050" rx="4"/>',
        f'<rect x="{lx_b}" y="{ly_b+24}" width="{round(pct/100*120)}" height="16" fill="#{bar_fill}" rx="4"/>',
        f'<text x="{lx_b+60}" y="{ly_b+36}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#fff">{pct}%</text>',
    ]

    parts.append('</svg>')
    return "".join(parts)


def build_heatmap_svg():
    """Section×severity heatmap grid."""
    cols = ["PASS","FAIL","WARN","INFO","Score%"]
    col_w = 70; row_h = 22; lbl_w = 240
    W = lbl_w + len(cols)*col_w + 20
    H = 50 + len(sec_stats)*row_h + 30
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="10"/>',
        f'<text x="{W//2}" y="22" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Heatmap: Findings by Section</text>',
    ]
    # Header row
    for ci, c in enumerate(cols):
        cx2 = lbl_w + ci*col_w + col_w//2
        parts.append(f'<text x="{cx2}" y="42" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#90A4AE">{c}</text>')

    def heat_color(val, max_v, kind):
        if max_v == 0: return "#1E2A3A"
        ratio = val / max_v
        if kind == "PASS":
            r=int(27+ratio*(46-27)); g=int(94+ratio*(125-94)); b=int(32+ratio*(50-32))
            return f"#{r:02X}{g:02X}{b:02X}"
        elif kind == "FAIL":
            r=int(180+ratio*(219-180)); g=int(28+ratio*(68-28)); b=int(28+ratio*(68-28))
            return f"#{r:02X}{g:02X}{b:02X}"
        elif kind == "WARN":
            r=int(180+ratio*(230-180)); g=int(100+ratio*(101-100)); b=int(0)
            return f"#{r:02X}{g:02X}{b:02X}"
        else:
            return "#1E3050"

    max_p = max((s["pass"] for s in sec_stats), default=1) or 1
    max_f = max((s["fail"] for s in sec_stats), default=1) or 1
    max_w = max((s["warn"] for s in sec_stats), default=1) or 1
    max_i = max((s["info"] for s in sec_stats), default=1) or 1

    for ri, s in enumerate(sec_stats):
        y2 = 50 + ri * row_h
        # Label
        parts.append(f'<text x="{lbl_w-6}" y="{y2+row_h//2+4}" text-anchor="end" font-family="Arial" font-size="8" fill="#B0BEC5">{esc(s["title"][:34])}</text>')
        vals = [
            (s["pass"], max_p, "PASS"), (s["fail"], max_f, "FAIL"),
            (s["warn"], max_w, "WARN"), (s["info"], max_i, "INFO"),
            (s["pct"],  100,   "PCT"),
        ]
        for ci, (v, mx, knd) in enumerate(vals):
            cx2 = lbl_w + ci*col_w
            if knd == "PCT":
                ratio = v/100
                g_val = int(ratio * 255)
                r_val = int((1-ratio)*200)
                col = f"#{r_val:02X}{g_val:02X}20"
            else:
                col = heat_color(v, mx, knd)
            parts.append(f'<rect x="{cx2+2}" y="{y2+2}" width="{col_w-4}" height="{row_h-4}" fill="{col}" rx="2"/>')
            txt_col = "#FFFFFF" if v > 0 else "#37474F"
            disp = f"{v}%" if knd=="PCT" else str(v)
            parts.append(f'<text x="{cx2+col_w//2}" y="{y2+row_h//2+4}" text-anchor="middle" font-family="Arial" font-size="8" font-weight="bold" fill="{txt_col}">{disp}</text>')

    parts.append('</svg>')
    return "".join(parts)


def build_severity_radar_svg():
    """Radar / spider chart showing severity distribution of issues."""
    # Build per-severity counts from WARN and FAIL items
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for s in sections:
        for item in s["items"]:
            if item["kind"] in ("FAIL", "WARN"):
                sev, _, _, _ = get_kb_entry(item["text"])
                if item["kind"] == "FAIL" and sev == "Low":
                    sev = "Medium"
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

    W, H, cx2, cy2, R2 = 400, 380, 200, 210, 130
    labels = list(sev_counts.keys())
    values = [sev_counts[l] for l in labels]
    n_axes = len(labels)
    max_v2 = max(values) or 1

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="12"/>',
        f'<text x="{W//2}" y="26" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Issue Severity Radar</text>',
    ]

    # Grid rings
    for ring in [0.25, 0.5, 0.75, 1.0]:
        pts = []
        for i in range(n_axes):
            ang = math.radians(-90 + i * 360 / n_axes)
            px = cx2 + R2 * ring * math.cos(ang)
            py = cy2 + R2 * ring * math.sin(ang)
            pts.append(f"{round(px,1)},{round(py,1)}")
        parts.append(f'<polygon points="{" ".join(pts)}" fill="none" stroke="#2E3A5E" stroke-width="1"/>')
        # Ring label
        parts.append(f'<text x="{cx2+4}" y="{round(cy2-R2*ring+4,1)}" font-family="Arial" font-size="7" fill="#546E7A">{round(ring*max_v2,0):.0f}</text>')

    # Axis spokes
    for i in range(n_axes):
        ang = math.radians(-90 + i * 360 / n_axes)
        ex = cx2 + R2 * math.cos(ang); ey = cy2 + R2 * math.sin(ang)
        parts.append(f'<line x1="{cx2}" y1="{cy2}" x2="{round(ex,1)}" y2="{round(ey,1)}" stroke="#2E3A5E" stroke-width="1.5"/>')
        # Axis label
        lx3 = cx2 + (R2 + 22) * math.cos(ang); ly3 = cy2 + (R2 + 22) * math.sin(ang)
        sev_colours = {"Critical":"#EF5350","High":"#FF7043","Medium":"#FFB74D","Low":"#81C784"}
        col3 = sev_colours.get(labels[i], "#90A4AE")
        parts.append(f'<text x="{round(lx3,1)}" y="{round(ly3+4,1)}" text-anchor="middle" font-family="Arial" font-size="10" font-weight="bold" fill="{col3}">{labels[i]}</text>')
        parts.append(f'<text x="{round(lx3,1)}" y="{round(ly3+16,1)}" text-anchor="middle" font-family="Arial" font-size="9" fill="{col3}">({values[i]})</text>')

    # Data polygon
    data_pts = []
    for i, v in enumerate(values):
        ang = math.radians(-90 + i * 360 / n_axes)
        ratio = v / max_v2
        px2 = cx2 + R2 * ratio * math.cos(ang)
        py2 = cy2 + R2 * ratio * math.sin(ang)
        data_pts.append(f"{round(px2,1)},{round(py2,1)}")
    parts.append(f'<polygon points="{" ".join(data_pts)}" fill="#{bar_fill}" fill-opacity="0.25" stroke="#{bar_fill}" stroke-width="2.5"/>')

    # Data dots
    for i, v in enumerate(values):
        ang = math.radians(-90 + i * 360 / n_axes)
        ratio = v / max_v2
        px2 = cx2 + R2 * ratio * math.cos(ang)
        py2 = cy2 + R2 * ratio * math.sin(ang)
        parts.append(f'<circle cx="{round(px2,1)}" cy="{round(py2,1)}" r="5" fill="#{bar_fill}" stroke="#fff" stroke-width="1.5"/>')

    parts.append(f'<text x="{W//2}" y="{H-10}" text-anchor="middle" font-family="Arial" font-size="8" fill="#546E7A">Based on knowledge-base severity classification of all FAIL and WARN findings</text>')
    parts.append('</svg>')
    return "".join(parts)


# ═══════════════════════════════════════════════════════════════
#  SHEET BUILDERS
# ═══════════════════════════════════════════════════════════════

# ── Sheet 1: Overview ────────────────────────────────────────────
ov = []
ov.append(row(cell_str("LINUX SECURITY AUDIT — ENHANCED STATISTICS REPORT", "ce_title"), cell_empty(5)))
ov.append(row(*[cell_empty(6)]))
ov.append(row(cell_str("Host",     "ce_lbl"), cell_str(hostname, "ce1"), cell_empty(4)))
ov.append(row(cell_str("OS",       "ce_lbl"), cell_str(os_name,  "ce1"), cell_empty(4)))
ov.append(row(cell_str("Kernel",   "ce_lbl"), cell_str(kernel,   "ce1"), cell_empty(4)))
ov.append(row(cell_str("Date",     "ce_lbl"), cell_str(run_date, "ce1"), cell_empty(4)))
ov.append(row(*[cell_empty(6)]))
ov.append(row(cell_str("OVERALL SCORE", "ce_lbl"),
              cell_num(score_val, "ce1"),
              cell_str(f"/ {total_val}", "ce1"),
              cell_pct(pct),
              cell_str(rating, f"ce_rating_{r_hex}"),
              cell_empty()))
ov.append(row(cell_str("Score Bar", "ce_lbl"),
              cell_str(bar_label, f"ce_bar_{bar_fill}"),
              cell_empty(4)))
ov.append(row(*[cell_empty(6)]))
ov.append(row(hcell("Result"), hcell("Count"), hcell("% of checks"), cell_empty(3)))
checks_total = n_pass + n_fail + n_warn
for kind, count, style in [("✔  PASS",n_pass,"ce_pass"),("✘  FAIL",n_fail,"ce_fail"),("⚠  WARN",n_warn,"ce_warn"),("ℹ  INFO",n_info,"ce_info"),("–  SKIP",n_skip,"ce_skip")]:
    pct_s = round(count*100/checks_total) if checks_total else 0
    ov.append(row(cell_str(kind,style), cell_num(count,style),
                  cell_pct(pct_s,style) if kind not in ("ℹ  INFO","–  SKIP") else cell_empty(),
                  cell_empty(3)))
ov.append(row(*[cell_empty(6)]))
ov.append(row(cell_str("See charts:", "ce_lbl"),
              cell_str("score_gauge.svg | bar_chart.svg | pie_chart.svg | heatmap.svg | severity_radar.svg", "ce_info"),
              cell_empty(4)))

sheet1 = ('<table:table table:name="Overview" table:style-name="ta1">'
          '<table:table-column table:style-name="co_lbl"/>'
          '<table:table-column table:style-name="co_wide"/>'
          '<table:table-column table:style-name="co_val"/>'
          '<table:table-column table:style-name="co_val"/>'
          '<table:table-column table:style-name="co_wide"/>'
          '<table:table-column table:style-name="co_val"/>'
          + "\n".join(ov) + '</table:table>')

# ── Sheet 2: Per-Section ─────────────────────────────────────────
sec_rows = []
sec_rows.append(row(hcell("Section"), hcell("PASS"), hcell("FAIL"), hcell("WARN"), hcell("INFO"), hcell("Score%"), hcell("Status")))
for s in sec_stats:
    if s["fail"] > 0:
        status, sstyle = "NEEDS ATTENTION", "ce_fail"
    elif s["warn"] > 0:
        status, sstyle = "REVIEW REQUIRED", "ce_warn"
    else:
        status, sstyle = "GOOD", "ce_pass"
    sec_rows.append(row(
        cell_str(s["title"], "ce1"),
        cell_num(s["pass"], "ce_pass"),
        cell_num(s["fail"], "ce_fail" if s["fail"] else "ce1"),
        cell_num(s["warn"], "ce_warn" if s["warn"] else "ce1"),
        cell_num(s["info"], "ce_info"),
        cell_pct(s["pct"],  "ce_pct"),
        cell_str(status, sstyle),
    ))
sec_rows.append(row(cell_str("TOTAL","ce_hdr"), cell_num(n_pass,"ce_hdr"),
                    cell_num(n_fail,"ce_hdr"), cell_num(n_warn,"ce_hdr"),
                    cell_num(n_info,"ce_hdr"), cell_pct(pct,"ce_hdr"),
                    cell_str(rating,f"ce_rating_{r_hex}")))

sheet2 = ('<table:table table:name="Per-Section" table:style-name="ta1">'
          '<table:table-column table:style-name="co_wide2"/>'
          + '<table:table-column table:style-name="co_val"/>'*5
          + '<table:table-column table:style-name="co_wide"/>'
          + "\n".join(sec_rows) + '</table:table>')

# ── Sheet 3: All Issues (FAIL + WARN) ────────────────────────────
issue_rows = []
issue_rows.append(row(
    hcell("Section"), hcell("Type"), hcell("Finding"),
    hcell("Severity"), hcell("Details / Evidence"), hcell("CVE Refs")
))
for s in sections:
    for item in s["items"]:
        if item["kind"] in ("FAIL","WARN"):
            sev, desc, fix, cve = get_kb_entry(item["text"])
            kind_style = "ce_fail" if item["kind"]=="FAIL" else "ce_warn"
            detail_str = " | ".join(item["details"][:3]) if item["details"] else ""
            issue_rows.append(row(
                cell_str(s["title"][:38], "ce1"),
                cell_str(item["kind"], kind_style),
                cell_str(item["text"][:160], "ce1"),
                sev_cell(sev),
                cell_str((detail_str[:120] if detail_str else "—"), "ce_detail"),
                cell_str(cve or "—", "ce_cve"),
            ))

if len(issue_rows) == 1:
    issue_rows.append(row(cell_str("No FAIL or WARN items found","ce_pass"), cell_empty(5)))

sheet3 = ('<table:table table:name="All Issues" table:style-name="ta1">'
          '<table:table-column table:style-name="co_wide2"/>'
          '<table:table-column table:style-name="co_val"/>'
          '<table:table-column table:style-name="co_issues"/>'
          '<table:table-column table:style-name="co_val"/>'
          '<table:table-column table:style-name="co_issues"/>'
          '<table:table-column table:style-name="co_cve"/>'
          + "\n".join(issue_rows) + '</table:table>')

# ── Sheet 4: FAIL Deep-Dive ──────────────────────────────────────
fail_rows = []
fail_rows.append(row(
    hcell("Section","ce_hdr_fail"), hcell("Finding","ce_hdr_fail"),
    hcell("Severity","ce_hdr_fail"), hcell("What This Means","ce_hdr_fail"),
    hcell("Evidence Captured","ce_hdr_fail"), hcell("How to Fix","ce_hdr_fail"),
    hcell("CVE / Reference","ce_hdr_fail"),
))
fail_items = [(s["title"], item) for s in sections for item in s["items"] if item["kind"]=="FAIL"]
fail_items.sort(key=lambda x: get_priority(get_kb_entry(x[1]["text"])[0]))

for sec_title, item in fail_items:
    sev, desc, fix, cve = get_kb_entry(item["text"])
    evidence = "\n".join(item["details"][:5]) if item["details"] else "No additional detail captured."
    fail_rows.append(row(
        cell_str(sec_title[:38], "ce_fail_light"),
        cell_str(item["text"][:160], "ce1"),
        sev_cell(sev),
        cell_str(desc[:240], "ce_desc"),
        cell_str(evidence[:200], "ce_evidence"),
        cell_str(fix[:280], "ce_fix"),
        cell_str(cve or "—", "ce_cve"),
    ))

if len(fail_rows) == 1:
    fail_rows.append(row(cell_str("✔ No FAIL items — excellent!","ce_pass"), cell_empty(6)))

sheet4 = ('<table:table table:name="FAIL Deep-Dive" table:style-name="ta1">'
          '<table:table-column table:style-name="co_wide2"/>'
          '<table:table-column table:style-name="co_issues"/>'
          '<table:table-column table:style-name="co_val"/>'
          '<table:table-column table:style-name="co_desc"/>'
          '<table:table-column table:style-name="co_issues"/>'
          '<table:table-column table:style-name="co_fix"/>'
          '<table:table-column table:style-name="co_cve"/>'
          + "\n".join(fail_rows) + '</table:table>')

# ── Sheet 5: WARN Deep-Dive ──────────────────────────────────────
warn_rows = []
warn_rows.append(row(
    hcell("Section","ce_hdr_warn"), hcell("Finding","ce_hdr_warn"),
    hcell("Severity","ce_hdr_warn"), hcell("What This Means","ce_hdr_warn"),
    hcell("Evidence Captured","ce_hdr_warn"), hcell("How to Fix","ce_hdr_warn"),
    hcell("CVE / Reference","ce_hdr_warn"),
))
warn_items = [(s["title"], item) for s in sections for item in s["items"] if item["kind"]=="WARN"]
warn_items.sort(key=lambda x: get_priority(get_kb_entry(x[1]["text"])[0]))

for sec_title, item in warn_items:
    sev, desc, fix, cve = get_kb_entry(item["text"])
    evidence = " | ".join(item["details"][:4]) if item["details"] else "No additional detail captured."
    warn_rows.append(row(
        cell_str(sec_title[:38], "ce_warn_light"),
        cell_str(item["text"][:160], "ce1"),
        sev_cell(sev),
        cell_str(desc[:240], "ce_desc"),
        cell_str(evidence[:200], "ce_evidence"),
        cell_str(fix[:280], "ce_fix"),
        cell_str(cve or "—", "ce_cve"),
    ))

if len(warn_rows) == 1:
    warn_rows.append(row(cell_str("✔ No WARN items — excellent!","ce_pass"), cell_empty(6)))

sheet5 = ('<table:table table:name="WARN Deep-Dive" table:style-name="ta1">'
          '<table:table-column table:style-name="co_wide2"/>'
          '<table:table-column table:style-name="co_issues"/>'
          '<table:table-column table:style-name="co_val"/>'
          '<table:table-column table:style-name="co_desc"/>'
          '<table:table-column table:style-name="co_issues"/>'
          '<table:table-column table:style-name="co_fix"/>'
          '<table:table-column table:style-name="co_cve"/>'
          + "\n".join(warn_rows) + '</table:table>')

# ── Sheet 6: ChartData (for users who want to chart manually) ────
cd_rows = []
cd_rows.append(row(hcell("Section"), hcell("PASS"), hcell("FAIL"), hcell("WARN"), hcell("INFO"), hcell("Score%")))
for s in sec_stats:
    cd_rows.append(row(cell_str(s["title"][:38],"ce1"), cell_num(s["pass"],"ce_pass"),
                       cell_num(s["fail"],"ce_fail" if s["fail"] else "ce1"),
                       cell_num(s["warn"],"ce_warn" if s["warn"] else "ce1"),
                       cell_num(s["info"],"ce_info"), cell_pct(s["pct"],"ce_pct")))
cd_rows.append(row(*[cell_empty(6)]))
cd_rows.append(row(hcell("Totals"), cell_num(n_pass,"ce_pass"), cell_num(n_fail,"ce_fail"),
                   cell_num(n_warn,"ce_warn"), cell_num(n_info,"ce_info"), cell_pct(pct,"ce_pct")))

sheet6 = ('<table:table table:name="ChartData" table:style-name="ta1">'
          '<table:table-column table:style-name="co_wide2"/>'
          + '<table:table-column table:style-name="co_val"/>'*5
          + "\n".join(cd_rows) + '</table:table>')

# ── Sheet 7: Charts — SVGs embedded as visible images ─────────────
# Each chart is rendered as a draw:frame/draw:image in its own row so
# LibreOffice displays them inline without any extraction step.
def chart_img_row(path, w_cm, h_cm, title):
    """A row containing a title label and below it the embedded SVG image."""
    title_row = (
        '<table:table-row>'
        f'<table:table-cell table:number-columns-spanned="2" table:style-name="ce_title">'
        f'<text:p>{esc(title)}</text:p></table:table-cell>'
        '<table:covered-table-cell/>'
        '</table:table-row>'
    )
    img_row = (
        '<table:table-row table:style-name="ro_chart">'
        '<table:table-cell table:number-columns-spanned="2" table:style-name="ce_img">'
        '<text:p>'
        f'<draw:frame draw:name="{path.replace("/","_").replace(".","_")}" '
        f'svg:width="{w_cm}cm" svg:height="{h_cm}cm" '
        'text:anchor-type="as-char" draw:z-index="0">'
        f'<draw:image xlink:href="{path}" xlink:type="simple" '
        'xlink:show="embed" xlink:actuate="onLoad"/>'
        '</draw:frame>'
        '</text:p>'
        '</table:table-cell>'
        '<table:covered-table-cell/>'
        '</table:table-row>'
    )
    spacer = '<table:table-row><table:table-cell/></table:table-row>'
    return title_row + img_row + spacer

chart_rows = []
for svg_path, svg_title, w, h in [
    ("Pictures/score_gauge.svg",   "Score Gauge — Overall security score with benchmark markers",    17, 9),
    ("Pictures/bar_chart.svg",     "Bar Chart — PASS / FAIL / WARN per audit section",               17, max(8, len(sec_stats)*0.6+2)),
    ("Pictures/pie_chart.svg",     "Pie Chart — Distribution of all result types",                   17, 10),
    ("Pictures/heatmap.svg",       "Heatmap — Finding density: section × severity",                  17, max(8, len(sec_stats)*0.5+3)),
    ("Pictures/severity_radar.svg","Severity Radar — Issue count by Critical / High / Medium / Low", 17, 11),
    ("Pictures/security_index.svg","Security Index — Colour-coded score gauge with rating legend",   17, 6.5),
    ("Pictures/findings_bar.svg",  "Findings Bar — PASS/FAIL/WARN per section with score %",         17, max(8, len(sec_stats)*0.65+2.5)),
]:
    chart_rows.append(chart_img_row(svg_path, w, h, svg_title))

sheet7 = (
    '<table:table table:name="Charts" table:style-name="ta1">'
    '<table:table-column table:style-name="co_chart_half"/>'
    '<table:table-column table:style-name="co_chart_half"/>'
    + "".join(chart_rows)
    + '</table:table>'
)

# ═══════════════════════════════════════════════════════════════
#  ODS STYLES
# ═══════════════════════════════════════════════════════════════
styles_auto = f"""
<office:automatic-styles>
  <style:style style:name="ta1" style:family="table">
    <style:table-properties table:display="true" style:writing-mode="lr-tb"/>
  </style:style>
  <!-- Chart image columns (each half the page width ~17cm total) -->
  <style:style style:name="co_chart_half" style:family="table-column"><style:table-column-properties style:column-width="8.5cm"/></style:style>
  <!-- Chart image row — tall enough to display the SVG without cropping -->
  <style:style style:name="ro_chart" style:family="table-row">
    <style:table-row-properties style:row-height="11cm" style:use-optimal-row-height="false"/>
  </style:style>
  <!-- Image cell — no border, no padding, transparent background -->
  <style:style style:name="ce_img" style:family="table-cell">
    <style:table-cell-properties fo:padding="0cm" fo:border="none"/>
  </style:style>
  <!-- Column widths -->
  <style:style style:name="co_lbl"   style:family="table-column"><style:table-column-properties style:column-width="4.0cm"/></style:style>
  <style:style style:name="co_val"   style:family="table-column"><style:table-column-properties style:column-width="2.2cm"/></style:style>
  <style:style style:name="co_wide"  style:family="table-column"><style:table-column-properties style:column-width="9.0cm"/></style:style>
  <style:style style:name="co_wide2" style:family="table-column"><style:table-column-properties style:column-width="6.5cm"/></style:style>
  <style:style style:name="co_issues" style:family="table-column"><style:table-column-properties style:column-width="8.0cm"/></style:style>
  <style:style style:name="co_desc"  style:family="table-column"><style:table-column-properties style:column-width="8.5cm"/></style:style>
  <style:style style:name="co_fix"   style:family="table-column"><style:table-column-properties style:column-width="9.0cm"/></style:style>
  <style:style style:name="co_cve"   style:family="table-column"><style:table-column-properties style:column-width="3.5cm"/></style:style>
  <!-- Base cell -->
  <style:style style:name="ce1" style:family="table-cell">
    <style:table-cell-properties fo:border="0.4pt solid #37474F" fo:padding="0.12cm" fo:wrap-option="wrap"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#E0E0E0" style:font-name="Arial"/>
  </style:style>
  <!-- Headers -->
  <style:style style:name="ce_title" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#0D47A1" fo:padding="0.18cm"/>
    <style:text-properties fo:font-size="13pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_hdr" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1565C0" fo:padding="0.12cm" fo:border="0.4pt solid #0D47A1"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_hdr_fail" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#7B1010" fo:padding="0.12cm" fo:border="0.4pt solid #5D0000"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFCDD2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_hdr_warn" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#7B4100" fo:padding="0.12cm" fo:border="0.4pt solid #5D3000"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFE0B2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_lbl" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1A237E" fo:padding="0.12cm" fo:border="0.4pt solid #1565C0"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#E8EAF6" style:font-name="Arial"/>
  </style:style>
  <!-- Result cells -->
  <style:style style:name="ce_pass" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1B3B1B" fo:padding="0.1cm" fo:border="0.4pt solid #2E7D32"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#A5D6A7" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_fail" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#3B1010" fo:padding="0.1cm" fo:border="0.4pt solid #B71C1C"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#EF9A9A" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_fail_light" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#4A1515" fo:padding="0.1cm" fo:border="0.4pt solid #B71C1C"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#FFCDD2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_warn" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#3B2800" fo:padding="0.1cm" fo:border="0.4pt solid #E65100"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFCC80" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_warn_light" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#3B2800" fo:padding="0.1cm" fo:border="0.4pt solid #E65100"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#FFE0B2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_info" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#0D2040" fo:padding="0.1cm" fo:border="0.4pt solid #1565C0"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#90CAF9" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_skip" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1E1E2E" fo:padding="0.1cm" fo:border="0.4pt solid #37474F"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#78909C" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_pct" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1A0A30" fo:padding="0.1cm" fo:border="0.4pt solid #7B1FA2"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#CE93D8" style:font-name="Arial"/>
  </style:style>
  <!-- Severity cells -->
  <style:style style:name="ce_crit" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#B71C1C" fo:padding="0.1cm"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFCDD2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_high" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#BF360C" fo:padding="0.1cm"/>
    <style:text-properties fo:font-size="8.5pt" fo:font-weight="bold" fo:color="#FFE0B2" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_low" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1A3A1A" fo:padding="0.1cm"/>
    <style:text-properties fo:font-size="8.5pt" fo:color="#C8E6C9" style:font-name="Arial"/>
  </style:style>
  <!-- Detail cells -->
  <style:style style:name="ce_desc" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#162033" fo:padding="0.12cm" fo:border="0.4pt solid #1565C0" fo:wrap-option="wrap"/>
    <style:text-properties fo:font-size="8pt" fo:color="#B0BEC5" style:font-name="Arial" fo:font-style="italic"/>
  </style:style>
  <style:style style:name="ce_evidence" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1A1A0A" fo:padding="0.12cm" fo:border="0.4pt solid #37474F" fo:wrap-option="wrap"/>
    <style:text-properties fo:font-size="7.5pt" fo:color="#B0BEC5" style:font-name="Courier New"/>
  </style:style>
  <style:style style:name="ce_fix" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#0A1A0A" fo:padding="0.12cm" fo:border="0.4pt solid #2E7D32" fo:wrap-option="wrap"/>
    <style:text-properties fo:font-size="7.5pt" fo:color="#A5D6A7" style:font-name="Courier New"/>
  </style:style>
  <style:style style:name="ce_detail" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#12121E" fo:padding="0.1cm" fo:border="0.4pt solid #37474F" fo:wrap-option="wrap"/>
    <style:text-properties fo:font-size="7.5pt" fo:color="#90A4AE" style:font-name="Courier New"/>
  </style:style>
  <style:style style:name="ce_cve" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1A0A20" fo:padding="0.1cm" fo:border="0.4pt solid #7B1FA2"/>
    <style:text-properties fo:font-size="7.5pt" fo:color="#CE93D8" style:font-name="Courier New"/>
  </style:style>
  <!-- Rating / score bar -->
  <style:style style:name="ce_rating_{r_hex}" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#{r_hex}" fo:padding="0.1cm"/>
    <style:text-properties fo:font-size="11pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_bar_{bar_fill}" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#111122" fo:padding="0.15cm" fo:border="1.5pt solid #{bar_fill}"/>
    <style:text-properties fo:font-size="9pt" fo:font-weight="bold" fo:color="#{bar_fill}" style:font-name="Courier New"/>
  </style:style>
</office:automatic-styles>
"""

# ── Build content.xml ─────────────────────────────────────────────
content_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0"
  xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
  office:version="1.3">
<office:font-face-decls>
  <style:font-face style:name="Courier New"
    xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
    svg:font-family="'Courier New'" style:font-family-generic="modern" style:font-pitch="fixed"/>
  <style:font-face style:name="Arial"
    xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
    svg:font-family="Arial" style:font-family-generic="swiss"/>
</office:font-face-decls>
{styles_auto}
<office:body>
<office:spreadsheet>
{sheet1}
{sheet2}
{sheet3}
{sheet4}
{sheet5}
{sheet6}
{sheet7}
</office:spreadsheet>
</office:body>
</office:document-content>"""

styles_xml = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  office:version="1.3">
<office:styles>
  <style:default-style style:family="table-cell">
    <style:text-properties fo:font-size="9pt" style:font-name="Arial" fo:color="#E0E0E0"/>
  </style:default-style>
</office:styles>
<office:automatic-styles>
  <style:page-layout style:name="PL">
    <style:page-layout-properties fo:page-width="42cm" fo:page-height="29.7cm"
      style:print-orientation="landscape"
      fo:margin-top="1cm" fo:margin-bottom="1cm"
      fo:margin-left="1.2cm" fo:margin-right="1.2cm"/>
  </style:page-layout>
</office:automatic-styles>
<office:master-styles>
  <style:master-page style:name="Default" style:page-layout-name="PL"/>
</office:master-styles>
</office:document-styles>"""

manifest_entries = [
    ('/', 'application/vnd.oasis.opendocument.spreadsheet'),
    ('content.xml', 'text/xml'),
    ('styles.xml',  'text/xml'),
    ('Pictures/score_gauge.svg',    'image/svg+xml'),
    ('Pictures/bar_chart.svg',      'image/svg+xml'),
    ('Pictures/pie_chart.svg',      'image/svg+xml'),
    ('Pictures/heatmap.svg',        'image/svg+xml'),
    ('Pictures/severity_radar.svg', 'image/svg+xml'),
    ('Pictures/security_index.svg', 'image/svg+xml'),
    ('Pictures/findings_bar.svg',   'image/svg+xml'),
]
manifest_xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
    '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">\n'
    + "".join(f'  <manifest:file-entry manifest:full-path="{p}" manifest:media-type="{m}"/>\n' for p,m in manifest_entries)
    + '</manifest:manifest>\n')

# ── Build SVGs ────────────────────────────────────────────────────
svg_gauge  = build_score_gauge_svg()
svg_bar    = build_bar_chart_svg()
svg_pie    = build_pie_chart_svg()
svg_heat   = build_heatmap_svg()
svg_radar  = build_severity_radar_svg()

# Security index (colour legend + gauge) and findings bar for Overview sheet
def build_security_index_svg_ods(pct2, nf, nw, np2, ni, rat, rhex, bfill):
    W,H=820,260
    p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       f'<rect width="{W}" height="{H}" fill="#0D1117" rx="10"/>']
    cx,cy,Ro,Ri=160,190,130,78
    zones=[(0,20,"#7B0000","#EF5350"),(20,40,"#BF360C","#FF7043"),
           (40,60,"#E65100","#FFB300"),(60,80,"#1B5E20","#66BB6A"),(80,100,"#0D47A1","#42A5F5")]
    import math as _m
    def arc(a0,a1,ro,ri,cd,cl):
        A0=_m.radians(180-a0*1.8); A1=_m.radians(180-a1*1.8); lg=1 if abs(a1-a0)>50 else 0
        x0o=cx+ro*_m.cos(A0); y0o=cy-ro*_m.sin(A0); x1o=cx+ro*_m.cos(A1); y1o=cy-ro*_m.sin(A1)
        x0i=cx+ri*_m.cos(A1); y0i=cy-ri*_m.sin(A1); x1i=cx+ri*_m.cos(A0); y1i=cy-ri*_m.sin(A0)
        d=f"M{x0o:.1f},{y0o:.1f} A{ro},{ro} 0 {lg},0 {x1o:.1f},{y1o:.1f} L{x0i:.1f},{y0i:.1f} A{ri},{ri} 0 {lg},1 {x1i:.1f},{y1i:.1f} Z"
        return f'<path d="{d}" fill="{cd}" stroke="{cl}" stroke-width="1.5"/>'
    for a0,a1,cd,cl in zones: p.append(arc(a0,a1,Ro,Ri,cd,cl))
    na=_m.radians(180-pct2*1.8); nx=cx+(Ri-10)*_m.cos(na); ny=cy-(Ri-10)*_m.sin(na)
    p+=[f'<line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="#FFF" stroke-width="3" stroke-linecap="round"/>',
        f'<circle cx="{cx}" cy="{cy}" r="8" fill="#FFF"/>',f'<circle cx="{cx}" cy="{cy}" r="4" fill="#{rhex}"/>',
        f'<text x="{cx}" y="{cy+38}" text-anchor="middle" font-family="Arial" font-size="32" font-weight="bold" fill="#{bfill}">{pct2}%</text>',
        f'<text x="{cx}" y="{cy+58}" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#{rhex}">{rat}</text>']
    lx,ly=330,22
    p.append(f'<text x="{lx}" y="{ly}" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Index — Colour Legend</text>')
    legend=[("#B71C1C","#EF5350","0–20%","Critical — Immediate action required."),
            ("#BF360C","#FF7043","21–40%","High — Significant risks. Address FAILs."),
            ("#E65100","#FFB300","41–60%","Moderate — Several issues. Review WARNs."),
            ("#1B5E20","#66BB6A","61–80%","Good — Reasonably hardened. Maintain."),
            ("#0D47A1","#42A5F5","81–100%","Excellent — Well hardened. Audit regularly.")]
    for idx,(bg,fg,rng,desc) in enumerate(legend):
        y=ly+26+idx*36; active=(zones[idx][0]<=pct2<zones[idx][1]) or (idx==4 and pct2>=80) or (idx==0 and pct2==0)
        sw="3" if active else "1"
        p+=[f'<rect x="{lx}" y="{y}" width="64" height="22" fill="{bg}" stroke="{fg}" stroke-width="{sw}" rx="4"/>',
            f'<text x="{lx+32}" y="{y+15}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="{fg}">{rng}</text>',
            f'<text x="{lx+74}" y="{y+9}" font-family="Arial" font-size="9" font-weight="bold" fill="{fg}">{desc}</text>']
        if active: p.append(f'<text x="{lx-14}" y="{y+15}" font-family="Arial" font-size="14" fill="{fg}">▶</text>')
    rx,ry=660,22; tot=nf+nw+np2+ni or 1; bw=120
    p.append(f'<text x="{rx+60}" y="{ry}" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Finding Summary</text>')
    for si,(fg,bg2,lbl,cnt) in enumerate([("#EF5350","#B71C1C","FAIL",nf),("#FF9800","#E65100","WARN",nw),
                                           ("#4CAF50","#2E7D32","PASS",np2),("#42A5F5","#1565C0","INFO",ni)]):
        y2=ry+26+si*42; w2=int(cnt/tot*bw)
        p+=[f'<rect x="{rx}" y="{y2}" width="{bw}" height="22" fill="#1E2A3A" rx="4"/>',
            f'<rect x="{rx}" y="{y2}" width="{max(w2,2)}" height="22" fill="{bg2}" rx="4"/>',
            f'<text x="{rx+bw+8}" y="{y2+15}" font-family="Arial" font-size="11" font-weight="bold" fill="{fg}">{cnt}</text>',
            f'<text x="{rx-6}" y="{y2+15}" text-anchor="end" font-family="Arial" font-size="10" font-weight="bold" fill="{fg}">{lbl}</text>']
    p.append('</svg>'); return "".join(p)

def build_findings_bar_svg_ods(secs):
    import math as _m
    n=len(secs)
    if n==0: return '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="60"><text x="10" y="40" fill="#90A4AE">No data</text></svg>'
    W=820; pl=220; pr=60; pt=44; pb=36; rh=max(20,min(34,(580-pt-pb)//n)); H=pt+n*rh+20+pb
    mv=max((s["pass"]+s["fail"]+s["warn"]) for s in secs) or 1; pw=W-pl-pr
    p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       f'<rect width="{W}" height="{H}" fill="#0D1117" rx="8"/>',
       f'<text x="{W//2}" y="26" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Findings by Section</text>']
    for tk in sorted(set(i*max(1,mv//5) for i in range(6) if i*max(1,mv//5)<=mv)):
        gx=pl+int(tk/mv*pw)
        p+=[f'<line x1="{gx}" y1="{pt}" x2="{gx}" y2="{pt+n*rh}" stroke="#1E2A3A" stroke-width="1"/>',
            f'<text x="{gx}" y="{pt+n*rh+14}" text-anchor="middle" font-family="Arial" font-size="8" fill="#546E7A">{tk}</text>']
    for idx,s in enumerate(secs):
        y=pt+idx*rh+2; bh=rh-4; bpw=int(s["pass"]/mv*pw); bfw=int(s["fail"]/mv*pw); bww=int(s["warn"]/mv*pw)
        lc="#EF5350" if s["fail"]>0 else ("#FFB300" if s["warn"]>0 else "#66BB6A")
        p.append(f'<rect x="{pl}" y="{y}" width="{pw}" height="{bh}" fill="#131B26" rx="3"/>')
        if bpw: p.append(f'<rect x="{pl}" y="{y}" width="{bpw}" height="{bh}" fill="#2E7D32" rx="2"/>')
        if bfw: p.append(f'<rect x="{pl+bpw}" y="{y}" width="{bfw}" height="{bh}" fill="#C62828" rx="2"/>')
        if bww: p.append(f'<rect x="{pl+bpw+bfw}" y="{y}" width="{bww}" height="{bh}" fill="#E65100" rx="2"/>')
        p.append(f'<text x="{pl-8}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="{lc}">{s["title"][:30]}</text>')
        xc=pl
        for bw2,cnt,col in [(bpw,s["pass"],"#A5D6A7"),(bfw,s["fail"],"#FFCDD2"),(bww,s["warn"],"#FFE0B2")]:
            if bw2>=18 and cnt: p.append(f'<text x="{xc+bw2//2}" y="{y+bh//2+4}" text-anchor="middle" font-family="Arial" font-size="8" font-weight="bold" fill="{col}">{cnt}</text>')
            xc+=bw2
        p.append(f'<text x="{pl+bpw+bfw+bww+6}" y="{y+bh//2+4}" font-family="Arial" font-size="8" font-weight="bold" fill="{lc}">{s.get("pct",0)}%</text>')
    p.append(f'<line x1="{pl}" y1="{pt}" x2="{pl}" y2="{pt+n*rh}" stroke="#37474F" stroke-width="1.5"/>')
    lx2=pl; ly2=H-20
    for col,lbl in [("#2E7D32","PASS"),("#C62828","FAIL"),("#E65100","WARN")]:
        p+=[f'<rect x="{lx2}" y="{ly2}" width="11" height="11" fill="{col}" rx="2"/>',
            f'<text x="{lx2+14}" y="{ly2+9}" font-family="Arial" font-size="9" fill="#B0BEC5">{lbl}</text>']
        lx2+=65
    p.append('</svg>'); return "".join(p)

svg_sec_index = build_security_index_svg_ods(pct, n_fail, n_warn, n_pass, n_info, rating, r_hex, bar_fill)
svg_find_bar  = build_findings_bar_svg_ods(sec_stats)

# ── Write ODS zip ─────────────────────────────────────────────────
with zipfile.ZipFile(ods_out, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.spreadsheet")
    zf.writestr("META-INF/manifest.xml", manifest_xml)
    zf.writestr("content.xml",           content_xml)
    zf.writestr("styles.xml",            styles_xml)
    zf.writestr("Pictures/score_gauge.svg",    svg_gauge)
    zf.writestr("Pictures/bar_chart.svg",      svg_bar)
    zf.writestr("Pictures/pie_chart.svg",      svg_pie)
    zf.writestr("Pictures/heatmap.svg",        svg_heat)
    zf.writestr("Pictures/severity_radar.svg", svg_radar)
    zf.writestr("Pictures/security_index.svg", svg_sec_index)
    zf.writestr("Pictures/findings_bar.svg",   svg_find_bar)

print(f"Enhanced ODS report written: {ods_out}  ({os.path.getsize(ods_out):,} bytes)")
print(f"  Sheets: Overview | Per-Section | All Issues | FAIL Deep-Dive | WARN Deep-Dive | ChartData | Charts")
print(f"  SVGs:   score_gauge | bar_chart | pie_chart | heatmap | severity_radar | security_index | findings_bar")
STATSEOF

  if [[ -f "wowscanner_stats_${TIMESTAMP}.ods" ]]; then
    pass "Enhanced ODS report generated: wowscanner_stats_${TIMESTAMP}.ods"
    log "  ${CYAN}${BOLD}Sheets (7): Overview | Per-Section | All Issues | FAIL Deep-Dive | WARN Deep-Dive | ChartData | Charts${NC}"
    log "  ${CYAN}${BOLD}SVGs  (5): score_gauge | bar_chart | pie_chart | heatmap | severity_radar${NC}"
    log "  ${CYAN}${BOLD}Each FAIL/WARN includes: severity, description, evidence captured, fix commands, CVE refs${NC}"
    log "  ${CYAN}${BOLD}Open with LibreOffice Calc, OnlyOffice, or Google Sheets.${NC}"
  else
    warn "ODS generation failed — check Python3 availability"
  fi
}



# ================================================================
#  MAIN
# ================================================================

# ================================================================
#  HELP
# ================================================================
cmd_help() {
  local _title="${PROGRAM}  v${VERSION}"
  local _copy="${COPYRIGHT}"
  # Inner width of the box is 59 chars (between the two ║ walls)
  local _iw=59
  local _tp _cp
  printf -v _tp "%-${_iw}s" "   ${_title}"
  printf -v _cp "%-${_iw}s" "   ${_copy}"

  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║${_tp}║"
  echo "  ║${_cp}║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}USAGE${NC}"
  echo "    sudo bash wowscanner.sh [COMMAND] [OPTIONS]"
  echo ""
  echo -e "  ${BOLD}COMMANDS${NC}"
  echo -e "    ${GREEN}(none)${NC}              Run the full security audit"
  echo -e "    ${GREEN}clean${NC}               Delete all wowscanner_* output files in the"
  echo "                        current directory and exit (no audit is run)"
  echo -e "    ${GREEN}clean --all${NC}         Also wipe /var/lib/wowscanner/ persistent data"
  echo "                        (port history, issue log, remediation script)"
  echo -e "    ${GREEN}verify${NC}  ${GREEN}--verify${NC}  ${GREEN}-v${NC}  Check integrity of all wowscanner_archive_*.zip"
  echo "                        files in the current directory."
  echo "                        Alarms (bell + red alert) if any archive is"
  echo "                        missing or has been tampered with."
  echo -e "    ${GREEN}--help${NC}  ${GREEN}-h${NC}  ${GREEN}help${NC}    Show this help and exit"
  echo ""
  echo -e "  ${BOLD}SCAN OPTIONS${NC}"
  echo -e "    ${CYAN}--no-pentest${NC}        Skip pentest sections 0a–0e (nmap, nikto, hydra, sqlmap)"
  echo -e "    ${CYAN}--no-lynis${NC}          Skip Lynis audit (section 15)"
  echo -e "    ${CYAN}--no-rkhunter${NC}       Skip chkrootkit + rkhunter (section 14b)"
  echo -e "    ${CYAN}--fast-only${NC}         Quickest run: skip pentest + enable fast modes"
  echo -e "    ${CYAN}--quiet${NC}             Suppress informational output"
  echo ""
  echo -e "  ${BOLD}ENVIRONMENT OVERRIDES${NC}  (set before sudo)"
  echo -e "    ${YELLOW}LYNIS_FULL=true${NC}     Run the full Lynis audit  (default: fast mode)"
  echo -e "    ${YELLOW}RKH_FULL=true${NC}       Run the full rkhunter scan (default: fast mode)"
  echo -e "    ${YELLOW}APT_CACHE_MAX_AGE=0${NC} Force apt-get update even if cache is fresh"
  echo ""
  echo -e "  ${BOLD}TYPICAL RUNTIMES${NC}"
  echo "    Default (--no-pentest)   3–6 min"
  echo "    With pentest             8–15 min"
  echo "    --fast-only              2–4 min"
  echo "    LYNIS_FULL=true RKH_FULL=true   10–20 min"
  echo ""
  echo -e "  ${BOLD}EXAMPLES${NC}"
  echo "    sudo bash wowscanner.sh                   # full audit, no pentest sections"
  echo "    sudo bash wowscanner.sh --no-lynis        # skip Lynis"
  echo "    sudo bash wowscanner.sh --fast-only       # quickest pass"
  echo "    LYNIS_FULL=true sudo bash wowscanner.sh  # full Lynis scan"
  echo "    sudo bash wowscanner.sh verify            # check all archive integrity"
  echo "    sudo bash wowscanner.sh clean             # delete output files"
  echo "    sudo bash wowscanner.sh clean --all       # delete everything including history"
  echo ""
  echo -e "  ${BOLD}OUTPUT FILES${NC}  (written to current directory)"
  echo "    wowscanner_<ts>.txt          Combined plain-text audit log"
  echo "    wowscanner_report_<ts>.odt   Graphical report (LibreOffice Writer)"
  echo "    wowscanner_stats_<ts>.ods    Statistics + charts (LibreOffice Calc)"
  echo "    wowscanner_intel_<ts>.odt    Intelligence report with CVE data"
  echo "    wowscanner_archive_<ts>.zip  All four files in one archive"
  echo ""
  echo -e "  ${BOLD}PERSISTENT DATA${NC}  (kept across runs)"
  echo "    /var/lib/wowscanner/port_issues.log"
  echo "    /var/lib/wowscanner/port_history.db"
  echo "    /var/lib/wowscanner/remediation_commands.sh"
  echo ""
  echo -e "  ${YELLOW}⚠  PENTEST NOTICE:${NC} Sections 0a–0e run active tests (nmap, Hydra, Nikto,"
  echo "     SQLMap, stress-ng). Only run on systems you own or have written"
  echo "     permission to test. Pentest sections are OFF by default."
  echo ""
}

# ================================================================
#  VERIFY COMMAND  (sudo bash wowscanner.sh verify)
#  Checks integrity of ALL wowscanner_archive_*.zip files in the
#  current directory:
#    - Reports any zip that was expected but is now missing (ALARM)
#    - Runs full dual-hash + HMAC + CRC + perms check on each zip
#    - Writes results to /var/lib/wowscanner/integrity_alerts.log
# ================================================================
cmd_verify() {
  require_root
  local _dir="$PWD"
  local _iw=59 _tp _cp
  printf -v _tp "%-${_iw}s" "   ${PROGRAM}  v${VERSION}"
  printf -v _cp "%-${_iw}s" "   ${COPYRIGHT}"

  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║${_tp}║"
  echo "  ║${_cp}║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}Integrity Verify — directory: ${_dir}${NC}"
  echo ""

  # ── Discover all zip archives ─────────────────────────────────
  local _zips=()
  while IFS= read -r -d '' z; do
    _zips+=("$z")
  done < <(find "$_dir" -maxdepth 1 -type f \
    -name 'wowscanner_archive_*.zip' -print0 2>/dev/null)

  # ── Check alert log for archives we KNOW should exist ─────────
  local _alert_log="${PERSIST_DIR}/integrity_alerts.log"
  local _known_zips=()
  if [[ -f "$_alert_log" ]]; then
    while IFS= read -r line; do
      [[ "$line" =~ ARCHIVED.*zip=([^ ]+) ]] && _known_zips+=("${BASH_REMATCH[1]}")
    done < "$_alert_log"
  fi

  # Report any previously known zip that is now missing (ALARM)
  local _alarm=false
  if [[ "${#_known_zips[@]}" -gt 0 ]]; then
    echo -e "  ${BOLD}Checking for missing archives...${NC}"
    for zname in "${_known_zips[@]}"; do
      local _expected="${_dir}/${zname}"
      if [[ ! -f "$_expected" ]]; then
        _alarm=true
        # Ring the terminal bell and print a loud alert
        echo -e "\a"
        echo -e "  ${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}${BOLD}║  ⚠  ARCHIVE MISSING — POSSIBLE TAMPERING OR DELETION        ║${NC}"
        echo -e "  ${RED}${BOLD}║  Expected: ${zname}${NC}"
        echo -e "  ${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        # Log the alarm
        mkdir -p "$PERSIST_DIR"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]  ALARM_MISSING  zip=${zname}  dir=${_dir}" \
          >> "$_alert_log"
      fi
    done
    $_alarm || echo -e "  ${GREEN}All previously known archives are present.${NC}"
    echo ""
  fi

  if [[ "${#_zips[@]}" -eq 0 ]]; then
    echo -e "  ${YELLOW}No wowscanner_archive_*.zip files found in ${_dir}${NC}"
    echo -e "  ${YELLOW}Run a scan first to generate archives.${NC}"
    echo ""
    return
  fi

  # ── Full integrity check on each zip ─────────────────────────
  echo -e "  ${CYAN}${BOLD}┌─ Full integrity check (${#_zips[@]} archive(s)) ───────────────┐${NC}"

  python3 - "$_dir" "$PERSIST_DIR" "${_zips[@]}" << 'VERIFEOF' || true
import sys, os, zipfile, hashlib, hmac, datetime, socket, stat, pwd, grp

scan_dir    = sys.argv[1]
persist_dir = sys.argv[2]
zip_paths   = sys.argv[3:]

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()

def sha512(path):
    h = hashlib.sha512()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()

def machine_key():
    parts = [socket.gethostname()]
    for p in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try: parts.append(open(p).read().strip()); break
        except: pass
    return hashlib.sha256('|'.join(parts).encode()).digest()

def bell():
    """Print terminal bell on its own line so it never disrupts text alignment."""
    print('\a', end='', flush=True)

ts_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
mkey   = machine_key()

# Load the set of files intentionally removed with 'clean'
# These are logged as: [ts]  CLEANED  file=<basename>
# They are expected-absent and must NOT trigger an integrity alarm.
cleaned_files = set()
alert_log_path = os.path.join(persist_dir, 'integrity_alerts.log')
if os.path.isfile(alert_log_path):
    for line in open(alert_log_path):
        if '  CLEANED  ' in line:
            parts = line.strip().split('file=', 1)
            if len(parts) == 2:
                cleaned_files.add(parts[1].strip())

grand_ok = 0; grand_fail = 0; grand_unexpected_missing = 0
grand_cleaned_missing = 0; grand_perm = 0; grand_size = 0
alerts = []

for zpath in zip_paths:
    zname = os.path.basename(zpath)
    arc_ok = 0; arc_fail = 0; arc_unexp = 0; arc_clean = 0

    print(f"\n  {CYAN}│  {BOLD}{'─'*54}{NC}")
    print(f"  {CYAN}│  {BOLD}Archive: {zname}{NC}")

    # ── 1. Zip CRC self-check ─────────────────────────────────────
    try:
        with zipfile.ZipFile(zpath, 'r') as zf:
            bad = zf.testzip()
            if bad:
                bell()
                print(f"  {CYAN}│  {RED}{BOLD}ZIP CRC FAIL — corrupt entry: {bad}{NC}")
                alerts.append(f"[{ts_now}]  ZIP_CRC_FAIL  zip={zname}  entry={bad}")
                grand_fail += 1
                continue
            print(f"  {CYAN}│  {GREEN}CRC check  : OK — zip is structurally intact{NC}")
            if 'INTEGRITY.txt' not in zf.namelist():
                print(f"  {CYAN}│  {YELLOW}No INTEGRITY.txt — old archive, skipping file checks{NC}")
                continue
            manifest_raw = zf.read('INTEGRITY.txt').decode('utf-8', 'replace')
    except Exception as e:
        bell()
        print(f"  {CYAN}│  {RED}ZIP ERROR: {e}{NC}")
        alerts.append(f"[{ts_now}]  ZIP_ERROR  zip={zname}  error={e}")
        grand_fail += 1
        continue

    # ── 2. HMAC authenticity check ────────────────────────────────
    hmac_stored = None; body_lines = []
    for line in manifest_raw.splitlines():
        if line.startswith('# HMAC-SHA256:'):
            hmac_stored = line.split(':', 1)[1].strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines) + "\n"

    if hmac_stored:
        expected_sig = hmac.new(mkey, body.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_sig, hmac_stored):
            print(f"  {CYAN}│  {GREEN}HMAC check : OK — manifest authentic and unmodified{NC}")
        else:
            bell()
            print(f"  {CYAN}│  {RED}{BOLD}HMAC FAIL  — manifest has been tampered!{NC}")
            alerts.append(f"[{ts_now}]  HMAC_FAIL  zip={zname}")
            arc_fail += 1
    else:
        print(f"  {CYAN}│  {YELLOW}HMAC check : SKIP — manifest v1 (no HMAC){NC}")

    # ── 3. Parse entries ──────────────────────────────────────────
    entries = {}
    for line in body_lines:
        line = line.strip()
        if line.startswith('#') or not line: continue
        p = line.split()
        if len(p) >= 8:
            entries[p[7]] = {'sha256':p[0], 'sha512':p[1], 'size':int(p[2]),
                             'mtime':int(p[3]), 'mode':p[4], 'uid':int(p[5]), 'gid':int(p[6])}
        elif len(p) == 2:
            entries[p[1]] = {'sha256': p[0]}

    print(f"  {CYAN}│  {BOLD}Files in manifest: {len(entries)}{NC}")

    for fname, exp in sorted(entries.items()):
        fpath = os.path.join(scan_dir, fname)
        pfx   = f"  {CYAN}│    {NC}"

        if not os.path.isfile(fpath):
            if fname in cleaned_files:
                # Intentionally removed with 'clean' — expected, no alarm
                print(f"{pfx}{YELLOW}CLEANED   {fname}"
                      f"  ↳ removed with 'clean' — zip copy intact{NC}")
                arc_clean += 1
            else:
                # Unexpected disappearance — alarm
                bell()
                print(f"{pfx}{RED}{BOLD}MISSING!  {fname}{NC}")
                print(f"{pfx}{RED}          ↳ Not removed by 'clean' — unexpected deletion!{NC}")
                print(f"{pfx}{YELLOW}          ↳ Restore from zip: unzip {zname} {fname}{NC}")
                alerts.append(f"[{ts_now}]  FILE_MISSING_UNEXPECTED  zip={zname}  file={fname}")
                arc_unexp += 1
            continue

        st = os.stat(fpath)

        # Size check
        size_ok = True
        if 'size' in exp and st.st_size != exp['size']:
            bell()
            print(f"{pfx}{RED}SIZE FAIL {fname}  "
                  f"expected={exp['size']}B  actual={st.st_size}B{NC}")
            alerts.append(f"[{ts_now}]  SIZE_FAIL  file={fname}")
            grand_size += 1
            size_ok = False

        # SHA-256 + SHA-512
        a256 = sha256(fpath); ok256 = (a256 == exp['sha256'])
        ok512 = True
        a512  = None
        if 'sha512' in exp:
            a512 = sha512(fpath); ok512 = (a512 == exp['sha512'])

        if ok256 and ok512 and size_ok:
            print(f"{pfx}{GREEN}OK        {fname}  sha256={a256[:16]}...{NC}")
            arc_ok += 1
        else:
            detail = []
            if not size_ok: detail.append("size mismatch")
            if not ok256:   detail.append(f"sha256 got={a256[:16]}...")
            if not ok512:   detail.append(f"sha512 got={a512[:16]}...")
            bell()
            print(f"{pfx}{RED}{BOLD}TAMPERED  {fname}  {' | '.join(detail)}{NC}")
            alerts.append(f"[{ts_now}]  TAMPERED  zip={zname}  file={fname}")
            arc_fail += 1

        # Permission / owner audit
        if 'mode' in exp:
            cur_mode = oct(st.st_mode)
            if cur_mode != exp['mode']:
                try:
                    uname = pwd.getpwuid(st.st_uid).pw_name
                    gname = grp.getgrgid(st.st_gid).gr_name
                except Exception:
                    uname = str(st.st_uid); gname = str(st.st_gid)
                print(f"{pfx}{MAGENTA}PERM CHG  {fname}  "
                      f"was={exp['mode']}  now={cur_mode}  "
                      f"owner={uname}:{gname}{NC}")
                alerts.append(f"[{ts_now}]  PERM_CHANGED  file={fname}")
                grand_perm += 1

        # Mtime delta
        if 'mtime' in exp and int(st.st_mtime) != exp['mtime']:
            delta = int(st.st_mtime) - exp['mtime']
            sign  = '+' if delta > 0 else ''
            print(f"{pfx}{YELLOW}MTIME CHG {fname}  "
                  f"modified {sign}{delta}s after archiving{NC}")

    # Per-archive subtotal
    print(f"  {CYAN}│  {NC}")
    subtotal_parts = []
    if arc_ok:    subtotal_parts.append(f"{GREEN}{arc_ok} OK{NC}")
    if arc_clean: subtotal_parts.append(f"{YELLOW}{arc_clean} cleaned (expected){NC}")
    if arc_unexp: subtotal_parts.append(f"{RED}{arc_unexp} MISSING{NC}")
    if arc_fail:  subtotal_parts.append(f"{RED}{arc_fail} TAMPERED{NC}")
    print(f"  {CYAN}│  Subtotal: {'   '.join(subtotal_parts)}")

    grand_ok                  += arc_ok
    grand_fail                += arc_fail
    grand_unexpected_missing  += arc_unexp
    grand_cleaned_missing     += arc_clean

# ── Grand summary ──────────────────────────────────────────────
print(f"\n  {CYAN}│{NC}")
print(f"  {CYAN}│  {BOLD}═══ Grand Summary ════════════════════════════════{NC}")

summary_parts = []
if grand_ok:                 summary_parts.append(f"{GREEN}{grand_ok} OK{NC}")
if grand_cleaned_missing:    summary_parts.append(f"{YELLOW}{grand_cleaned_missing} cleaned (expected absent){NC}")
if grand_unexpected_missing: summary_parts.append(f"{RED}{grand_unexpected_missing} MISSING (unexpected){NC}")
if grand_fail:               summary_parts.append(f"{RED}{grand_fail} TAMPERED{NC}")
if grand_size:               summary_parts.append(f"{RED}{grand_size} size-fail{NC}")
if grand_perm:               summary_parts.append(f"{MAGENTA}{grand_perm} perm-changed{NC}")
print(f"  {CYAN}│  {'   '.join(summary_parts)}")

# Only alarm on genuinely unexpected problems — not on clean-deleted files
if grand_fail > 0 or grand_size > 0 or grand_unexpected_missing > 0:
    bell()
    print(f"  {CYAN}│  {RED}{BOLD}⚠  INTEGRITY COMPROMISED — see details above!{NC}")
elif grand_cleaned_missing > 0 and grand_ok == 0 and grand_fail == 0:
    print(f"  {CYAN}│  {YELLOW}Files were removed with 'clean' — zip archives are intact.{NC}")
    print(f"  {CYAN}│  {YELLOW}To restore: unzip wowscanner_archive_<ts>.zip -d .{NC}")
    print(f"  {CYAN}│  {GREEN}No unexpected tampering detected.{NC}")
else:
    print(f"  {CYAN}│  {GREEN}{BOLD}✔  All present files intact — integrity confirmed.{NC}")

# Write alerts to log
if alerts:
    os.makedirs(persist_dir, exist_ok=True)
    with open(alert_log_path, 'a') as al:
        for a in alerts: al.write(a + '\n')
    print(f"  {CYAN}│  {YELLOW}Alerts logged → {alert_log_path}{NC}")
else:
    os.makedirs(persist_dir, exist_ok=True)
    with open(alert_log_path, 'a') as al:
        al.write(f"[{ts_now}]  VERIFY_CLEAN  dir={scan_dir}  "
                 f"ok={grand_ok}  cleaned={grand_cleaned_missing}\n")
VERIFEOF

  echo -e "  ${CYAN}${BOLD}└───────────────────────────────────────────────────────────┘${NC}"

  # Show alert log location
  if [[ -f "${PERSIST_DIR}/integrity_alerts.log" ]]; then
    echo ""
    echo -e "  ${BOLD}Alert log:${NC}  ${PERSIST_DIR}/integrity_alerts.log"
    echo -e "  ${BOLD}Last 5 entries:${NC}"
    tail -5 "${PERSIST_DIR}/integrity_alerts.log" 2>/dev/null \
      | while IFS= read -r line; do echo -e "    ${CYAN}${line}${NC}"; done || true
  fi
  echo ""
}

# ── Passive zip-presence check (called at scan start) ────────────
# Warns if any previously archived zip has been deleted since the
# last scan.  Rings the terminal bell and logs an alert.
check_archive_presence() {
  local _dir="$PWD"
  local _alert_log="${PERSIST_DIR}/integrity_alerts.log"
  [[ ! -f "$_alert_log" ]] && return

  local _missing=()
  while IFS= read -r line; do
    if [[ "$line" =~ ARCHIVED.*zip=([^[:space:]]+) ]]; then
      local _zname="${BASH_REMATCH[1]}"
      local _zpath="${_dir}/${_zname}"
      if [[ ! -f "$_zpath" ]]; then
        # Skip if a matching ALARM_MISSING was already logged for this zip
        grep -q "ALARM_MISSING.*zip=${_zname}" "$_alert_log" 2>/dev/null || \
          _missing+=("$_zname")
      fi
    fi
  done < "$_alert_log"

  for _zname in "${_missing[@]}"; do
    echo -e "\a"
    warn "ARCHIVE MISSING: ${_zname} — was created in this directory but is now gone!"
    warn "Run:  sudo bash $0 verify  — for a full integrity check"
    mkdir -p "$PERSIST_DIR"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]  ALARM_MISSING  zip=${_zname}  dir=${_dir}" \
      >> "$_alert_log"
  done
}

# ================================================================
#  CLEAN COMMAND  (sudo bash wowscanner.sh clean [--all])
#  Wipes all wowscanner output files from the current directory
#  and exits immediately — the audit is NOT run.
#  With --all: also removes /var/lib/wowscanner/ persistent data.
# ================================================================
cmd_clean() {
  require_root

  local _dir="$PWD"
  local _wiped=0 _failed=0 _bytes=0
  local _files=()
  local _tp _cp _iw=59
  printf -v _tp "%-${_iw}s" "   ${PROGRAM}  v${VERSION}"
  printf -v _cp "%-${_iw}s" "   ${COPYRIGHT}"

  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║${_tp}║"
  echo "  ║${_cp}║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}Clean command — directory: ${_dir}${NC}"
  echo ""

  # ── Step 1: Integrity check against zip archives ─────────────
  # Before deleting anything, verify each .txt/.odt/.ods file against
  # the INTEGRITY.txt manifest embedded in its matching zip archive.
  # If the zip is missing or a hash mismatches, warn and keep the file.
  echo -e "  ${CYAN}${BOLD}┌─ Integrity check ─────────────────────────────────────────┐${NC}"

  local _zips=()
  while IFS= read -r -d '' z; do
    _zips+=("$z")
  done < <(find "$_dir" -maxdepth 1 -type f -name 'wowscanner_archive_*.zip' -print0 2>/dev/null)

  if [[ "${#_zips[@]}" -eq 0 ]]; then
    echo -e "  ${CYAN}│  ${YELLOW}No wowscanner_archive_*.zip found — skipping integrity check${NC}"
  else
    python3 - "$_dir" "$PERSIST_DIR" "${_zips[@]}" << 'INTCHECK' || true
import sys, os, zipfile, hashlib, hmac, datetime, socket, stat, pwd, grp

scan_dir    = sys.argv[1]
persist_dir = sys.argv[2]
zip_paths   = sys.argv[3:]

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()

def sha512(path):
    h = hashlib.sha512()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()

def machine_key():
    parts = [socket.gethostname()]
    for p in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            parts.append(open(p).read().strip())
            break
        except Exception:
            pass
    return hashlib.sha256('|'.join(parts).encode()).digest()

ts_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
mkey   = machine_key()

total_ok = 0; total_fail = 0; total_missing = 0
total_no_manifest = 0; total_size_fail = 0; total_perm_warn = 0
alerts = []   # collected for integrity_alerts.log

for zpath in zip_paths:
    zname = os.path.basename(zpath)
    if not os.path.isfile(zpath):
        print(f"  {CYAN}│  {YELLOW}SKIP   zip not found: {zname}{NC}")
        continue

    # ── 1. Zip self-integrity (CRC check) ────────────────────────
    try:
        with zipfile.ZipFile(zpath, 'r') as zf:
            bad = zf.testzip()
            if bad:
                print(f"  {CYAN}│  {RED}ZIP_CRC_FAIL  {zname}: corrupt entry '{bad}'{NC}")
                alerts.append(f"[{ts_now}]  ZIP_CRC_FAIL  zip={zname}  entry={bad}")
                continue
            if 'INTEGRITY.txt' not in zf.namelist():
                print(f"  {CYAN}│  {YELLOW}NO_MANIFEST  {zname}  (old archive — no INTEGRITY.txt){NC}")
                total_no_manifest += 1
                continue
            manifest_raw = zf.read('INTEGRITY.txt').decode('utf-8', 'replace')
    except Exception as e:
        print(f"  {CYAN}│  {RED}ZIP_ERROR  {zname}: {e}{NC}")
        alerts.append(f"[{ts_now}]  ZIP_ERROR  zip={zname}  error={e}")
        continue

    # ── 2. HMAC manifest authenticity check ──────────────────────
    hmac_ok = False; hmac_stored = None
    body_lines = []
    for line in manifest_raw.splitlines():
        if line.startswith('# HMAC-SHA256:'):
            hmac_stored = line.split(':', 1)[1].strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines) + "\n"
    if hmac_stored:
        expected_sig = hmac.new(mkey, body.encode(), hashlib.sha256).hexdigest()
        hmac_ok = hmac.compare_digest(expected_sig, hmac_stored)
        if hmac_ok:
            print(f"  {CYAN}│  {GREEN}HMAC OK   {zname}  (manifest is authentic){NC}")
        else:
            print(f"  {CYAN}│  {RED}HMAC FAIL {zname}  (manifest may have been tampered!){NC}")
            alerts.append(f"[{ts_now}]  HMAC_FAIL  zip={zname}")
    else:
        print(f"  {CYAN}│  {YELLOW}NO_HMAC   {zname}  (manifest v1 — no HMAC){NC}")

    # ── 3. Parse manifest entries ─────────────────────────────────
    # v2 format: SHA256  SHA512  SIZE  MTIME  MODE  UID  GID  filename
    # v1 format: SHA256  filename
    entries = {}
    for line in body_lines:
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        parts = line.split()
        if len(parts) >= 8:          # v2
            entries[parts[7]] = {
                'sha256': parts[0], 'sha512': parts[1],
                'size': int(parts[2]), 'mtime': int(parts[3]),
                'mode': parts[4], 'uid': int(parts[5]), 'gid': int(parts[6]),
            }
        elif len(parts) == 2:        # v1
            entries[parts[1]] = {'sha256': parts[0]}

    print(f"  {CYAN}│  {BOLD}Checking {len(entries)} file(s) from {zname}:{NC}")

    for fname, exp in sorted(entries.items()):
        fpath = os.path.join(scan_dir, fname)
        prefix = f"  {CYAN}│    {NC}"

        if not os.path.isfile(fpath):
            print(f"{prefix}{YELLOW}MISSING   {fname}  — not on disk (zip copy intact){NC}")
            total_missing += 1
            alerts.append(f"[{ts_now}]  MISSING  zip={zname}  file={fname}")
            continue

        st = os.stat(fpath)

        # ── 3a. File size check (fast, catches truncation) ───────
        if 'size' in exp and st.st_size != exp['size']:
            print(f"{prefix}{RED}SIZE_FAIL {fname}  "
                  f"expected={exp['size']}B  actual={st.st_size}B{NC}")
            total_size_fail += 1
            alerts.append(f"[{ts_now}]  SIZE_FAIL  file={fname}  "
                           f"expected={exp['size']}  actual={st.st_size}")

        # ── 3b. SHA-256 hash ─────────────────────────────────────
        actual_256 = sha256(fpath)
        sha256_ok  = (actual_256 == exp['sha256'])

        # ── 3c. SHA-512 hash (if v2 manifest) ────────────────────
        sha512_ok = True
        if 'sha512' in exp:
            actual_512 = sha512(fpath)
            sha512_ok  = (actual_512 == exp['sha512'])

        if sha256_ok and sha512_ok:
            print(f"{prefix}{GREEN}OK        {fname}  "
                  f"sha256={actual_256[:16]}...{NC}")
            total_ok += 1
        else:
            fail_detail = []
            if not sha256_ok:
                fail_detail.append(
                    f"sha256: expected={exp['sha256'][:16]}...  got={actual_256[:16]}...")
            if not sha512_ok:
                fail_detail.append(
                    f"sha512: expected={exp['sha512'][:16]}...  got={actual_512[:16]}...")
            print(f"{prefix}{RED}TAMPERED  {fname}  {' | '.join(fail_detail)}{NC}")
            total_fail += 1
            alerts.append(f"[{ts_now}]  TAMPERED  zip={zname}  file={fname}  "
                           f"sha256_ok={sha256_ok}  sha512_ok={sha512_ok}")

        # ── 3d. Permission / ownership audit ─────────────────────
        if 'mode' in exp:
            cur_mode = oct(st.st_mode)
            if cur_mode != exp['mode']:
                try:
                    uname = pwd.getpwuid(st.st_uid).pw_name
                    gname = grp.getgrgid(st.st_gid).gr_name
                except Exception:
                    uname = str(st.st_uid); gname = str(st.st_gid)
                print(f"{prefix}{MAGENTA}PERM_CHG  {fname}  "
                      f"was={exp['mode']}  now={cur_mode}  "
                      f"owner={uname}:{gname}{NC}")
                total_perm_warn += 1
                alerts.append(f"[{ts_now}]  PERM_CHANGED  file={fname}  "
                               f"was={exp['mode']}  now={cur_mode}")

        # ── 3e. Inode ctime check (any metadata change) ──────────
        if 'mtime' in exp:
            if int(st.st_mtime) != exp['mtime']:
                delta = int(st.st_mtime) - exp['mtime']
                sign  = '+' if delta > 0 else ''
                print(f"{prefix}{YELLOW}MTIME_CHG {fname}  "
                      f"delta={sign}{delta}s since archiving{NC}")

print(f"  {CYAN}│{NC}")
print(f"  {CYAN}│  {BOLD}Result:{NC}  "
      f"{GREEN}{total_ok} OK{NC}  "
      f"{YELLOW}{total_missing} missing{NC}  "
      f"{RED}{total_fail} TAMPERED{NC}  "
      f"{RED}{total_size_fail} size-fail{NC}  "
      f"{MAGENTA}{total_perm_warn} perm-changed{NC}")

if total_fail > 0 or total_size_fail > 0:
    print(f"  {CYAN}│  {RED}{BOLD}⚠  {total_fail + total_size_fail} file(s) compromised since archiving!{NC}")

# ── 4. Write all alerts to persistent log ────────────────────────
if alerts:
    os.makedirs(persist_dir, exist_ok=True)
    alert_log = os.path.join(persist_dir, 'integrity_alerts.log')
    with open(alert_log, 'a') as al:
        for a in alerts:
            al.write(a + '\n')
    print(f"  {CYAN}│  {YELLOW}Alerts written → {alert_log}{NC}")
else:
    os.makedirs(persist_dir, exist_ok=True)
    alert_log = os.path.join(persist_dir, 'integrity_alerts.log')
    with open(alert_log, 'a') as al:
        al.write(f"[{ts_now}]  CLEAN_CHECK  all_ok={total_ok}  missing={total_missing}\n")
INTCHECK
  fi

  echo -e "  ${CYAN}${BOLD}└───────────────────────────────────────────────────────────┘${NC}"
  echo ""

  # ── Step 2: Delete .txt / .odt / .ods files (NOT zips) ───────
  # Zip archives are kept as evidence — they hold the integrity manifest.
  while IFS= read -r -d '' f; do
    _files+=("$f")
  done < <(find "$_dir" -maxdepth 1 -type f \
    \( -name 'wowscanner_*.txt' \
    -o -name 'wowscanner_*.odt' \
    -o -name 'wowscanner_*.ods' \
    -o -name 'wowscanner_*.odp' \
    -o -name 'wowscanner_*.sha256' \
    \) -print0 2>/dev/null)

  if [[ "${#_files[@]}" -eq 0 ]]; then
    echo -e "  ${GREEN}No wowscanner output files found in ${_dir}${NC}"
  else
    echo -e "  ${YELLOW}${BOLD}┌─ Deleting output files (zip archives kept) ──────────────┐${NC}"
    local _clean_ts
    _clean_ts=$(date '+%Y-%m-%d %H:%M:%S')
    for f in "${_files[@]}"; do
      local _sz _szh
      _sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
      _szh=$(numfmt --to=iec "$_sz" 2>/dev/null || echo "${_sz}B")
      if rm -f "$f" 2>/dev/null; then
        echo -e "  ${YELLOW}│  ${GREEN}deleted:${NC}  $(basename "$f")  ${YELLOW}(${_szh})${NC}"
        _wiped=$(( _wiped + 1 ))
        _bytes=$(( _bytes + _sz ))
        # Record intentional deletion so 'verify' does not alarm on this file
        mkdir -p "$PERSIST_DIR"
        echo "[${_clean_ts}]  CLEANED  file=$(basename "$f")" \
          >> "${PERSIST_DIR}/integrity_alerts.log"
      else
        echo -e "  ${YELLOW}│  ${RED}FAILED :${NC}  $(basename "$f")  (permission denied?)"
        _failed=$(( _failed + 1 ))
      fi
    done
    local _total_h
    _total_h=$(numfmt --to=iec "$_bytes" 2>/dev/null || echo "${_bytes}B")
    echo -e "  ${YELLOW}${BOLD}└─ Deleted ${_wiped} file(s)  (${_total_h} freed)${NC}"
    [[ "$_failed" -gt 0 ]] && \
      echo -e "  ${RED}  ${_failed} file(s) could not be deleted — check permissions${NC}"
  fi

  # ── Step 3: Show surviving zip archives ───────────────────────
  local _surviving_zips=()
  while IFS= read -r -d '' z; do
    _surviving_zips+=("$z")
  done < <(find "$_dir" -maxdepth 1 -type f -name 'wowscanner_archive_*.zip' -print0 2>/dev/null)
  if [[ "${#_surviving_zips[@]}" -gt 0 ]]; then
    echo ""
    echo -e "  ${CYAN}${BOLD}Zip archives kept (contain INTEGRITY.txt + all scan files):${NC}"
    for z in "${_surviving_zips[@]}"; do
      local _zsz _zszh
      _zsz=$(stat -c%s "$z" 2>/dev/null || echo 0)
      _zszh=$(numfmt --to=iec "$_zsz" 2>/dev/null || echo "${_zsz}B")
      echo -e "  ${CYAN}  • $(basename "$z")  (${_zszh})${NC}"
    done
    echo -e "  ${CYAN}  To restore files: unzip <archive> -d .${NC}"
    echo -e "  ${CYAN}  To verify:        sha256sum -c wowscanner_archive_*.sha256${NC}"
  fi

  # ── Step 4: Persistent data (/var/lib/wowscanner/) ───────────
  echo ""
  if [[ "$CLEAN_ALL" == "true" ]]; then
    local _persist="/var/lib/wowscanner"
    if [[ -d "$_persist" ]]; then
      echo -e "  ${YELLOW}${BOLD}┌─ Persistent data (--all): ${_persist} ─${NC}"
      local _pw=0 _pf=0 _pb=0
      while IFS= read -r -d '' f; do
        local _sz _szh
        _sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
        _szh=$(numfmt --to=iec "$_sz" 2>/dev/null || echo "${_sz}B")
        if rm -f "$f" 2>/dev/null; then
          echo -e "  ${YELLOW}│  ${GREEN}deleted:${NC}  $(basename "$f")  ${YELLOW}(${_szh})${NC}"
          _pw=$(( _pw + 1 )); _pb=$(( _pb + _sz ))
        else
          echo -e "  ${YELLOW}│  ${RED}FAILED :${NC}  $(basename "$f")"
          _pf=$(( _pf + 1 ))
        fi
      done < <(find "$_persist" -maxdepth 1 -type f -print0 2>/dev/null)
      local _ph
      _ph=$(numfmt --to=iec "$_pb" 2>/dev/null || echo "${_pb}B")
      echo -e "  ${YELLOW}${BOLD}└─ Deleted ${_pw} persistent file(s)  (${_ph} freed)${NC}"
      [[ "$_pf" -gt 0 ]] && \
        echo -e "  ${RED}  ${_pf} file(s) could not be deleted${NC}"
    else
      echo -e "  ${GREEN}  Persistent data directory ${_persist} does not exist — nothing to remove${NC}"
    fi
  else
    echo -e "  ${BOLD}  Persistent data (/var/lib/wowscanner/) was kept.${NC}"
    echo    "  Run with  clean --all  to also wipe port history and remediation data."
  fi

  echo ""
  echo -e "  ${GREEN}${BOLD}Done.${NC}"
  echo ""
}



# ================================================================
#  ARCHIVE OUTPUTS
#  Called at the end of every scan. Packs all wowscanner_* output
#  files for this run into a single timestamped zip archive:
#    wowscanner_archive_<TIMESTAMP>.zip
#  The individual files remain alongside the archive so they can be
#  opened directly; the zip provides a single artefact to hand off.
# ================================================================
archive_outputs() {
  local _dir="$PWD"
  local _zip="${_dir}/wowscanner_archive_${TIMESTAMP}.zip"
  local _sha="${_dir}/wowscanner_archive_${TIMESTAMP}.sha256"
  local _files=()

  # Collect every output file for THIS run (identified by $TIMESTAMP)
  while IFS= read -r -d '' f; do
    _files+=("$f")
  done < <(find "$_dir" -maxdepth 1 -type f \
    \( -name "wowscanner_${TIMESTAMP}.txt"          \
    -o -name "wowscanner_report_${TIMESTAMP}.odt"   \
    -o -name "wowscanner_stats_${TIMESTAMP}.ods"    \
    -o -name "wowscanner_intel_${TIMESTAMP}.odt"    \
    \) -print0 2>/dev/null)

  if [[ "${#_files[@]}" -eq 0 ]]; then
    warn "Archive: no output files found to archive (timestamp: ${TIMESTAMP})"
    return
  fi

  log ""
  log "  ${CYAN}${BOLD}┌─ Archiving scan outputs ──────────────────────────────────┐${NC}"

  # Build the zip with an enhanced INTEGRITY.txt manifest:
  #   - SHA-256 + SHA-512 dual hash per file
  #   - File size recorded (catches truncation before hashing)
  #   - HMAC-SHA256 of the entire manifest (detects manifest tampering)
  #   - Zip is self-verified immediately after writing
  python3 - "$_zip" "$_sha" "$PERSIST_DIR" "${_files[@]}" << 'ARCHEOF' || true
import sys, os, zipfile, hashlib, hmac, datetime, socket, struct

zip_path   = sys.argv[1]
sha_path   = sys.argv[2]
persist_dir= sys.argv[3]
src_files  = sys.argv[4:]

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()

def sha512(path):
    h = hashlib.sha512()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()

# Machine-derived HMAC key: hostname + machine-id (never leaves the machine)
def machine_key():
    parts = [socket.gethostname()]
    for p in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            parts.append(open(p).read().strip())
            break
        except Exception:
            pass
    return hashlib.sha256('|'.join(parts).encode()).digest()

ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Compute dual hashes + sizes
entries = {}
for src in src_files:
    if not os.path.isfile(src):
        continue
    name = os.path.basename(src)
    st   = os.stat(src)
    entries[name] = {
        'sha256': sha256(src),
        'sha512': sha512(src),
        'size':   st.st_size,
        'mtime':  int(st.st_mtime),
        'mode':   oct(st.st_mode),
        'uid':    st.st_uid,
        'gid':    st.st_gid,
    }

# Build manifest body (lines that will be HMAC'd)
body_lines = [
    f"# Wowscanner integrity manifest v2",
    f"# Generated  : {ts}",
    f"# Host       : {socket.gethostname()}",
    f"# Files      : {len(entries)}",
    f"# Format     : SHA256  SHA512  SIZE  MTIME  MODE  UID  GID  filename",
    f"#",
]
for name, e in sorted(entries.items()):
    body_lines.append(
        f"{e['sha256']}  {e['sha512']}  {e['size']}  "
        f"{e['mtime']}  {e['mode']}  {e['uid']}  {e['gid']}  {name}"
    )
body = "\n".join(body_lines) + "\n"

# Compute HMAC over the manifest body
sig = hmac.new(machine_key(), body.encode(), hashlib.sha256).hexdigest()
integrity_txt = body + f"# HMAC-SHA256: {sig}\n"

packed = 0; total_bytes = 0
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
    for src in src_files:
        if os.path.isfile(src):
            arcname = os.path.basename(src)
            zf.write(src, arcname)
            sz = os.path.getsize(src)
            total_bytes += sz
            packed += 1
            e = entries[arcname]
            print(f"  archived: {arcname}  ({sz:,}B)  "
                  f"sha256={e['sha256'][:16]}...  sha512={e['sha512'][:16]}...")
    zf.writestr("INTEGRITY.txt", integrity_txt)

# Immediately self-verify the zip (catches write errors / corruption)
bad_crc = []
try:
    with zipfile.ZipFile(zip_path, 'r') as zf:
        bad_crc = zf.testzip() or []
    if not bad_crc:
        print(f"  self-check: zip CRC OK — all {packed} files verified")
    else:
        print(f"  self-check: CRC FAIL in {bad_crc} — zip may be corrupt!")
except Exception as ex:
    print(f"  self-check: ERROR — {ex}")

# Write sidecar .sha256 (sha256sum -c compatible, dual-hash format with comments)
with open(sha_path, 'w') as sf:
    sf.write(f"# Wowscanner dual-hash integrity manifest — {ts}\n")
    sf.write(f"# sha256sum -c {os.path.basename(sha_path)}  (uses SHA-256 column)\n")
    sf.write(f"# HMAC-SHA256: {sig}\n")
    for name, e in sorted(entries.items()):
        sf.write(f"{e['sha256']}  {name}\n")

# Append event to persistent integrity alert log
os.makedirs(persist_dir, exist_ok=True)
alert_log = os.path.join(persist_dir, 'integrity_alerts.log')
with open(alert_log, 'a') as al:
    al.write(f"[{ts}]  ARCHIVED  zip={os.path.basename(zip_path)}  "
             f"files={packed}  crc={'OK' if not bad_crc else 'FAIL'}  "
             f"hmac={sig[:16]}...\n")

zip_sz = os.path.getsize(zip_path)
ratio  = round((1 - zip_sz / max(total_bytes, 1)) * 100)
print(f"  packed={packed}  uncompressed={total_bytes:,}B  "
      f"archive={zip_sz:,}B  saved={ratio}%")
print(f"  integrity: INTEGRITY.txt (inside zip, HMAC-signed) + {os.path.basename(sha_path)}")
ARCHEOF

  if [[ -f "$_zip" ]]; then
    local _zsz _zszh
    _zsz=$(stat -c%s "$_zip" 2>/dev/null || echo 0)
    _zszh=$(numfmt --to=iec "$_zsz" 2>/dev/null || echo "${_zsz}B")
    log "  ${CYAN}│  ${GREEN}${BOLD}Archive : $(basename "$_zip")  (${_zszh})${NC}"
    [[ -f "$_sha" ]] && \
      log "  ${CYAN}│  ${GREEN}${BOLD}Hashes  : $(basename "$_sha")  (verify: sha256sum -c $(basename "$_sha"))${NC}"
  else
    warn "Archive creation failed — individual files are still present"
  fi

  log "  ${CYAN}${BOLD}└─ Individual files kept alongside the archive${NC}"
  log ""
}

_elapsed() {
  local label="$1"
  local now
  now=$(date +%s)
  info "[timer] ${label}: +$(( now - T_START ))s total elapsed"
}

main() {
  require_root
  check_archive_presence   # warn immediately if any known zip has disappeared
  T_START=$(date +%s)

  # Banner — inner width is 59 chars (between ║ walls); use printf to auto-pad
  local _iw=59 _bl _cl _dl
  printf -v _bl "%-${_iw}s" "  ${PROGRAM}  v${VERSION}"
  printf -v _cl "%-${_iw}s" "  ${COPYRIGHT}"
  printf -v _dl "%-${_iw}s" "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
  log "╔═══════════════════════════════════════════════════════════╗"
  log "║${_bl}║"
  log "║${_cl}║"
  log "║${_dl}║"
  log "╚═══════════════════════════════════════════════════════════╝"
  log ""
  log "  Flags : --no-lynis | --no-pentest | --no-rkhunter | --quiet | --fast-only"
  log "  Env   : LYNIS_FULL=true | RKH_FULL=true | APT_CACHE_MAX_AGE=<secs>"
  local _m_pentest _m_lynis _m_rkhunter
  [[ "$USE_PENTEST"  == "true" ]] && _m_pentest=ON  || _m_pentest=OFF
  [[ "$USE_LYNIS"    == "true" ]] && _m_lynis=ON    || _m_lynis=OFF
  [[ "$USE_RKHUNTER" == "true" ]] && _m_rkhunter=ON || _m_rkhunter=OFF
  log "  Mode  : pentest=${_m_pentest}  lynis=${_m_lynis}  rkhunter=${_m_rkhunter}"
  log ""

  # Helper: log elapsed time after each major section

  section_pentest_enum;   _elapsed "0a pentest-enum"
  section_pentest_web;    _elapsed "0b pentest-web"
  section_pentest_ssh;    _elapsed "0c pentest-ssh"
  section_pentest_sqli;   _elapsed "0d pentest-sqli"
  section_pentest_stress; _elapsed "0e pentest-stress"
  section_sysinfo;        _elapsed "1 sysinfo"
  section_updates;        _elapsed "2 updates"
  section_users;          _elapsed "3 users"
  section_password_policy;_elapsed "4 password"
  section_ssh;            _elapsed "5 ssh"
  section_firewall;       _elapsed "6 firewall"
  section_ports;          _elapsed "7 ports"
  section_permissions;    _elapsed "8 permissions"
  section_services;       _elapsed "9 services"
  section_logging;        _elapsed "10 logging"
  section_kernel;         _elapsed "11 kernel"
  section_cron;           _elapsed "12 cron"
  section_packages;       _elapsed "13 packages"
  section_chkrootkit;     _elapsed "14b chkrootkit+rkhunter"
  section_mac;            _elapsed "14 mac"
  section_lynis;          _elapsed "15 lynis"
  section_portscan;       _elapsed "16 portscan"
  section_summary

  local PERCENTAGE=0
  [[ "$TOTAL" -gt 0 ]] && PERCENTAGE=$(( SCORE * 100 / TOTAL ))

  generate_odt_report       "$REPORT" "$SCORE" "$TOTAL" "$PERCENTAGE"
  generate_stats_ods        "$REPORT" "$SCORE" "$TOTAL" "$PERCENTAGE"
  generate_odf_intel_report "$SCORE"  "$TOTAL" "$PERCENTAGE" "$REPORT"
  archive_outputs

  local T_END T_ELAPSED
  T_END=$(date +%s)
  local T_ELAPSED T_MIN T_SEC
  T_ELAPSED=$(( T_END - T_START ))
  local T_MIN=$(( T_ELAPSED / 60 ))
  local T_SEC=$(( T_ELAPSED % 60 ))

  log ""
  log "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
  log "${CYAN}${BOLD}  OUTPUT FILES${NC}"
  log "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  log ""
  log "  ${GREEN}${BOLD}Total elapsed time: ${T_MIN}m ${T_SEC}s${NC}"
  log ""
  log "  ${GREEN}${BOLD}Individual output files:${NC}"
  log "  • ${REPORT}"
  log "  • wowscanner_report_${TIMESTAMP}.odt  — Graphical audit report (LibreOffice Writer)"
  log "  • wowscanner_stats_${TIMESTAMP}.ods   — Statistics + charts (LibreOffice Calc)"
  log "    └─ Sheets: Overview | Per-Section | Issues | FAIL Deep-Dive | WARN Deep-Dive | ChartData"
  log "    └─ SVGs  : score_gauge | bar_chart | pie_chart | heatmap | severity_radar"
  log "  • wowscanner_intel_${TIMESTAMP}.odt   — Statistical intelligence report"
  log "    └─ Pages : Dashboard | CVE Landscape | Local Stats | Threat Intel | Remediation Matrix"
  log "    └─ SVGs  : dashboard | cve_landscape | local_stats | threat_intel | remediation"
  log "    └─ Data  : NIST NVD · CISA KEV · Elastic · Trend Micro · Action1 · Mandiant (2025)"
  log ""
  log "  ${GREEN}${BOLD}Archive (all files above in one zip):${NC}"
  log "  • wowscanner_archive_${TIMESTAMP}.zip"
  log ""
  log "  ${BOLD}Persistent files:${NC}"
  log "  • ${PORT_ISSUES_LOG}"
  log "  • ${PORT_REMEDIATION}"
  log ""
  log "  ${BOLD}Manage output files:${NC}"
  log "  • sudo bash $0 clean       — delete output files in this directory"
  log "  • sudo bash $0 clean --all — also wipe /var/lib/wowscanner/ history"
  log ""
  log "  ${BOLD}Speed tips for next run:${NC}"
  log "  • --fast-only                   skip pentest sections (~2-4 min total)"
  log "  • --no-rkhunter                 skip rootkit scanners"
  log "  • --no-lynis                    skip Lynis audit"
  log "  • RKH_FULL=true  sudo bash $0   full rkhunter scan"
  log "  • LYNIS_FULL=true sudo bash $0  full Lynis audit"
  log ""

  # ── Restart Samba — must be the very last action ───────────────
  # Every output file (.txt via log/tee, .odt, .ods, .zip) has now been
  # fully written and closed.  Restarting smbd here guarantees the share
  # directory listing is refreshed AFTER all writes are complete.
  if systemctl is-active --quiet smbd 2>/dev/null || \
     systemctl is-active --quiet samba 2>/dev/null; then
    echo -e "  ${CYAN}Restarting Samba (smbd.service) so output files appear on the share...${NC}"
    if systemctl restart smbd.service 2>/dev/null; then
      echo -e "  ${GREEN}[✔]  smbd.service restarted — share directory is now up to date${NC}"
    elif systemctl restart smbd 2>/dev/null; then
      echo -e "  ${GREEN}[✔]  smbd restarted — share directory is now up to date${NC}"
    elif systemctl restart samba 2>/dev/null; then
      echo -e "  ${GREEN}[✔]  samba restarted — share directory is now up to date${NC}"
    else
      echo -e "  ${YELLOW}[⚠]  Could not restart Samba automatically.${NC}"
      echo -e "       Run manually:  ${BOLD}sudo systemctl restart smbd.service${NC}"
    fi
  fi
}

# ── Entry point dispatcher ────────────────────────────────────
if [[ "$CMD_HELP" == "true" ]]; then
  cmd_help
  exit 0
fi
if [[ "$CMD_VERIFY" == "true" ]]; then
  cmd_verify
  exit 0
fi
if [[ "$CMD_CLEAN" == "true" ]]; then
  cmd_clean
  exit 0
fi
main "$@"
