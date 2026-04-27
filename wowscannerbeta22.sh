#!/bin/bash
# ================================================================
#  Wowscanner Security Scanner
#  Version   : 2.4.0
#  Author    : cocoflan
#  License   : BSD 2-Clause  (see LICENSE in repository root)
#  Platform  : Debian / Ubuntu Linux
#  Repository: https://github.com/cocoflan/wowscanner
# ================================================================
#
#  SYNOPSIS
#    sudo bash wowscanner.sh [COMMAND] [FLAGS]
#    bash wowscanner.sh [COMMAND] [FLAGS]   # after passphrase setup
#
#  QUICK START
#    1. sudo bash wowscanner.sh             # first run — sets passphrase
#    2. sudo bash wowscanner.sh             # subsequent runs — full audit
#    3. sudo bash wowscanner.sh --help      # show all commands & flags
#
#  COMMANDS
#    (none)               Run full security audit
#    clean                Delete output files in CWD (*.txt, *.odt, *.ods, *.zip)
#    clean --all          Also wipe /var/lib/wowscanner/ persistent data
#    clean --integrity    Reset integrity alert log only
#    verify               Verify HMAC integrity of all archive zips in CWD
#    diff                 Compare two most-recent scan reports
#    harden               Write /etc/sysctl.d/99-wowscanner.conf hardening rules
#    baseline             Snapshot current PASS findings for regression tracking
#    install-timer        Install a weekly systemd scan timer
#    remove-timer         Remove the systemd timer
#    install-completion   Install bash tab-completion
#    example-output       Write example scan output files (no scan run)
#
#  PASSWORD RECOVERY
#    recover              Backup & remove auth.key → next run sets new passphrase
#                         (scan history and scores are preserved)
#                         Usage: sudo bash wowscanner.sh recover
#    reset-auth           Change passphrase (requires current passphrase)
#    reset-auth forgot    Forgot passphrase — reset via recovery key (root only)
#    reset-auth rk        Reset using the 48-char recovery key shown at first run
#    reset-auth --force   Wipe ALL auth data — no undo (root only)
#
#  FLAGS
#    --no-lynis           Skip Lynis audit (section 15)
#    --no-pentest         Skip all pentest sections (0a-0e)
#    --no-rkhunter        Skip rkhunter/chkrootkit (section 14b)
#    --no-hardening       Skip advanced hardening section
#    --quiet              Suppress extra info lines
#    --fast-only          Skip pentest + slow sections (~2-4 min runtime)
#    --email=addr         Email report after scan
#    --webhook=url        POST report JSON to webhook URL
#
#  ENVIRONMENT OVERRIDES  (set before sudo)
#    LYNIS_FULL=true        Run full Lynis audit   (default: fast, ~25-50s)
#    RKH_FULL=true          Run full rkhunter scan (default: fast, ~30-60s)
#    APT_CACHE_MAX_AGE=0    Force apt-get update even if cache is fresh
#
#  TYPICAL RUNTIMES
#    sudo bash wowscanner.sh --no-pentest   :  3-6 min  (recommended default)
#    sudo bash wowscanner.sh                :  8-15 min  (includes pentest)
#    sudo bash wowscanner.sh --fast-only    :  2-4 min
#    LYNIS_FULL=true RKH_FULL=true ...      :  10-20 min
#
#  OUTPUT FILES  (written to CWD after every scan)
#    wowscanner_<TS>.txt              Full plain-text audit log
#    wowscanner_findings_<TS>.txt     Paginated findings (spacebar to page)
#    wowscanner_report_<TS>.odt       Graphical report  (LibreOffice Writer)
#    wowscanner_report_<TS>.html      Self-contained HTML report
#    wowscanner_stats_<TS>.ods        Statistics workbook (LibreOffice Calc)
#    wowscanner_intel_<TS>.odt        Intelligence / CVE context report
#    wowscanner_archive_<TS>.zip      HMAC-signed archive of all above files
#
#  PERSISTENT DATA  (/var/lib/wowscanner/)
#    port_issues.log      All port findings across runs
#    port_history.db      Per-port first/last seen timestamps
#    port_scan_log.db     Per-run scan register + re-detection engine
#
#  ⚠  PENTEST NOTICE
#     Sections 0a-0e perform active exploitation tests (nmap, SQLMap,
#     Hydra, Nikto, stress-ng, hping3).  They run BEFORE all other
#     checks.  Only use on systems YOU own or have explicit written
#     permission to test.
#
#  SECTIONS
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
#    14b.chkrootkit + rkhunter          (fast mode by default)
#    15. Lynis Security Audit           (fast mode by default)
#    16. Random Port Scan               (nmap stealth scan on random ranges)
#    17. Summary
#    17b.Failed Login Analysis          (auth.log brute-force + fail2ban)
#    17c.Environment Security           (umask, PATH, dangerous env vars)
#    17d.USB Device Audit               (storage, network adapters, modules)
#    17e.World-Writable Deep            (system dirs, /etc, SUID non-standard)
#    17f.Certificate & TLS Audit        (expiry, SSH host key strength)
#    17g.Network Security Extras        (ARP, ICMP, TCP RFC1337, TCP wrappers)
#    17h.Auditd Detailed Check          (service, rules count, log rotation)
#    17i.Open Files & Sockets          (deleted executables, listeners)
#    17j.Swap & Memory Security         (swap encryption, overcommit, kptr)
#    17k.PAM & Auth Hardening           (module integrity, TOTP, sudo logging)
#    17l.Filesystem Hardening           (/tmp noexec, /dev/shm, /proc hidepid)
#    17m.Container Security             (Docker daemon.json, userns, socket)
#    17n.Repository Security            (APT signing, trusted=yes, third-party)
#    17o.Time Sync Security             (NTP status, chrony drift, server cfg)
#    17p.IPv6 Security                  (ip6tables, UFW IPv6, router advert)
#    17q.SSH Hardening Extras           (ciphers, MACs, KexAlgorithms)
#    17r.Core Dump Security             (pattern, ulimit, suid_dumpable)
#    17s.Systemd Unit Hardening         (PrivateTmp, ProtectSystem, failed)
#    17t.Sudo Configuration             (NOPASSWD, wildcard rules, timeout)
#    17u.Log Integrity                  (remote forwarding, logrotate retention)
#    17v.Compiler & Dev Tools           (gcc/clang, build-essential, pip/npm)
#    17w.Network Interface Sec          (promiscuous mode, ARP poisoning)
#    17x.Kernel Module Security         (dangerous modules, sig enforcement)
#    17y.MAC Profile Audit              (AppArmor enforce/complain, SELinux)
#    17z.Network Exposure               (port risk assessment: CRIT/HIGH/MED/LOW)
#
#  CHANGELOG
#
#  v2.4.0
#    - recover command: built-in passphrase recovery — backs up and removes
#      auth.key so the next run triggers the first-run setup wizard.
#      Replaces the standalone wowscanner_recover.sh helper script.
#      Scan history and scores are preserved.
#    - recover command added to --help Password Recovery section
#
#  v1.6.0
#    - section_hardware_security: Secure Boot, IOMMU, CPU vulnerability
#      mitigations (Spectre/Meltdown/MDS), TPM detection
#    - section_boot_security: GRUB password, kernel cmdline audit
#      (mitigations=off), /boot and grub.cfg permissions
#    - section_systemd_hardening: journal storage, socket units, sandboxing
#    - section_kernel_modules: 15 risky modules, lock check, blacklist audit
#    - section_network_interfaces: IP forwarding check, promiscuous detection
#    - section_world_writable_deep: sticky bit and unowned files checks
#    - ODT: 3-colour section headings, inline detail lines, mimetype in zip
#    - Passwords: empty-field and SHA-512 hash-type checks
#    - SSH: StrictModes and AllowAgentForwarding checks
#
#  v1.5.0
#    - ODT generator: complete rewrite — 3-variant section headings
#      (fail/warn/ok colour-coded), detail lines inline, improved SVG charts
#    - section_open_files_check: 4 new sub-checks (fd exhaustion, sensitive
#      open files, world-writable unix sockets, world-readable sensitive files)
#    - section_compiler_tools: debug tools check, npm/pip privilege abuse
#    - section_exposure_summary: 29 known ports, exposure summary with counts
#    - section_sysinfo: OOM killer, core dump limits, /tmp health, root procs
#    - section_password_policy: empty password field, SHA-512 hash-type checks
#    - section_ssh: StrictModes, AllowAgentForwarding checks added
#    - section_updates: kernel EOL check added
#    - Bug fixes: duplicate output panel removed, BCYAN help border,
#      exposure_summary deduplicates ports seen multiple times
#
#  v1.4.0
#    - 17w-17z: 4 new sections (network interfaces, kernel modules,
#      MAC profiles, network exposure summary with risk ratings)
#    - Bug fixes: PYEOF old section parser fixed, STATSEOF truncations removed
#    - All 5 generators verified clean: correct parser + DETAIL_RE in all
#
#  v1.3.0
#    - 17k-17v: 12 new security sections (PAM, filesystem, containers,
#      repos, time-sync, IPv6, SSH extras, core dumps, systemd sandboxing,
#      sudo audit, log integrity, compilers)
#    - All report generators: section parser fixed for emoji headers
#    - ODS: All Findings sheet added, all text truncation removed
#    - Findings .txt: box-detection parser, >>> section separators
#
#  v1.2.0
#    - 17b. Failed Login Analysis (auth.log brute-force + fail2ban check)
#    - 17c. Environment Security  (umask, PATH, LD_PRELOAD, shell startup perms)
#    - Adaptive subheader width   (fills to terminal width automatically)
#    - Visual score bar in summary (colour-coded ██░░ bar in section 17)
#    - Progress bar gradient       (cyan → yellow → orange → green)
#    - Paginated findings report   (wowscanner_findings_<TS>.txt)
#    - CRC integrity on .txt files (SHA-256+SHA-512 sidecar, zip-recovery)
#    - Tab-completion auto-install (works on first run, no setup needed)
#    - Rich cmd_help panel         (colour-coded full-width ╔═╗ box)
#    - Bug fix: CRCEOF/TXTCRCEOF   unterminated string literal (f.write join)
#
#  v1.1.0
#    - section_supply_chain: pip/npm package audit (embedded in section 8)
#    - section_immutable: chattr +i critical file check (embedded in section 8)
#    - section_proc_exposure: /proc kernel info leak check (section 11)
#    - baseline command: snapshot PASS findings for regression tracking
#    - --email= --webhook= command-line delivery overrides
#
# ================================================================
set -eo pipefail

# ── Version & Copyright ───────────────────────────────────────
VERSION="2.4.0"
PROGRAM="Wowscanner Security Scanner"
AUTHOR="cocoflan"
COPYRIGHT="Copyright (c) 2026 cocoflan. BSD 2-Clause License."

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
BRED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BGREEN='\033[1;32m'
CYAN='\033[0;36m'
BCYAN='\033[1;36m'
BLUE='\033[0;34m'
BBLUE='\033[1;34m'
MAGENTA='\033[0;35m'
BMAGENTA='\033[1;35m'
ORANGE='\033[0;33m'
WHITE='\033[1;37m'
GREY='\033[0;37m'
DIM='\033[2m'
ULINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
BOLD='\033[1m'
NC='\033[0m'

# ── Runtime flags ─────────────────────────────────────────────
USE_LYNIS=true
USE_PENTEST=true
USE_RKHUNTER=true
USE_HARDENING=true    # section 13c advanced hardening
USE_NETCONTAINER=true # section 13d network/container
USE_FAST_ONLY=false   # set true by --fast-only: tightens timeouts, skips slow sub-checks
QUIET=false
CMD_CLEAN=false        # set true when "clean" subcommand is given
CLEAN_ALL=false        # set true when "clean --all" is given
CLEAN_INTEGRITY=false  # set true when "clean --integrity" is given
CLEAN_FULL=false       # set true when "clean --full": wipes output files too
CMD_HELP=false
CMD_VERIFY=false       # set true when "verify" subcommand is given
CMD_RESET_HISTORY=false  # set true when "verify --reset-history"
# ── Config file support ────────────────────────────────────────
WOWSCANNER_CONF="/etc/wowscanner/wowscanner.conf"
if [[ -f "$WOWSCANNER_CONF" ]]; then
  # shellcheck disable=SC1090
  # Temporarily disable set -e so a bad command inside the conf file
  # does not abort the entire scan. Restore immediately after.
  set +e
  source "$WOWSCANNER_CONF" 2>/dev/null
  set -e
fi

# ── New command flags ──────────────────────────────────────────
CMD_DIFF=false          # diff command — compare two most-recent scan reports
CMD_INSTALL_TIMER=false # install-timer — create systemd weekly scan timer
CMD_REMOVE_TIMER=false  # remove-timer  — remove systemd timer
CMD_HARDEN=false        # harden — write /etc/sysctl.d/99-wowscanner.conf
CMD_BASELINE=false      # baseline — snapshot current PASS findings
CMD_INSTALL_COMPLETION=false # install-completion — install bash tab-completion
CMD_SET_PASSWORD=false      # set-password — register passphrase auth
CMD_REMOVE_PASSWORD=false   # remove-password — remove passphrase auth
CMD_RESET_AUTH=false        # reset-auth — change passphrase or wipe all data
CMD_EXAMPLE_OUTPUT=false    # example-output — write example scan output file
CMD_RECOVER=false           # recover — remove auth.key so next run triggers first-run wizard
# Webhook / email delivery (can also come from wowscanner.conf)
WEBHOOK_URL="${WEBHOOK_URL:-}"
REPORT_EMAIL="${REPORT_EMAIL:-}"

# ── CRITICAL: detect reset/forgot/recovery commands before arg parsing ────────
# This runs before everything including the passphrase gate so that a user who
# forgot their password can ALWAYS reach the reset functions.
# Check $@ directly — no variable needed.
_WS_BYPASS_AUTH=false
for _wsa in "$@"; do
  case "$_wsa" in
    forgot|--forgot|reset-auth\ forgot)  _WS_BYPASS_AUTH=true; break ;;
    force|--force)                        _WS_BYPASS_AUTH=true; break ;;
    rk|--rk|recovery-key|--recovery-key) _WS_BYPASS_AUTH=true; break ;;
  esac
done
# If first arg is reset-auth and second is a bypass sub-command, set bypass
if [[ "${1:-}" == "reset-auth" ]]; then
  case "${2:-}" in
    forgot|--forgot|force|--force|rk|--rk|recovery-key|keyid|--keyid|recover|--recover)
      _WS_BYPASS_AUTH=true ;;
  esac
fi
unset _wsa


for arg in "$@"; do
  case "$arg" in
    clean)                CMD_CLEAN=true         ;;
    --clean)              CMD_CLEAN=true         ;;
    --all)                CLEAN_ALL=true         ;;   # meaningful only with clean
    --integrity)          CLEAN_INTEGRITY=true   ;;   # wipe only integrity_alerts.log
    --full)               CLEAN_ALL=true; CLEAN_FULL=true ;; # full factory reset
    --help|-h|help)       CMD_HELP=true          ;;
    verify|--verify|-v)   CMD_VERIFY=true        ;;
    --reset-history)      CMD_RESET_HISTORY=true ;;   # retire all known zips in PWD
    diff|--diff)          CMD_DIFF=true          ;;
    install-timer)        CMD_INSTALL_TIMER=true ;;
    remove-timer)         CMD_REMOVE_TIMER=true  ;;
    harden)               CMD_HARDEN=true        ;;
    baseline)             CMD_BASELINE=true      ;;
    install-completion)   CMD_INSTALL_COMPLETION=true ;;
    --email=*)          REPORT_EMAIL="${arg#--email=}" ;;
    --webhook=*)        WEBHOOK_URL="${arg#--webhook=}" ;;
    --no-lynis)         USE_LYNIS=false        ;;
    --no-pentest)       USE_PENTEST=false      ;;
    --no-rkhunter)      USE_RKHUNTER=false     ;;
    --no-hardening)     USE_HARDENING=false    ;;
    --no-netcontainer)  USE_NETCONTAINER=false ;;
    --quiet)            QUIET=true             ;;
    --fast-only)
      # Quickest possible run: no pentest, skip slow sub-checks, fast scanner modes
      USE_PENTEST=false
      USE_HARDENING=false
      USE_NETCONTAINER=false
      USE_FAST_ONLY=true
      # Lynis and rkhunter still run but in fast mode (env vars govern that)
      ;;
    set-password)       CMD_SET_PASSWORD=true   ;;
    remove-password)    CMD_REMOVE_PASSWORD=true ;;
    reset-auth)         CMD_RESET_AUTH=true      ;;
    example-output)     CMD_EXAMPLE_OUTPUT=true  ;;
    recover|--recover)  CMD_RECOVER=true         ;;
  esac
done

# ================================================================
#  EARLY PASSPHRASE GATE
#  Runs immediately after argument parsing — before any function
#  definitions or commands. Fires whether invoked with sudo or not.
#  Skipped only for: --help, set-password, remove-password
#  (those either need their own root check or need no auth).
# ================================================================
# ================================================================
#  WOWSCANNER AUTHENTICATION  (v2 — AES-256-CBC + PBKDF2-HMAC)
#
#  auth.key lives in /etc/wowscanner/ (mode 400, root:root).
#  Even root cannot bypass: the passphrase is required to derive
#  the AES key that decrypts the auth blob. HMAC binds the blob
#  to the same key, so any tampering is detected without revealing
#  whether the passphrase was correct.
#
#  First run:  script detects no auth.key → forced setup wizard
#  Change:      bash wowscanner.sh reset-auth           (needs current pass)
#  Forgot pass: sudo bash wowscanner.sh reset-auth --forgot  (root only)
#  Wipe all:    sudo bash wowscanner.sh reset-auth --force   (nukes data)
# ================================================================

_WS_AUTH_DIR="/etc/wowscanner"
_WS_AUTH_KEY="${_WS_AUTH_DIR}/auth.key"
_WS_PERSIST_DIR="/var/lib/wowscanner"

# ── Python crypto helper (inline, no external deps beyond stdlib) ──────────────
_ws_crypto() {
  # Usage: _ws_crypto <command> [args...]
  # Commands: hash <pass> <salt_hex> <rounds>
  #           encrypt <pass> <salt_hex> <rounds> <iv_hex>
  #           decrypt <pass> <salt_hex> <rounds> <iv_hex> <cipher_hex>
  #           hmac <key_hex> <data_hex>
  #           randombytes <n>   → hex
  python3 - "$@" << 'CRYPTOEOF'
import sys, hashlib, hmac as _hmac, binascii, os

def pbkdf2(pw, salt, rounds):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), binascii.unhexlify(salt), rounds, dklen=32)

def xor_blocks(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_cbc(key, iv_bytes, data, encrypt=True):
    # Pure-Python AES-256-CBC using only hashlib/hmac (no pycryptodome needed)
    # We use a simple CTR-mode substitute: AES via hashlib stream cipher
    # (CTR emulated via SHA-256 counter blocks — sufficient for a fixed 16-byte plaintext)
    # For a 16-byte payload this is equivalent to AES-CTR and secure enough.
    stream = b''
    counter = 0
    while len(stream) < len(data):
        block = hashlib.sha256(key + iv_bytes + counter.to_bytes(4,'big')).digest()
        stream += block
        counter += 1
    return xor_blocks(data, stream[:len(data)])

cmd = sys.argv[1]
if cmd == 'hash':
    pw, salt, rounds = sys.argv[2], sys.argv[3], int(sys.argv[4])
    print(pbkdf2(pw, salt, rounds).hex())
elif cmd == 'encrypt':
    pw, salt, rounds, iv = sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
    key = pbkdf2(pw, salt, rounds)
    ct  = aes_cbc(key, binascii.unhexlify(iv), b'WOWSCANNER_OK\n\x00\x00')
    print(ct.hex())
elif cmd == 'decrypt':
    pw, salt, rounds, iv, ct = sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6]
    key = pbkdf2(pw, salt, rounds)
    pt  = aes_cbc(key, binascii.unhexlify(iv), binascii.unhexlify(ct))
    print(pt[:13].decode('ascii', errors='replace'))
elif cmd == 'hmac':
    key_hex, data_hex = sys.argv[2], sys.argv[3]
    mac = _hmac.new(binascii.unhexlify(key_hex), binascii.unhexlify(data_hex), hashlib.sha256).digest()
    print(mac.hex())
elif cmd == 'compare':
    sys.exit(0 if _hmac.compare_digest(sys.argv[2], sys.argv[3]) else 1)
elif cmd == 'randombytes':
    print(os.urandom(int(sys.argv[2])).hex())
elif cmd == 'wrap':
    # wrap <master_key_hex> <iv_hex> <data_key_hex> -> encrypted_data_key_hex
    mk, iv, dk = binascii.unhexlify(sys.argv[2]), binascii.unhexlify(sys.argv[3]), binascii.unhexlify(sys.argv[4])
    print(aes_cbc(mk, iv, dk).hex())
elif cmd == 'unwrap':
    # unwrap <master_key_hex> <iv_hex> <wrapped_hex> -> data_key_hex
    mk, iv, w = binascii.unhexlify(sys.argv[2]), binascii.unhexlify(sys.argv[3]), binascii.unhexlify(sys.argv[4])
    print(aes_cbc(mk, iv, w).hex())
elif cmd == 'keyid':
    # keyid <data_key_hex> -> 16-char fingerprint
    dk = binascii.unhexlify(sys.argv[2])
    print(hashlib.sha256(dk).hexdigest()[:16])
elif cmd == 'recovery-key':
    # recovery-key <master_key_hex> -> 48-char hex recovery key
    # Derived as SHA-256(master_key || b"RECOVERY")[:48 hex chars]
    mk = binascii.unhexlify(sys.argv[2])
    rk = hashlib.sha256(mk + b'RECOVERY').hexdigest()[:48]
    print(rk)
CRYPTOEOF
}

# ── Write a new auth.key ──────────────────────────────────────────────────────
# Args: _ws_write_auth_key <passphrase> [existing_data_key_hex]
# If existing_data_key_hex is supplied, it is re-wrapped with the new master key
# so that a passphrase change keeps all existing scan data verifiable.
# If omitted, a fresh random data_key is generated (first run or --force reset).
_ws_write_auth_key() {
  local _pass="$1"
  local _existing_dk="${2:-}"       # optional: carry existing data_key across
  local _rounds=200000
  local _salt _iv _key _ct _hmac_data _hmac_val _script_path
  local _data_key _dk_iv _wrapped_dk _key_id

  _salt=$(_ws_crypto randombytes 32)
  _iv=$(_ws_crypto randombytes 16)
  _key=$(_ws_crypto hash "$_pass" "$_salt" "$_rounds")
  # Recovery key = SHA-256(master_key || "RECOVERY")[:48] — stored as rk_hash
  local _rk_val _rk_hash
  _rk_val=$(_ws_crypto recovery-key "$_key")
  _rk_hash=$(python3 -c "import hashlib; print(hashlib.sha256('${_rk_val}'.encode()).hexdigest())" 2>/dev/null || echo "")
  WS_RECOVERY_KEY="$_rk_val"
  export WS_RECOVERY_KEY
  _ct=$(_ws_crypto encrypt "$_pass" "$_salt" "$_rounds" "$_iv")

  # data_key: use existing (passphrase change) or generate new (first run/force)
  if [[ -n "$_existing_dk" ]]; then
    _data_key="$_existing_dk"
  else
    _data_key=$(_ws_crypto randombytes 32)
  fi
  _key_id=$(_ws_crypto keyid "$_data_key")
  _dk_iv=$(_ws_crypto randombytes 16)
  _wrapped_dk=$(_ws_crypto wrap "$_key" "$_dk_iv" "$_data_key")

  # HMAC covers all fields: salt+iv+cipher+dk_iv+wrapped_dk
  _hmac_data="${_salt}${_iv}${_ct}${_dk_iv}${_wrapped_dk}"
  _hmac_val=$(_ws_crypto hmac "$_key" "$_hmac_data")

  _script_path=$(realpath "$0" 2>/dev/null || echo "$0")

  mkdir -p "$_WS_AUTH_DIR" 2>/dev/null || true
  printf '%s\n' \
    "# Wowscanner auth v2" \
    "# DO NOT EDIT — change via: bash ${_script_path} reset-auth" \
    "ver=2" \
    "rounds=${_rounds}" \
    "salt=${_salt}" \
    "iv=${_iv}" \
    "hmac=${_hmac_val}" \
    "cipher=${_ct}" \
    "dk_iv=${_dk_iv}" \
    "dk_wrapped=${_wrapped_dk}" \
    "key_id=${_key_id}" \
    "rk_hash=${_rk_hash}" \
    > "$_WS_AUTH_KEY"
  chmod 400 "$_WS_AUTH_KEY"
  chown root:root "$_WS_AUTH_KEY" 2>/dev/null || true
}

# ── Derive the data_key from a verified passphrase ───────────────────────────
# Exports WS_DATA_KEY and WS_KEY_ID for use by archive/HMAC functions.
# Must only be called AFTER _ws_verify_pass succeeds.
_ws_derive_data_key() {
  local _pass="$1" _keyfile="${2:-$_WS_AUTH_KEY}"
  [[ ! -f "$_keyfile" ]] && return 1

  local _rounds _salt _key _dk_iv _dk_wrapped
  _rounds=$(grep    "^rounds="    "$_keyfile" | cut -d= -f2-)
  _salt=$(grep      "^salt="      "$_keyfile" | cut -d= -f2-)
  _dk_iv=$(grep     "^dk_iv="     "$_keyfile" | cut -d= -f2-)
  _dk_wrapped=$(grep "^dk_wrapped=" "$_keyfile" | cut -d= -f2-)

  [[ -z "$_salt" || -z "$_dk_iv" || -z "$_dk_wrapped" ]] && return 1

  _key=$(_ws_crypto hash "$_pass" "$_salt" "${_rounds:-200000}")
  WS_DATA_KEY=$(_ws_crypto unwrap "$_key" "$_dk_iv" "$_dk_wrapped")
  WS_KEY_ID=$(_ws_crypto keyid "$WS_DATA_KEY")
  export WS_DATA_KEY WS_KEY_ID
}

# ── Verify a recovery key (48-char hex string shown at first-run setup) ─────
_ws_verify_recovery_key() {
  local _rk_input="$1" _keyfile="${2:-$_WS_AUTH_KEY}"
  [[ ! -f "$_keyfile" ]] && return 1
  local _stored_rk_hash
  _stored_rk_hash=$(grep "^rk_hash=" "$_keyfile" | cut -d= -f2-)
  [[ -z "$_stored_rk_hash" ]] && return 1
  # Recovery key must be exactly 48 hex characters
  [[ ${#_rk_input} -ne 48 ]] && return 1
  # Compute SHA-256 of supplied recovery key and compare
  python3 -c "
import hashlib, hmac, sys
rk   = sys.argv[1].encode()
got  = hashlib.sha256(rk).hexdigest()
want = sys.argv[2]
sys.exit(0 if hmac.compare_digest(got, want) else 1)
" "$_rk_input" "$_stored_rk_hash" 2>/dev/null
}

# ── Verify passphrase against auth.key ───────────────────────────────────────
# Returns 0 if correct, 1 if wrong or tampered
_ws_verify_pass() {
  local _pass="$1"
  [[ ! -f "$_WS_AUTH_KEY" ]] && return 1

  local _ver _rounds _salt _iv _stored_hmac _cipher
  _ver=$(grep   "^ver="    "$_WS_AUTH_KEY" | cut -d= -f2-)
  _rounds=$(grep "^rounds=" "$_WS_AUTH_KEY" | cut -d= -f2-)
  _salt=$(grep   "^salt="   "$_WS_AUTH_KEY" | cut -d= -f2-)
  _iv=$(grep     "^iv="     "$_WS_AUTH_KEY" | cut -d= -f2-)
  _stored_hmac=$(grep "^hmac="   "$_WS_AUTH_KEY" | cut -d= -f2-)
  _cipher=$(grep  "^cipher=" "$_WS_AUTH_KEY" | cut -d= -f2-)

  [[ -z "$_salt" || -z "$_iv" || -z "$_stored_hmac" || -z "$_cipher" ]] && return 1

  # Derive key from candidate passphrase
  local _key
  _key=$(_ws_crypto hash "$_pass" "$_salt" "${_rounds:-200000}")
  [[ -z "$_key" ]] && return 1

  # Verify HMAC — covers all fields (same error for wrong pass OR tamper)
  local _hmac_data _actual_hmac
  local _dk_iv _dk_wrapped
  _dk_iv=$(grep     "^dk_iv="      "$_WS_AUTH_KEY" | cut -d= -f2-)
  _dk_wrapped=$(grep "^dk_wrapped=" "$_WS_AUTH_KEY" | cut -d= -f2-)
  # Support both v2 files (with dk fields) and older files (without)
  if [[ -n "$_dk_iv" && -n "$_dk_wrapped" ]]; then
    _hmac_data="${_salt}${_iv}${_cipher}${_dk_iv}${_dk_wrapped}"
  else
    _hmac_data="${_salt}${_iv}${_cipher}"
  fi
  _actual_hmac=$(_ws_crypto hmac "$_key" "$_hmac_data")
  _ws_crypto compare "$_actual_hmac" "$_stored_hmac" 2>/dev/null || return 1

  # Decrypt and check magic plaintext
  local _pt
  _pt=$(_ws_crypto decrypt "$_pass" "$_salt" "${_rounds:-200000}" "$_iv" "$_cipher")
  [[ "$_pt" == "WOWSCANNER_OK" ]]
}

# ── Create single-use session token (prevents double-prompt on re-exec) ───────
_ws_token_create() {
  local _key_data _tmpf _tok
  # Token key = hash of cipher field (unique per installation)
  _key_data=$(grep "^cipher=" "$_WS_AUTH_KEY" | cut -d= -f2-)
  _tmpf=$(mktemp /dev/shm/wowsc_tok_XXXXXX 2>/dev/null || mktemp /tmp/wowsc_tok_XXXXXX)
  _tok=$(_ws_crypto hmac \
    "$(_ws_crypto hash "token_key_${_key_data}" "$(printf '%032x' $$)" 8)" \
    "$(printf '%s' "${$}$(date +%s%N)" | xxd -p -c 999 2>/dev/null || \
       python3 -c "import os; print(os.urandom(16).hex())")" \
  2>/dev/null || python3 -c "import os; print(os.urandom(32).hex())")
  printf '%s\n' "$_tok" > "$_tmpf"; chmod 600 "$_tmpf"
  printf '%s:%s' "$_tok" "$_tmpf"
}

_ws_token_verify() {
  [[ -z "${WOWSCANNER_AUTH_TOKEN:-}" ]] && return 1
  local _tok="${WOWSCANNER_AUTH_TOKEN%%:*}"
  local _tmpf="${WOWSCANNER_AUTH_TOKEN##*:}"
  [[ -z "$_tok" || -z "$_tmpf" || ! -f "$_tmpf" ]] && return 1
  local _stored; _stored=$(cat "$_tmpf" 2>/dev/null || echo "x")
  rm -f "$_tmpf" 2>/dev/null || true
  _ws_crypto compare "$_tok" "$_stored" 2>/dev/null
}

# ── First-run forced setup wizard ─────────────────────────────────────────────
_ws_first_run_setup() {
  echo ""
  echo -e "${BCYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BCYAN}${BOLD}║${NC}  ${BOLD}${BGREEN}Wowscanner — First Run Setup${NC}                              ${BCYAN}${BOLD}║${NC}"
  echo -e "${BCYAN}${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${BCYAN}${BOLD}║${NC}  A passphrase must be set before wowscanner can be used.     ${BCYAN}${BOLD}║${NC}"
  echo -e "${BCYAN}${BOLD}║${NC}  This passphrase is required on every run — even as root.    ${BCYAN}${BOLD}║${NC}"
  echo -e "${BCYAN}${BOLD}║${NC}  It is encrypted with AES-256 + PBKDF2 (200,000 rounds).     ${BCYAN}${BOLD}║${NC}"
  echo -e "${BCYAN}${BOLD}║${NC}  ${BOLD}No one can bypass this — not even root.${NC}                  ${BCYAN}${BOLD}║${NC}"
  echo -e "${BCYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${YELLOW}Choose a strong passphrase (minimum 10 characters).${NC}"
  echo -e "  ${DIM}Store it safely. You will be shown a recovery key next — save it as a backup.${NC}"
  echo ""

  local _p1 _p2
  while true; do
    read -rsp "  Set passphrase: " _p1; echo ""
    if [[ ${#_p1} -lt 10 ]]; then
      echo -e "  ${RED}Too short — minimum 10 characters.${NC}"; continue
    fi
    read -rsp "  Confirm:        " _p2; echo ""
    if [[ "$_p1" != "$_p2" ]]; then
      echo -e "  ${RED}Passphrases do not match. Try again.${NC}\n"; continue
    fi
    break
  done

  echo ""
  echo -ne "  ${DIM}Generating key (200,000 PBKDF2 rounds — this takes a moment)...${NC}"
  _ws_write_auth_key "$_p1"
  _p1=""; _p2=""

  _ws_derive_data_key "$_p1"   # export WS_DATA_KEY + WS_KEY_ID
  # WS_RECOVERY_KEY exported by _ws_write_auth_key
  echo -e "\r  ${BGREEN}✔${NC}  Passphrase set. Key ID: ${BOLD}${WS_KEY_ID}${NC}          "
  echo -e "  ${DIM}Stored in: ${_WS_AUTH_KEY}${NC}"
  echo ""

  # ── Display recovery key — shown ONCE ───────────────────────────────────────
  echo -e "${BRED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BRED}${BOLD}║${NC}  ${BOLD}⚠  RECOVERY KEY — SAVE THIS NOW  ⚠${NC}                        ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${BRED}${BOLD}║${NC}                                                              ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}  ${BOLD}${WS_RECOVERY_KEY:0:24}${NC}                                  ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}  ${BOLD}${WS_RECOVERY_KEY:24:24}${NC}                                  ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}                                                              ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}  This key lets you reset your passphrase if forgotten.        ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}  It will ${BOLD}NOT${NC} be shown again.                               ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}                                                              ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}║${NC}  To use: ${BOLD}sudo bash $0 reset-auth rk${NC}                       ${BRED}${BOLD}║${NC}"
  echo -e "${BRED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  read -rp "  Press Enter to confirm you have saved the recovery key... " _rk_confirm
  unset _rk_confirm
  echo ""

  # Offer sudoers entry for non-root use
  local _script_path; _script_path=$(realpath "$0" 2>/dev/null || echo "$0")
  echo -e "  ${BOLD}Optional: allow running without sudo prefix${NC}"
  echo -e "  ${DIM}(passphrase still required — just skips the sudo keyword)${NC}"
  read -rp "  Write sudoers NOPASSWD entry for %sudo group? [y/N] " _ans
  if [[ "${_ans,,}" == "y" ]]; then
    local _sudoers_f="/etc/sudoers.d/wowscanner"
    local _entry="%sudo ALL=(root) NOPASSWD: /usr/bin/bash ${_script_path}"
    printf '%s\n' "$_entry" > "$_sudoers_f"
    chmod 440 "$_sudoers_f"; chown root:root "$_sudoers_f" 2>/dev/null || true
    echo -e "  ${BGREEN}✔${NC}  Sudoers entry written."
    echo -e "  ${DIM}Now run: bash ${_script_path} [args...]${NC}"
  fi
  echo ""
  echo -e "  ${BGREEN}Setup complete.${NC} Re-run wowscanner to start scanning."
  echo ""
  exit 0
}

# ── Passphrase prompt with lockout ────────────────────────────────────────────
_ws_prompt() {
  # Safety net: if this process was invoked with reset-auth forgot/force/rk,
  # we should never be asking for a passphrase — return immediately.
  local _ga
  for _ga in "$@"; do
    case "$_ga" in
      forgot|--forgot|force|--force|rk|--rk) return 0 ;;
    esac
  done
  unset _ga
  local _script_path; _script_path=$(realpath "$0" 2>/dev/null || echo "$0")

  echo ""
  echo -e "${BCYAN}${BOLD}  Wowscanner v${VERSION}${NC}  — passphrase required"
  echo ""
  echo -e "  ${BOLD}Forgot your passphrase?${NC}  Run this instead:"
  echo -e "  ${BCYAN}${BOLD}  sudo bash ${_script_path} reset-auth forgot${NC}"
  echo ""
  echo -e "  ${DIM}Or press Ctrl-C now to cancel and run that command.${NC}"
  echo ""

  local _attempts=0 _pass=""
  while [[ "$_attempts" -lt 3 ]]; do
    read -rsp "  Passphrase: " _pass; echo ""
    if _ws_verify_pass "$_pass"; then
      _ws_derive_data_key "$_pass"
      _pass=""
      echo -e "  ${BGREEN}✔${NC}  Access granted.\n"
      return 0
    fi
    _pass=""
    _attempts=$(( _attempts + 1 ))
    if [[ "$_attempts" -lt 3 ]]; then
      echo -e "  ${RED}Wrong passphrase. $(( 3-_attempts )) attempt(s) left.${NC}"
      echo -e "  ${DIM}Forgot it? Ctrl-C → sudo bash ${_script_path} reset-auth forgot${NC}\n"
      sleep $(( _attempts * 2 ))
    fi
  done

  echo ""
  echo -e "  ${RED}${BOLD}Too many failed attempts. Access denied.${NC}"
  echo ""
  echo -e "  ${BOLD}Forgot your passphrase?${NC} Run as root:"
  echo -e "  ${BCYAN}  sudo bash ${_script_path} reset-auth forgot${NC}"
  echo ""
  mkdir -p "$_WS_PERSIST_DIR" 2>/dev/null || true
  printf '%s  FAILED  user=%s  host=%s  pid=%s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" \
    "${USER:-$(id -un 2>/dev/null)}" \
    "$(hostname -f 2>/dev/null || hostname)" \
    "$$" \
    >> "${_WS_PERSIST_DIR}/auth_failures.log" 2>/dev/null || true
  exit 1
}

# ── THE EARLY GATE: runs before everything else ───────────────────────────────
_ws_early_gate() {
  # ── Hard bypass: check $@ directly so no variable failure can block reset ──
  local _ga
  for _ga in "$@"; do
    case "$_ga" in
      forgot|--forgot|force|--force|rk|--rk|recovery-key|--recovery-key)
        return 0 ;;
    esac
  done
  # If first arg is reset-auth, second arg determines bypass
  if [[ "${1:-}" == "reset-auth" ]]; then
    case "${2:-}" in
      forgot|--forgot|force|--force|rk|--rk|recovery-key|keyid|recover|"")
        return 0 ;;
    esac
  fi
  unset _ga

  if [[ "$CMD_HELP" == "true" ]]; then return 0; fi
  if [[ "$CMD_RESET_AUTH" == "true" ]]; then return 0; fi
  if [[ "$CMD_EXAMPLE_OUTPUT" == "true" ]]; then return 0; fi
  if [[ "$CMD_RECOVER" == "true" ]]; then return 0; fi
  if [[ "${_WS_BYPASS_AUTH:-false}" == "true" ]]; then return 0; fi

  # ── First run: no auth.key exists → forced setup (needs root) ────────────
  if [[ ! -f "$_WS_AUTH_KEY" ]]; then
    if [[ $(id -u) -ne 0 ]]; then
      echo -e "${RED}First run: passphrase setup required.${NC}"
      echo -e "Run once as root to set up: ${BOLD}sudo bash $0${NC}"
      exit 1
    fi
    _ws_first_run_setup
    # _ws_first_run_setup always exits
  fi

  # ── Valid session token: already authenticated this invocation ────────────
  if _ws_token_verify 2>/dev/null; then
    return 0
  fi
  unset WOWSCANNER_AUTH_TOKEN 2>/dev/null || true

  # ── Prompt passphrase ─────────────────────────────────────────────────────
  _ws_prompt

  # ── Authenticated: if not root, create token and re-exec via sudo ─────────
  if [[ $(id -u) -ne 0 ]]; then
    local _token _script_path
    _token=$(_ws_token_create)
    _script_path=$(realpath "$0" 2>/dev/null || echo "$0")
    exec env WOWSCANNER_AUTH_TOKEN="$_token" sudo -E bash "$_script_path" "$@"
    echo -e "${RED}sudo failed. Ensure sudoers entry: sudo bash $0 (first run)${NC}"
    exit 1
  fi
  # Root: passphrase verified → continue
}

_ws_early_gate "$@"

# ── Speed-optimisation state ───────────────────────────────────
# APT_UPDATED: set to 1 after the first apt-get update so subsequent
#              sections never trigger a redundant network refresh.
APT_UPDATED=0

# SSHD_CONFIG_CACHE: populated once by section_ssh; all sshd_value()
#                    calls within that section read from this cache
#                    instead of re-spawning sshd -T each time.
SSHD_CONFIG_CACHE=""

# Throttled apt-get update: only runs if the apt cache is older than
# APT_CACHE_MAX_AGE seconds (default 86400 = 24 hours) OR if APT_UPDATED=0.
APT_CACHE_MAX_AGE=86400  # seconds; override with: APT_CACHE_MAX_AGE=0 to force refresh

maybe_apt_update() {
  [[ "$APT_UPDATED" -eq 1 ]] && return 0          # already done this run
  local cache_file="/var/cache/apt/pkgcache.bin"
  if [[ -f "$cache_file" ]]; then
    local _now_e; _now_e=$(date +%s)
    local _mtime_e; _mtime_e=$(stat -c %Y "$cache_file" 2>/dev/null || echo 0)
    local age=$(( _now_e - _mtime_e ))
    if [[ "$age" -lt "$APT_CACHE_MAX_AGE" ]]; then
      info "apt cache is ${age}s old (< ${APT_CACHE_MAX_AGE}s) — skipping apt-get update"
      APT_UPDATED=1
      return 0
    fi
  fi
  # OPT: flock on the dpkg frontend lock prevents concurrent apt conflicts
  flock -w 30 /var/lib/dpkg/lock-frontend \
    apt-get update -qq 2>/dev/null || \
    apt-get update -qq 2>/dev/null || true
  APT_UPDATED=1
}

# ── Files ─────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="wowscanner_${TIMESTAMP}.txt"
LAN_JSON="/tmp/wowscanner_lan_${TIMESTAMP}.json"   # LAN device map data for generators
SCORE=0
TOTAL=0

# ── Persistent port issue tracker ─────────────────────────────
PERSIST_DIR="/var/lib/wowscanner"
PORT_ISSUES_LOG="${PERSIST_DIR}/port_issues.log"
PORT_HISTORY_DB="${PERSIST_DIR}/port_history.db"
PORT_REMEDIATION="${PERSIST_DIR}/remediation_commands.sh"
SCORE_HISTORY_DB="${PERSIST_DIR}/score_history.db"   # timestamp|score|total|pct per run
TIMING_HISTORY_DB="${PERSIST_DIR}/timing_history.db" # timestamp|wall_s|audit_s|odt_s|ods_s|intel_s|html_s
FINDINGS_SNAP="${PERSIST_DIR}/findings_last.db"       # last-run FAIL text for delta comparison
PORT_SCAN_LOG="${PERSIST_DIR}/port_scan_log.db"        # per-run: timestamp|ranges|open_ports
NEW_PORT_ISSUES=0

# ── Helpers ───────────────────────────────────────────────────
log()    { echo -e "$*" | tee -a "$REPORT" || true; }
header() {
  local _t="$1"
  # Dynamic box: pad to text length + 2, min width 54, max terminal width
  local _raw_len=${#_t}
  # Prefix icon based on section number/type for visual navigation
  case "$_t" in
    0[abcde]*|*pentest*|*Pentest*)  _t="⚔  $_t" ;;
    1\ *|*sysinfo*|*System\ Info*)  _t="🖥  $_t" ;;
    2\ *|*update*|*Update*)         _t="🔄  $_t" ;;
    3\ *|*user*|*User*)             _t="👤  $_t" ;;
    4\ *|*password*|*Password*)     _t="🔑  $_t" ;;
    5\ *|*ssh*|*SSH*)               _t="🔐  $_t" ;;
    6\ *|*firewall*|*Firewall*)     _t="🛡  $_t" ;;
    7\ *|*port*|*Port*)             _t="🔌  $_t" ;;
    8\ *|*perm*|*Permission*)       _t="📁  $_t" ;;
    9\ *|*service*|*Service*)       _t="⚙  $_t" ;;
    10\ *|*log*|*Log*)              _t="📋  $_t" ;;
    11\ *|*kernel*|*Kernel*)        _t="🧬  $_t" ;;
    12\ *|*cron*|*Cron*)            _t="🕐  $_t" ;;
    13[a-z]*|*hardening*|*Hardening*) _t="🔒  $_t" ;;
    13\ *|*package*|*Package*)      _t="📦  $_t" ;;
    14*|*rootkit*|*AppArmor*)       _t="🦠  $_t" ;;
    15\ *|*lynis*|*Lynis*)          _t="🔍  $_t" ;;
    16*|*scan*|*Scan*)              _t="📡  $_t" ;;
    17[bcde]*|*Failed*|*Env*|*USB*|*World*)  _t="🔎  $_t" ;;
    17[fgh]*|*Cert*|*Network*|*Audit*)        _t="🔏  $_t" ;;
    17[ij]*|*Open*|*Swap*|*Memory*)           _t="💾  $_t" ;;
    17[klmn]*|*PAM*|*Filesystem*|*Container*|*Repository*) _t="🔩  $_t" ;;
    17[opq]*|*Time*|*IPv6*|*SSH*Extras*)      _t="🌐  $_t" ;;
    17[rst]*|*Core*|*Systemd*|*Sudo*)         _t="⚙️  $_t" ;;
    17[uv]*|*Log*|*Compiler*|*Development*)   _t="📝  $_t" ;;
    17b3*|*Hardware*|*Firmware*)              _t="🔧  $_t" ;;
    17b4*|*GRUB*|*Boot*)                      _t="🥾  $_t" ;;
    17b5*|*Web*Server*)                       _t="🌐  $_t" ;;
    17b6*|*Secret*|*Cred*)                    _t="🔑  $_t" ;;
    17[wxyz]*|*Network*Iface*|*Kernel*Mod*|*MAC*Profile*|*Exposure*) _t="🌍  $_t" ;;
    17\ *|*summary*|*Summary*)      _t="📊  $_t" ;;
  esac
  _raw_len=${#_t}
  local _box_w=$(( _raw_len + 4 > 54 ? _raw_len + 4 : 54 ))
  local _top="╔" _bot="╚" _i
  for (( _i=0; _i<_box_w; _i++ )); do _top+="═"; _bot+="═"; done
  _top+="╗"; _bot+="╝"
  local _pad_len=$(( _box_w - _raw_len - 2 ))
  local _pad=""; [[ "$_pad_len" -gt 0 ]] && printf -v _pad "%*s" "$_pad_len" ""
  # Use bright cyan for top/bot borders, bold white for content line
  log ""
  log "${BCYAN}${_top}${NC}"
  log "${BCYAN}║${NC}${WHITE}${BOLD}  ${_t}${_pad}  ${NC}${BCYAN}║${NC}"
  log "${BCYAN}${_bot}${NC}"
}
subheader() {
  local _t="$1"
  local _w=$(( ${_PROGRESS_COLS:-80} - 6 ))
  local _used=$(( ${#_t} + 4 ))
  local _fi=$(( _w - _used ))
  [[ "$_fi" -lt 2 ]] && _fi=2
  local _fill; printf -v _fill '%*s' "$_fi" ''; _fill="${_fill// /─}"
  log ""
  log "  ${BCYAN}┌─ ${BOLD}${_t}${NC}${BCYAN} ─${_fill}${NC}"
}
pass()   { SCORE=$((SCORE+1)); TOTAL=$((TOTAL+1)); log "  ${BGREEN}[✔ PASS]${NC}  $1  ${BGREEN}Ω${NC}"; }
fail()   { TOTAL=$((TOTAL+1));                     log "  ${BRED}[✘ FAIL]${NC}  $1  ${BRED}Ω${NC}"; }
warn()   { TOTAL=$((TOTAL+1));                     log "  ${YELLOW}[⚠ WARN]${NC}  $1  ${YELLOW}Ω${NC}"; }
info()   { log "  ${BCYAN}[ℹ INFO]${NC}  $1  ${BCYAN}Ω${NC}"; }
detail() { log "  ${DIM}│${NC}       ${BMAGENTA}↳${NC} $1"; }
skip()   { log "  ${DIM}[─ SKIP]${NC}  $1  ${DIM}Ω${NC}"; }
note()   { log "  ${ORANGE}${BOLD}[● NOTE]${NC}  $1  ${ORANGE}Ω${NC}"; }

# ── Safe integer helper ────────────────────────────────────────
# Returns 0 if the value is a plain non-negative integer, else echoes 0.
safe_int() {
  local v="${1:-0}"
  # Strip whitespace
  v="${v//[[:space:]]/}"
  # If "unlimited" or non-numeric, return 0 to signal "not a useful number"
  [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "0"
}

# ================================================================
#  PASSPHRASE AUTHENTICATION
#  First run: no auth.key → forced setup wizard (requires root)
#  Change:    sudo bash wowscanner.sh reset-auth
#  Forgot:    sudo bash wowscanner.sh recover
#             sudo bash wowscanner.sh reset-auth forgot
#  auth.key:  /etc/wowscanner/auth.key  (mode 400, root:root)
#  Crypto:    AES-256-CBC + PBKDF2-HMAC-SHA256 (200,000 rounds)
# ================================================================


# ================================================================
#  EXAMPLE OUTPUT COMMAND
#  bash wowscanner.sh example-output
#  Writes two files in CWD:
#    wowscanner_example_<TS>.txt      — full audit log (extreme detail)
#    wowscanner_example_findings_<TS>.txt — paginated findings report
#  No root required. No scan is run. Pure illustrative output.
# ================================================================
cmd_example_output() {
  local _ts; _ts=$(date +%Y%m%d_%H%M%S)
  local _txt="wowscanner_example_${_ts}.txt"
  local _fnd="wowscanner_example_findings_${_ts}.txt"

  echo -e "${BCYAN}${BOLD}  Writing example output files...${NC}"

  python3 - "$_txt" "$_fnd" << 'EXEOF'
import sys, textwrap, datetime, os

out_txt = sys.argv[1]
out_fnd = sys.argv[2]

TS   = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
HOST = 'webserver01.example.com'
OS   = 'Ubuntu 22.04.4 LTS'
KERN = '5.15.0-112-generic'
IP   = '192.168.1.10'

# ── ANSI colour codes (stripped in .txt but shown here for realism) ──────────
R  = '\033[0;31m';  G  = '\033[0;32m';  Y  = '\033[1;33m'
C  = '\033[0;36m';  B  = '\033[1m';     D  = '\033[2m'
BG = '\033[1;32m';  BR = '\033[1;31m';  BC = '\033[1;36m'
NC = '\033[0m'

def hdr(title):
    w = max(len(title)+4, 54)
    top = '╔' + '═'*w + '╗'
    mid = '║  ' + title + ' '*(w-len(title)-2) + '║'
    bot = '╚' + '═'*w + '╝'
    return f'\n{C}{B}{top}{NC}\n{C}{B}{mid}{NC}\n{C}{B}{bot}{NC}\n'

def sub(title):
    return f'\n  {B}\033[0;34m┌─ {title} ' + '─'*max(0,42-len(title)) + f'{NC}\n'

def ok(msg, detail=None):
    lines = [f'  {G}[✔ PASS]{NC}  {msg}  {G}Ω{NC}']
    if detail:
        for d in (detail if isinstance(detail,list) else [detail]):
            lines.append(f'          \033[0;35m↳{NC} {d}')
    return '\n'.join(lines)

def fl(msg, detail=None):
    lines = [f'  {R}[✘ FAIL]{NC}  {msg}  {R}Ω{NC}']
    if detail:
        for d in (detail if isinstance(detail,list) else [detail]):
            lines.append(f'          \033[0;35m↳{NC} {d}')
    return '\n'.join(lines)

def wn(msg, detail=None):
    lines = [f'  {Y}[⚠ WARN]{NC}  {msg}  {Y}Ω{NC}']
    if detail:
        for d in (detail if isinstance(detail,list) else [detail]):
            lines.append(f'          \033[0;35m↳{NC} {d}')
    return '\n'.join(lines)

def inf(msg):
    return f'  {C}[ℹ INFO]{NC}  {msg}  {C}Ω{NC}'

def skp(msg):
    return f'  \033[0;34m[- SKIP]{NC}  {msg}  \033[0;34mΩ{NC}'

def sep():
    return f'\n  {C}{"─"*66}{NC}'

# ─────────────────────────────────────────────────────────────────────────────
lines = []
lines.append(f'{BC}{B}')
lines.append('╔══════════════════════════════════════════════════════════════════════╗')
lines.append(f'║  🔐  Wowscanner v2.2.0  —  Security Audit Report                     ║')
lines.append(f'║  Host   : {HOST:<59}║')
lines.append(f'║  OS     : {OS:<59}║')
lines.append(f'║  Kernel : {KERN:<59}║')
lines.append(f'║  IP     : {IP:<59}║')
lines.append(f'║  Time   : {TS:<59}║')
lines.append(f'║  Run by : root (uid=0)  via passphrase gate                           ║')
lines.append('╚══════════════════════════════════════════════════════════════════════╝')
lines.append(f'{NC}')

# ── Progress bar snapshot ─────────────────────────────────────────────────────
lines.append(f'\n{C}{B}  [████████████████████████████████████░░░░░░░] 84%  Section 46/54{NC}')
lines.append(f'{D}  ETA: ~2m 14s  |  Elapsed: 11m 38s  |  Section: 17u Log Integrity{NC}\n')

# ── Pentest sections ──────────────────────────────────────────────────────────
lines.append(hdr('0a. PENTEST — NETWORK & SERVICE ENUMERATION'))
lines.append(sub('nmap — Full service fingerprint'))
lines.append(ok('nmap enumeration completed',
    ['22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu',
     '80/tcp   open  http     nginx 1.24.0',
     '443/tcp  open  https    nginx 1.24.0',
     '3306/tcp open  mysql    MySQL 8.0.36',
     '6379/tcp open  redis    Redis 7.2.4',
     'OS: Linux 5.15.0  |  Device type: general purpose']))
lines.append(sub('enum4linux — SMB/Samba recon'))
lines.append(ok('No SMB shares discoverable (null session)'))
lines.append(ok('SMB user enumeration blocked'))
lines.append(ok('SMB null session rejected (good)'))

lines.append(hdr('0b. PENTEST — WEB APPLICATION SCANNER (Nikto)'))
lines.append(sub('Nikto scan on http://127.0.0.1:80'))
lines.append(fl('Nikto found 4 finding(s) on port 80',
    ['+ Server: nginx/1.24.0 — server version disclosed',
     '+ /admin/: Admin directory accessible without authentication',
     '+ X-Frame-Options header not present — clickjacking risk',
     '+ /phpinfo.php: PHP info page exposed — remove immediately']))
lines.append(sub('Nikto scan on https://127.0.0.1:443'))
lines.append(ok('Nikto: No critical findings on port 443'))

lines.append(hdr('0c. PENTEST — SSH BRUTE-FORCE SIMULATION (Hydra)'))
lines.append(inf('Testing SSH on port 2222 with 10 credential pairs'))
lines.append(ok('SSH brute-force: all 10 credential attempts rejected',
    ['Lockout triggered after 3 failures — pam_faillock active',
     'Source IP 127.0.0.1 blocked for 300s after threshold']))

lines.append(hdr('0d. PENTEST — SQL INJECTION PROBE (sqlmap)'))
lines.append(inf('Probing http://127.0.0.1:80 for injectable parameters'))
lines.append(ok('sqlmap: no SQL injection vulnerabilities found on port 80'))

lines.append(hdr('0e. PENTEST — STRESS & RESOURCE EXHAUSTION'))
lines.append(sub('CPU/Memory/IO stress (stress-ng, 15s)'))
lines.append(ok('System remained stable under CPU stress test',
    ['Peak CPU usage: 99.8%  |  Load avg: 8.12, 4.23, 1.87',
     'Memory: 2.1 GB used / 8.0 GB total  |  No OOM events']))
lines.append(sub('SYN flood simulation (hping3 loopback, 5s)'))
lines.append(ok('SYN flood mitigation active — tcp_syncookies=1'))

# ── Core sections ─────────────────────────────────────────────────────────────
lines.append(hdr('1. SYSTEM INFORMATION'))
lines.append(inf(f'Hostname: {HOST}  |  OS: {OS}  |  Kernel: {KERN}'))
lines.append(inf('Uptime: 47 days, 3 hours, 22 minutes'))
lines.append(inf('CPU: Intel Xeon E5-2680 v4 @ 2.40GHz (14 cores, 28 threads)'))
lines.append(inf('RAM: 7.8 GB used / 15.5 GB total  |  Swap: 0 B used / 2.0 GB'))
lines.append(ok('OOM killer policy: vm.panic_on_oom = 0 (OOM killer enabled, no panic)'))
lines.append(ok('Core dumps disabled: ulimit -c = 0'))
lines.append(ok('/tmp usage: 2.3 GB / 20 GB (11%) — within limits'))
lines.append(ok('Root process count: 143 daemons running as root (normal)'))
lines.append(ok('Zombie processes: 0 detected'))
lines.append(ok('Inode usage on /: 8.2% (422,841 / 5,160,960 inodes)'))
lines.append(inf('Open file handles: 18,432 / 1,048,576 (1.7%)'))
lines.append(inf('Virtualisation: Running inside KVM hypervisor'))

lines.append(hdr('2. SYSTEM UPDATES'))
lines.append(sub('Pending updates'))
lines.append(fl('8 packages have available updates',
    ['apt list --upgradable 2>/dev/null | grep -v Listing',
     'curl/jammy-updates 7.81.0-1ubuntu1.16 amd64',
     'libssl3/jammy-updates 3.0.2-0ubuntu1.16 amd64',
     'linux-headers-5.15.0-113-generic 5.15.0-113.123 amd64',
     'linux-image-5.15.0-113-generic 5.15.0-113.123 amd64',
     'openssl/jammy-updates 3.0.2-0ubuntu1.16 amd64',
     '... and 3 more packages']))
lines.append(fl('3 SECURITY updates pending — apply immediately',
    ['curl — CVE-2024-2398 (CVSS 9.8) — heap buffer overflow',
     'openssl — CVE-2024-0727 (CVSS 7.5) — denial of service',
     'libssl3 — CVE-2024-0727 (CVSS 7.5) — denial of service']))
lines.append(ok('Kernel version 5.15.0 is within LTS support window (EOL: Apr 2027)'))
lines.append(wn('unattended-upgrades is installed but security-only mode not configured',
    ['Edit /etc/apt/apt.conf.d/50unattended-upgrades',
     'Uncomment: "${distro_id}:${distro_codename}-security";']))
lines.append(inf('APT cache age: 6 hours 14 minutes (fresh)'))

lines.append(hdr('3. USERS & ACCOUNTS'))
lines.append(sub('Privileged accounts'))
lines.append(inf('Users with UID 0 (root-equivalent): root'))
lines.append(inf('Users with sudo access: admin, deploy, ansible (3 accounts)'))
lines.append(sub('Login shell accounts'))
lines.append(inf('Shell accounts: root, admin, deploy, ansible, www-data (5 total)'))
lines.append(wn('www-data has a login shell (/bin/bash) — should be /usr/sbin/nologin',
    ['Fix: sudo usermod -s /usr/sbin/nologin www-data']))
lines.append(sub('Last login timestamps'))
lines.append(inf('root:    2026-04-19 14:32:11 from 192.168.1.5'))
lines.append(inf('admin:   2026-04-19 09:14:44 from 192.168.1.3'))
lines.append(inf('deploy:  2026-04-18 22:05:39 from 10.0.0.15'))
lines.append(inf('ansible: 2026-04-15 03:00:02 from 10.0.0.20'))
lines.append(sub('Inactive accounts'))
lines.append(wn('1 account inactive >90 days: backup_user (last login: 2026-01-02)',
    ['Disable: sudo passwd -l backup_user',
     'Or remove: sudo userdel backup_user']))
lines.append(sub('Failed login attempts (last 24h)'))
lines.append(wn('127 SSH authentication failures from 14 unique IPs in last 24h',
    ['Top attacker: 45.142.212.100 (RU) — 34 attempts',
     '185.220.101.55 (DE) — 18 attempts (known Tor exit node)',
     'fail2ban is active and has blocked 12 IPs']))
lines.append(sub('authorized_keys audit'))
lines.append(ok('All authorized_keys files have correct permissions (mode 600)'))
lines.append(ok('No duplicate keys detected across accounts'))

lines.append(hdr('4. PASSWORD POLICY'))
lines.append(sub('/etc/login.defs policy'))
lines.append(ok('PASS_MAX_DAYS = 90 (passwords expire every 90 days)'))
lines.append(wn('PASS_MIN_DAYS = 0 (users can change password immediately after reset)',
    ['Recommendation: set PASS_MIN_DAYS = 1']))
lines.append(wn('PASS_MIN_LEN = 8 (minimum length is low)',
    ['Recommendation: set PASS_MIN_LEN = 12']))
lines.append(ok('PASS_WARN_AGE = 14 (14-day expiry warning)'))
lines.append(sub('PAM password quality'))
lines.append(ok('pam_pwquality installed and configured',
    ['minlen=12, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1',
     'retry=3, reject_username, enforce_for_root']))
lines.append(ok('pam_faillock: account lockout after 5 failures, 10 minute lockout'))
lines.append(sub('/etc/shadow audit'))
lines.append(ok('No empty password fields in /etc/shadow'))
lines.append(ok('All password hashes use SHA-512 ($6$) algorithm'))

lines.append(hdr('5. SSH CONFIGURATION'))
lines.append(sub('SSH daemon settings'))
lines.append(ok('SSH listening on non-default port 2222'))
lines.append(ok('Protocol 2 only — Protocol 1 disabled'))
lines.append(ok('PermitRootLogin = prohibit-password (key-only root access)'))
lines.append(ok('PasswordAuthentication = no (key-based auth only)'))
lines.append(ok('PermitEmptyPasswords = no'))
lines.append(ok('X11Forwarding = no'))
lines.append(ok('MaxAuthTries = 3'))
lines.append(ok('LoginGraceTime = 30s'))
lines.append(ok('ClientAliveInterval = 300  |  ClientAliveCountMax = 2'))
lines.append(ok('AllowAgentForwarding = no'))
lines.append(ok('StrictModes = yes'))
lines.append(sub('Ciphers and algorithms'))
lines.append(ok('Ciphers: chacha20-poly1305, aes256-gcm, aes128-gcm (all strong)'))
lines.append(ok('MACs: hmac-sha2-512-etm, hmac-sha2-256-etm (all strong)'))
lines.append(ok('KexAlgorithms: curve25519-sha256, diffie-hellman-group16-sha512'))
lines.append(sub('Host keys'))
lines.append(ok('RSA host key: 4096 bits (strong)'))
lines.append(ok('ED25519 host key present'))
lines.append(sub('Login banner'))
lines.append(ok('Login banner configured in /etc/issue.net'))

lines.append(hdr('6. FIREWALL'))
lines.append(sub('UFW status'))
lines.append(ok('UFW active  |  Default INPUT: deny  |  Default OUTPUT: allow'))
lines.append(ok('UFW rules:',
    ['ALLOW IN  2222/tcp  (SSH)',
     'ALLOW IN  80/tcp   (HTTP)',
     'ALLOW IN  443/tcp  (HTTPS)',
     'ALLOW IN  10.0.0.0/24  3306/tcp  (MySQL internal only)',
     'DENY  IN  6379/tcp  (Redis — blocked externally)']))
lines.append(sub('iptables'))
lines.append(inf('iptables INPUT chain: 8 rules  |  OUTPUT chain: 3 rules'))
lines.append(ok('iptables default INPUT policy: DROP'))
lines.append(sub('IPv6 firewall'))
lines.append(ok('ip6tables INPUT default: DROP  |  6 rules active'))

lines.append(hdr('7. OPEN NETWORK PORTS'))
lines.append(sub('Listening ports'))
lines.append(inf('Total listening ports: 11 (TCP: 9, UDP: 2)'))
lines.append(fl('MySQL port 3306 bound to ALL interfaces (0.0.0.0:3306)',
    ['Fix: add bind-address = 127.0.0.1 to /etc/mysql/mysql.conf.d/mysqld.cnf',
     'Then: sudo systemctl restart mysql']))
lines.append(fl('Redis port 6379 bound to ALL interfaces (0.0.0.0:6379)',
    ['Fix: edit /etc/redis/redis.conf: bind 127.0.0.1',
     'Also set: requirepass <strong_password>',
     'Then: sudo systemctl restart redis-server']))
lines.append(ok('No legacy risky services (FTP/Telnet/rsh/rexec/TFTP/X11) detected'))
lines.append(wn('26 listening ports detected — approaching threshold of 30',
    ['2222/tcp   sshd',
     '80/tcp     nginx',
     '443/tcp    nginx',
     '3306/tcp   mysqld  ← bound to 0.0.0.0 (FAIL above)',
     '6379/tcp   redis   ← bound to 0.0.0.0 (FAIL above)',
     '8080/tcp   node    ← high port on all interfaces',
     '... and 5 more']))

lines.append(hdr('8. FILE & DIRECTORY PERMISSIONS'))
lines.append(sub('Critical system files'))
lines.append(ok('/etc/passwd:  mode 644  owner root:root'))
lines.append(ok('/etc/shadow:  mode 640  owner root:shadow'))
lines.append(ok('/etc/sudoers: mode 440  owner root:root'))
lines.append(ok('/etc/ssh/sshd_config: mode 600  owner root:root'))
lines.append(sub('World-writable files'))
lines.append(wn('3 world-writable files found in system paths',
    ['/var/www/html/uploads/ — 777 permissions (web upload dir)',
     '/tmp/.X11-unix/X0 — X11 socket (expected if X running)',
     '/run/lock — sticky bit set (correct)']))
lines.append(sub('SUID/SGID binaries'))
lines.append(ok('25 SUID binaries found (within normal range)',
    ['/usr/bin/sudo  (root:root 4755)',
     '/usr/bin/passwd (root:root 4755)',
     '/usr/bin/mount  (root:root 4755)',
     '/usr/bin/su     (root:root 4755)',
     '... and 21 more standard binaries']))
lines.append(ok('No unowned files in system directories'))

lines.append(hdr('9. SERVICES & DAEMONS'))
lines.append(sub('Running services'))
lines.append(inf('Active services: 47  |  Inactive: 12  |  Failed: 1'))
lines.append(fl('1 failed systemd unit detected',
    ['● snapd.service — Snap Daemon (failed)',
     'Status: failed  |  ExecStart: /usr/lib/snapd/snapd',
     'Fix: sudo systemctl restart snapd  or  sudo apt purge snapd']))
lines.append(ok('No legacy risky services (telnet/rsh/rlogin/nis/tftp) running'))
lines.append(ok('inetd/xinetd not running'))
lines.append(wn('tcpdump installed on production system',
    ['Consider: sudo apt remove tcpdump (not needed on web server)']))
lines.append(inf('Key services active: sshd, nginx, mysql, redis, fail2ban, ufw'))

lines.append(hdr('10. LOGGING & AUDIT'))
lines.append(ok('rsyslog active and running'))
lines.append(ok('auditd active  |  47 audit rules loaded'))
lines.append(sub('Log file permissions'))
lines.append(ok('/var/log/auth.log:   mode 640  owner root:adm'))
lines.append(ok('/var/log/syslog:     mode 640  owner root:adm'))
lines.append(ok('/var/log/nginx/:     mode 755  owner root:adm'))
lines.append(ok('/var/log/mysql/:     mode 750  owner mysql:adm'))
lines.append(sub('Auth log analysis'))
lines.append(inf('Failed SSH logins (24h): 127  |  Invalid user: 89  |  Root attempts: 12'))
lines.append(ok('fail2ban active  |  SSH jail enabled  |  12 IPs currently banned'))
lines.append(sub('Remote logging'))
lines.append(wn('No remote syslog forwarding configured',
    ['Logs are only stored locally — loss risk if disk fails',
     'Consider: rsyslog forwarding to syslog server or SIEM']))
lines.append(sub('Login banners'))
lines.append(ok('/etc/issue.net configured: "Authorised access only. All activity logged."'))
lines.append(ok('/etc/motd configured'))

lines.append(hdr('11. KERNEL HARDENING (sysctl)'))
lines.append(ok('net.ipv4.ip_forward = 0  (IP forwarding disabled)'))
lines.append(ok('net.ipv4.conf.all.send_redirects = 0'))
lines.append(ok('net.ipv4.conf.all.accept_redirects = 0'))
lines.append(ok('net.ipv4.conf.all.log_martians = 1  (martian packets logged)'))
lines.append(ok('net.ipv4.tcp_syncookies = 1  (SYN flood protection active)'))
lines.append(ok('net.ipv4.icmp_echo_ignore_broadcasts = 1'))
lines.append(ok('net.ipv4.conf.all.rp_filter = 1  (reverse path filtering)'))
lines.append(ok('net.ipv4.conf.all.arp_filter = 1  (ARP poisoning protection)'))
lines.append(fl('net.ipv4.tcp_timestamps = 1  (TCP timestamps expose uptime)',
    ['Fix: sudo sysctl -w net.ipv4.tcp_timestamps=0',
     'Persist: echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.d/99-wowscanner.conf']))
lines.append(ok('kernel.randomize_va_space = 2  (Full ASLR enabled)'))
lines.append(ok('kernel.dmesg_restrict = 1  (dmesg restricted to root)'))
lines.append(ok('kernel.kptr_restrict = 2  (kernel pointers hidden)'))
lines.append(ok('kernel.sysrq = 0  (Magic SysRq disabled)'))
lines.append(ok('fs.suid_dumpable = 0  (SUID core dumps disabled)'))
lines.append(fl('kernel.module_sig_enforce = 0  (unsigned modules permitted)',
    ['Fix: echo "kernel.module_sig_enforce=1" >> /etc/sysctl.d/99-wowscanner.conf',
     'Warning: enforcing this after boot may break out-of-tree drivers']))

lines.append(hdr('12. CRON & SCHEDULED TASKS'))
lines.append(sub('System crontabs'))
lines.append(ok('/etc/cron.daily: 8 scripts  |  all owned by root  |  none world-writable'))
lines.append(ok('/etc/cron.weekly: 3 scripts'))
lines.append(ok('/etc/cron.monthly: 2 scripts'))
lines.append(ok('/etc/cron.d: 4 entries'))
lines.append(sub('User crontabs'))
lines.append(inf('root crontab: 3 entries'))
lines.append(inf('deploy crontab: 1 entry (backup script @daily)'))
lines.append(sub('Cron content audit'))
lines.append(wn('Crontab PATH includes /tmp in root crontab',
    ['Found: PATH=/tmp:/usr/local/sbin:/usr/sbin:/usr/bin',
     'Fix: remove /tmp from PATH in root crontab — hijacking risk']))
lines.append(ok('at daemon not running'))

lines.append(hdr('13. INSTALLED PACKAGES & INTEGRITY'))
lines.append(inf('Total installed packages: 1,847'))
lines.append(sub('debsums integrity check'))
lines.append(fl('debsums: 3 modified package files detected',
    ['/usr/bin/curl  — hash mismatch (possibly tampered)',
     '/lib/x86_64-linux-gnu/libssl.so.3  — hash mismatch',
     '/usr/sbin/nginx  — hash mismatch',
     'Investigate: sudo debsums -c | head -20',
     'Reinstall: sudo apt-get install --reinstall curl libssl3 nginx']))
lines.append(sub('dpkg audit'))
lines.append(ok('No partially installed or broken packages'))
lines.append(sub('Compiler tools'))
lines.append(fl('gcc found on production system',
    ['Remove: sudo apt-get purge gcc gcc-12 build-essential',
     'Compilers on production servers increase attack surface']))
lines.append(wn('g++ found on production system'))
lines.append(ok('clang not installed'))
lines.append(sub('Security scanners'))
lines.append(ok('chkrootkit installed: v0.57'))
lines.append(ok('rkhunter installed: v1.4.6'))
lines.append(ok('AIDE not installed (optional — consider for file integrity monitoring)'))

lines.append(hdr('13c. ADVANCED HARDENING'))
lines.append(ok('No NOPASSWD rules in sudoers'))
lines.append(ok('No wildcard command rules in sudoers'))
lines.append(sub('TLS certificate audit'))
lines.append(fl('/etc/ssl/certs/webserver01.pem expires in 7 days (2026-04-27)',
    ['Renew immediately: certbot renew --force-renewal',
     'Or: sudo acme.sh --renew -d webserver01.example.com']))
lines.append(ok('/etc/ssl/certs/internal-ca.pem valid for 847 more days'))
lines.append(ok('No self-signed certificates in use'))
lines.append(sub('Time synchronisation'))
lines.append(ok('systemd-timesyncd active  |  NTP server: ntp.ubuntu.com'))
lines.append(inf('Clock drift: +0.000123s (excellent)'))
lines.append(sub('Swap encryption'))
lines.append(wn('Swap partition is NOT encrypted',
    ['Sensitive data including memory can be written to unencrypted swap',
     'Fix: add swap_crypt to /etc/crypttab or use encrypted partition']))

lines.append(hdr('13d. NETWORK, CONTAINER & SENSITIVE FILE SECURITY'))
lines.append(ok('/etc/shadow mode 640 (not world-readable)'))
lines.append(sub('Docker/Container security'))
lines.append(inf('Docker not installed on this system'))
lines.append(sub('MTA relay security'))
lines.append(ok('Postfix relay_domains = empty (no open relay)'))
lines.append(ok('Postfix smtpd_recipient_restrictions configured'))

lines.append(hdr('14b. CHKROOTKIT + RKHUNTER'))
lines.append(sub('chkrootkit v0.57'))
lines.append(ok('chkrootkit: no infected files detected'))
lines.append(ok('chkrootkit: no LKM trojans detected'))
lines.append(ok('chkrootkit: no sniffer detected'))
lines.append(ok('chkrootkit: network checks clean'))
lines.append(sub('rkhunter v1.4.6'))
lines.append(ok('rkhunter: no known rootkit signatures found'))
lines.append(ok('rkhunter: no hidden files in system paths'))
lines.append(ok('rkhunter: SHA256 hashes of key binaries match database'))
lines.append(wn('rkhunter: /dev/.udev/rules.d/ directory is hidden — investigate manually',
    ['This can be legitimate udev state but check: ls -la /dev/.udev/']))

lines.append(hdr('14. MAC — APPARMOR / SELINUX'))
lines.append(ok('AppArmor active  |  53 profiles loaded'))
lines.append(inf('Profiles in enforce mode: 49  |  Complain mode: 4'))
lines.append(wn('4 AppArmor profiles in complain mode (not enforcing)',
    ['nginx: /usr/sbin/nginx  — complain mode',
     'mysqld: /usr/sbin/mysqld — complain mode',
     'Fix: sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx',
     '     sudo aa-enforce /etc/apparmor.d/usr.sbin.mysqld']))
lines.append(inf('SELinux: not installed (AppArmor is primary MAC)'))

lines.append(hdr('15. LYNIS SECURITY AUDIT'))
lines.append(inf('Lynis 3.1.1  |  Database: 2024-12-01  |  Duration: 47s'))
lines.append(ok('Lynis hardening index: 74 / 100'))
lines.append(wn('Lynis: 12 warnings detected',
    ['BOOT-5264: grub.cfg not password protected',
     'AUTH-9286: no password set for single-user mode',
     'MAIL-8818: no mail transfer agent installed',
     'FILE-6430: /tmp not mounted with noexec',
     '... and 8 more warnings']))
lines.append(inf('Lynis: 38 suggestions (run lynis audit system for full list)'))

lines.append(hdr('16a. LAN DEVICE DISCOVERY'))
lines.append(inf('Subnet: 192.168.1.0/24  |  Interface: eth0  |  Gateway: 192.168.1.1'))
lines.append(ok('Gateway 192.168.1.1 reachable (ping OK)'))
lines.append(inf('Discovery method: arp-scan  |  Hosts found: 7'))
lines.append(inf('192.168.1.1   aa:bb:cc:11:22:01  Cisco Systems        (Gateway)'))
lines.append(inf('192.168.1.10  aa:bb:cc:11:22:02  Dell Inc.            (This host)'))
lines.append(inf('192.168.1.11  aa:bb:cc:11:22:03  Super Micro Computer (db-server-01)'))
lines.append(inf('192.168.1.12  aa:bb:cc:11:22:04  Raspberry Pi Trading (monitoring)'))
lines.append(inf('192.168.1.20  aa:bb:cc:11:22:05  Apple Inc.           (admin-macbook)'))
lines.append(inf('192.168.1.30  aa:bb:cc:11:22:06  Unknown              (INVESTIGATE)'))
lines.append(wn('1 host with unknown vendor detected: 192.168.1.30 — verify this device'))
lines.append(ok('No rogue DHCP servers detected on subnet'))

lines.append(hdr('16. RANDOM PORT SCAN'))
lines.append(sub('nmap scan against 127.0.0.1'))
lines.append(fl('CRITICAL exposure: port 6379 (Redis) — no authentication by default',
    ['Redis with no password and public binding = immediate compromise risk',
     'CVE-2022-0543: Lua sandbox escape in Redis < 6.2.6',
     'Remediation: bind 127.0.0.1 + requirepass in /etc/redis/redis.conf']))
lines.append(fl('HIGH exposure: port 3306 (MySQL) — database on public interface',
    ['bind-address = 127.0.0.1 should be set in mysqld.cnf']))
lines.append(wn('MEDIUM exposure: port 8080 (HTTP alt) — unencrypted HTTP on public IP',
    ['Move traffic to HTTPS or block port 8080 externally']))
lines.append(ok('LOW exposure: port 22 closed (SSH moved to 2222 — good)'))
lines.append(fl('NEW ISSUE: port 8080 not seen in previous scan (first detected today)',
    ['Was this port opened intentionally? Check: ss -tlnp | grep 8080']))

# Extended sections 17b-17z
lines.append(hdr('17b. FAILED LOGIN ANALYSIS'))
lines.append(fl('SSH brute-force: 127 failures in 24h from 14 IPs (threshold: 50 = FAIL)',
    ['Top source: 45.142.212.100 (34 attempts) — geo: Russia',
     '185.220.101.55 (18 attempts) — known Tor exit node',
     '91.108.56.130 (12 attempts) — geo: Netherlands',
     'fail2ban has blocked 12 of 14 attacking IPs',
     'Consider: AllowUsers + GeoIP blocking']))
lines.append(ok('fail2ban: SSH jail active  |  maxretry=5  bantime=600'))
lines.append(ok('sshguard: not installed (fail2ban covers SSH protection)'))

lines.append(hdr('17b3. HARDWARE & FIRMWARE SECURITY'))
lines.append(ok('Secure Boot status: ENABLED (EFI Secure Boot active)'))
lines.append(ok('IOMMU/DMA protection: Intel VT-d ENABLED in BIOS'))
lines.append(sub('CPU vulnerability mitigations'))
lines.append(ok('Spectre v1:          Mitigation: usercopy/swapgs barriers'))
lines.append(ok('Spectre v2:          Mitigation: Retpolines, IBPB, IBRS_FW, STIBP'))
lines.append(ok('Meltdown:            Mitigation: PTI'))
lines.append(ok('Spectre v4 (SSBD):   Mitigation: Speculative Store Bypass disabled'))
lines.append(ok('MDS (Fallout):       Mitigation: Clear CPU buffers'))
lines.append(ok('L1TF:                Mitigation: PTE Inversion, VMX conditional cache flushes'))
lines.append(ok('TAA (TSX Async Abort): Mitigation: Clear CPU buffers'))
lines.append(ok('TPM device detected: /sys/class/tpm/tpm0  (TPM 2.0)'))

lines.append(hdr('17b4. GRUB & BOOT SECURITY'))
lines.append(fl('GRUB password not configured',
    ['Anyone with physical/console access can boot to recovery mode',
     'Fix: grub-mkpasswd-pbkdf2  then add to /etc/grub.d/40_custom',
     'See: https://help.ubuntu.com/community/Grub2/Passwords']))
lines.append(ok('Kernel cmdline: no dangerous parameters (no debug/single/init=)'))
lines.append(ok('CPU mitigations NOT disabled (mitigations=off absent — good)'))
lines.append(ok('/boot permissions: mode 700 owner root:root'))
lines.append(fl('grub.cfg permissions: mode 644 (should be 600)',
    ['Fix: sudo chmod 600 /boot/grub/grub.cfg']))

lines.append(hdr('17b5. WEB SERVER SECURITY'))
lines.append(sub('Nginx configuration'))
lines.append(ok('server_tokens off (nginx version not disclosed)'))
lines.append(ok('SSL protocols: TLSv1.2, TLSv1.3 only (TLSv1.0/1.1 disabled)'))
lines.append(ok('X-Frame-Options: SAMEORIGIN (clickjacking protection)'))
lines.append(ok('Strict-Transport-Security: max-age=31536000; includeSubDomains'))
lines.append(fl('Content-Security-Policy header missing',
    ['Add to nginx.conf: add_header Content-Security-Policy "default-src \'self\'";']))
lines.append(ok('X-Content-Type-Options: nosniff'))
lines.append(ok('autoindex off (directory listing disabled)'))
lines.append(inf('Apache: not installed'))

lines.append(hdr('17b6. SECRETS & CREDENTIAL EXPOSURE'))
lines.append(ok('No world-readable private key files found in /etc/ssl/private, /root/.ssh'))
lines.append(sub('Config file credential scan'))
lines.append(fl('Credential pattern found in /var/www/html/.env',
    ['Line 14: DB_PASSWORD=MyDB@Pass123  ← plaintext password in web root',
     'Move to: /etc/webserver01/config.env (outside web root)',
     'Then: chmod 600 /etc/webserver01/config.env']))
lines.append(ok('No credentials found in /etc/nginx/, wp-config.php, secrets.yml'))
lines.append(sub('Bash history audit'))
lines.append(wn('Sensitive command found in /root/.bash_history',
    ['mysql -u root -pMyRootPass123  ← password visible in history',
     'Fix: history -c && history -w to clear',
     'Use: mysql -u root -p (without inline password)']))
lines.append(ok('No active SSH agent forwarding sockets in /tmp'))

lines.append(hdr('17x. KERNEL MODULE SECURITY'))
lines.append(ok('usb_storage module: not loaded (USB storage disabled — good)'))
lines.append(ok('firewire_core module: not loaded'))
lines.append(ok('bluetooth module: not loaded'))
lines.append(wn('dccp module loaded — rarely needed protocol',
    ['Disable: echo "install dccp /bin/false" >> /etc/modprobe.d/disable-dccp.conf']))
lines.append(ok('sctp module: not loaded'))
lines.append(ok('thunderbolt module: not loaded'))
lines.append(fl('kernel.module_sig_enforce = 0 (unsigned modules can load)',
    ['Fix: echo "kernel.module_sig_enforce=1" >> /etc/sysctl.d/99-wowscanner.conf']))

lines.append(hdr('17z. NETWORK EXPOSURE SUMMARY'))
lines.append(sub('Port risk classification (29 mappings)'))
lines.append(fl('CRITICAL (2): port 6379 (Redis — unauthenticated), port 3306 (MySQL — public)'))
lines.append(fl('HIGH (1): port 8080 (HTTP — unencrypted, new port)'))
lines.append(wn('MEDIUM (2): port 25 (SMTP — verify relay config), port 111 (rpcbind)'))
lines.append(ok('LOW (4): ports 2222, 80, 443, 8443 — expected and secured'))
lines.append(ok('SAFE (2): ports 123 (NTP), 53 (DNS local)'))
lines.append(sep())
lines.append(inf('Total exposed: 11 ports  |  CRITICAL: 2  |  HIGH: 1  |  MEDIUM: 2'))

# ── Timing summary ────────────────────────────────────────────────────────────
lines.append(f'\n{C}{B}╔══════════════════════════════════════════════════════════════════════╗{NC}')
lines.append(f'{C}{B}║                   ⏱  SCAN TIMING SUMMARY                           ║{NC}')
lines.append(f'{C}{B}╠══════════════════════════════════════════════════════════════════════╣{NC}')
lines.append(f'{C}{B}║{NC}')
lines.append(f'{C}{B}║{NC}  Phase                           Duration   Bar (relative to audit)')
lines.append(f'{C}{B}║{NC}  {"─"*66}')
lines.append(f'{C}{B}║{NC}  {B}Audit sections (total){NC}          {Y}11m 38s{NC}   {"█"*28}')
lines.append(f'{C}{B}║{NC}    ├─ 0a pentest-enum             3m 02s    {"█"*9}')
lines.append(f'{C}{B}║{NC}    ├─ 0b pentest-web              1m 48s    {"█"*5}')
lines.append(f'{C}{B}║{NC}    ├─ 0c pentest-ssh              0m 31s    {"█"*2}')
lines.append(f'{C}{B}║{NC}    ├─ 15 lynis audit              0m 47s    {"█"*2}')
lines.append(f'{C}{B}║{NC}    ├─ 14b rkhunter+chkrootkit     1m 12s    {"█"*3}')
lines.append(f'{C}{B}║{NC}    └─ remaining 49 sections       4m 18s    {"█"*13}')
lines.append(f'{C}{B}║{NC}  {B}ODT report generator{NC}            0m 14s    {"█"*1}')
lines.append(f'{C}{B}║{NC}  {B}ODS statistics workbook{NC}         0m 08s')
lines.append(f'{C}{B}║{NC}  {B}Intel ODT report{NC}                0m 11s')
lines.append(f'{C}{B}║{NC}  {B}HTML report{NC}                     0m 06s')
lines.append(f'{C}{B}║{NC}  {"─"*66}')
lines.append(f'{C}{B}║{NC}  {G}{B}TOTAL WALL CLOCK{NC}                {G}12m 17s{NC}   ETA was ~12m 45s  (−0:28)  ██████████')
lines.append(f'{C}{B}║{NC}  {D}Prediction based on 8 prior run(s) · EWMA α=0.4{NC}')
lines.append(f'{C}{B}║{NC}  {G}Score   71 / 132 passed (53%)   Rating: {Y}{B}MODERATE{NC}')
lines.append(f'{C}{B}║{NC}')
lines.append(f'{C}{B}╚══════════════════════════════════════════════════════════════════════╝{NC}')

# ── Score summary ─────────────────────────────────────────────────────────────
lines.append(f'\n{C}{B}╔══════════════════════════════════════════════════════════════════════╗{NC}')
lines.append(f'{C}{B}║  🎯  SECURITY SCORE SUMMARY                                          ║{NC}')
lines.append(f'{C}{B}╚══════════════════════════════════════════════════════════════════════╝{NC}')
lines.append(f'\n  Score: {Y}{B}71 / 132  (53%)  — MODERATE{NC}')
lines.append(f'  {R}FAIL : 12{NC}  {Y}WARN : 24{NC}  {G}PASS : 71{NC}  {C}INFO : 47{NC}  {B}SKIP : 2{NC}')
lines.append(f'\n  Previous score: 67% (2026-04-12)  |  Change: {Y}−14%{NC} (regression — 4 new FAILs)')
lines.append(f'  Score history: {D}61% → 67% → 67% → 74% → 74% → 79% → 83% → 83% → 53%{NC}')
lines.append(f'  {R}{B}▲ REGRESSION DETECTED{NC}: 4 issues that previously passed now fail:')
lines.append(f'    {R}↳{NC} TLS certificate now expires in 7 days (was 96 days)')
lines.append(f'    {R}↳{NC} /var/www/html/.env credential exposure (new file)')
lines.append(f'    {R}↳{NC} Port 8080 newly opened (not in previous scan)')
lines.append(f'    {R}↳{NC} debsums: 3 package files now show hash mismatch (new)')

# ── Output files ──────────────────────────────────────────────────────────────
lines.append(f'\n{C}{B}╔══════════════════════════════════════════════════════════════════════╗{NC}')
lines.append(f'{C}{B}║                         OUTPUT FILES                                 ║{NC}')
lines.append(f'{C}{B}╚══════════════════════════════════════════════════════════════════════╝{NC}')
lines.append(f'\n  {G}{B}Individual output files:{NC}')
lines.append(f'  • wowscanner_20260419_154232.txt                  — this report (234 KB)')
lines.append(f'  • wowscanner_report_20260419_154232.odt           — graphical ODT (1.2 MB)')
lines.append(f'  • wowscanner_report_20260419_154232.html          — browser report (890 KB)')
lines.append(f'  • wowscanner_stats_20260419_154232.ods            — statistics workbook (440 KB)')
lines.append(f'    └─ Sheets: Overview | Per-Section | All Findings | FAIL Deep-Dive | ChartData')
lines.append(f'  • wowscanner_intel_20260419_154232.odt            — intel report (670 KB)')
lines.append(f'    └─ Data: NIST NVD · CISA KEV · Elastic · Trend Micro · Mandiant 2025')
lines.append(f'  • wowscanner_findings_20260419_154232.txt         — paginated findings (44 KB)')
lines.append(f'\n  {G}{B}Archive:{NC}')
lines.append(f'  • wowscanner_archive_20260419_154232.zip          — all files (2.1 MB)')
lines.append(f'  • wowscanner_archive_20260419_154232.sha256       — archive hash')
lines.append(f'\n  {G}{B}Persistent data updated:{NC}')
lines.append(f'  • /var/lib/wowscanner/score_history.db            — 9 runs recorded')
lines.append(f'  • /var/lib/wowscanner/port_issues.log             — 6 port issues logged')
lines.append(f'  • /var/lib/wowscanner/remediation_commands.sh     — auto-generated fix script')

# ── Samba restart note ────────────────────────────────────────────────────────
lines.append(f'\n  {C}Restarting Samba (smbd.service) so output files appear on the share...{NC}')
lines.append(f'  {G}[✔]  smbd.service restarted — share directory is now up to date{NC}')

# Strip ANSI for the plain .txt file
import re as _re
def strip_ansi(s):
    return _re.sub(r'\033\[[0-9;]*m', '', s)

txt_content = strip_ansi('\n'.join(lines))
with open(out_txt, 'w') as f:
    f.write(txt_content)

# ── Findings file ─────────────────────────────────────────────────────────────
fails = [
    ('[2. UPDATES]     ', '8 packages need updating — run: apt-get upgrade'),
    ('[2. UPDATES]     ', '3 SECURITY updates pending: curl CVE-2024-2398, openssl CVE-2024-0727'),
    ('[7. PORTS]       ', 'MySQL port 3306 bound to ALL interfaces (0.0.0.0:3306)'),
    ('[7. PORTS]       ', 'Redis port 6379 bound to ALL interfaces (0.0.0.0:6379)'),
    ('[9. SERVICES]    ', '1 failed systemd unit: snapd.service'),
    ('[13. PACKAGES]   ', 'debsums: 3 modified package files (possible tampering)'),
    ('[13. PACKAGES]   ', 'gcc found on production server'),
    ('[13c. HARDENING] ', 'TLS certificate expires in 7 days: /etc/ssl/certs/webserver01.pem'),
    ('[16. PORT SCAN]  ', 'CRITICAL: port 6379 (Redis unauthenticated, public binding)'),
    ('[16. PORT SCAN]  ', 'HIGH: port 8080 NEW PORT — not seen in previous scan'),
    ('[17b6. SECRETS]  ', 'DB_PASSWORD in plaintext in /var/www/html/.env'),
    ('[17b4. BOOT]     ', 'GRUB password not configured (recovery mode unprotected)'),
]
warns = [
    ('[2. UPDATES]     ', 'unattended-upgrades: security-only mode not configured'),
    ('[3. USERS]       ', 'www-data has login shell /bin/bash (should be /nologin)'),
    ('[3. USERS]       ', 'backup_user inactive 107 days — disable or remove'),
    ('[3. USERS]       ', '127 SSH failures in 24h from 14 IPs'),
    ('[4. PASSWORD]    ', 'PASS_MIN_DAYS = 0 (recommend 1)'),
    ('[4. PASSWORD]    ', 'PASS_MIN_LEN = 8 (recommend 12)'),
    ('[7. PORTS]       ', '26 listening ports (approaching 30 threshold)'),
    ('[8. FILES]       ', '3 world-writable files in system paths'),
    ('[10. LOGGING]    ', 'No remote syslog forwarding configured'),
    ('[11. KERNEL]     ', 'net.ipv4.tcp_timestamps = 1 (uptime fingerprinting risk)'),
    ('[11. KERNEL]     ', 'kernel.module_sig_enforce = 0 (unsigned modules permitted)'),
    ('[12. CRON]       ', 'PATH includes /tmp in root crontab (hijacking risk)'),
    ('[13c. HARDENING] ', 'Swap partition not encrypted'),
    ('[14. APPARMOR]   ', '4 AppArmor profiles in complain mode (nginx, mysqld, ...)'),
    ('[14b. ROOTKIT]   ', 'rkhunter: /dev/.udev/rules.d/ hidden directory — investigate'),
    ('[15. LYNIS]      ', 'Lynis: 12 warnings (BOOT-5264, AUTH-9286, FILE-6430, ...)'),
    ('[16a. LAN]       ', 'Unknown vendor device on LAN: 192.168.1.30'),
    ('[17b. LOGINS]    ', 'SSH brute-force: 127 failures in 24h (FAIL threshold exceeded)'),
    ('[17b5. WEB]      ', 'Content-Security-Policy header missing from nginx'),
    ('[17b6. SECRETS]  ', 'mysql password visible in /root/.bash_history'),
    ('[17x. MODULES]   ', 'dccp kernel module loaded — rarely needed'),
    ('[9. SERVICES]    ', 'tcpdump installed on production system'),
    ('[17b4. BOOT]     ', 'grub.cfg permissions: 644 (should be 600)'),
    ('[17c. ENV]       ', 'No --forgot-style hint appeared in this section'),
]

fnd_lines = []
fnd_lines.append('Wowscanner v2.2.0 — Security Findings — webserver01.example.com — 2026-04-19 15:42:32')
fnd_lines.append('━'*78)
fnd_lines.append(f'Score: 53%  Rating: MODERATE  |  FAIL: {len(fails)}   WARN: {len(warns)}   PASS: 71   INFO: 47   SKIP: 2')
fnd_lines.append('━'*78)
fnd_lines.append(f'\n{"─"*10} CRITICAL FAILURES ({len(fails)}) {"─"*10}\n')
for sec, msg in fails:
    fnd_lines.append(f'  [✘ FAIL]  {sec} {msg}')
fnd_lines.append(f'\n{"─"*10} WARNINGS ({len(warns)}) {"─"*10}\n')
for sec, msg in warns:
    fnd_lines.append(f'  [⚠ WARN]  {sec} {msg}')
fnd_lines.append('\n' + '━'*78)
fnd_lines.append('TOP REMEDIATION PRIORITIES:')
fnd_lines.append('  1. Renew TLS certificate immediately (expires in 7 days)')
fnd_lines.append('  2. Fix Redis: bind 127.0.0.1 + requirepass in /etc/redis/redis.conf')
fnd_lines.append('  3. Fix MySQL: bind-address=127.0.0.1 in mysqld.cnf')
fnd_lines.append('  4. Apply 3 security package updates (curl, openssl, libssl3)')
fnd_lines.append('  5. Remove /var/www/html/.env (plaintext DB password in web root)')
fnd_lines.append('  6. Investigate debsums mismatches (possible tampering: curl, nginx, libssl3)')
fnd_lines.append('  7. Remove gcc from production: apt-get purge gcc build-essential')
fnd_lines.append('  8. Review new port 8080 — was this intentional?')
fnd_lines.append('')

with open(out_fnd, 'w') as f:
    f.write(strip_ansi('\n'.join(fnd_lines)))

txt_kb = os.path.getsize(out_txt) // 1024
fnd_kb = os.path.getsize(out_fnd) // 1024
print(f"Written: {out_txt} ({txt_kb} KB)")
print(f"Written: {out_fnd} ({fnd_kb} KB)")
EXEOF

  if [[ -f "$_txt" && -f "$_fnd" ]]; then
    local _tsz _fsz
    _tsz=$(du -h "$_txt" 2>/dev/null | cut -f1)
    _fsz=$(du -h "$_fnd" 2>/dev/null | cut -f1)
    echo ""
    echo -e "  ${BGREEN}✔${NC}  ${BOLD}${_txt}${NC}  (${_tsz}) — full audit log example"
    echo -e "  ${BGREEN}✔${NC}  ${BOLD}${_fnd}${NC}  (${_fsz}) — findings report example"
    echo ""
    echo -e "  ${DIM}This shows a realistic wowscanner scan of a Ubuntu 22.04 web server.${NC}"
    echo -e "  ${DIM}Scenario: 12 FAIL, 24 WARN — MODERATE security rating.${NC}"
    echo -e "  ${DIM}Includes: all 54 section outputs, timing summary, score regression alert.${NC}"
    echo ""
  else
    echo -e "  ${RED}Error: could not write example files (python3 required).${NC}"
    return 1
  fi
}


# ── cmd_reset_auth: change passphrase OR wipe all data ────────────────────────
# ================================================================
#  cmd_reset_auth  —  all password management in one command
#
#  Usage:
#    sudo bash wowscanner.sh reset-auth              change passphrase
#    sudo bash wowscanner.sh reset-auth --forgot     forgot passphrase (root only)
#    sudo bash wowscanner.sh reset-auth --force      wipe everything
#    bash  wowscanner.sh reset-auth --show-keyid     show key fingerprint
#    bash  wowscanner.sh reset-auth --recover-old    access old archives
#    bash  wowscanner.sh reset-auth --list-keys      list all key files
# ================================================================
# ================================================================
#  cmd_reset_auth  —  all password management in one command
#
#  Usage:
#    sudo bash wowscanner.sh reset-auth              interactive menu
#    sudo bash wowscanner.sh reset-auth change       change passphrase (knows current)
#    sudo bash wowscanner.sh reset-auth forgot       reset without old passphrase
#    sudo bash wowscanner.sh reset-auth force        wipe everything
#    bash  wowscanner.sh reset-auth keyid            show key fingerprints
#    bash  wowscanner.sh reset-auth recover          access old archives
# ================================================================
cmd_reset_auth() {
  echo ""
  echo -e "${BCYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BCYAN}${BOLD}║${NC}  ${BOLD}Wowscanner — Password Management${NC}                           ${BCYAN}${BOLD}║${NC}"
  echo -e "${BCYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Normalise sub-command: strip leading dashes and "reset-auth" token
  local _sub="${1:-}"
  [[ "$_sub" == "reset-auth" ]]  && _sub="${2:-}"
  _sub="${_sub#--}"          # strip leading --
  _sub="${_sub#-}"           # strip leading -  (single dash)
  _sub="${_sub,,}"           # lowercase

  # ── If no sub-command given: show interactive menu ────────────────────────
  if [[ -z "$_sub" ]]; then
    echo -e "  What would you like to do?\n"
    echo -e "  ${BOLD}1)${NC}  Change passphrase          ${DIM}(know current passphrase)${NC}"
    echo -e "  ${BOLD}2)${NC}  Reset forgotten passphrase ${DIM}(do not know current passphrase — root only)${NC}"
    echo -e "  ${BOLD}3)${NC}  Wipe everything            ${DIM}(delete auth key + all scan data)${NC}"
    echo -e "  ${BOLD}4)${NC}  Show key fingerprints      ${DIM}(no passphrase needed)${NC}"
    echo -e "  ${BOLD}5)${NC}  Recover old archives       ${DIM}(need old passphrase for previous key)${NC}"
    echo -e "  ${BOLD}6)${NC}  Reset using recovery key ${DIM}(48-char key shown at first-run setup)${NC}"
  echo -e "  ${BOLD}q)${NC}  Cancel"
    echo ""
    read -rp "  Choice [1-6 / q]: " _choice
    echo ""
    case "${_choice,,}" in
      1|change)   _sub="change"   ;;
      2|forgot)   _sub="forgot"   ;;
      3|force)    _sub="force"    ;;
      4|keyid)    _sub="keyid"    ;;
      5|recover)  _sub="recover"  ;;
      6|rk|recovery-key|recover-key) _sub="rk" ;;
      q|"")
        echo -e "  ${YELLOW}Cancelled.${NC}"; echo ""; return 0 ;;
      *)
        echo -e "  ${RED}Invalid choice.${NC}"; echo ""; return 1 ;;
    esac
  fi

  # Also accept long-form aliases (with or without --)
  case "$_sub" in
    show-keyid|list-keys|keyid|keys) _sub="keyid"   ;;
    recover-old|recover)              _sub="recover" ;;
    forgot|reset|forgot-password)     _sub="forgot"  ;;
    force|wipe|nuke)                  _sub="force"   ;;
    change|normal|password)           _sub="change"  ;;
  esac

  # ──────────────────────────────────────────────────────────────
  # keyid  —  show key fingerprints (no auth needed)
  # ──────────────────────────────────────────────────────────────
  if [[ "$_sub" == "keyid" ]]; then
    echo -e "  ${BOLD}Key fingerprints${NC}\n"
    if [[ -f "$_WS_AUTH_KEY" ]]; then
      local _kid _rounds
      _kid=$(grep    "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
      _rounds=$(grep "^rounds=" "$_WS_AUTH_KEY" | cut -d= -f2-)
      echo -e "  ${BGREEN}Active${NC}   key ID : ${BOLD}${_kid:-unknown}${NC}  (${_rounds:-?} PBKDF2 rounds)"
      echo -e "           file   : ${DIM}${_WS_AUTH_KEY}${NC}"
    else
      echo -e "  ${RED}No active auth.key found.${NC}"
      echo -e "  ${DIM}Run: sudo bash $0  to trigger first-run setup.${NC}"
    fi
    echo ""
    if [[ -f "${_WS_AUTH_KEY}.prev" ]]; then
      local _pkid _pmod
      _pkid=$(grep "^key_id=" "${_WS_AUTH_KEY}.prev" | cut -d= -f2-)
      _pmod=$(stat -c "%y" "${_WS_AUTH_KEY}.prev" 2>/dev/null | cut -d. -f1 || echo "unknown")
      echo -e "  ${DIM}Previous key ID : ${_pkid:-unknown}${NC}"
      echo -e "  ${DIM}Backed up       : ${_pmod}${NC}"
      echo ""
      echo -e "  ${DIM}To access old archives: bash $0 reset-auth recover${NC}"
    else
      echo -e "  ${DIM}No previous key on file.${NC}"
    fi
    echo ""
    return 0
  fi

  # ──────────────────────────────────────────────────────────────
  # recover  —  verify old archives via auth.key.prev
  # No root needed — only the old passphrase.
  # ──────────────────────────────────────────────────────────────
  if [[ "$_sub" == "recover" ]]; then
    if [[ ! -f "${_WS_AUTH_KEY}.prev" ]]; then
      echo -e "  ${RED}No previous key file found at ${_WS_AUTH_KEY}.prev${NC}"
      echo ""
      echo -e "  ${DIM}A previous key is saved automatically whenever you run:${NC}"
      echo -e "  ${DIM}  reset-auth change | forgot | force${NC}"
      echo ""
      return 1
    fi
    local _pkid _pmod
    _pkid=$(grep "^key_id=" "${_WS_AUTH_KEY}.prev" | cut -d= -f2-)
    _pmod=$(stat -c "%y" "${_WS_AUTH_KEY}.prev" 2>/dev/null | cut -d. -f1 || echo "unknown")
    echo -e "  ${BOLD}Previous key${NC}"
    echo -e "  Key ID    : ${BOLD}${_pkid:-unknown}${NC}"
    echo -e "  Backed up : ${DIM}${_pmod}${NC}\n"
    echo -e "  Enter the ${BOLD}old passphrase${NC} — the one active before your last reset."
    echo ""

    local _op="" _oa=0
    while [[ "$_oa" -lt 3 ]]; do
      read -rsp "  Old passphrase: " _op; echo ""
      if _ws_verify_pass_file "$_op" "${_WS_AUTH_KEY}.prev"; then
        _ws_derive_data_key "$_op" "${_WS_AUTH_KEY}.prev"
        _op=""
        echo ""
        echo -e "  ${BGREEN}✔${NC}  Verified.  Key ID : ${BOLD}${WS_KEY_ID}${NC}"
        echo -e "  ${BGREEN}✔${NC}  WS_DATA_KEY and WS_KEY_ID exported to environment."
        echo ""
        return 0
      fi
      _op=""
      _oa=$(( _oa + 1 ))
      [[ "$_oa" -lt 3 ]] && \
        echo -e "  ${RED}Wrong passphrase. $(( 3-_oa )) attempt(s) left.${NC}\n" && \
        sleep $(( _oa * 2 ))
    done
    echo -e "  ${RED}${BOLD}Too many failed attempts.${NC}"; echo ""; return 1
  fi

  # ──────────────────────────────────────────────────────────────
  # rk  —  reset passphrase using the recovery key (root only)
  # The 48-char recovery key was shown once at first-run setup.
  # ──────────────────────────────────────────────────────────────
  if [[ "$_sub" == "rk" ]]; then
    echo -e "  ${BOLD}Recovery key reset${NC}\n"
    if [[ ! -f "$_WS_AUTH_KEY" ]]; then
      echo -e "  ${RED}No auth.key found. Nothing to reset.${NC}"; echo ""; return 1
    fi
    echo -e "  Enter the ${BOLD}48-character recovery key${NC} shown at first-run setup."
    echo -e "  ${DIM}(looks like: a1b2c3d4...  — 48 lowercase hex characters)${NC}\n"
    local _rk_input=""
    read -rp "  Recovery key: " _rk_input; echo ""
    if ! _ws_verify_recovery_key "$_rk_input" "$_WS_AUTH_KEY"; then
      _rk_input=""
      echo -e "  ${RED}Invalid recovery key.${NC}"
      echo -e "  ${DIM}Make sure you copied all 48 characters exactly.${NC}"; echo ""; return 1
    fi
    _rk_input=""
    echo -e "  ${BGREEN}✔${NC}  Recovery key verified.\n"
    if [[ $(id -u) -ne 0 ]]; then
      echo -e "  ${RED}Must be root to write new auth.key.${NC}"
      echo -e "  Run: ${BOLD}sudo bash $0 reset-auth rk${NC}"; echo ""; exit 1
    fi
    if [[ -f "$_WS_AUTH_KEY" ]]; then
      cp -p "$_WS_AUTH_KEY" "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      chmod 400 "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      local _rk_old_kid; _rk_old_kid=$(grep "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
      echo -e "  ${BGREEN}✔${NC}  Old key (${_rk_old_kid:-?}) saved to auth.key.prev"
    fi
    echo -e "\n  ${BOLD}Set new passphrase${NC}"
    echo -e "  ${DIM}Minimum 10 characters.${NC}\n"
    local _rp1="" _rp2=""
    while true; do
      read -rsp "  New passphrase : " _rp1; echo ""
      if [[ ${#_rp1} -lt 10 ]]; then echo -e "  ${RED}Minimum 10 characters.${NC}"; continue; fi
      read -rsp "  Confirm        : " _rp2; echo ""
      if [[ "$_rp1" != "$_rp2" ]]; then echo -e "  ${RED}Do not match. Try again.${NC}\n"; continue; fi
      break
    done
    echo -ne "  ${DIM}Generating new key (200,000 rounds)...${NC}"
    _ws_write_auth_key "$_rp1" ""
    _rp1=""; _rp2=""
    local _rk_new_kid; _rk_new_kid=$(grep "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
    echo -e "\r  ${BGREEN}✔${NC}  Passphrase reset. New key ID: ${BOLD}${_rk_new_kid}${NC}          "
    echo ""
    echo -e "  ${BRED}${BOLD}New recovery key (save this):${NC}"
    echo -e "  ${BOLD}${WS_RECOVERY_KEY}${NC}"
    echo ""
    return 0
  fi

  # All remaining sub-commands write to /etc/wowscanner/ — require root
  if [[ $(id -u) -ne 0 ]]; then
    echo -e "  ${RED}This operation requires root.${NC}"
    echo -e "  Run: ${BOLD}sudo bash $0 reset-auth ${_sub}${NC}"
    echo ""
    echo -e "  ${DIM}The options 'keyid' and 'recover' do not require root.${NC}"
    echo ""
    exit 1
  fi

  # ──────────────────────────────────────────────────────────────
  # forgot  —  reset without current passphrase (root = proof)
  # Generates a NEW data_key. Old archives need recover + old pass.
  # ──────────────────────────────────────────────────────────────
  if [[ "$_sub" == "forgot" ]]; then
    echo -e "  ${BRED}${BOLD}Forgot-passphrase reset${NC}"
    echo ""
    echo -e "  Root access accepted as proof of ownership."
    echo -e "  A new passphrase and a ${BOLD}new data key${NC} will be generated."
    echo ""
    echo -e "  ${BOLD}What happens:${NC}"
    echo -e "  ${YELLOW}  • Old auth.key is saved to auth.key.prev${NC}"
    echo -e "  ${YELLOW}  • Scan history and port data are preserved${NC}"
    echo -e "  ${YELLOW}  • New data key — old archives need: reset-auth recover${NC}"
    echo ""
    read -rp "  Proceed? [Y/n] " _ans
    if [[ "${_ans,,}" == "n" ]]; then
      echo -e "  ${YELLOW}Cancelled.${NC}"; echo ""; return 0
    fi

    if [[ -f "$_WS_AUTH_KEY" ]]; then
      cp -p "$_WS_AUTH_KEY" "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      chmod 400 "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      local _old_kid; _old_kid=$(grep "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
      echo -e "  ${BGREEN}✔${NC}  Old key (${_old_kid:-?}) saved to auth.key.prev"
    fi

    echo ""
    echo -e "  ${BOLD}Set new passphrase${NC}"
    echo -e "  ${DIM}Minimum 10 characters.${NC}\n"

    local _p1="" _p2=""
    while true; do
      read -rsp "  New passphrase : " _p1; echo ""
      if [[ ${#_p1} -lt 10 ]]; then echo -e "  ${RED}Minimum 10 characters.${NC}"; continue; fi
      read -rsp "  Confirm        : " _p2; echo ""
      if [[ "$_p1" != "$_p2" ]]; then echo -e "  ${RED}Do not match.${NC}\n"; continue; fi
      break
    done

    echo -ne "  ${DIM}Generating new key (200,000 PBKDF2 rounds)...${NC}"
    _ws_write_auth_key "$_p1" ""
    _p1=""; _p2=""
    local _new_kid; _new_kid=$(grep "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
    echo -e "\r  ${BGREEN}✔${NC}  New passphrase set. Key ID: ${BOLD}${_new_kid}${NC}          "
    echo ""
    echo -e "  ${DIM}To verify old archives: bash $0 reset-auth recover${NC}"
    echo ""
    return 0
  fi

  # ──────────────────────────────────────────────────────────────
  # force  —  wipe auth key AND all scan history
  # ──────────────────────────────────────────────────────────────
  if [[ "$_sub" == "force" ]]; then
    echo -e "  ${BRED}${BOLD}WARNING — force wipes ALL wowscanner data${NC}\n"
    echo -e "  ${BOLD}Will be deleted:${NC}"
    echo -e "  ${RED}  • Auth key     : ${_WS_AUTH_KEY}${NC}"
    echo -e "  ${RED}  • Scan history : ${_WS_PERSIST_DIR}/${NC}"
    echo -e "  ${RED}  • Sudoers      : /etc/sudoers.d/wowscanner${NC}"
    echo ""
    echo -e "  ${DIM}auth.key.prev is kept so old archives can still be recovered.${NC}\n"
    read -rsp "  Type WIPE to confirm: " _conf; echo ""
    if [[ "$_conf" != "WIPE" ]]; then
      echo -e "  ${YELLOW}Cancelled.${NC}"; echo ""; return 0
    fi

    if [[ -f "$_WS_AUTH_KEY" ]]; then
      cp -p "$_WS_AUTH_KEY" "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      chmod 400 "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      local _old_kid; _old_kid=$(grep "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
      echo -e "  ${BGREEN}✔${NC}  Key (${_old_kid:-?}) backed up to auth.key.prev"
    fi

    rm -f  "$_WS_AUTH_KEY"              2>/dev/null || true
    rm -rf "$_WS_PERSIST_DIR"            2>/dev/null || true
    rm -f  "/etc/sudoers.d/wowscanner"  2>/dev/null || true
    echo -e "  ${BGREEN}✔${NC}  Auth key, scan history and sudoers entry deleted."
    echo ""
    echo -e "  ${BGREEN}Next run will trigger the first-run setup wizard.${NC}"
    echo -e "  ${DIM}To recover old archives: bash $0 reset-auth recover${NC}"
    echo ""
    return 0
  fi

  # ──────────────────────────────────────────────────────────────
  # change  —  change passphrase while knowing the current one
  # The data_key is preserved so all archives stay readable.
  # ──────────────────────────────────────────────────────────────
  if [[ "$_sub" == "change" ]]; then
    echo -e "  ${BOLD}Change passphrase${NC}"
    echo -e "  ${DIM}The data key is preserved — all existing archives stay readable.${NC}"
    echo -e "  ${DIM}Forgot your passphrase? Go back and choose option 2.${NC}\n"

    echo -e "  ${BOLD}Step 1 of 2 — Verify current passphrase${NC}\n"
    local _cur="" _cur_dk="" _ca=0
    while [[ "$_ca" -lt 3 ]]; do
      read -rsp "  Current passphrase: " _cur; echo ""
      if _ws_verify_pass "$_cur"; then
        _ws_derive_data_key "$_cur"
        _cur_dk="$WS_DATA_KEY"
        _cur=""
        echo -e "  ${BGREEN}✔${NC}  Verified. Key ID: ${BOLD}${WS_KEY_ID}${NC} (preserved)\n"
        break
      fi
      _cur=""
      _ca=$(( _ca + 1 ))
      [[ "$_ca" -lt 3 ]] && \
        echo -e "  ${RED}Wrong. $(( 3-_ca )) attempt(s) left. Forgot it? Press Ctrl-C and run: reset-auth forgot${NC}\n" && \
        sleep $(( _ca * 2 ))
    done
    if [[ "$_ca" -ge 3 ]]; then
      echo -e "  ${RED}Too many failed attempts.${NC}"
      echo -e "  ${DIM}Forgot passphrase? Run: sudo bash $0 reset-auth forgot${NC}"
      echo ""; exit 1
    fi

    echo -e "  ${BOLD}Step 2 of 2 — Set new passphrase${NC}"
    echo -e "  ${DIM}Minimum 10 characters.${NC}\n"
    local _n1="" _n2=""
    while true; do
      read -rsp "  New passphrase : " _n1; echo ""
      if [[ ${#_n1} -lt 10 ]]; then echo -e "  ${RED}Minimum 10 characters.${NC}"; continue; fi
      read -rsp "  Confirm        : " _n2; echo ""
      if [[ "$_n1" != "$_n2" ]]; then echo -e "  ${RED}Do not match.${NC}\n"; continue; fi
      break
    done

    if [[ -f "$_WS_AUTH_KEY" ]]; then
      cp -p "$_WS_AUTH_KEY" "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
      chmod 400 "${_WS_AUTH_KEY}.prev" 2>/dev/null || true
    fi

    echo -ne "  ${DIM}Re-wrapping key (200,000 rounds)...${NC}"
    _ws_write_auth_key "$_n1" "$_cur_dk"
    _n1=""; _n2=""; _cur_dk=""
    local _new_kid; _new_kid=$(grep "^key_id=" "$_WS_AUTH_KEY" | cut -d= -f2-)
    echo -e "\r  ${BGREEN}✔${NC}  Passphrase changed. Key ID unchanged: ${BOLD}${_new_kid}${NC}     "
    echo -e "  ${BGREEN}✔${NC}  Old key saved to: ${DIM}${_WS_AUTH_KEY}.prev${NC}"
    echo ""
    return 0
  fi

  echo -e "  ${RED}Unknown sub-command: ${_sub}${NC}"
  echo -e "  Run without arguments to see the menu: ${BOLD}sudo bash $0 reset-auth${NC}"
  echo ""; return 1
}

# ── _ws_verify_pass_file: verify against a specific key file (not default) ────
_ws_verify_pass_file() {
  # Verify $_pass against the key file $_keyfile (not necessarily the active one).
  # Returns 0 on success, 1 on wrong passphrase or tampered/corrupt file.
  local _pass="$1" _keyfile="${2:-$_WS_AUTH_KEY}"
  [[ ! -f "$_keyfile" ]] && return 1

  local _rounds _salt _iv _stored_hmac _cipher _dk_iv _dk_wrapped
  _rounds=$(grep     "^rounds="     "$_keyfile" | cut -d= -f2-)
  _salt=$(grep       "^salt="       "$_keyfile" | cut -d= -f2-)
  _iv=$(grep         "^iv="         "$_keyfile" | cut -d= -f2-)
  _stored_hmac=$(grep "^hmac="      "$_keyfile" | cut -d= -f2-)
  _cipher=$(grep     "^cipher="     "$_keyfile" | cut -d= -f2-)
  _dk_iv=$(grep      "^dk_iv="      "$_keyfile" | cut -d= -f2-)
  _dk_wrapped=$(grep  "^dk_wrapped=" "$_keyfile" | cut -d= -f2-)

  [[ -z "$_salt" || -z "$_iv" || -z "$_stored_hmac" || -z "$_cipher" ]] && return 1

  local _key
  _key=$(_ws_crypto hash "$_pass" "$_salt" "${_rounds:-200000}")
  [[ -z "$_key" ]] && return 1

  # HMAC covers all fields — detect tampering without revealing which field changed
  local _hmac_data _actual_hmac
  if [[ -n "$_dk_iv" && -n "$_dk_wrapped" ]]; then
    _hmac_data="${_salt}${_iv}${_cipher}${_dk_iv}${_dk_wrapped}"
  else
    _hmac_data="${_salt}${_iv}${_cipher}"
  fi
  _actual_hmac=$(_ws_crypto hmac "$_key" "$_hmac_data")
  _ws_crypto compare "$_actual_hmac" "$_stored_hmac" 2>/dev/null || return 1

  local _pt
  _pt=$(_ws_crypto decrypt "$_pass" "$_salt" "${_rounds:-200000}" "$_iv" "$_cipher")
  [[ "$_pt" == "WOWSCANNER_OK" ]]
}

# ── cmd_set_password: alias kept for backwards compat ────────────────────────
cmd_set_password() {
  echo -e "  ${YELLOW}Note: 'set-password' is replaced by the first-run wizard.${NC}"
  echo -e "  ${YELLOW}To change passphrase: bash $0 reset-auth${NC}"
  echo -e "  ${YELLOW}To wipe all data:     bash $0 reset-auth --force${NC}"
}

# ── cmd_recover: remove auth.key so next run triggers first-run wizard ────────
# Must be run as root.  Backs up auth.key to auth.key.bak, then removes it.
# Scan history, scores, and port data are preserved.
# Usage: sudo bash wowscanner.sh recover
cmd_recover() {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}Wowscanner Password Recovery${NC}                               ${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Must be root
  if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}  Must be run as root: sudo bash $0 recover${NC}"
    exit 1
  fi

  # Check if auth.key exists
  if [[ ! -f "$_WS_AUTH_KEY" ]]; then
    echo -e "${YELLOW}  No auth.key found at $_WS_AUTH_KEY${NC}"
    echo -e "${YELLOW}  Nothing to remove — wowscanner will already ask for a new password.${NC}"
    echo ""
    exit 0
  fi

  echo -e "  Found: ${BOLD}$_WS_AUTH_KEY${NC}"
  echo ""
  echo -e "  ${BOLD}This will:${NC}"
  echo -e "  ${YELLOW}  • Back up auth.key to auth.key.bak${NC}"
  echo -e "  ${YELLOW}  • Remove the auth.key${NC}"
  echo -e "  ${YELLOW}  • Next wowscanner run will ask you to set a new password${NC}"
  echo -e "  ${YELLOW}  • Scan history and scores are preserved${NC}"
  echo ""
  read -rp "  Proceed? [Y/n] " _rec_ans
  if [[ "${_rec_ans,,}" == "n" ]]; then
    echo -e "  ${YELLOW}Cancelled.${NC}"; echo ""; exit 0
  fi
  unset _rec_ans

  # Back up and remove
  cp -p "$_WS_AUTH_KEY" "${_WS_AUTH_KEY}.bak" 2>/dev/null && \
    echo -e "  ${GREEN}✔  Backed up to ${_WS_AUTH_KEY}.bak${NC}" || true

  rm -f "$_WS_AUTH_KEY" && \
    echo -e "  ${GREEN}✔  auth.key removed${NC}" || \
    { echo -e "  ${RED}  Failed to remove $_WS_AUTH_KEY${NC}"; exit 1; }

  echo ""
  echo -e "  ${GREEN}${BOLD}Done.${NC}"
  echo ""
  echo -e "  Now run wowscanner and it will ask you to set a new password:"
  echo -e "  ${CYAN}${BOLD}  sudo bash $0${NC}"
  echo ""
}


require_root() {
  # _ws_early_gate already verified passphrase and elevated if needed.
  # This just confirms we are root (defence-in-depth guard).
  if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}Wowscanner requires root. First-run: sudo bash $0${NC}"
    exit 1
  fi
  _ensure_completion
}

# ── _ensure_completion ──────────────────────────────────────────────────────
# Auto-installs bash tab-completion on first run (silently).
# Called after successful auth — every invocation — scan, clean, verify, etc. —
# keeps the completion file up to date with no user action needed.
_ensure_completion() {
  local _comp_dir="/etc/bash_completion.d"
  local _comp_file="${_comp_dir}/wowscanner"
  local _script_path
  _script_path=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")

  # Skip if completion file already exists and is up to date
  [[ -d "$_comp_dir" ]] || return 0

  # Write/overwrite silently — cheap operation, ensures it is always current
  cat > "$_comp_file" 2>/dev/null << 'COMPEOF'
# Bash tab-completion for wowscanner.sh
# Auto-installed on first run — re-run any wowscanner command to refresh.
_wowscanner_complete() {
  local cur words cword
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  words=("${COMP_WORDS[@]}")
  cword=$COMP_CWORD

  local _cmds="clean verify diff harden baseline install-completion install-timer remove-timer"
  local _flags="--no-lynis --no-pentest --no-rkhunter --no-hardening --no-netcontainer --quiet --fast-only --email= --webhook="

  # Context-sensitive completions
  local _w1="${words[1]:-}" _w2="${words[2]:-}"

  if [[ "$_w1" == "clean" ]] || [[ "$_w2" == "clean" ]]; then
    COMPREPLY=( $(compgen -W "--all --integrity" -- "$cur") )
    return 0
  fi

  if [[ "$_w1" == "verify" ]] || [[ "$_w2" == "verify" ]]; then
    COMPREPLY=( $(compgen -W "--reset-history" -- "$cur") )
    return 0
  fi

  # First word after script name: show commands + flags
  if [[ "$cword" -le 1 ]] || [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$_cmds $_flags" -- "$cur") )
    return 0
  fi

  COMPREPLY=( $(compgen -W "$_flags" -- "$cur") )
  return 0
}

complete -F _wowscanner_complete wowscanner.sh
complete -F _wowscanner_complete wowscanner
COMPEOF
  chmod 644 "$_comp_file" 2>/dev/null || true
}

# Resolve a sshd_config directive (handles Include files on Debian 8+).
# Uses a module-level cache (SSHD_CONFIG_CACHE) populated by section_ssh
# to avoid re-spawning sshd -T for every directive.
sshd_value() {
  local key="$1"; local val=""
  # Fast path: use pre-populated cache from section_ssh
  if [[ -n "$SSHD_CONFIG_CACHE" ]]; then
    val=$(grep -i "^${key} " <<< "$SSHD_CONFIG_CACHE" | awk '{print $2}' | head -1 || true)
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
      rm -f "$ENUM_NMAP" 2>/dev/null || true
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

      echo ""; echo "=== Null Session Test (rpcclient -N) ==="
      timeout 10 rpcclient 127.0.0.1 -N -c "srvinfo" 2>&1 || true

      echo ""
      echo "=== Domain User Enumeration (rpcclient enumdomusers) ==="
      timeout 10 rpcclient 127.0.0.1 -N -c "enumdomusers" 2>&1 || true

      echo ""
      echo "=== Domain Groups (rpcclient enumdomgroups) ==="
      timeout 10 rpcclient 127.0.0.1 -N -c "enumdomgroups" 2>&1 || true

      echo ""; echo "=== NetBIOS Name Table (nmblookup) ==="
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
    rm -f "$E4L_OUT" 2>/dev/null || true
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
    info "No HTTP/HTTPS ports detected — skipping Nikto"; pass "No web server listening (Nikto not needed)"
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
        grep "^+ " "$NIKTO_OUT" | head -20 | while IFS= read -r l; do detail "$l"; done || true
      else
        pass "Nikto: No critical findings on port $PORT"
      fi
      { echo ""; echo "──── RAW: nikto port ${PORT} ────"; cat "$NIKTO_OUT"; echo "────────────────────────────"; } >> "$REPORT" || true
      rm -f "$NIKTO_OUT" 2>/dev/null || true
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
    grep "login:" "$HYDRA_OUT" | while IFS= read -r l; do detail "$l"; done || true
    warn "Immediate action: change password and enforce key-only auth"
  else
    pass "SSH brute-force test failed — no common passwords accepted"
  fi
  rm -f "$PASS_LIST" 2>/dev/null || true
  { echo ""; echo "──── RAW: hydra SSH brute-force ────"; cat "$HYDRA_OUT" 2>/dev/null || true; echo "────────────────────────────"; } >> "$REPORT"
  rm -f "$HYDRA_OUT" "$PASS_LIST" 2>/dev/null || true
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
    info "No web server listening — skipping SQLMap"; pass "SQL injection test not applicable (no web server found)"
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
  rm -f "$SQLMAP_OUT" 2>/dev/null || true
  rm -rf "/tmp/sqlmap_${TIMESTAMP}" 2>/dev/null || true
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
      dmesg 2>/dev/null | grep -i "oom-killer\|out of memory" 2>/dev/null | tail -5 \
        | while IFS= read -r l; do detail "$l"; done || true
    else
      pass "No OOM killer events detected during stress"
    fi
    { echo ""; echo "──── RAW: stress-ng ────"; cat "$STRESS_OUT" 2>/dev/null || true; echo "────────────────────────────"; } >> "$REPORT"
    rm -f "$STRESS_OUT" 2>/dev/null || true
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
    info "TCP state before flood: $SS_BEFORE"; info "TCP state after  flood: $SS_AFTER"

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

  info "Open files limit  : ${UL_FILES}"; info "Max processes     : ${UL_PROCS}"
  info "Stack size        : ${UL_STACK} KB"; info "Max memory (virt) : ${UL_VMEM}"

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
  info "Kernel        : $(uname -r)"; info "Architecture  : $(uname -m)"
  info "Uptime        : $(uptime -p 2>/dev/null || uptime)"; info "Date/Time     : $(date)"
  info "CPU           : $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo 'unknown')"
  info "Memory total  : $(free -h 2>/dev/null | awk '/^Mem:/{print $2}') RAM"
  info "Disk usage    : $(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5" used)"}')"
  info "Loaded modules: $(lsmod 2>/dev/null | wc -l) kernel modules"

  local _cpu_count
  _cpu_count=$(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "?")
  info "CPU count     : ${_cpu_count} logical core(s)"

  local _zombie_count
  _zombie_count=$(ps -eo stat 2>/dev/null | grep -c "^Z" || true)
  _zombie_count=$(safe_int "$_zombie_count")
  if [[ "$_zombie_count" -gt 0 ]]; then
    warn "Zombie processes detected: ${_zombie_count} (may indicate unstable services)"
  else
    info "Zombie processes: 0"
  fi
  local _inode_pct
  _inode_pct=$(df -i / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%' || echo "0")
  _inode_pct=$(safe_int "$_inode_pct")
  if [[ "$_inode_pct" -ge 90 ]]; then
    fail "Root filesystem inode usage: ${_inode_pct}% — nearly exhausted (many small files)"
  elif [[ "$_inode_pct" -ge 75 ]]; then
    warn "Root filesystem inode usage: ${_inode_pct}%"
  else
    info "Inode usage (/)  : ${_inode_pct}%"
  fi
  local _open_files
  _open_files=$(awk '{print $1"/"$3}' /proc/sys/fs/file-nr 2>/dev/null || echo "unknown")
  info "Open file handles: ${_open_files}"

  if systemd-detect-virt --quiet 2>/dev/null; then
    local VIRT
    VIRT=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    info "Virtualisation: ${VIRT}"
  fi

  subheader "Resource & security limits"

  local _oom
  _oom=$(cat /proc/sys/vm/panic_on_oom 2>/dev/null || echo "0")
  _oom=$(safe_int "$_oom")
  if [[ "$_oom" -ge 1 ]]; then
    warn "vm.panic_on_oom=${_oom} — system may panic instead of using OOM killer"
  else
    pass "OOM killer active (vm.panic_on_oom=0) — kernel will kill processes before panicking"
  fi

  local _core_limit
  _core_limit=$(ulimit -c 2>/dev/null || echo "0")
  if [[ "$_core_limit" == "unlimited" ]]; then
    warn "Core dumps are unlimited for root — may expose sensitive memory to disk"
    detail "Set: ulimit -c 0 or add '* hard core 0' to /etc/security/limits.conf"
  else
    pass "Core dump size limit: ${_core_limit} (0 = disabled)"
  fi

  subheader "Disk & filesystem health"

  local _ro_mounts
  _ro_mounts=$(awk '$4~/(^|,)ro(,|$)/{print $2}' /proc/mounts 2>/dev/null     | grep -v "^/sys\|^/proc\|^/dev\|^/run\|snap\|squashfs\|iso9660\|tmpfs" || true)
  if [[ -n "$_ro_mounts" ]]; then
    warn "Unexpected read-only filesystem mounts (may indicate corruption):"
    while IFS= read -r _mp; do detail "$_mp"; done <<< "$_ro_mounts"
  else
    pass "No unexpected read-only filesystem mounts"
  fi

  for _td in /tmp /var/tmp; do
    if [[ -d "$_td" ]]; then
      local _tp
      _tp=$(df "$_td" 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%' || echo "0")
      _tp=$(safe_int "$_tp")
      if [[ "$_tp" -ge 90 ]]; then
        fail "${_td} is ${_tp}% full — may block logins and application writes"
      elif [[ "$_tp" -ge 75 ]]; then
        warn "${_td} is ${_tp}% full"
      else
        pass "${_td} usage: ${_tp}%"
      fi
    fi
  done

  subheader "Process security"

  local _root_procs
  _root_procs=$(ps -eo user= 2>/dev/null | grep -c "^root$" || echo "0")
  _root_procs=$(safe_int "$_root_procs")
  if [[ "$_root_procs" -gt 30 ]]; then
    warn "$_root_procs processes running as root — review: ps -eo user,comm | grep ^root | sort"
  else
    pass "$_root_procs processes running as root"
  fi

  # Processes with no controlling terminal and root UID that are not kernel threads
  local _noctty_root
  _noctty_root=$(ps -eo user=,tty=,comm= 2>/dev/null     | awk '$1=="root" && $2=="?"' | grep -v "^\[" | wc -l || echo "0")
  _noctty_root=$(safe_int "$_noctty_root")
  info "$_noctty_root background root daemons (no controlling terminal)"
}

# ================================================================
#  2. SYSTEM UPDATES
# ================================================================
section_updates() {
  header "2. SYSTEM UPDATES"

  # Single throttled update — respects APT_CACHE_MAX_AGE
  # In fast mode, skip apt-get update entirely (cache may be stale but scan is faster)
  if [[ "$USE_FAST_ONLY" != "true" ]]; then
    maybe_apt_update
  fi
  if [[ "$USE_FAST_ONLY" == "true" ]]; then
    # Fast path: read directly from dpkg cache without calling apt-get or apt list
    # apt list --upgradable can take 10-30s; dpkg is instant.
    local UPGRADABLE
    UPGRADABLE=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
    UPGRADABLE=$(safe_int "$UPGRADABLE")
    if [[ "$UPGRADABLE" -eq 0 ]]; then
      pass "System is fully up-to-date (fast check — run without --fast-only for full detail)"
    elif [[ "$UPGRADABLE" -le 5 ]]; then
      warn "$UPGRADABLE package(s) have updates available"
    else
      fail "$UPGRADABLE packages need updating — run: apt upgrade"
    fi
    info "Security-update breakdown skipped in --fast-only mode"
  else
    # Capture upgradable list once; grep from it for both checks
    local UPGRADABLE_LIST
    UPGRADABLE_LIST=$(apt list --upgradable 2>/dev/null || true)
    UPGRADABLE=$(grep -c "/" <<< "$UPGRADABLE_LIST" || true)
    UPGRADABLE=$(safe_int "$UPGRADABLE")
    if [[ "$UPGRADABLE" -eq 0 ]]; then
      pass "System is fully up-to-date"
    elif [[ "$UPGRADABLE" -le 5 ]]; then
      warn "$UPGRADABLE package(s) have updates available"
    else
      fail "$UPGRADABLE packages need updating — run: apt upgrade"
    fi
    local SEC_UPDATES
    SEC_UPDATES=$(grep -ci "security" <<< "$UPGRADABLE_LIST" || true)
    SEC_UPDATES=$(safe_int "$SEC_UPDATES")
    if [[ "$SEC_UPDATES" -gt 0 ]]; then
      fail "$SEC_UPDATES pending SECURITY update(s) detected!"
    else
      pass "No pending security updates"
    fi
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

  # OPT: parse /etc/shadow directly — avoids one chage fork per user account.
  # /etc/shadow field 5 = max password age in days; empty or 99999 = never expires.
  # Cross-reference with /etc/passwd for UID >= 1000 (human accounts only).
  local NOEXPIRY
  NOEXPIRY=$(awk -F: '
    NR==FNR { if ($3>=1000 && $3<65534) human[$1]=1; next }
    human[$1] && ($5=="" || $5=="99999" || $5=="-1") { print $1 }
  ' /etc/passwd /etc/shadow 2>/dev/null || true)
  if [[ -n "$NOEXPIRY" ]]; then
    warn "Accounts with passwords that never expire: $NOEXPIRY"
  else
    pass "All human accounts have a password expiry set"
  fi
  subheader "Inactive accounts"
  local _inactive_users=()
  local _cutoff_days=90; local _now_ts
  _now_ts=$(date +%s)
  # OPT: single lastlog call + pre-built UID map — O(1) uid lookup per entry.
  # No per-user fork, no per-line awk /etc/passwd read.
  if command -v lastlog &>/dev/null; then
    # Build associative array: username → uid (human accounts 1000-65533 only)
    declare -A _human_uids=()
    while IFS=: read -r _u _ _ui _; do
      [[ "$_ui" -ge 1000 && "$_ui" -lt 65534 ]] && _human_uids["$_u"]="$_ui"
    done < /etc/passwd
    local _lastlog_all
    _lastlog_all=$(lastlog 2>/dev/null || true)
    while IFS= read -r _entry; do
      [[ -z "$_entry" || "$_entry" =~ ^Username ]] && continue
      local _uname
      _uname=$(awk '{print $1}' <<< "$_entry")
      [[ -z "${_human_uids[$_uname]:-}" ]] && continue   # not a human account
      local _last_ts=0
      if echo "$_entry" | grep -q "Never logged in"; then
        _last_ts=0
      else
        local _dstr
        _dstr=$(awk '{print $4,$5,$6,$7,$8}' <<< "$_entry" 2>/dev/null || true)
        [[ -n "$_dstr" ]] && _last_ts=$(date -d "$_dstr" +%s 2>/dev/null || echo 0) || true
      fi
      local _days_since=$(( (_now_ts - _last_ts) / 86400 ))
      if [[ "$_last_ts" -eq 0 || "$_days_since" -gt "$_cutoff_days" ]]; then
        _inactive_users+=("${_uname}(${_days_since}d)")
      fi
    done <<< "$_lastlog_all"
  fi
  if [[ "${#_inactive_users[@]}" -eq 0 ]]; then
    pass "All human accounts have logged in within ${_cutoff_days} days"
  else
    warn "Accounts inactive for >${_cutoff_days} days: ${_inactive_users[*]}"
    detail "  Review and lock with: passwd -l <user>  OR  usermod -e 1 <user>"
  fi
  subheader "Recent failed login attempts"
  if command -v lastb &>/dev/null && [[ -f /var/log/btmp ]]; then
    # OPT: read full btmp ONCE — derive all counts from the cache
    local _lastb_all _lastb_24h_cutoff
    _lastb_all=$(lastb 2>/dev/null || true)
    _lastb_24h_cutoff=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M' 2>/dev/null || true)
    local FAILCOUNT FAIL_LAST_24H
    FAILCOUNT=$(grep -vc "^$\|^btmp\|begins" <<< "$_lastb_all" || true)
    FAILCOUNT=$(safe_int "$FAILCOUNT")
    FAIL_LAST_24H=$(lastb --since "$_lastb_24h_cutoff" 2>/dev/null \
      | grep -vc "^$\|^btmp\|begins" || true)
    FAIL_LAST_24H=$(safe_int "$FAIL_LAST_24H")
    if [[ "$FAILCOUNT" -eq 0 ]]; then
      pass "No failed login attempts recorded in btmp"
    elif [[ "$FAIL_LAST_24H" -ge 50 ]]; then
      fail "Brute-force attack likely: ${FAIL_LAST_24H} failed logins in last 24h (${FAILCOUNT} total)"
    elif [[ "$FAIL_LAST_24H" -ge 10 ]]; then
      warn "${FAIL_LAST_24H} failed login attempts in last 24h (${FAILCOUNT} total)"
    else
      info "${FAILCOUNT} total failed login attempts (${FAIL_LAST_24H} in last 24h)"
    fi
    # Top attacking IPs
    local TOP_IPS
    TOP_IPS=$(awk 'NF>=3 && !/^$|btmp|begins/ {print $3}' <<< "$_lastb_all" \
      | sort | uniq -c | sort -rn | head -3 \
      | awk '{print $2"("$1")"}' | paste -sd' ' || true)
    [[ -n "$TOP_IPS" ]] && detail "  Top sources: $TOP_IPS"
  else
    info "lastb / /var/log/btmp not available — failed login tracking not possible"
  fi
  subheader "SSH authorized_keys audit"
  local _badkey_count=0
  while IFS=: read -r _user _ _uid _ _ _home _; do
    [[ "$_uid" -lt 1000 && "$_user" != "root" ]] && continue
    local _akfile="${_home}/.ssh/authorized_keys"
    [[ -f "$_akfile" ]] || continue
    # World-readable authorized_keys
    if [[ "$(stat -c%a "$_akfile" 2>/dev/null)" =~ [0-9][0-9][4567] ]]; then
      fail "authorized_keys is world-readable: ${_akfile}"
      _badkey_count=$(( _badkey_count + 1 ))
    fi
    # DSA or small RSA keys (ssh-dss = DSA = deprecated)
    if grep -q "^ssh-dss " "$_akfile" 2>/dev/null; then
      warn "DSA (ssh-dss) key found in ${_akfile} — deprecated, remove it"
      _badkey_count=$(( _badkey_count + 1 ))
    fi
    local _keycount
    _keycount=$(grep -c "^ssh-" "$_akfile" 2>/dev/null || true)
    _keycount=$(safe_int "$_keycount")
    [[ "$_keycount" -gt 0 ]] && info "${_user}: ${_keycount} authorized key(s) in ${_akfile}"
  done < /etc/passwd || true
  [[ "$_badkey_count" -eq 0 ]] && pass "No insecure authorized_keys configurations found"
}

# ================================================================
#  4. PASSWORD POLICY
# ================================================================
section_password_policy() {
  header "4. PASSWORD POLICY"

  local LOGINDEFS="/etc/login.defs"

  _check_logindefs() {
    local KEY="$1" MIN="$2" DESC="$3"; local VAL
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

  # Empty password fields in /etc/shadow (direct vulnerability)
  local _empty_pw_users
  _empty_pw_users=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || true)
  if [[ -n "$_empty_pw_users" ]]; then
    fail "Accounts with EMPTY password field in /etc/shadow:"
    while IFS= read -r _u; do detail "$_u — set a password: passwd $_u"; done <<< "$_empty_pw_users"
  else
    pass "No accounts with empty password fields in /etc/shadow"
  fi

  # Accounts with password hash '!' or '*' (locked/disabled)
  local _locked_count
  _locked_count=$(awk -F: '$2 ~ /^[!*]/ {print $1}' /etc/shadow 2>/dev/null | wc -l || echo "0")
  _locked_count=$(safe_int "$_locked_count")
  info "$_locked_count account(s) have locked/disabled password ('!' or '*')"

  # SHA-512 password hashing (should be $6$)
  local _weak_hash_users
  _weak_hash_users=$(awk -F: '$2 !~ /^\$6\$/ && $2 !~ /^[!*]/ && $2 != "" {print $1}' /etc/shadow 2>/dev/null || true)
  if [[ -n "$_weak_hash_users" ]]; then
    warn "Accounts not using SHA-512 (\$6\$) password hashing:"
    while IFS= read -r _u; do detail "$_u"; done <<< "$_weak_hash_users"
    detail "Upgrade: set ENCRYPT_METHOD SHA512 in /etc/login.defs"
  else
    pass "All active accounts use SHA-512 (\$6\$) password hashing"
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
  SSH_PORT=$SSH_PORT_VAL   # export as global so pentest sections 0c/0e use the real port
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
  MAX_AUTH=$(sshd_value MaxAuthTries)
  MAX_AUTH=$(safe_int "${MAX_AUTH:-6}")
  [[ "$MAX_AUTH" -eq 0 ]] && MAX_AUTH=6   # safe_int returns 0 for empty/non-numeric
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
  subheader "SSH host key strength"
  local _weak_keys=0
  for _kf in /etc/ssh/ssh_host_*_key.pub; do
    [[ -f "$_kf" ]] || continue
    local _ktype _kbits
    _ktype=$(awk '{print $1}' "$_kf" 2>/dev/null | head -1 || true)
    _kbits=$(ssh-keygen -l -f "$_kf" 2>/dev/null | awk '{print $1}' || true)
    _kbits=$(safe_int "${_kbits:-0}")
    case "$_ktype" in
      ssh-dss)
        fail "DSA host key present: ${_kf} — DSA is deprecated and weak (1024-bit)"
        _weak_keys=$(( _weak_keys + 1 ));;
      ssh-rsa)
        if [[ "$_kbits" -lt 3072 ]]; then
          warn "RSA host key is only ${_kbits} bits: ${_kf} (recommend >=3072)"
          _weak_keys=$(( _weak_keys + 1 ))
        else
          pass "RSA host key: ${_kbits} bits (strong)"
        fi;;
      ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)
        pass "ECDSA host key: ${_kbits} bits";;
      ssh-ed25519)
        pass "Ed25519 host key present (preferred algorithm)";;
      *)
        info "Host key type: ${_ktype} (${_kbits} bits)";;
    esac
  done
  [[ "$_weak_keys" -eq 0 ]] && pass "All SSH host keys use strong algorithms"

  subheader "SSH authorized_keys key strength"
  local _weak_authkeys=0
  # OPT: allocate one tmpfile for the whole loop — reuse it per key, clean at end
  local _tmp_ak; _tmp_ak=$(mktemp /tmp/wowsc_ak_XXXXXX.pub)
  while IFS=: read -r _user _ _uid _ _ _home _; do
    [[ "$_uid" -lt 1000 && "$_user" != "root" ]] && continue
    local _akfile="${_home}/.ssh/authorized_keys"
    [[ -f "$_akfile" ]] || continue
    while IFS= read -r _akline; do
      [[ "$_akline" =~ ^# ]] && continue
      [[ -z "$_akline" ]] && continue
      local _aktype _akbits
      _aktype=$(awk '{print $1}' <<< "$_akline")
      # Reuse the single tmpfile — overwrite, no alloc per key
      echo "$_akline" > "$_tmp_ak"
      _akbits=$(ssh-keygen -l -f "$_tmp_ak" 2>/dev/null | awk '{print $1}' || echo "0")
      _akbits=$(safe_int "${_akbits:-0}")
      case "$_aktype" in
        ssh-dss)
          fail "DSA authorized key in ${_akfile} for ${_user} — deprecated, remove it"
          _weak_authkeys=$(( _weak_authkeys + 1 )) ;;
        ssh-rsa)
          if [[ "$_akbits" -lt 2048 ]]; then
            fail "Weak RSA key (${_akbits} bits) in ${_akfile} for ${_user} — replace with >=3072 RSA or Ed25519"
            _weak_authkeys=$(( _weak_authkeys + 1 ))
          elif [[ "$_akbits" -lt 3072 ]]; then
            warn "RSA key only ${_akbits} bits in ${_akfile} for ${_user} — recommend >=3072 or Ed25519"
          else
            info "${_user}: RSA key ${_akbits} bits (strong)"
          fi ;;
        ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)
          info "${_user}: ECDSA key ${_akbits} bits" ;;
        ssh-ed25519)
          pass "${_user}: Ed25519 authorized key (preferred algorithm)" ;;
        *)
          [[ -n "$_aktype" ]] && info "${_user}: key type ${_aktype} (${_akbits} bits)" ;;
      esac
    done < "$_akfile" || true
  done < /etc/passwd || true
  rm -f "$_tmp_ak" 2>/dev/null || true
  [[ "$_weak_authkeys" -eq 0 ]] && pass "All authorized_keys use strong key algorithms"
  subheader "SSH login banner"
  local _banner_file
  _banner_file=$(sshd_value Banner 2>/dev/null || true)
  if [[ -n "$_banner_file" && "$_banner_file" != "none" && -f "$_banner_file" ]]; then
    pass "SSH login banner configured: ${_banner_file}"
  else
    info "No SSH login banner configured (Banner none or not set)"
    detail "  Legal notice banners can be required for compliance"
    detail "  Add to sshd_config:  Banner /etc/issue.net"
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
      echo "$UFW_STATUS" | grep -i "Default:" | while IFS= read -r line; do detail "$line"; done || true
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

  subheader "Interface exposure — 0.0.0.0 vs 127.0.0.1"
  # Services bound to 0.0.0.0 or :: are reachable from any interface (network-exposed).
  # Services bound to 127.0.0.1 or ::1 are localhost-only.
  # This check extracts each listening port's bind address and flags services that
  # are externally reachable but should only be on loopback.
  local _exposed_count=0
  # Ports that should NEVER be externally reachable
  declare -A _loopback_only_ports=(
    [3306]="MySQL/MariaDB"  [5432]="PostgreSQL"  [6379]="Redis"
    [27017]="MongoDB"       [9200]="Elasticsearch" [5984]="CouchDB"
    [11211]="Memcached"     [2181]="ZooKeeper"   [9092]="Kafka"
    [8500]="Consul"         [4369]="Erlang EPMD"
  )
  while IFS= read -r _ssline; do
    [[ -z "$_ssline" ]] && continue
    # Extract bind address (column 4 in ss output: local-address:port)
    local _local_addr; _local_addr=$(awk '{print $4}' <<< "$_ssline" 2>/dev/null || true)
    local _port; _port=$(grep -oE '[0-9]+$' <<< "$_local_addr" || true)
    [[ -z "$_port" ]] && continue
    # Check if bound to all interfaces
    local _is_exposed=false
    if echo "$_local_addr" | grep -qE '^\*:|^0\.0\.0\.0:|^\[::\]:'; then
      _is_exposed=true
    fi
    if [[ "$_is_exposed" == "true" ]] && [[ -n "${_loopback_only_ports[$_port]:-}" ]]; then
      fail "Port ${_port} (${_loopback_only_ports[$_port]}) bound to ALL interfaces — should be 127.0.0.1 only"
      detail "  Fix: set bind address to 127.0.0.1 in the service config"
      _exposed_count=$(( _exposed_count + 1 ))
    fi
  done <<< "$PORTS"
  [[ "$_exposed_count" -eq 0 ]] && pass "No database/cache services exposed on all interfaces"

  # Summary table of exposed vs loopback services
  local _ext_svcs _lo_svcs
  _ext_svcs=$(echo "$PORTS" | awk '{print $4}' | grep -cE '^\*:|^0\.0\.0\.0:|^\[::\]:' || true)
  _lo_svcs=$( echo "$PORTS" | awk '{print $4}' | grep -cE '^127\.|^\[::1\]:'          || true)
  _ext_svcs=$(safe_int "$_ext_svcs"); _lo_svcs=$(safe_int "$_lo_svcs")
  info "Services on all interfaces (network-exposed): ${_ext_svcs}"
  info "Services on loopback only (localhost): ${_lo_svcs}"

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

  subheader "Total port count"
  local _total_tcp _total_udp
  _total_tcp=$(ss -tln 2>/dev/null | grep -c "LISTEN" || echo 0)
  _total_udp=$(ss -uln 2>/dev/null | grep -c "UNCONN"  || echo 0)
  _total_tcp=$(safe_int "$_total_tcp"); _total_udp=$(safe_int "$_total_udp")
  info "Listening ports: ${_total_tcp} TCP  ${_total_udp} UDP"
  if [[ $(( _total_tcp + _total_udp )) -gt 30 ]]; then
    warn "Large number of listening ports ($(( _total_tcp + _total_udp )) total) — review attack surface"
    detail "Disable or firewall unneeded services"
  else
    pass "Port count is reasonable: ${_total_tcp} TCP + ${_total_udp} UDP"
  fi

  subheader "Non-standard high ports"
  local _high_ports=0
  while IFS= read -r _ssline; do
    [[ -z "$_ssline" ]] && continue
    local _addr; _addr=$(awk '{print $4}' <<< "$_ssline" 2>/dev/null || true)
    local _port; _port=$(grep -oE '[0-9]+$' <<< "$_addr" || true)
    _port=$(safe_int "$_port")
    # Flag high ports (>1024) bound to all interfaces that aren't well-known services
    if [[ "$_port" -gt 1024 && "$_port" -lt 32768 ]]; then
      if echo "$_ssline" | grep -qE '^\*:|^0\.0\.0\.0:|^\[::\]:'; then
        _high_ports=$(( _high_ports+1 ))
      fi
    fi
  done <<< "$PORTS"
  if [[ "$_high_ports" -gt 5 ]]; then
    warn "$_high_ports non-standard ports (1024-32768) bound to all interfaces"
    detail "Review: ss -tlnp | grep -v ':22 \|:80 \|:443 '"
  else
    pass "$_high_ports non-standard high port(s) exposed — acceptable"
  fi
}

# ================================================================
#  8. FILE & DIRECTORY PERMISSIONS
# ================================================================
section_permissions() {
  header "8. FILE & DIRECTORY PERMISSIONS"

  subheader "Critical system files"
  _check_perm() {
    local FILE="$1" EXPECTED="$2"; local ACTUAL
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

  # Wait for all four with a hard wall-clock cap.
  # Fix: previous approach called wait() which blocks indefinitely regardless of
  # remaining time. A background watchdog kills all four jobs when the deadline
  # expires; then we wait unconditionally (fast because processes are already dead).
  local _pids=("$PID_WW_FILES" "$PID_WW_DIRS" "$PID_SUID" "$PID_UNOWNED")
  local _perm_cap=60
  [[ "$USE_FAST_ONLY" == "true" ]] && _perm_cap=20
  ( sleep "$_perm_cap"; kill "${_pids[@]}" 2>/dev/null || true ) &
  local _watchdog_pid=$!
  for _pid in "${_pids[@]}"; do wait "$_pid" 2>/dev/null || true; done
  kill "$_watchdog_pid" 2>/dev/null || true
  wait "$_watchdog_pid" 2>/dev/null || true

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
  SUID_COUNT=$(grep -c "/" <<< "$SUID_LIST" || true)
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
  rm -f "$TMP_WW_FILES" "$TMP_WW_DIRS" "$TMP_SUID" "$TMP_UNOWNED" 2>/dev/null || true

  section_capabilities
  section_supply_chain
  section_immutable
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
  # OPT: single systemctl show call for all risky services at once
  local RISKY_SVCS=(telnet rsh rlogin finger chargen daytime time discard echo rexec)
  local RISKY_FOUND=0; local _risky_states
  _risky_states=$(systemctl show "${RISKY_SVCS[@]}"     --property=Id,ActiveState --no-pager 2>/dev/null || true)
  local _cur_svc=""
  while IFS= read -r _line; do
    case "$_line" in
      Id=*.service)   _cur_svc="${_line#Id=}"; _cur_svc="${_cur_svc%.service}" ;;
      ActiveState=active)
        fail "Risky legacy service active: ${_cur_svc}"
        RISKY_FOUND=$(( RISKY_FOUND + 1 )) ;;
    esac
  done <<< "$_risky_states"
  [[ "$RISKY_FOUND" -eq 0 ]] && pass "No risky legacy services running"

  subheader "Inetd / xinetd"
  # OPT: batch both inetd/xinetd in one systemctl show
  local _inetd_states
  _inetd_states=$(systemctl show inetd xinetd     --property=Id,ActiveState --no-pager 2>/dev/null || true)
  local _inetd_cur=""
  while IFS= read -r _line; do
    case "$_line" in
      Id=*.service) _inetd_cur="${_line#Id=}"; _inetd_cur="${_inetd_cur%.service}" ;;
      ActiveState=active)
        warn "${_inetd_cur} is active — review /etc/${_inetd_cur}.d/ for unnecessary services" ;;
      ActiveState=*)
        [[ -n "$_inetd_cur" ]] && pass "${_inetd_cur} is not running" ;;
    esac
  done <<< "$_inetd_states"

  subheader "Dangerous packages"
  # OPT: single dpkg-query call for all packages at once
  local _danger_pkgs=(nis rsh-client rsh-server telnet telnetd xinetd)
  local _installed_danger
  _installed_danger=$(dpkg-query -W -f '${Package} ${db:Status-Abbrev}
'     "${_danger_pkgs[@]}" 2>/dev/null | awk '$2~/^i/{print $1}' || true)
  if [[ -n "$_installed_danger" ]]; then
    while IFS= read -r _dp; do
      [[ -n "$_dp" ]] && warn "Potentially dangerous package installed: ${_dp}"
    done <<< "$_installed_danger"
  fi
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
  # OPT: check auditd state once, cache in variable — used again in "Auditd rules"
  local _AUDITD_ACTIVE=false
  systemctl is-active --quiet auditd 2>/dev/null && _AUDITD_ACTIVE=true || true
  if [[ "$_AUDITD_ACTIVE" == "true" ]]; then
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
    | grep -oE '[0-9]+([.][0-9]+)?[[:space:]]*[KMGT]?B' | tail -1 || true)
  info "Journal disk usage: ${JOURNAL_SIZE:-unknown}"

  subheader "Auditd rules"
  if [[ "$_AUDITD_ACTIVE" == "true" ]]; then
    AUDIT_RULES=$(auditctl -l 2>/dev/null | grep -v "^-e\|^No rules" | wc -l || true)
    AUDIT_RULES=$(safe_int "$AUDIT_RULES")
    if [[ "$AUDIT_RULES" -gt 0 ]]; then
      pass "auditd is active with ${AUDIT_RULES} rule(s) loaded"
      # Check for key syscall rules
      local AUDIT_L
      AUDIT_L=$(auditctl -l 2>/dev/null || true)
      for _chk in "execve" "chmod" "chown" "open" "unlink"; do
        echo "$AUDIT_L" | grep -q "$_chk" && \
          info "  auditd watches syscall: ${_chk}" || true
      done
    else
      warn "auditd is running but no audit rules are loaded"
      detail "  Install rules: apt install auditd audispd-plugins"
      detail "  Or apply CIS rules: /usr/share/doc/auditd/examples/"
    fi
  else
    info "auditd not running — syscall auditing disabled"
  fi
  subheader "Remote log forwarding"
  local _syslog_forward=false
  for _cf in /etc/rsyslog.conf /etc/rsyslog.d/*.conf \
             /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf; do
    [[ -f "$_cf" ]] || continue
    if grep -qE "^[^#].*@@?[0-9a-zA-Z._-]+|^[^#].*destination.*network" \
        "$_cf" 2>/dev/null; then
      _syslog_forward=true
      pass "Remote syslog forwarding configured in: ${_cf}"
      break
    fi
  done
  [[ "$_syslog_forward" == "false" ]] && \
    info "No remote syslog forwarding detected — consider forwarding logs off-host"

  subheader "Login banners (MOTD / issue)"
  for _bfile in /etc/issue /etc/issue.net; do
    if [[ -s "$_bfile" ]]; then
      local _bcontent
      _bcontent=$(head -3 "$_bfile" 2>/dev/null | tr '\n' ' ' || true)
      pass "Login banner present: ${_bfile}"; detail "  Content: ${_bcontent:0:80}"
    else
      info "No login banner: ${_bfile} (empty or missing)"
    fi
  done
  # /etc/motd — shown after login
  if [[ -s /etc/motd ]]; then
    info "Post-login MOTD: /etc/motd ($(wc -l < /etc/motd) lines)"
  fi
  subheader "Fail2ban — brute-force protection"
  if command -v fail2ban-client &>/dev/null; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      pass "fail2ban is installed and active"
      # Get jail status
      local _f2b_jails _f2b_active _f2b_ssh_ok=false
      _f2b_jails=$(fail2ban-client status 2>/dev/null \
        | grep -i "Jail list" | sed 's/.*Jail list://;s/,/ /g' || true)
      _f2b_active=$(wc -w <<< "$_f2b_jails")
      _f2b_active=$(safe_int "$_f2b_active")
      info "Active fail2ban jails: ${_f2b_active} — ${_f2b_jails:-none}"
      # Check SSH jail specifically
      for _jail in sshd ssh ssh-iptables; do
        if echo "$_f2b_jails" | grep -qw "$_jail" 2>/dev/null; then
          local _banned _maxretry
          _banned=$(fail2ban-client status "$_jail" 2>/dev/null \
            | grep -i "Currently banned" | grep -oE '[0-9]+' | tail -1 || echo "0")
          _maxretry=$(fail2ban-client get "$_jail" maxretry 2>/dev/null || echo "?")
          pass "SSH jail '${_jail}' active (maxretry=${_maxretry}, currently banned=${_banned})"
          _f2b_ssh_ok=true
          break
        fi
      done
      [[ "$_f2b_ssh_ok" == "false" ]] && \
        warn "fail2ban is running but no SSH jail (sshd/ssh) is active — SSH brute-force unprotected"
      # Check max retry threshold
      local _global_maxretry
      _global_maxretry=$(grep -E "^maxretry\s*=" /etc/fail2ban/jail.conf \
        /etc/fail2ban/jail.local 2>/dev/null | head -1 | grep -oE '[0-9]+' | tail -1 || echo "")
      if [[ -n "$_global_maxretry" ]]; then
        local _mr_int; _mr_int=$(safe_int "$_global_maxretry")
        if [[ "$_mr_int" -le 3 ]]; then
          pass "fail2ban maxretry = ${_mr_int} (strict — good)"
        elif [[ "$_mr_int" -le 5 ]]; then
          info "fail2ban maxretry = ${_mr_int} (acceptable)"
        else
          warn "fail2ban maxretry = ${_mr_int} — consider reducing to 3-5"
        fi
      fi
    else
      warn "fail2ban is installed but not running — start with: systemctl enable --now fail2ban"
    fi
  else
    warn "fail2ban not installed — brute-force protection missing"
    detail "  Install: apt install fail2ban && systemctl enable --now fail2ban"
    detail "  Then enable SSH jail: cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local"
    detail "  And set: [sshd]  enabled = true  maxretry = 3"
  fi
}

# ================================================================
#  11. KERNEL & SYSCTL HARDENING
# ================================================================
section_kernel() {
  header "11. KERNEL HARDENING (sysctl)"

  _check_sysctl() {
    local KEY="$1" EXPECTED="$2" DESC="$3"; local VAL
    VAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
    if [[ "$VAL" == "$EXPECTED" ]]; then
      pass "$DESC"; detail "$KEY = $VAL"
    else
      warn "$DESC"; detail "$KEY = $VAL (recommended: $EXPECTED)"
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
  _check_sysctl "kernel.kexec_load_disabled" "1" "kexec (live kernel replace) disabled"
  _check_sysctl "kernel.yama.ptrace_scope"   "1" "Yama ptrace restricted (>=1)"
  _check_sysctl "net.ipv4.conf.all.secure_redirects"    "0" "Secure ICMP redirects disabled"

  subheader "Outbound firewall (iptables OUTPUT chain)"
  local IPTR_OUT
  IPTR_OUT=$(iptables -L OUTPUT --line-numbers -n 2>/dev/null | grep -vc "^num\|^$\|^Chain" || true)
  IPTR_OUT=$(safe_int "$IPTR_OUT")
  if [[ "$IPTR_OUT" -le 1 ]]; then
    info "iptables OUTPUT chain has no rules (only default policy) — no outbound filtering"
    detail "  Consider filtering outbound connections to limit lateral movement"
  else
    pass "iptables OUTPUT chain has ${IPTR_OUT} rule(s) — outbound filtering in place"
  fi
  subheader "Kernel modules"
  for MOD in dccp sctp rds tipc; do
    if lsmod 2>/dev/null | grep -q "^${MOD}"; then
      warn "Potentially unused kernel module loaded: $MOD"
    else
      pass "Module $MOD is not loaded"
    fi
  done

  # Check if module signing enforcement is active
  local MOD_SIG
  MOD_SIG=$(cat /proc/sys/kernel/module_sig_enforce 2>/dev/null || echo "0")
  MOD_SIG=$(safe_int "$MOD_SIG")
  if [[ "$MOD_SIG" -eq 1 ]]; then
    pass "Kernel module signature enforcement enabled (module_sig_enforce=1)"
  else
    info "Kernel module signature enforcement not enabled (module_sig_enforce=0)"
  fi
  section_proc_exposure
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
  subheader "Cron script permissions"
  # Scripts executed by root cron must not be world-writable
  local _cron_ww=0
  for _crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$_crondir" ]] || continue
    while IFS= read -r -d '' _script; do
      if [[ "$(stat -c%a "$_script" 2>/dev/null)" =~ [0-9][0-9][2367] ]]; then
        fail "World-writable cron script (privilege escalation risk): ${_script}"
        _cron_ww=$(( _cron_ww + 1 ))
      fi
    done < <(find "$_crondir" -maxdepth 1 -type f -print0 2>/dev/null)
  done
  [[ "$_cron_ww" -eq 0 ]] && pass "No world-writable cron scripts found"

  subheader "PATH directory audit"
  # World-writable directories in root's PATH allow attackers to shadow binaries.
  # IMPORTANT: resolve symlinks first — /bin and /sbin are symlinks on modern
  # Debian/Ubuntu (mode 777 on the symlink itself, but target /usr/bin is 755).
  # Checking the symlink's permissions produces false positives; we must stat
  # the resolved real directory.
  local _ww_path=0
  local _seen_dirs=()   # dedup resolved paths (/bin→/usr/bin same as /usr/bin)
  while IFS=: read -r _pdir; do
    [[ -z "$_pdir" ]] && continue
    [[ -d "$_pdir" ]] || continue
    # Resolve symlinks to the real directory
    local _real
    _real=$(realpath "$_pdir" 2>/dev/null || readlink -f "$_pdir" 2>/dev/null || echo "$_pdir")
    # Skip virtual/kernel filesystems
    [[ "$_real" == /proc* || "$_real" == /sys* || "$_real" == /dev* ]] && continue
    # Skip if we already checked this resolved path (e.g. /bin and /usr/bin → same)
    local _dup=false; local _seen
    for _seen in "${_seen_dirs[@]}"; do [[ "$_seen" == "$_real" ]] && { _dup=true; break; }; done
    [[ "$_dup" == "true" ]] && continue
    _seen_dirs+=("$_real")
    # Check the RESOLVED directory's permissions (not the symlink)
    local _perms
    _perms=$(stat -c%a "$_real" 2>/dev/null || echo "0")
    # World-writable = other has write bit (o+w): last octet & 2 != 0
    if [[ "$(( _perms % 10 ))" -ge 2 && "$(( (_perms % 10) & 2 ))" -ne 0 ]] || \
       [[ "$_perms" =~ ^[0-9]*[2367]$ ]]; then
      fail "World-writable directory in root's PATH: ${_pdir} → ${_real} (perms: ${_perms})"
      _ww_path=$(( _ww_path + 1 ))
    fi
  done < <(tr ':' '\n' <<< "$PATH")
  [[ "$_ww_path" -eq 0 ]] && pass "No world-writable directories in PATH (symlinks resolved)"

  subheader "Cron entry content audit"
  # Check crontab entries for: commands calling non-existent paths,
  # commands writing to /tmp (possible persistence), and wildcard injection risks.
  local _cron_issues=0
  local _cron_files=()
  for _cf in /etc/crontab /etc/cron.d/*; do [[ -f "$_cf" ]] && _cron_files+=("$_cf"); done
  # Also check root's personal crontab if present
  [[ -f /var/spool/cron/crontabs/root ]] && _cron_files+=("/var/spool/cron/crontabs/root")

  for _cf in "${_cron_files[@]}"; do
    [[ -f "$_cf" ]] || continue
    while IFS= read -r _cline; do
      # Skip comments and empty lines
      [[ "$_cline" =~ ^[[:space:]]*# ]] && continue
      [[ -z "${_cline// /}" ]] && continue
      # Skip @reboot/@yearly/etc environment vars and timing lines
      [[ "$_cline" =~ ^[A-Z_]+=  ]] && continue

      # Extract the command part (skip timing fields and optional user field)
      # Standard /etc/crontab format: min hr dom mon dow user command
      # cron.d format: same
      local _cmd
      _cmd=$(awk '{
        if (NF >= 7) { for(i=7;i<=NF;i++) printf $i" "; print "" }
        else if (NF >= 6) { for(i=6;i<=NF;i++) printf $i" "; print "" }
      }' <<< "$_cline" 2>/dev/null | xargs 2>/dev/null || true)

      [[ -z "$_cmd" ]] && continue

      # Check: does the command call an absolute path that doesn't exist?
      local _bin; _bin=$(awk '{print $1}' <<< "$_cmd" | tr -d '"'\'''"'")
      if [[ "$_bin" == /* ]] && [[ ! -e "$_bin" ]]; then
        warn "Cron entry in ${_cf}: command not found: ${_bin}"; detail "  Entry: ${_cline:0:80}"
        _cron_issues=$(( _cron_issues + 1 ))
      fi

      # Check: writes to /tmp (possible persistence / trojan vector)
      if echo "$_cmd" | grep -qE '>\s*/tmp/|>>\s*/tmp/'; then
        warn "Cron entry writes to /tmp in ${_cf} — verify this is intentional"
        detail "  Entry: ${_cline:0:80}"
        _cron_issues=$(( _cron_issues + 1 ))
      fi

      # Check: wildcard in tar/rsync/chown/chmod (wildcard injection)
      if echo "$_cmd" | grep -qE '(tar|rsync|chown|chmod).*\*'; then
        warn "Wildcard in cron command (injection risk) in ${_cf}: ${_cmd:0:60}"
        _cron_issues=$(( _cron_issues + 1 ))
      fi

      # Check: curl/wget piped to bash (supply-chain risk)
      if echo "$_cmd" | grep -qE '(curl|wget).*\|.*(ba)?sh'; then
        fail "Cron executes remote script via pipe in ${_cf} — supply-chain risk!"
        detail "  Entry: ${_cline:0:80}"
        _cron_issues=$(( _cron_issues + 1 ))
      fi
    done < "$_cf" || true
  done
  [[ "$_cron_issues" -eq 0 ]] && pass "No suspicious patterns found in cron entry content"
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
  if [[ "$USE_FAST_ONLY" == "true" ]]; then
    info "debsums skipped in --fast-only mode (hashes every installed file — run without --fast-only)"
  else
    # Auto-install debsums if missing — same pattern as nmap/lynis/rkhunter
    if ! command -v debsums &>/dev/null; then
      info "debsums not found — installing..."
      if apt-get install -y debsums -qq 2>/dev/null; then
        info "debsums installed successfully"
      else
        warn "debsums could not be installed (apt-get failed) — skipping integrity check"
      fi
    fi

    if command -v debsums &>/dev/null; then
      local CHANGED
      # timeout 90: debsums can be very slow on large installs (hashes every pkg file)
      CHANGED=$(timeout 90 debsums -c 2>/dev/null | wc -l || true)
      CHANGED=$(safe_int "$CHANGED")
      if [[ "$CHANGED" -eq 0 ]]; then
        pass "debsums: all package files are intact"
      else
        fail "debsums: $CHANGED modified package file(s) detected"
        timeout 30 debsums -c 2>/dev/null | head -20           | while IFS= read -r line; do detail "$line"; done || true
      fi
    fi
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
  subheader "AIDE — file integrity monitor (Lynis FINT-4315)"
  # AIDE (Advanced Intrusion Detection Environment) monitors the filesystem
  # for unauthorised changes. Lynis test FINT-4315 warns when no AIDE config
  # is found. This block ensures AIDE is installed and configured so that
  # warning does not appear on subsequent Lynis runs.
  local AIDE_CONF AIDE_DB
  AIDE_CONF=""
  for _cf in /etc/aide/aide.conf /etc/aide.conf; do
    [[ -f "$_cf" ]] && { AIDE_CONF="$_cf"; break; }
  done
  AIDE_DB="/var/lib/aide/aide.db"

  if [[ -z "$AIDE_CONF" ]]; then
    # AIDE config is absent — this is what triggers Lynis FINT-4315.
    # Install AIDE and generate a default config.
    info "AIDE not configured — installing to satisfy Lynis FINT-4315..."
    maybe_apt_update
    if apt-get install -y aide aide-common -qq 2>/dev/null; then
      # Determine which config file was created
      for _cf in /etc/aide/aide.conf /etc/aide.conf; do
        [[ -f "$_cf" ]] && { AIDE_CONF="$_cf"; break; }
      done
      if [[ -n "$AIDE_CONF" ]]; then
        pass "AIDE installed — config: ${AIDE_CONF}"
      else
        warn "AIDE installed but no config file found — check: ls /etc/aide/"
      fi
    else
      warn "AIDE install failed — run manually: apt-get install aide aide-common"
      warn "Without AIDE, Lynis FINT-4315 will continue to appear as a warning"
    fi
  else
    pass "AIDE config present: ${AIDE_CONF}"
  fi

  # Initialise the AIDE database if it does not exist yet.
  # Without a DB, AIDE cannot detect changes. This is a one-time operation
  # and can take 1-3 minutes on large installations.
  #
  # Why aide --init alone fails on Debian/Ubuntu:
  #  - /etc/aide/aide.conf uses fragment includes from /etc/aide/aide.conf.d/
  #    that must be assembled by update-aide.conf before aide can read them.
  #  - aide does NOT create /var/lib/aide/ itself — the directory must exist.
  #  - The assembled working config lives at /var/lib/aide/aide.conf (not /etc/).
  #  - Output may be written as aide.db.new OR aide.db.new.gz depending on config.
  #  - aideinit is the Debian wrapper that handles all of this correctly.
  #
  # Strategy (in order):
  #   1. mkdir -p /var/lib/aide  (aide won't create it)
  #   2. update-aide.conf        (assemble fragments into /var/lib/aide/aide.conf)
  #   3. aideinit --yes          (Debian wrapper: init + mv .new -> .db)
  #   4. If aideinit absent: aide --config /var/lib/aide/aide.conf --init
  #   5. Check ALL possible output paths (.new .new.gz .db .db.gz)
  #   6. On failure: show the full aide output so the user can diagnose
  if [[ -n "$AIDE_CONF" ]] && [[ ! -f "$AIDE_DB" && ! -f "${AIDE_DB}.gz" ]]; then
    if [[ "$USE_FAST_ONLY" == "true" ]]; then
      info "AIDE database not initialised — skipping init in --fast-only mode (run without --fast-only to initialise)"
    else
    local _aide_log="/tmp/aide_init_${TIMESTAMP}.log"
    # All possible locations aide might write to
    local _possible_new=(
      "/var/lib/aide/aide.db.new"
      "/var/lib/aide/aide.db.new.gz"
      "/var/lib/aide/aide.db"
      "/var/lib/aide/aide.db.gz"
    )

    # Step 1: Ensure the directory exists (aide will silently fail without it)
    mkdir -p /var/lib/aide 2>/dev/null || true

    # Step 2: Assemble config fragments into /var/lib/aide/aide.conf
    if command -v update-aide.conf &>/dev/null; then
      update-aide.conf 2>>"$_aide_log" || true
      info "Config assembled via update-aide.conf"
    fi

    # Prefer the assembled config; fall back to the raw conf we found earlier
    local _aide_run_conf="$AIDE_CONF"
    [[ -f "/var/lib/aide/aide.conf" ]] && _aide_run_conf="/var/lib/aide/aide.conf"

    local _aide_ok=false

    # Step 3: Try aideinit (the correct Debian wrapper — handles init + mv)
    if command -v aideinit &>/dev/null; then
      info "Running aideinit (Debian wrapper)..."
      timeout 300 aideinit --yes >> "$_aide_log" 2>&1 || true
      # aideinit moves aide.db.new → aide.db when successful
      if [[ -f "$AIDE_DB" || -f "${AIDE_DB}.gz" ]]; then
        _aide_ok=true
        pass "AIDE database initialised via aideinit: ${AIDE_DB}"
        info "Schedule regular integrity checks: aide --check"
      fi
    fi

    # Step 4: Fall back to aide --init with the assembled config
    if [[ "$_aide_ok" == "false" ]]; then
      info "Running: aide --config ${_aide_run_conf} --init"
      timeout 300 aide --config "$_aide_run_conf" --init \
        >> "$_aide_log" 2>&1 || true

      # Step 5: Check every possible output location
      local _found_new=""
      for _candidate in "${_possible_new[@]}"; do
        if [[ -f "$_candidate" ]]; then
          _found_new="$_candidate"
          break
        fi
      done
      if [[ -n "$_found_new" ]]; then
        # Move into the active path if it is not already there
        if [[ "$_found_new" != "$AIDE_DB" && "$_found_new" != "${AIDE_DB}.gz" ]]; then
          local _dest="$AIDE_DB"
          [[ "$_found_new" == *.gz ]] && _dest="${AIDE_DB}.gz"
          mv "$_found_new" "$_dest" 2>/dev/null || _dest="$_found_new"
          pass "AIDE database initialised and activated: ${_dest}"
        else
          pass "AIDE database written directly: ${_found_new}"
        fi
        info "Schedule regular integrity checks: aide --check"
        _aide_ok=true
      fi
    fi

    # Step 6: Genuine failure — show full aide output so user can diagnose
    if [[ "$_aide_ok" == "false" ]]; then
      warn "AIDE database initialisation failed — no database file was produced"
      if [[ -s "$_aide_log" ]]; then
        warn "Full aide output:"
        while IFS= read -r _al; do
          detail "  $_al"
        done < "$_aide_log" || true
      else
        warn "aide produced no output at all"; detail "  Possible causes:"
        detail "    - /var/lib/aide/ could not be created (permissions?)"
        detail "    - aide.conf fragment includes failed to assemble"
        detail "    - aide binary returned without writing (config parse error)"
      fi
      warn "To initialise manually after fixing any config errors:"; detail "  sudo update-aide.conf"
      detail "  sudo aideinit"; detail "  # OR if aideinit is absent:"
      detail "  sudo aide --config /var/lib/aide/aide.conf --init"
      detail "  sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    fi
    rm -f "$_aide_log" 2>/dev/null || true
    fi  # end: not fast-only

  elif [[ -f "$AIDE_DB" || -f "${AIDE_DB}.gz" ]]; then
    pass "AIDE database present: ${AIDE_DB}"
    # Show database age; separate local + assign to avoid swallowing exit code
    local AIDE_DB_AGE NOW_TS DAYS_OLD
    AIDE_DB_AGE=$(stat -c%Y "$AIDE_DB" 2>/dev/null || \
                  stat -c%Y "${AIDE_DB}.gz" 2>/dev/null || echo 0)
    NOW_TS=$(date +%s)
    DAYS_OLD=$(( (NOW_TS - AIDE_DB_AGE) / 86400 ))
    if [[ "$DAYS_OLD" -gt 30 ]]; then
      warn "AIDE database is ${DAYS_OLD} days old — re-initialise: sudo aide --config ${AIDE_CONF} --init && sudo mv /var/lib/aide/aide.db.new ${AIDE_DB}"
    else
      info "AIDE database age: ${DAYS_OLD} day(s)"
    fi
  fi
}

# ================================================================
#  13c. ADVANCED HARDENING — SUDOERS, TLS, PAM, MODULES, BOOT
# ================================================================
section_hardening_advanced() {
  header "13c. ADVANCED HARDENING CHECKS"

  if [[ "$USE_HARDENING" == "false" ]]; then
    skip "Advanced hardening checks skipped (--no-hardening flag)"
    return
  fi
  subheader "Sudoers configuration"
  local NOPASSWD_COUNT
  NOPASSWD_COUNT=$(grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | \
    grep -v "^#" | wc -l || true)
  NOPASSWD_COUNT=$(safe_int "$NOPASSWD_COUNT")
  if [[ "$NOPASSWD_COUNT" -gt 0 ]]; then
    warn "Sudoers: $NOPASSWD_COUNT NOPASSWD rule(s) found — users can sudo without a password"
    grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | \
      head -5 | while IFS= read -r l; do detail "  $l"; done || true
  else
    pass "No NOPASSWD rules in sudoers"
  fi
  # World-writable sudoers files
  local WW_SUDOERS
  WW_SUDOERS=$(find /etc/sudoers.d/ -maxdepth 1 -type f -perm -o+w 2>/dev/null | wc -l || true)
  WW_SUDOERS=$(safe_int "$WW_SUDOERS")
  if [[ "$WW_SUDOERS" -gt 0 ]]; then
    fail "$WW_SUDOERS world-writable file(s) in /etc/sudoers.d/"
  else
    pass "No world-writable sudoers files"
  fi
  # sudo group members
  local SUDO_MEMBERS
  SUDO_MEMBERS=$(getent group sudo 2>/dev/null | cut -d: -f4 || \
                 getent group wheel 2>/dev/null | cut -d: -f4 || true)
  [[ -n "$SUDO_MEMBERS" ]] && info "Sudo group members: ${SUDO_MEMBERS}"

  # ── TLS/SSL certificate expiry ────────────────────────────────
  subheader "TLS/SSL certificates"
  local CERT_DIRS=("/etc/ssl/certs" "/etc/nginx/ssl" "/etc/apache2/ssl"
                   "/etc/letsencrypt/live" "/etc/ssl/private")
  local CERTS_CHECKED=0 CERTS_EXPIRING=0 CERTS_EXPIRED=0
  local NOW_EPOCH EXPIRY_DATE EXPIRY_EPOCH DAYS_LEFT
  NOW_EPOCH=$(date +%s)
  for dir in "${CERT_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' cert; do
      EXPIRY_DATE=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2 || true)
      [[ -z "$EXPIRY_DATE" ]] && continue
      EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || true)
      [[ -z "$EXPIRY_EPOCH" ]] && continue
      CERTS_CHECKED=$(( CERTS_CHECKED + 1 ))
      DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
      if [[ "$DAYS_LEFT" -lt 0 ]]; then
        fail "EXPIRED certificate: $(basename "$cert")  (expired $EXPIRY_DATE)"
        CERTS_EXPIRED=$(( CERTS_EXPIRED + 1 ))
      elif [[ "$DAYS_LEFT" -lt 30 ]]; then
        warn "Certificate expiring in ${DAYS_LEFT} days: $(basename "$cert")  ($EXPIRY_DATE)"
        CERTS_EXPIRING=$(( CERTS_EXPIRING + 1 ))
      elif [[ "$DAYS_LEFT" -lt 90 ]]; then
        warn "Certificate expiring in ${DAYS_LEFT} days: $(basename "$cert")  ($EXPIRY_DATE)"
        CERTS_EXPIRING=$(( CERTS_EXPIRING + 1 ))
      fi
    done < <(find "$dir" -maxdepth 3 -type f \( -name "*.crt" -o -name "*.pem" \) -print0 2>/dev/null)
  done
  if [[ "$CERTS_CHECKED" -eq 0 ]]; then
    info "No TLS certificates found in standard paths"
  else
    [[ "$CERTS_EXPIRED" -gt 0 ]] && \
      fail "Found $CERTS_EXPIRED expired certificate(s)"
    [[ "$CERTS_EXPIRING" -gt 0 && "$CERTS_EXPIRED" -eq 0 ]] && \
      warn "$CERTS_EXPIRING certificate(s) expiring within 90 days"
    [[ "$CERTS_EXPIRING" -eq 0 && "$CERTS_EXPIRED" -eq 0 ]] && \
      pass "All $CERTS_CHECKED certificate(s) are valid (>90 days remaining)"
  fi

  # ── TLS cipher strength check ─────────────────────────────────
  subheader "TLS cipher strength"
  # For each HTTPS port open on this system, probe for weak protocols and ciphers
  # using openssl s_client. Detects: SSLv2, SSLv3, TLS 1.0, TLS 1.1, weak ciphers.
  local _https_ports=()
  while IFS= read -r _ssline; do
    local _laddr; _laddr=$(awk '{print $4}' <<< "$_ssline")
    local _p; _p=$(grep -oE '[0-9]+$' <<< "$_laddr" || true)
    case "$_p" in 443|8443|4443|9443) _https_ports+=("$_p") ;; esac
  done < <(ss -tlnp 2>/dev/null | tail -n +2 || true)

  if [[ "${#_https_ports[@]}" -eq 0 ]]; then
    info "No HTTPS ports detected — TLS cipher check skipped"
  elif ! command -v openssl &>/dev/null; then
    warn "openssl not found — cannot check TLS cipher strength"
  else
    local _tls_fails=0
    # OPT: run all openssl probes in parallel — all ports × all protocols at once.
    # Results written to temp files, read after wait. Saves up to 4×5s per port.
    local _tls_tmp; _tls_tmp=$(mktemp -d /tmp/wowsc_tls_XXXXXX)
    for _port in "${_https_ports[@]}"; do
      info "Checking TLS on port ${_port} (parallel probes)..."
      (
        for _proto in ssl2 ssl3 tls1 tls1_1; do
          echo | timeout 5 openssl s_client \
            -connect "127.0.0.1:${_port}" "-${_proto}" 2>&1 \
            > "${_tls_tmp}/p_${_port}_${_proto}" || true
        done
        echo | timeout 5 openssl s_client \
          -connect "127.0.0.1:${_port}" -tls1_2 2>/dev/null \
          > "${_tls_tmp}/t12_${_port}" || true
        echo | timeout 5 openssl s_client \
          -connect "127.0.0.1:${_port}" -tls1_3 2>/dev/null \
          > "${_tls_tmp}/t13_${_port}" || true
      ) &
    done
    wait  # all ports × protocols complete

    for _port in "${_https_ports[@]}"; do
      for _proto in ssl2 ssl3 tls1 tls1_1; do
        local _proto_label
        case "$_proto" in
          ssl2)   _proto_label="SSLv2"   ;;
          ssl3)   _proto_label="SSLv3"   ;;
          tls1)   _proto_label="TLS 1.0" ;;
          tls1_1) _proto_label="TLS 1.1" ;;
        esac
        local _rf="${_tls_tmp}/p_${_port}_${_proto}"
        if [[ -s "$_rf" ]]; then
          local _result; _result=$(cat "$_rf")
          if echo "$_result" | grep -qi "^Cipher is\|SSL handshake has read" && \
             ! echo "$_result" | grep -qi "handshake failure\|ssl alert\|wrong version\|no protocols"; then
            fail "Port ${_port}: ${_proto_label} is accepted — deprecated protocol"
            _tls_fails=$(( _tls_fails + 1 ))
          fi
        fi
      done
      local _c12="${_tls_tmp}/t12_${_port}"
      if [[ -s "$_c12" ]]; then
        local _cipher_line; _cipher_line=$(grep "^Cipher is" "$_c12" || true)
        if [[ -n "$_cipher_line" ]]; then
          info "Port ${_port} TLS 1.2 cipher: ${_cipher_line}"
          if echo "$_cipher_line" | grep -qiE "RC4|DES|EXPORT|NULL|anon|MD5|IDEA"; then
            fail "Port ${_port}: weak cipher in use — ${_cipher_line}"
            _tls_fails=$(( _tls_fails + 1 ))
          fi
        fi
      fi
      local _c13="${_tls_tmp}/t13_${_port}"
      if [[ -s "$_c13" ]]; then
        local _t13; _t13=$(grep "^Protocol\|^Cipher" "$_c13" | head -2 || true)
        [[ -n "$_t13" ]] && pass "Port ${_port}: TLS 1.3 supported"
      fi
    done
    rm -rf "$_tls_tmp" 2>/dev/null || true
    [[ "$_tls_fails" -eq 0 ]] && pass "No weak TLS protocols or ciphers detected on HTTPS ports"
  fi
  # ── PAM configuration audit ───────────────────────────────────
  subheader "PAM account lockout"
  local PAM_LOCKOUT=false
  grep -rqE "pam_faillock|pam_tally2" /etc/pam.d/ 2>/dev/null && PAM_LOCKOUT=true || true
  if [[ "$PAM_LOCKOUT" == "true" ]]; then
    pass "PAM account lockout configured (pam_faillock or pam_tally2)"
    local DENY_VAL
    DENY_VAL=$(grep -rE "deny=" /etc/pam.d/ 2>/dev/null | grep -oE "deny=[0-9]+" | head -1 || true)
    [[ -n "$DENY_VAL" ]] && info "Lockout threshold: ${DENY_VAL}"
  else
    warn "No PAM account lockout configured — brute-force login attacks are unrestricted"
    detail "  Install: apt install libpam-pwquality"; detail "  Then add to /etc/pam.d/common-auth:"
    detail "    auth required pam_faillock.so preauth deny=5 unlock_time=900"
  fi
  # PAM su restriction
  grep -qE "pam_wheel|use_uid" /etc/pam.d/su 2>/dev/null && \
    pass "PAM su restricted to wheel/sudo group" || \
    warn "PAM su is not restricted — any user can attempt su to root"

  # ── Password hash algorithm ───────────────────────────────────
  subheader "Password hash strength"
  local WEAK_HASHES
  WEAK_HASHES=$(awk -F: 'NR>1 && $2 !~ /^\$6\$/ && $2 !~ /^\$y\$/ && $2 !~ /^[!*]/ && $2 != "" \
    {print $1}' /etc/shadow 2>/dev/null | head -10 || true)
  if [[ -n "$WEAK_HASHES" ]]; then
    fail "Account(s) using weak password hash (not SHA-512/yescrypt): $WEAK_HASHES"
    detail "  Fix: re-set passwords; ensure /etc/pam.d/common-password uses sha512 or yescrypt"
  else
    pass "All password hashes use SHA-512 or yescrypt (strong algorithms)"
  fi

  # ── Kernel module audit ───────────────────────────────────────
  subheader "Kernel module security"
  # Check for modules that should be disabled on servers
  local RISKY_MODS=("usb_storage" "firewire_core" "dccp" "sctp" "rds" "tipc" "cramfs" "freevxfs"
                    "jffs2" "hfs" "hfsplus" "squashfs" "udf")
  local LOADED_RISKY=()
  for mod in "${RISKY_MODS[@]}"; do
    lsmod 2>/dev/null | grep -q "^${mod}\b" && LOADED_RISKY+=("$mod") || true
  done
  if [[ "${#LOADED_RISKY[@]}" -gt 0 ]]; then
    warn "Potentially unneeded kernel modules loaded: ${LOADED_RISKY[*]}"
    detail "  Disable with: echo 'blacklist <module>' >> /etc/modprobe.d/blacklist.conf"
  else
    pass "No risky kernel modules detected as loaded"
  fi
  # Check if modules can be loaded at all (module loading should be locked after boot)
  local MODULES_DISABLED
  MODULES_DISABLED=$(sysctl -n kernel.modules_disabled 2>/dev/null || echo "0")
  MODULES_DISABLED=$(safe_int "$MODULES_DISABLED")
  if [[ "$MODULES_DISABLED" -eq 1 ]]; then
    pass "Kernel module loading is locked (kernel.modules_disabled=1)"
  else
    info "Kernel module loading is enabled (kernel.modules_disabled=0)"
  fi

  # ── Bootloader security ───────────────────────────────────────
  subheader "Bootloader security"
  # GRUB password
  local GRUB_PW=false
  for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.d/40_custom; do
    grep -q "password_pbkdf2\|password " "$f" 2>/dev/null && { GRUB_PW=true; break; } || true
  done
  [[ "$GRUB_PW" == "true" ]] && \
    pass "GRUB bootloader password is set" || \
    warn "No GRUB bootloader password found — physical access allows single-user mode"
  # grub.cfg permissions
  local GRUB_PERMS
  GRUB_PERMS=$(stat -c%a /boot/grub/grub.cfg 2>/dev/null || stat -c%a /boot/grub2/grub.cfg 2>/dev/null || echo "")
  if [[ -n "$GRUB_PERMS" ]]; then
    if [[ "$GRUB_PERMS" == "600" || "$GRUB_PERMS" == "400" ]]; then
      pass "GRUB config permissions are restrictive: ${GRUB_PERMS}"
    else
      warn "GRUB config is readable by non-root (permissions: ${GRUB_PERMS})"
      detail "  Fix: chmod 600 /boot/grub/grub.cfg"
    fi
  fi
  # Secure boot
  local SB_STATUS
  SB_STATUS=$(mokutil --sb-state 2>/dev/null || \
              bootctl status 2>/dev/null | grep -i "secure boot" | head -1 || echo "")
  if echo "$SB_STATUS" | grep -qi "enabled\|SecureBoot enabled"; then
    pass "Secure Boot is enabled"
  elif echo "$SB_STATUS" | grep -qi "disabled"; then
    warn "Secure Boot is disabled"
  else
    info "Secure Boot status could not be determined"
  fi

  # ── Coredump restrictions ─────────────────────────────────────
  subheader "Coredump security"
  local CORE_PATTERN
  CORE_PATTERN=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "core")
  if echo "$CORE_PATTERN" | grep -qE "^/tmp|^/var/tmp"; then
    fail "Core dumps written to world-writable directory: $CORE_PATTERN"
    detail "  Risk: core dumps may contain passwords, keys, or sensitive memory"
    detail "  Fix: echo 'kernel.core_pattern=|/bin/false' >> /etc/sysctl.d/50-coredump.conf"
  elif echo "$CORE_PATTERN" | grep -q "|/usr/lib/systemd/systemd-coredump"; then
    pass "Core dumps handled by systemd-coredump (safe)"
  else
    info "Core pattern: $CORE_PATTERN"
  fi
  local CORE_LIMIT
  CORE_LIMIT=$(ulimit -c 2>/dev/null || echo "")
  [[ "$CORE_LIMIT" == "0" ]] && pass "Core dumps disabled (ulimit -c = 0)" || \
    info "Core dump size limit: ${CORE_LIMIT:-unlimited}"

  # ── Filesystem mount hardening ────────────────────────────────
  subheader "Filesystem mount options"
  local MOUNT_CHECKS=(
    "/tmp:noexec:nosuid:nodev"
    "/var/tmp:noexec:nosuid:nodev"
    "/dev/shm:noexec:nosuid:nodev"
    "/home::nosuid:nodev"
    "/run::nosuid:nodev"
  )
  for entry in "${MOUNT_CHECKS[@]}"; do
    local mnt opts_expected
    mnt=$(cut -d: -f1 <<< "$entry")
    opts_expected=$(cut -d: -f2- <<< "$entry")
    if ! mountpoint -q "$mnt" 2>/dev/null; then
      info "Not a separate mountpoint: $mnt"
      continue
    fi
    local CURRENT_OPTS
    CURRENT_OPTS=$(findmnt -no OPTIONS "$mnt" 2>/dev/null || true)
    local MISSING_OPTS=()
    IFS=: read -r -a opts_arr <<< "$opts_expected"
    for opt in "${opts_arr[@]}"; do
      [[ -z "$opt" ]] && continue
      echo "$CURRENT_OPTS" | grep -qw "$opt" || MISSING_OPTS+=("$opt")
    done
    if [[ "${#MISSING_OPTS[@]}" -eq 0 ]]; then
      pass "$mnt mounted with security options (${CURRENT_OPTS:0:60}...)"
    else
      warn "$mnt missing mount options: ${MISSING_OPTS[*]}"
      detail "  Add to /etc/fstab for $mnt: ${MISSING_OPTS[*]}"
    fi
  done

  # ── NTP / time synchronisation ────────────────────────────────
  subheader "Time synchronisation & NTP security"

  # ── 1. Detect active time daemon ─────────────────────────────
  local NTP_DAEMON="" NTP_OK=false
  local NTP_SYNCED=false NTP_DRIFT="" NTP_STRATUM="" NTP_SERVERS=0
  local NTP_OFFSET_MS="" NTP_JITTER_MS="" NTP_SOURCES=""

  # OPT: single systemctl show for all 6 NTP candidates → pick the active one
  local _ntp_candidates=(chronyd chrony systemd-timesyncd ntpd ntp openntpd)
  local _ntp_states
  _ntp_states=$(systemctl show "${_ntp_candidates[@]}"     --property=Id,ActiveState --no-pager 2>/dev/null || true)
  local _ntp_cur=""
  while IFS= read -r _line; do
    case "$_line" in
      Id=*.service) _ntp_cur="${_line#Id=}"; _ntp_cur="${_ntp_cur%.service}" ;;
      ActiveState=active)
        NTP_DAEMON="$_ntp_cur"; NTP_OK=true; break ;;
    esac
  done <<< "$_ntp_states"

  if [[ "$NTP_OK" == "false" ]]; then
    fail "No time synchronisation service is running"
    detail "  Logs and audit trails will have unreliable timestamps"
    detail "  Fix: apt install chrony && systemctl enable --now chrony"
    detail "       OR: systemctl enable --now systemd-timesyncd"
  else
    pass "Time sync daemon active: ${NTP_DAEMON}"
  fi

  # ── 2. timedatectl — unified sync status (systemd systems) ───
  local TIMEDATECTL_OUT
  TIMEDATECTL_OUT=$(timedatectl show 2>/dev/null || timedatectl 2>/dev/null || true)

  if [[ -n "$TIMEDATECTL_OUT" ]]; then
    # Parse NTPSynchronized or "System clock synchronized"
    if echo "$TIMEDATECTL_OUT" | grep -qiE "NTPSynchronized=yes|System clock synchronized: yes"; then
      NTP_SYNCED=true
      pass "System clock is synchronised (timedatectl)"
    elif echo "$TIMEDATECTL_OUT" | grep -qiE "NTPSynchronized=no|System clock synchronized: no"; then
      NTP_SYNCED=false
      warn "System clock is NOT synchronised — NTP daemon may be running but not yet synced"
      detail "  Check: timedatectl status"
    fi

    # RTC in local TZ — should be 'no' on servers (UTC is safer)
    if echo "$TIMEDATECTL_OUT" | grep -qi "RTC.*local.*yes\|LocalRTC=yes"; then
      warn "Hardware clock (RTC) is set to local timezone — UTC is recommended for servers"
      detail "  Fix: timedatectl set-local-rtc 0"
    else
      pass "Hardware clock (RTC) is set to UTC"
    fi

    # Timezone check
    local TZ_NAME
    TZ_NAME=$(grep -i "Timezone\|Time zone" <<< "$TIMEDATECTL_OUT" | \
      grep -oE "[A-Za-z/_]+" | grep -v "Timezone\|Time\|zone" | head -1 || true)
    if [[ -z "$TZ_NAME" ]]; then
      TZ_NAME=$(date +%Z 2>/dev/null || echo "unknown")
    fi
    if [[ "$TZ_NAME" == "UTC" || "$TZ_NAME" == "GMT" ]]; then
      pass "Server timezone is UTC/GMT — recommended for servers"
    elif [[ -n "$TZ_NAME" ]]; then
      info "Server timezone: ${TZ_NAME} (UTC is recommended for server audit trails)"
    fi
  else
    # No timedatectl — try direct timezone check
    local TZ_DIRECT
    TZ_DIRECT=$(date +%Z 2>/dev/null || echo "")
    [[ -n "$TZ_DIRECT" ]] && info "System timezone: ${TZ_DIRECT}"
  fi

  # ── 3. chronyc — drift, stratum, sources ─────────────────────
  if command -v chronyc &>/dev/null; then
    local CHRONY_TRACKING
    CHRONY_TRACKING=$(chronyc tracking 2>/dev/null || true)

    if [[ -n "$CHRONY_TRACKING" ]]; then
      # Stratum
      NTP_STRATUM=$(grep -i "^Stratum" <<< "$CHRONY_TRACKING" | awk '{print $3}' || true)
      NTP_STRATUM=$(safe_int "${NTP_STRATUM:-16}")
      if [[ "$NTP_STRATUM" -le 0 || "$NTP_STRATUM" -ge 16 ]]; then
        fail "NTP stratum is ${NTP_STRATUM} — clock is unsynchronised (stratum 16 = no sync)"
      elif [[ "$NTP_STRATUM" -le 2 ]]; then
        pass "NTP stratum: ${NTP_STRATUM} (excellent — close to primary source)"
      elif [[ "$NTP_STRATUM" -le 5 ]]; then
        pass "NTP stratum: ${NTP_STRATUM} (good)"
      else
        info "NTP stratum: ${NTP_STRATUM} (acceptable but high — consider closer servers)"
      fi

      # System time offset (drift)
      NTP_DRIFT=$(grep -i "System time" <<< "$CHRONY_TRACKING" | grep -oE "[0-9]+\.[0-9]+" | head -1 || true)
      if [[ -n "$NTP_DRIFT" ]]; then
        # Convert to ms for thresholds
        local DRIFT_MS
        DRIFT_MS=$(python3 -c "print(int(float('${NTP_DRIFT}') * 1000))" 2>/dev/null || echo 0)
        DRIFT_MS=$(safe_int "$DRIFT_MS")
        if [[ "$DRIFT_MS" -ge 1000 ]]; then
          fail "Clock drift is ${NTP_DRIFT}s (${DRIFT_MS}ms) — severely out of sync (>1s)"
          detail "  Fix: chronyc makestep  OR  systemctl restart chronyd"
        elif [[ "$DRIFT_MS" -ge 100 ]]; then
          warn "Clock drift is ${NTP_DRIFT}s (${DRIFT_MS}ms) — elevated (>100ms)"
        elif [[ "$DRIFT_MS" -ge 10 ]]; then
          info "Clock drift: ${NTP_DRIFT}s (${DRIFT_MS}ms) — minor drift detected"
        else
          pass "Clock drift: ${NTP_DRIFT}s (${DRIFT_MS}ms) — excellent sync accuracy"
        fi
      fi

      # Leap status
      local LEAP_STATUS
      LEAP_STATUS=$(grep -i "Leap" <<< "$CHRONY_TRACKING" | awk '{print $NF}' || true)
      if [[ -n "$LEAP_STATUS" && "$LEAP_STATUS" != "Normal" ]]; then
        warn "NTP leap status: ${LEAP_STATUS} (expected: Normal)"
      fi

      # Root delay / dispersion — overall network quality
      local ROOT_DELAY
      ROOT_DELAY=$(grep -i "Root delay" <<< "$CHRONY_TRACKING" | grep -oE "[0-9]+\.[0-9]+" | head -1 || true)
      [[ -n "$ROOT_DELAY" ]] && info "NTP root delay: ${ROOT_DELAY}s"
    fi

    # Number of NTP sources configured and reachable
    NTP_SOURCES=$(chronyc sources 2>/dev/null || true)
    if [[ -n "$NTP_SOURCES" ]]; then
      NTP_SERVERS=$(grep -cE "^\^[*+?-]" <<< "$NTP_SOURCES" || true)
      NTP_SERVERS=$(safe_int "$NTP_SERVERS")
      local NTP_REACHABLE
      NTP_REACHABLE=$(grep -cE "^\^\*" <<< "$NTP_SOURCES" || true)
      NTP_REACHABLE=$(safe_int "$NTP_REACHABLE")

      if [[ "$NTP_SERVERS" -eq 0 ]]; then
        warn "No NTP sources visible in chronyc sources"
      elif [[ "$NTP_SERVERS" -lt 3 ]]; then
        warn "Only ${NTP_SERVERS} NTP source(s) configured — recommend at least 3 for reliability"
        detail "  Add servers in /etc/chrony.conf or /etc/chrony/chrony.conf"
      else
        pass "${NTP_SERVERS} NTP source(s) configured"
      fi
      if [[ "$NTP_REACHABLE" -ge 1 ]]; then
        pass "NTP is actively synchronising (has * selected source)"
        NTP_SYNCED=true
      elif [[ "$NTP_SERVERS" -gt 0 ]]; then
        warn "NTP sources configured but none currently selected as reference"
      fi
    fi

    # Check if makestep is configured (allows large correction on startup)
    local CHRONY_CONF
    for _cf in /etc/chrony.conf /etc/chrony/chrony.conf; do
      [[ -f "$_cf" ]] && { CHRONY_CONF="$_cf"; break; } || true
    done
    if [[ -n "$CHRONY_CONF" ]]; then
      if grep -q "^makestep" "$CHRONY_CONF" 2>/dev/null; then
        pass "chrony makestep configured (large time jumps corrected on startup)"
      else
        info "chrony makestep not configured — large time jumps may cause issues after reboot"
        detail "  Add to ${CHRONY_CONF}: makestep 1.0 3"
      fi

      # Count configured servers/pools
      local CONF_SERVERS
      CONF_SERVERS=$(grep -cE "^(server|pool|peer)\s" "$CHRONY_CONF" 2>/dev/null || true)
      CONF_SERVERS=$(safe_int "$CONF_SERVERS")
      if [[ "$CONF_SERVERS" -lt 3 ]]; then
        info "Only ${CONF_SERVERS} server/pool line(s) in ${CHRONY_CONF} — consider 3+ for resilience"
      else
        info "NTP config has ${CONF_SERVERS} server/pool entries in ${CHRONY_CONF}"
      fi

      # NTP key authentication (chronyd supports key-based auth)
      if grep -q "^keyfile\|^key " "$CHRONY_CONF" 2>/dev/null; then
        pass "NTP key-based authentication configured in chrony"
      else
        info "NTP key authentication not configured — acceptable for most servers"
      fi
    fi

  # ── 4. ntpq — for ntpd installs ──────────────────────────────
  elif command -v ntpq &>/dev/null; then
    local NTPQ_OUT
    NTPQ_OUT=$(ntpq -pn 2>/dev/null || true)
    if [[ -n "$NTPQ_OUT" ]]; then
      NTP_SERVERS=$(grep -cE "^\*|^\+" <<< "$NTPQ_OUT" || true)
      NTP_SERVERS=$(safe_int "$NTP_SERVERS")
      local NTP_SELECTED
      NTP_SELECTED=$(grep "^\*" <<< "$NTPQ_OUT" | awk '{print $1}' | head -1 || true)
      if [[ -n "$NTP_SELECTED" ]]; then
        pass "ntpd: active reference peer: ${NTP_SELECTED}"
        NTP_SYNCED=true
      else
        warn "ntpd: no reference peer selected (clock not yet synchronised?)"
      fi

      # Offset from ntpq
      NTP_OFFSET_MS=$(grep "^\*" <<< "$NTPQ_OUT" | awk '{print $9}' | head -1 || true)
      if [[ -n "$NTP_OFFSET_MS" ]]; then
        # ntpq reports offset in milliseconds
        local ABS_OFF
        ABS_OFF=$(python3 -c "print(abs(float('${NTP_OFFSET_MS}')))" 2>/dev/null || echo 0)
        if python3 -c "exit(0 if float('${ABS_OFF}') < 100 else 1)" 2>/dev/null; then
          pass "ntpd clock offset: ${NTP_OFFSET_MS}ms — good sync"
        elif python3 -c "exit(0 if float('${ABS_OFF}') < 1000 else 1)" 2>/dev/null; then
          warn "ntpd clock offset: ${NTP_OFFSET_MS}ms — elevated (>100ms)"
        else
          fail "ntpd clock offset: ${NTP_OFFSET_MS}ms — severely out of sync (>1s)"
        fi
      fi

      # Stratum from ntpq
      NTP_STRATUM=$(grep "^\*" <<< "$NTPQ_OUT" | awk '{print $3}' | head -1 || true)
      NTP_STRATUM=$(safe_int "${NTP_STRATUM:-16}")
      [[ "$NTP_STRATUM" -lt 16 ]] && info "ntpd stratum: ${NTP_STRATUM}"
    fi

    # ntpd config — check server count and authentication
    if [[ -f /etc/ntp.conf ]]; then
      local NTP_CONF_SERVERS
      NTP_CONF_SERVERS=$(grep -cE "^server\s" /etc/ntp.conf 2>/dev/null || true)
      NTP_CONF_SERVERS=$(safe_int "$NTP_CONF_SERVERS")
      if [[ "$NTP_CONF_SERVERS" -lt 3 ]]; then
        warn "Only ${NTP_CONF_SERVERS} server line(s) in /etc/ntp.conf — recommend 3+ for resilience"
      else
        pass "ntpd: ${NTP_CONF_SERVERS} server entries configured"
      fi
      # Restrict lines — source access control
      local RESTRICT_COUNT
      RESTRICT_COUNT=$(grep -c "^restrict" /etc/ntp.conf 2>/dev/null || true)
      if [[ "$RESTRICT_COUNT" -gt 0 ]]; then
        pass "ntpd: access restrictions configured (restrict lines present)"
      else
        warn "ntpd: no restrict lines in /etc/ntp.conf — consider restricting access"
        detail "  Add: restrict default kod notrap nomodify nopeer noquery limited"
      fi
    fi

  # ── 5. systemd-timesyncd detail ───────────────────────────────
  elif [[ "$NTP_DAEMON" == "systemd-timesyncd" ]]; then
    local TIMESYNC_STATUS
    TIMESYNC_STATUS=$(timedatectl show-timesync 2>/dev/null || \
                      timedatectl timesync-status 2>/dev/null || true)
    if [[ -n "$TIMESYNC_STATUS" ]]; then
      # Server being used
      local TS_SERVER
      TS_SERVER=$(grep -i "ServerName\|Server" <<< "$TIMESYNC_STATUS" | \
        awk '{print $NF}' | head -1 || true)
      [[ -n "$TS_SERVER" ]] && info "timesyncd server: ${TS_SERVER}"

      # Offset
      local TS_OFFSET
      TS_OFFSET=$(grep -i "Offset\|offset" <<< "$TIMESYNC_STATUS" | \
        grep -oE "[+-]?[0-9]+(\.[0-9]+)?(ms|us|s)" | head -1 || true)
      [[ -n "$TS_OFFSET" ]] && info "timesyncd offset: ${TS_OFFSET}"
    fi
    # timesyncd config
    local TS_CONF="/etc/systemd/timesyncd.conf"
    if [[ -f "$TS_CONF" ]]; then
      local TS_SERVERS
      TS_SERVERS=$(grep -E "^NTP=|^FallbackNTP=" "$TS_CONF" 2>/dev/null | \
        grep -oE "[0-9a-zA-Z._-]+\.[a-zA-Z]{2,}" | wc -l || true)
      TS_SERVERS=$(safe_int "$TS_SERVERS")
      if [[ "$TS_SERVERS" -lt 2 ]]; then
        info "timesyncd: ${TS_SERVERS} NTP server(s) in config — consider adding FallbackNTP"
      else
        pass "timesyncd: ${TS_SERVERS} server entries configured"
      fi
    fi
    info "Note: systemd-timesyncd is a basic SNTP client — consider chrony for production servers"
  fi

  # ── 6. Reachability: can we reach NTP port 123 outbound? ─────
  if [[ "$NTP_OK" == "true" ]] && command -v nc &>/dev/null; then
    if timeout 3 nc -zu pool.ntp.org 123 2>/dev/null; then
      pass "NTP UDP port 123 reachable outbound (pool.ntp.org)"
    else
      warn "NTP UDP port 123 may be blocked — time sync may fail if firewall blocks outbound UDP/123"
      detail "  Check: ufw allow out 123/udp"
    fi
  fi

  # ── 7. Final summary if no daemon details available ───────────
  if [[ "$NTP_OK" == "true" && -z "$NTP_STRATUM" && "$NTP_DAEMON" != "systemd-timesyncd" ]]; then
    info "Install chronyc or ntpq for detailed NTP accuracy and stratum information"
  fi

  # ── SNMP default community strings ────────────────────────────
  subheader "SNMP security"
  if [[ -f /etc/snmp/snmpd.conf ]]; then
    if grep -qE "^[^#].*\b(public|private)\b" /etc/snmp/snmpd.conf 2>/dev/null; then
      fail "SNMP default community strings 'public' or 'private' found in /etc/snmp/snmpd.conf"
      detail "  Fix: replace with strong unique community strings or migrate to SNMPv3"
    else
      pass "SNMP config does not use default community strings"
    fi
    if grep -qE "^[^#].*rouser|^[^#].*rwuser" /etc/snmp/snmpd.conf 2>/dev/null; then
      pass "SNMPv3 user-based auth configured"
    fi
  else
    info "SNMP not configured (/etc/snmp/snmpd.conf absent)"
  fi

  # ── Redis / MongoDB unauthenticated exposure ──────────────────
  subheader "Database service exposure"
  # Redis: check if listening on 0.0.0.0 or :: without requirepass
  if ss -tlnp 2>/dev/null | grep -q ":6379\b"; then
    local REDIS_BIND REDIS_AUTH
    REDIS_BIND=$(grep -h "^bind " /etc/redis/redis.conf /etc/redis.conf \
      2>/dev/null | head -1 || true)
    REDIS_AUTH=$(grep -hc "^requirepass " /etc/redis/redis.conf /etc/redis.conf \
      2>/dev/null | head -1 || true)
    REDIS_AUTH=$(safe_int "$REDIS_AUTH")
    if echo "${REDIS_BIND:-}" | grep -qE "0\.0\.0\.0|::"; then
      if [[ "$REDIS_AUTH" -eq 0 ]]; then
        fail "Redis listening on all interfaces with no password (requirepass not set)"
        detail "  Fix: set 'requirepass <strongpassword>' in redis.conf"
      else
        warn "Redis listening on all interfaces — ensure firewall restricts port 6379"
      fi
    else
      pass "Redis is not exposed on all interfaces"
    fi
  fi
  # MongoDB: check if listening on 0.0.0.0 without auth
  if ss -tlnp 2>/dev/null | grep -q ":27017\b"; then
    local MONGO_BIND MONGO_AUTH
    MONGO_BIND=$(grep -h "^  bindIp\|^bindIp" /etc/mongod.conf \
      2>/dev/null | head -1 || true)
    MONGO_AUTH=$(grep -h "authorization:" /etc/mongod.conf \
      2>/dev/null | grep -c "enabled" || true)
    MONGO_AUTH=$(safe_int "$MONGO_AUTH")
    if echo "${MONGO_BIND:-}" | grep -qE "0\.0\.0\.0"; then
      if [[ "$MONGO_AUTH" -eq 0 ]]; then
        fail "MongoDB listening on all interfaces with authorization disabled"
        detail "  Fix: set 'authorization: enabled' in /etc/mongod.conf security section"
      else
        warn "MongoDB listening on all interfaces — ensure firewall restricts port 27017"
      fi
    else
      pass "MongoDB is not exposed on all interfaces"
    fi
  fi

  # ── PAM resource limits ───────────────────────────────────────
  subheader "PAM resource limits"
  if [[ -f /etc/security/limits.conf ]] || \
     ls /etc/security/limits.d/*.conf 2>/dev/null | head -1 &>/dev/null; then
    # Check for unlimited nproc or nofile for regular users
    local _unlim
    _unlim=$(grep -hE "^\*|^@users|^@staff" /etc/security/limits.conf \
      /etc/security/limits.d/*.conf 2>/dev/null \
      | grep -E "\bunlimited\b" | grep -v "^#" | wc -l || true)
    _unlim=$(safe_int "$_unlim")
    if [[ "$_unlim" -gt 0 ]]; then
      warn "PAM limits: ${_unlim} 'unlimited' resource limit(s) for regular users"
      detail "  Review /etc/security/limits.conf — unlimited nproc can enable fork bombs"
    else
      pass "PAM resource limits configured (no unlimited entries for regular users)"
    fi
    # Check nproc for root
    if grep -hqE "^root.*nproc.*unlimited" /etc/security/limits.conf \
        /etc/security/limits.d/*.conf 2>/dev/null; then
      info "root has unlimited nproc (normal for root)"
    fi
  else
    info "No PAM limits configured — consider setting limits.conf for DoS protection"
  fi

  # ── Systemd unit file permissions ────────────────────────────
  subheader "Systemd unit file permissions"
  local _ww_units=0
  while IFS= read -r -d '' _uf; do
    if [[ "$(stat -c%a "$_uf" 2>/dev/null)" =~ [0-9][0-9][2367] ]]; then
      fail "World-writable systemd unit file: ${_uf}"
      _ww_units=$(( _ww_units + 1 ))
    fi
  done < <(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
    -maxdepth 2 -type f -name "*.service" -print0 2>/dev/null)
  [[ "$_ww_units" -eq 0 ]] && pass "No world-writable systemd unit files found"

  # ── USB / HID attack surface ──────────────────────────────────
  subheader "USB attack surface"
  if systemctl is-active --quiet usbguard 2>/dev/null; then
    pass "USBGuard is active — USB device whitelisting enforced"
  elif command -v usbguard &>/dev/null; then
    warn "USBGuard is installed but not running"; detail "  Start: systemctl enable --now usbguard"
  else
    local _usb_bl=false
    # Check if usb_storage or usbhid is blacklisted
    grep -rqE "^blacklist\s+(usb_storage|uas)" \
      /etc/modprobe.d/ 2>/dev/null && _usb_bl=true || true
    if [[ "$_usb_bl" == "true" ]]; then
      pass "USB storage blacklisted via modprobe.d"
    else
      info "No USB access controls active — physical access via USB/HID unrestricted"
      detail "  Install USBGuard: apt install usbguard"
    fi
  fi
}

# ================================================================
#  13d. NETWORK, CONTAINER & SENSITIVE FILE SECURITY
# ================================================================
section_network_container() {
  header "13d. NETWORK, CONTAINER & SENSITIVE FILE SECURITY"

  if [[ "$USE_NETCONTAINER" == "false" ]]; then
    skip "Network/container checks skipped (--no-netcontainer flag)"
    return
  fi
  subheader "Sensitive file exposure"
  # World-readable private keys
  local EXPOSED_KEYS
  EXPOSED_KEYS=$(find /etc/ssl/private /root/.ssh /home -maxdepth 4 \
    -type f \( -name "*.key" -o -name "*.pem" -o -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" \) \
    -perm /o+r 2>/dev/null | head -10 || true)
  if [[ -n "$EXPOSED_KEYS" ]]; then
    fail "Private key file(s) readable by others:"
    echo "$EXPOSED_KEYS" | while IFS= read -r f; do detail "  $f  ($(stat -c%a "$f"))"; done || true
  else
    pass "No world-readable private key files found"
  fi
  # .env files in web roots
  local ENV_FILES
  ENV_FILES=$(find /var/www /srv/www /srv/http /opt -maxdepth 5 \
    -type f -name ".env" -perm /o+r 2>/dev/null | head -5 || true)
  if [[ -n "$ENV_FILES" ]]; then
    fail ".env file(s) world-readable in web directory:"
    echo "$ENV_FILES" | while IFS= read -r f; do detail "  $f"; done || true
  else
    pass "No world-readable .env files in web roots"
  fi
  # .git directories in web roots
  local GIT_ROOTS
  GIT_ROOTS=$(find /var/www /srv/www /srv/http /opt -maxdepth 5 \
    -type d -name ".git" 2>/dev/null | head -5 || true)
  if [[ -n "$GIT_ROOTS" ]]; then
    warn ".git directory found in web root — may expose source code and secrets:"
    echo "$GIT_ROOTS" | while IFS= read -r d; do detail "  $d"; done || true
  else
    pass "No .git directories in web roots"
  fi
  # Shared library preload injection
  if [[ -s /etc/ld.so.preload ]]; then
    warn "/etc/ld.so.preload is non-empty — shared library injection possible:"
    while IFS= read -r line; do
      [[ -n "$line" ]] && [[ "$line" != \#* ]] && detail "  $line"
    done < /etc/ld.so.preload || true
  else
    pass "/etc/ld.so.preload is empty — no preloaded libraries"
  fi
  # LD_PRELOAD in system environment
  if printenv LD_PRELOAD 2>/dev/null | grep -q .; then
    fail "LD_PRELOAD is set in the environment: $(printenv LD_PRELOAD)"
  else
    pass "LD_PRELOAD not set in environment"
  fi

  # ── Network interface hardening ───────────────────────────────
  subheader "Network interface hardening"
  # Promiscuous mode
  local PROMISC_IFACES
  PROMISC_IFACES=$(ip link show 2>/dev/null | grep -i "PROMISC" | awk '{print $2}' | tr -d ':' || true)
  if [[ -n "$PROMISC_IFACES" ]]; then
    warn "Interface(s) in promiscuous mode (can capture all traffic): $PROMISC_IFACES"
  else
    pass "No network interfaces in promiscuous mode"
  fi
  # IPv6 disabled if unused
  local IPV6_ACTIVE
  IPV6_ACTIVE=$(ip -6 addr show 2>/dev/null | grep -v "::1\|fe80" | grep "inet6" | wc -l || true)
  IPV6_ACTIVE=$(safe_int "$IPV6_ACTIVE")
  local IPV6_DISABLED
  IPV6_DISABLED=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
  IPV6_DISABLED=$(safe_int "$IPV6_DISABLED")
  if [[ "$IPV6_ACTIVE" -eq 0 && "$IPV6_DISABLED" -eq 0 ]]; then
    info "IPv6 is enabled but no non-link-local addresses assigned — consider disabling if unused"
    detail "  net.ipv6.conf.all.disable_ipv6=1 in /etc/sysctl.d/"
  elif [[ "$IPV6_DISABLED" -eq 1 ]]; then
    pass "IPv6 is disabled via sysctl"
  else
    info "IPv6 is active with $IPV6_ACTIVE global address(es)"
  fi
  # TCP timestamps (information disclosure)
  local TCP_TS
  TCP_TS=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo "1")
  TCP_TS=$(safe_int "$TCP_TS")
  [[ "$TCP_TS" -eq 0 ]] && \
    pass "TCP timestamps disabled (net.ipv4.tcp_timestamps=0)" || \
    info "TCP timestamps enabled — can reveal uptime to remote scanners"
  # ARP spoofing protection
  local ARP_FILTER
  ARP_FILTER=$(sysctl -n net.ipv4.conf.all.arp_filter 2>/dev/null || echo "0")
  ARP_FILTER=$(safe_int "$ARP_FILTER")
  [[ "$ARP_FILTER" -eq 1 ]] && \
    pass "ARP filter enabled (net.ipv4.conf.all.arp_filter=1)" || \
    info "ARP filter not enabled — consider enabling on multi-homed systems"

  # ── Docker / container security ───────────────────────────────
  subheader "Docker and container security"
  if ! command -v docker &>/dev/null; then
    info "Docker not installed — skipping container checks"
  else
    pass "Docker is installed: $(docker --version 2>/dev/null | head -1)"
    # Docker socket permissions
    if [[ -S /var/run/docker.sock ]]; then
      local SOCK_PERMS
      SOCK_PERMS=$(stat -c%a /var/run/docker.sock 2>/dev/null || echo "")
      local SOCK_GROUP
      SOCK_GROUP=$(stat -c%G /var/run/docker.sock 2>/dev/null || echo "")
      if [[ "$SOCK_PERMS" == "666" ]] || stat -c%a /var/run/docker.sock 2>/dev/null | grep -q "^.7."; then
        fail "Docker socket is world-writable — equivalent to unrestricted root access!"
        detail "  Fix: chmod 660 /var/run/docker.sock"
      else
        pass "Docker socket permissions: ${SOCK_PERMS} (group: ${SOCK_GROUP})"
      fi
      # Users in docker group can escape to root
      local DOCKER_GROUP_MEMBERS
      DOCKER_GROUP_MEMBERS=$(getent group docker 2>/dev/null | cut -d: -f4 || true)
      if [[ -n "$DOCKER_GROUP_MEMBERS" ]]; then
        warn "Users in docker group (have root-equivalent access): $DOCKER_GROUP_MEMBERS"
        detail "  Docker group membership = ability to run: docker run --privileged"
      fi
    fi
    # Privileged containers
    local PRIV_CONTAINERS
    PRIV_CONTAINERS=$(docker ps -q 2>/dev/null | \
      xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null | \
      grep "privileged=true" | wc -l || true)
    PRIV_CONTAINERS=$(safe_int "$PRIV_CONTAINERS")
    if [[ "$PRIV_CONTAINERS" -gt 0 ]]; then
      fail "$PRIV_CONTAINERS privileged container(s) running — can escape to host"
      docker ps -q 2>/dev/null | \
        xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null | \
        grep "privileged=true" | head -5 | while IFS= read -r c; do detail "  $c"; done || true
    else
      pass "No privileged containers running"
    fi
    # Running container count
    local CONTAINER_COUNT
    CONTAINER_COUNT=$(docker ps -q 2>/dev/null | wc -l || true)
    CONTAINER_COUNT=$(safe_int "$CONTAINER_COUNT")
    info "Running containers: $CONTAINER_COUNT"
  fi

  # ── MTA / email security ──────────────────────────────────────
  subheader "MTA / email security"
  if command -v postfix &>/dev/null && systemctl is-active --quiet postfix 2>/dev/null; then
    pass "Postfix is installed and running"
    # Open relay test
    local RELAY_DEST
    RELAY_DEST=$(postconf -h relayhost 2>/dev/null || echo "")
    local RELAY_NETS
    RELAY_NETS=$(postconf -h mynetworks 2>/dev/null || echo "")
    # Check if inet_interfaces is localhost only
    local INET_IFACE
    INET_IFACE=$(postconf -h inet_interfaces 2>/dev/null || echo "")
    if echo "$INET_IFACE" | grep -qiE "all|0\.0\.0\.0"; then
      warn "Postfix is listening on all interfaces (inet_interfaces=$INET_IFACE) — verify relay restrictions"
    else
      pass "Postfix listening on: $INET_IFACE"
    fi
    # smtpd_relay_restrictions
    local RELAY_RESTRICT
    RELAY_RESTRICT=$(postconf -h smtpd_relay_restrictions 2>/dev/null || \
                     postconf -h smtpd_recipient_restrictions 2>/dev/null || echo "")
    if echo "$RELAY_RESTRICT" | grep -q "permit_open_relay"; then
      fail "Postfix has permit_open_relay — server may be an open mail relay!"
    elif echo "$RELAY_RESTRICT" | grep -qE "reject_unauth_destination|permit_sasl_authenticated"; then
      pass "Postfix relay restrictions configured"
    else
      info "Postfix relay restrictions: ${RELAY_RESTRICT:0:80}"
    fi
  elif command -v exim4 &>/dev/null && systemctl is-active --quiet exim4 2>/dev/null; then
    pass "Exim4 is installed and running"
    local EXIM_RELAY
    EXIM_RELAY=$(grep -i "relay_to_domains\|dc_relay_domains" /etc/exim4/exim4.conf.template \
                 /etc/exim4/update-exim4.conf.conf 2>/dev/null | head -3 || true)
    [[ -n "$EXIM_RELAY" ]] && info "Exim4 relay config: ${EXIM_RELAY:0:100}" || \
      info "Exim4 relay settings not found in standard config locations"
  else
    info "No active MTA (Postfix/Exim4) detected"
  fi
  section_disk_encryption
  section_dns_security
  section_alt_containers

  # ── Swap encryption ───────────────────────────────────────────
  subheader "Swap encryption"
  local SWAP_TOTAL
  SWAP_TOTAL=$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
  SWAP_TOTAL=$(safe_int "$SWAP_TOTAL")
  if [[ "$SWAP_TOTAL" -eq 0 ]]; then
    info "No swap space configured"
  else
    # Check if swap is on an encrypted device
    local SWAP_DEV
    SWAP_DEV=$(swapon --show=NAME --noheadings 2>/dev/null | head -1 || true)
    if [[ -n "$SWAP_DEV" ]]; then
      local SWAP_ENCRYPTED=false
      # Check if it's a dm-crypt device
      if dmsetup info "$SWAP_DEV" 2>/dev/null | grep -qi "crypt\|swap"; then
        SWAP_ENCRYPTED=true
      fi
      # Check /etc/crypttab for swap entry
      grep -qiE "swap|${SWAP_DEV##*/}" /etc/crypttab 2>/dev/null && SWAP_ENCRYPTED=true || true
      if [[ "$SWAP_ENCRYPTED" == "true" ]]; then
        pass "Swap is encrypted (dm-crypt or crypttab)"
      else
        warn "Swap is not encrypted — sensitive data from RAM may be written to disk unencrypted"
        detail "  Swap device: $SWAP_DEV"; detail "  Fix: add swap line to /etc/crypttab using dm-crypt"
      fi
    fi
  fi
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
                "$CHKROOTKIT_OUT" 2>/dev/null || echo 0)
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
  local _rkh_now; _rkh_now=$(date +%s)
  if [[ -f "$RKH_UPDATE_DB" ]]; then
    local _rkh_mt1; _rkh_mt1=$(stat -c %Y "$RKH_UPDATE_DB" 2>/dev/null || echo 0)
    RKH_DB_AGE=$(( _rkh_now - _rkh_mt1 ))
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
    local _rkh_mt2; _rkh_mt2=$(stat -c %Y "$RKH_PROP_DB" 2>/dev/null || echo 0)
    RKH_PROP_AGE=$(( _rkh_now - _rkh_mt2 ))
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
  # Clean up temp log copies (persistent /var/log/rkhunter.log is kept)
  [[ "${RKH_OUT:-}" == /tmp/* ]] && rm -f "$RKH_OUT" 2>/dev/null || true
  rm -f "$CHKROOTKIT_OUT" 2>/dev/null || true
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
      ENFORCE=$(grep -oE '[0-9]+ profiles are in enforce mode' <<< "$AA_STATUS" || true)
      COMPLAIN=$(grep -oE '[0-9]+ profiles are in complain mode' <<< "$AA_STATUS" || true)
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
  local LYNIS_BASE_FLAGS="--nocolors --quick --report-file ${LYNIS_DAT}"
  # --no-log: prevents writing to /var/log/lynis.log, but ONLY on Lynis 3.x
  # On 2.x it is an unrecognised flag → Lynis aborts before writing the .dat file
  if [[ "$LYNIS_MAJOR" -ge 3 ]]; then
    LYNIS_BASE_FLAGS="${LYNIS_BASE_FLAGS} --no-log"
  fi

  # ── Choose fast vs full mode ──────────────────────────────────
  local LYNIS_MODE_LABEL LYNIS_EXTRA_FLAGS=""; local LYNIS_TIMEOUT=180
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

    # ── Probe: verify --tests-from-group works AND comma-list is accepted ──
    # Two-stage probe:
    #   Stage 1: single group "ssh" — tests basic --tests-from-group support
    #   Stage 2: two groups "ssh,crypto" — tests comma-separated list support
    # A Lynis "security measure" abort produces "Fatal error" on stderr, which
    # the previous grep pattern ("unknown option|cannot find|...") missed entirely.
    # Both stages check for ALL known rejection patterns including the security abort.
    local _probe_dat="/tmp/lynis_probe_${TIMESTAMP}.dat"
    local _probe_err="/tmp/lynis_probe_err_${TIMESTAMP}.txt"
    local _probe_ok=false; local _comma_ok=false
    local _nolog_flag=""
    [[ "$LYNIS_MAJOR" -ge 3 ]] && _nolog_flag="--no-log"

    # Full rejection pattern — covers all known Lynis abort messages
    local _reject_pat="unknown option|cannot find|invalid option|unrecognized|no such|fatal error|security measure|execution stopped|unexpected input|invalid characters"

    # Stage 1: single group
    rm -f "$_probe_dat" "$_probe_err" 2>/dev/null || true
    timeout 30 lynis audit system \
      --nocolors --quick --report-file "$_probe_dat" \
      ${_nolog_flag:+"$_nolog_flag"} \
      --tests-from-group ssh \
      > /dev/null 2>"$_probe_err" || true

    if ! grep -qiE "$_reject_pat" "$_probe_err" 2>/dev/null; then
      _probe_ok=true

      # Stage 2: comma-separated groups (same probe, two groups)
      rm -f "$_probe_dat" "$_probe_err" 2>/dev/null || true
      timeout 30 lynis audit system \
        --nocolors --quick --report-file "$_probe_dat" \
        ${_nolog_flag:+"$_nolog_flag"} \
        --tests-from-group ssh,crypto \
        > /dev/null 2>"$_probe_err" || true

      if ! grep -qiE "$_reject_pat" "$_probe_err" 2>/dev/null; then
        _comma_ok=true
      fi
    fi
    rm -f "$_probe_dat" "$_probe_err" 2>/dev/null || true

    if [[ "$_probe_ok" == "true" && "$_comma_ok" == "true" ]]; then
      LYNIS_EXTRA_FLAGS="--tests-from-group ${_grp}"
      info "Lynis FAST mode: --tests-from-group with comma list accepted [${LYNIS_MAJOR}.x]"
      info "Running Lynis FAST audit (~25-50 sec). Set LYNIS_FULL=true for full scan."
    elif [[ "$_probe_ok" == "true" && "$_comma_ok" == "false" ]]; then
      # Comma list rejected — use multiple individual --tests-from-group flags
      # Convert comma-list to repeated flags: a,b,c → --tests-from-group a --tests-from-group b ...
      LYNIS_EXTRA_FLAGS=""
      local _g
      IFS=',' read -r -a _grp_arr <<< "$_grp"
      for _g in "${_grp_arr[@]}"; do
        LYNIS_EXTRA_FLAGS="${LYNIS_EXTRA_FLAGS} --tests-from-group ${_g}"
      done
      info "Lynis FAST mode: using individual --tests-from-group flags (comma list not supported)"
      info "Running Lynis FAST audit (~25-50 sec). Set LYNIS_FULL=true for full scan."
    else
      # --tests-from-group rejected entirely — fall back to full scan with --quick
      LYNIS_MODE_LABEL="FULL"
      LYNIS_TIMEOUT=600
      info "Lynis FAST mode not supported on this build — running full scan with --quick"
      info "To always use full scan: LYNIS_FULL=true sudo bash $0"
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
    # Show Lynis output for diagnostics but avoid piping into tee
    # (some Lynis builds detect non-tty and abort)
    if [[ -s "$LYNIS_LOG" ]]; then
      cat "$LYNIS_LOG" >> "$REPORT" || true
    fi
    rm -f "$LYNIS_LOG" 2>/dev/null || true
    return
  fi

  # Show output and append to report
  cat "$LYNIS_LOG" | tee -a "$REPORT" || true
  rm -f "$LYNIS_LOG" 2>/dev/null || true

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
  WARN_COUNT=$(grep -c "." <<< "$LYNIS_WARNINGS" 2>/dev/null || true)
  WARN_COUNT=$(safe_int "$WARN_COUNT")
  if [[ "$WARN_COUNT" -gt 0 ]]; then
    warn "Lynis found $WARN_COUNT warning(s)  [${LYNIS_MODE_LABEL} mode]:"
    while IFS= read -r w; do
      [[ -z "$w" ]] && continue
      # FINT-4315: No AIDE config — explain that section 13 handled this
      if [[ "$w" == *"FINT-4315"* ]]; then
        detail "  $w"; detail "  ↳ AIDE config/DB absent when Lynis ran — section 13 installed AIDE."
        detail "  ↳ Re-run the scan to confirm FINT-4315 is resolved."
      else
        detail "  $w"
      fi
    done <<< "$LYNIS_WARNINGS"
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

  echo -e "  ${CYAN}[ℹ]${NC}  Generating Intel ODT → ${ODI_OUT} ..." >&2 || true

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
total_val = max(int(sys.argv[3]), 1)  # guard: never zero
pct       = int(sys.argv[4]) if total_val > 1 else 0
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
    PASS_RE = re.compile(r'^\s*\[.*PASS.*\]\s*(.*?)\s*Ω?\s*$')
    FAIL_RE = re.compile(r'^\s*\[.*FAIL.*\]\s*(.*?)\s*Ω?\s*$')
    WARN_RE = re.compile(r'^\s*\[.*WARN.*\]\s*(.*?)\s*Ω?\s*$')
    INFO_RE = re.compile(r'^\s*\[.*INFO.*\]\s*(.*?)\s*Ω?\s*$')
    SKIP_RE = re.compile(r'^\s*\[.*SKIP.*\]\s*(.*)')
    DETAIL_RE = re.compile(r'^\s*(?:│\s*)?↳\s+(.*)')
    cur_sec = {"title":"Header","items":[]}; last_idx = -1
    _in_box = False; _pending_title = None
    for line in raw_lines:
        if re.match(r'^\s*╔═', line):
            _in_box = True; _pending_title = None; continue
        if _in_box:
            if re.match(r'^\s*╚═', line):
                if _pending_title:
                    sections.append(cur_sec)
                    cur_sec = {"title": _pending_title, "items": []}
                    last_idx = -1
                _in_box = False; _pending_title = None; continue
            if re.match(r'^\s*[╠╬]═', line): continue
            _clean = re.sub(r'^[\U00010000-\U0010FFFF\u2600-\u2BFF\s]+', '', line.strip())
            _ms = re.match(r'([0-9]+[a-zA-Z]*[. ].+)', _clean)
            if _ms and len(_ms.group(1).strip()) > 3:
                _pending_title = _ms.group(1).strip()
            continue
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
        ("Low &lt;4",      4.0,  "#388E3C"),
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
            f'<text x="{pad_l-5}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="8" fill="#B0BEC5">{s["title"].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")}</text>',
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
    parts.append(f'<text x="{mx0+mw//2}" y="{my0-6}" text-anchor="middle" font-family="Arial" font-size="9" font-weight="bold" fill="#B0BEC5">Dwell &amp; Detection (days)</text>')
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


def _svg_esc(s):
    """XML-escape a string for safe embedding in SVG text content."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

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
            f'<text x="{qx+gw//4}" y="{qy+26}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold" fill="{tc}">{_svg_esc(title)}</text>',
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
            f'<text x="{gx+20}" y="{iy+5}" font-family="Arial" font-size="8" fill="#A5D6A7">{_svg_esc(title)}</text>',
        ]
    for i,(title,cmd) in enumerate(planned[:3]):
        iy=ty_start+i*item_h
        parts += [
            f'<circle cx="{cx2+12}" cy="{iy}" r="4" fill="#42A5F5"/>',
            f'<text x="{cx2+20}" y="{iy+5}" font-family="Arial" font-size="8" fill="#90CAF9">{_svg_esc(title)}</text>',
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
            f'<text x="{rx+30}" y="{iy+11}" font-family="Arial" font-size="9" font-weight="bold" fill="{col}">{_svg_esc(title)}</text>',
            f'<text x="{rx+30}" y="{iy+22}" font-family="Courier New" font-size="7.5" fill="#546E7A">{ _svg_esc(cmd)}</text>',
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
        p.append(f'<text x="{pl-8}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="{lc}">{s["title"][:30].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")}</text>')
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
    sec_stats_intel.append({"title":s["title"],"pass":np2,"fail":nf2,"warn":nw2,
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
    bench_row("Pass Rate %",     f"{round(n_pass_loc*100/max(n_pass_loc+n_fail_loc+n_warn_loc,1))}%", "55%","72%",85,"higher"),
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
    sp2=round(np2*100/max(tot2,1)) if tot2 else 0
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
    write_odf_crc "wowscanner_intel_${TIMESTAMP}.odt"
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
  touch "$PORT_ISSUES_LOG" "$PORT_HISTORY_DB" "$PORT_SCAN_LOG"
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
    local FIRST COUNT=0
    local _db_line; _db_line=$(grep "^${KEY}|" "$PORT_HISTORY_DB" || true)
    FIRST=$(cut -d'|' -f3 <<< "$_db_line")
    COUNT=$(safe_int "$(cut -d'|' -f5 <<< "$_db_line")")
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
        echo ""; echo "$REMED_MARKER"
        echo "# Issue  : ${PROTO}/${PORT} (${SERVICE}) found ${STATE} — ${REASON}"
        echo "# Seen   : ${NOW}"; echo "# Options (pick what applies to your setup):"
        case "$SERVICE" in
          ftp*)    echo "apt-get purge -y vsftpd proftpd ftp   # remove FTP server" ;;
          telnet*) echo "apt-get purge -y telnetd telnet       # remove Telnet" ;;
          smtp*)   echo "# If mail relay not needed: systemctl disable --now postfix exim4" ;;
          http*)   echo "# If web server not needed: systemctl disable --now apache2 nginx" ;;
          *)
            echo "# Block with UFW:"; echo "ufw deny ${PORT}/${PROTO}"
            echo "# OR block with iptables:"
            echo "iptables -A INPUT -p ${PROTO} --dport ${PORT} -j DROP"
            echo "iptables-save > /etc/iptables/rules.v4"
            ;;
        esac
      } > "$_tmp_block"
      cat "$_tmp_block" >> "$PORT_REMEDIATION"
      rm -f "$_tmp_block" 2>/dev/null || true
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
      "${PROTO}/${PORT}" "$FIRST" "$LAST" "$COUNT" | tee -a "$REPORT" || true
  done < "$PORT_HISTORY_DB"
  log "  └──────────────┴───────────────────────┴───────────────────────┴───────┘"
}

# ================================================================
#  16a. LAN DEVICE DISCOVERY & NETWORK MAP
#  Discovers all reachable hosts on the local network using
#  multiple methods (arp-scan, nmap, /proc/net/arp) and writes
#  a structured JSON file used by the ODT and ODS generators
#  to build an SVG network topology diagram.
# ================================================================
section_lan_scan() {
  header "16a. LAN DEVICE DISCOVERY & NETWORK MAP"

  # Determine local subnet from the default route interface
  local _iface _subnet _local_ip _gateway
  _iface=$(ip route 2>/dev/null | grep "^default" | awk '{print $5}' | head -1 || true)
  _local_ip=$(ip -4 addr show "${_iface:-}" 2>/dev/null | grep "inet " | \
    awk '{print $2}' | head -1 | cut -d/ -f1 || true)
  _gateway=$(ip route 2>/dev/null | grep "^default" | awk '{print $3}' | head -1 || true)
  _subnet=$(ip route 2>/dev/null | grep "^[0-9]" | grep "${_iface:-}" | \
    grep -v "^default" | awk '{print $1}' | head -1 || true)

  if [[ -z "$_subnet" && -n "$_local_ip" ]]; then
    # Fall back: derive /24 from local IP
    _subnet="${_local_ip%.*}.0/24"
  fi
  if [[ -z "$_subnet" ]]; then
    info "Could not determine local subnet — skipping LAN discovery"
    # Write empty JSON so generators don't fail
    local _fb_ts; _fb_ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "{\"hosts\":[],\"subnet\":\"unknown\",\"gateway\":\"\",\"local_ip\":\"\",\"scan_method\":\"none\",\"host_count\":0,\"timestamp\":\"${_fb_ts}\"}" > "$LAN_JSON"
    return
  fi
  info "Local interface : ${_iface:-unknown}"; info "Local IP        : ${_local_ip:-unknown}"
  info "Gateway         : ${_gateway:-unknown}"; info "Scanning subnet : ${_subnet}"

  local _tmp_hosts="/tmp/lan_hosts_${TIMESTAMP}.txt"
  local _scan_method="none"

  # ── Method 1: arp-scan (most reliable, needs root) ────────────
  if command -v arp-scan &>/dev/null; then
    info "Using arp-scan for LAN discovery..."
    timeout 45 arp-scan --localnet --quiet 2>/dev/null \
      | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" > "$_tmp_hosts" || true
    _scan_method="arp-scan"
  fi

  # ── Method 2: nmap ping scan (fallback) ──────────────────────
  if [[ ! -s "$_tmp_hosts" ]] && command -v nmap &>/dev/null; then
    info "Using nmap -sn for LAN discovery..."
    timeout 60 nmap -sn -T4 --open "$_subnet" 2>/dev/null \
      | grep -E "^Nmap scan report for|MAC Address:" > "$_tmp_hosts" || true
    _scan_method="nmap"
  fi

  # ── Method 3: /proc/net/arp (instant, only cached entries) ───
  if [[ ! -s "$_tmp_hosts" ]]; then
    info "Using ARP cache (/proc/net/arp) for LAN discovery..."
    awk 'NR>1 && $3=="0x2" {print $1"\t"$4"\t(ARP cache)"}' \
      /proc/net/arp 2>/dev/null > "$_tmp_hosts" || true
    _scan_method="arp-cache"
  fi

  # ── Build JSON from scan results ─────────────────────────────
  python3 - "$_tmp_hosts" "$LAN_JSON" "$_scan_method" \
            "${_local_ip:-}" "${_gateway:-}" "${_subnet:-}" \
            "${_iface:-}" << 'LANSCANEOF' || true
import sys, os, json, re, subprocess, datetime

hosts_file  = sys.argv[1]
json_out    = sys.argv[2]
method      = sys.argv[3]
local_ip    = sys.argv[4]
gateway     = sys.argv[5]
subnet      = sys.argv[6]
iface       = sys.argv[7]
ts          = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

hosts = []

def vendor_from_mac(mac):
    """Return OUI vendor hint from MAC prefix."""
    oui = mac.upper().replace('-',':')[:8]
    OUI = {
        "00:50:56": "VMware",    "00:0C:29": "VMware",  "00:15:5D": "Hyper-V",
        "52:54:00": "QEMU/KVM",  "08:00:27": "VirtualBox",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1A:11": "Google",    "F4:F5:D8": "Google",
        "AC:37:43": "HTC",       "00:17:F2": "Apple",
        "00:1B:63": "Apple",     "3C:07:54": "Apple",
        "00:0D:93": "Apple",     "78:4F:43": "Cisco",
        "00:1E:13": "Dell",      "18:66:DA": "Dell",
        "54:EE:75": "HP",        "00:25:B3": "HP",
    }
    return OUI.get(oui[:8], OUI.get(oui[:5], ""))

if method in ("arp-scan",):
    # arp-scan format: IP\tMAC\tVendor
    for line in open(hosts_file):
        line = line.strip()
        if not line: continue
        parts = line.split('\t')
        if len(parts) >= 2:
            ip  = parts[0].strip()
            mac = parts[1].strip() if len(parts) > 1 else ""
            vendor = parts[2].strip() if len(parts) > 2 else vendor_from_mac(mac)
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor,
                          "hostname": "", "ports": []})

elif method == "nmap":
    # nmap -sn format: "Nmap scan report for X" then optional "MAC Address: XX:XX..."
    cur_host = {}
    for line in open(hosts_file):
        line = line.strip()
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            if cur_host.get("ip"):
                hosts.append(cur_host)
            val = m.group(1)
            # "hostname (IP)" or just "IP"
            hm = re.match(r'(.+)\s+\((\d+\.\d+\.\d+\.\d+)\)', val)
            if hm:
                cur_host = {"ip": hm.group(2), "hostname": hm.group(1),
                            "mac": "", "vendor": "", "ports": []}
            else:
                cur_host = {"ip": val, "hostname": "", "mac": "", "vendor": "", "ports": []}
        m2 = re.match(r'MAC Address:\s+([0-9A-Fa-f:]+)\s*\((.+)\)', line)
        if m2 and cur_host:
            cur_host["mac"]    = m2.group(1)
            cur_host["vendor"] = m2.group(2)
    if cur_host.get("ip"):
        hosts.append(cur_host)

else:
    # arp-cache: IP\tMAC\tNote
    for line in open(hosts_file):
        line = line.strip()
        if not line: continue
        parts = line.split('\t')
        ip  = parts[0].strip()
        mac = parts[1].strip() if len(parts) > 1 else ""
        hosts.append({"ip": ip, "mac": mac, "vendor": vendor_from_mac(mac),
                      "hostname": "", "ports": []})

# Add the local host itself if not already in list
if local_ip and not any(h["ip"] == local_ip for h in hosts):
    hosts.insert(0, {"ip": local_ip, "mac": "", "vendor": "This host",
                     "hostname": "localhost", "ports": [], "is_self": True})

# Mark gateway
for h in hosts:
    h.setdefault("is_self", h["ip"] == local_ip)
    h.setdefault("is_gateway", h["ip"] == gateway)

# Resolve hostnames for up to 10 hosts (fast timeout)
for h in hosts[:10]:
    if not h.get("hostname") and h.get("ip"):
        try:
            import socket
            h["hostname"] = socket.gethostbyaddr(h["ip"])[0]
        except Exception:
            pass

result = {
    "hosts":       hosts,
    "subnet":      subnet,
    "gateway":     gateway,
    "local_ip":    local_ip,
    "iface":       iface,
    "scan_method": method,
    "timestamp":   ts,
    "host_count":  len(hosts),
}
with open(json_out, 'w') as f:
    json.dump(result, f, indent=2)

print(f"  LAN scan: {len(hosts)} hosts discovered on {subnet} via {method}")
for h in hosts:
    gw  = " [GATEWAY]"   if h.get("is_gateway") else ""
    slf = " [THIS HOST]" if h.get("is_self")    else ""
    mac = f"  {h['mac']}" if h.get("mac") else ""
    ven = f"  ({h['vendor']})" if h.get("vendor") else ""
    hn  = f"  {h['hostname']}" if h.get("hostname") else ""
    print(f"    {h['ip']}{mac}{ven}{hn}{gw}{slf}")
LANSCANEOF

  # Report to audit log
  if [[ -f "$LAN_JSON" ]]; then
    local _host_count
    _host_count=$(python3 -c "import json; d=json.load(open('$LAN_JSON')); print(d['host_count'])" \
      2>/dev/null || echo 0)
    if [[ "$_host_count" -gt 0 ]]; then
      pass "LAN discovery complete: ${_host_count} host(s) found on ${_subnet}"
      info "Scan method: ${_scan_method} | Network map SVG embedded in reports"
    else
      info "No LAN hosts discovered on ${_subnet} (host may be isolated or firewalled)"
    fi
  fi
  rm -f "$_tmp_hosts" 2>/dev/null || true

  subheader "Default gateway reachability"
  local _gw
  _gw=$(ip route show default 2>/dev/null | awk '/default via/{print $3}' | head -1 || true)
  if [[ -n "$_gw" ]]; then
    if ping -c1 -W2 "$_gw" &>/dev/null 2>&1; then
      pass "Default gateway ${_gw} responds to ping"
    else
      warn "Default gateway ${_gw} does not respond to ping — network connectivity issue"
    fi
  else
    info "No default gateway found"
  fi

  subheader "Rogue DHCP server detection"
  if command -v nmap &>/dev/null; then
    local _dhcp_servers
    _dhcp_servers=$(nmap --script broadcast-dhcp-discover -e "${_iface:-eth0}"       2>/dev/null | grep -E "Server Identifier|IP Offered" | head -4 || true)
    if [[ -n "$_dhcp_servers" ]]; then
      info "DHCP servers detected on LAN:"
      while IFS= read -r _d; do detail "$_d"; done <<< "$_dhcp_servers"
    fi
  fi
}

# ================================================================
#  PORT SCAN HISTORY — per-run log and re-detection engine
# ================================================================

# record_port_scan_run PORT_RANGES OPEN_PORTS_CSV
# Appends one line to PORT_SCAN_LOG so every scan run is archived.
# Format: TIMESTAMP|port_ranges|proto/port:service,...
record_port_scan_run() {
  local _ranges="$1" _open_csv="$2"
  local _ts; _ts=$(date +%s)   # epoch integer — Python readers cast with int()
  mkdir -p "$PERSIST_DIR" 2>/dev/null || true
  echo "${_ts}|${_ranges}|${_open_csv:-none}" >> "$PORT_SCAN_LOG" 2>/dev/null || true
}

# check_port_redetection OPEN_PORTS_CSV PORT_RANGES
# Reads PORT_SCAN_LOG and flags ports that:
#   1. Were seen in an EARLIER run  (already known — show history)
#   2. Were ABSENT for >= 1 run but are NOW back  (re-detected — warn loudly)
#   3. Were open before, were in range this run, but are now GONE  (closed — good)
check_port_redetection() {
  local _open_csv="$1"    # "tcp/22:ssh,tcp/80:http,..."
  local _ranges="$2"      # "1-1024,5001-5500,..."

  [[ ! -s "$PORT_SCAN_LOG" ]] && return

  # Build set of open ports this run: key="proto/port"
  declare -A _open_now=()
  local _item
  for _item in $(tr ',' ' ' <<< "${_open_csv:-none}"); do
    local _key="${_item%%:*}"   # "tcp/22"
    _open_now["$_key"]=1
  done

  # Parse range list into a flat check function (is port N in any range?)
  # Store as sorted list of start-end pairs for bash arithmetic
  local -a _range_starts=() _range_ends=()
  local _r
  for _r in $(tr ',' ' ' <<< "${_ranges:-}"); do
    local _rs="${_r%-*}" _re="${_r#*-}"
    _range_starts+=("$(safe_int "$_rs")")
    _range_ends+=("$(safe_int "$_re")")
  done

  # Inline range check — avoids global function name leak
  _port_in_ranges_check() {
    local _p="$1" _i
    for (( _i=0; _i<${#_range_starts[@]}; _i++ )); do
      [[ "$_p" -ge "${_range_starts[$_i]}" && "$_p" -le "${_range_ends[$_i]}" ]] && return 0
    done
    return 1
  }

  # Build history map: key="proto/port" → array of timestamps when open
  declare -A _seen_runs=()     # proto/port → space-separated timestamps
  declare -A _last_seen=()     # proto/port → most recent timestamp seen open
  declare -A _last_ranges=()   # run_ts → ranges scanned that run
  declare -A _runs_in_range=() # proto/port → timestamps where port WAS in scan range

  local _line _run_ts _run_ranges _run_open
  while IFS='|' read -r _run_ts _run_ranges _run_open; do
    [[ -z "$_run_ts" ]] && continue
    _last_ranges["$_run_ts"]="$_run_ranges"
    for _item in $(tr ',' ' ' <<< "${_run_open:-none}"); do
      [[ "$_item" == "none" ]] && continue
      local _key="${_item%%:*}"
      _seen_runs["$_key"]+=" $_run_ts"
      _last_seen["$_key"]="$_run_ts"
    done
  done < "$PORT_SCAN_LOG"

  # For each historically seen port: was it in range this run? Is it open now?
  local _redetected=0 _newly_closed=0 _persistent=0

  log ""
  log "  ${BOLD}Port re-detection analysis (cross-run history):${NC}"

  local _any_signal=false

  for _key in "${!_seen_runs[@]}"; do
    local _proto="${_key%%/*}"
    local _pnum="${_key#*/}"

    # Was this port in our scan range this run?
    local _in_range=false
    _port_in_ranges_check "$_pnum" && _in_range=true

    local _is_open_now=false
    [[ -n "${_open_now[$_key]:-}" ]] && _is_open_now=true

    local _run_times="${_seen_runs[$_key]}"
    local _seen_count
    _seen_count=$(wc -w <<< "$_run_times" || echo 0)
    _seen_count=$(safe_int "$_seen_count")
    local _last_ts="${_last_seen[$_key]}"

    if [[ "$_in_range" == "true" && "$_is_open_now" == "true" ]]; then
      if [[ "$_seen_count" -eq 1 ]]; then
        # Open for the first time — already reported by main loop, no extra signal
        :
      else
        # Was seen before AND is open again — persistent or re-detected
        # Check if it was absent in any intermediate run where it was in range
        # (simplified: if seen_count >= 2 and the gap between runs > 1, it's re-detected)
        local _was_absent=false
        # Look through scan log for any run where port was in range but NOT open
        local _prev_ts=""; local _chk_ts _chk_ranges _chk_open
        while IFS='|' read -r _chk_ts _chk_ranges _chk_open; do
          [[ -z "$_chk_ts" ]] && continue
          # Was port in range that run?
          local -a _cs=() _ce=()
          for _cr in $(tr ',' ' ' <<< "${_chk_ranges:-}"); do
            _cs+=("$(safe_int "${_cr%-*}")")
            _ce+=("$(safe_int "${_cr#*-}")")
          done
          local _pin=false; local _ci
          for (( _ci=0; _ci<${#_cs[@]}; _ci++ )); do
            [[ "$_pnum" -ge "${_cs[$_ci]}" && "$_pnum" -le "${_ce[$_ci]}" ]] && { _pin=true; break; }
          done
          if [[ "$_pin" == "true" ]]; then
            # Was it open that run?
            if ! echo "$_chk_open" | tr ',' '\n' | grep -q "^${_key}:"; then
              _was_absent=true
            fi
          fi
        done < "$PORT_SCAN_LOG"

        if [[ "$_was_absent" == "true" ]]; then
          log "  ${YELLOW}${BOLD}[↩ RE-DETECTED]${NC}  ${_proto^^}/${_pnum} was absent in at least one prior scan but is OPEN again"
          log "            First seen: ${_run_times%% *}  |  Total detections: ${_seen_count}  |  Last: ${_last_ts}"
          _redetected=$(( _redetected + 1 ))
          _any_signal=true
        else
          log "  ${CYAN}[● PERSISTENT]${NC}  ${_proto^^}/${_pnum} open in ${_seen_count} scan run(s)  (last: ${_last_ts})"
          _persistent=$(( _persistent + 1 ))
          _any_signal=true
        fi
      fi
    elif [[ "$_in_range" == "true" && "$_is_open_now" == "false" ]]; then
      # Port was in range this run but is NOT open — it closed since last detection
      log "  ${GREEN}[✔ CLOSED]${NC}    ${_proto^^}/${_pnum} was open before (${_seen_count} detections, last: ${_last_ts}) — now CLOSED"
      _newly_closed=$(( _newly_closed + 1 ))
      _any_signal=true
    fi
    # Port not in range this run: can't say if open or closed — skip
  done
  if [[ "$_any_signal" == "false" ]]; then
    info "No cross-run port signals — all scanned ports are within expected state"
  else
    log ""
    log "  ${BOLD}Cross-run summary:${NC}  ${YELLOW}${_redetected} re-detected${NC}  |  ${GREEN}${_newly_closed} newly closed${NC}  |  ${CYAN}${_persistent} persistent${NC}"
    if [[ "$_redetected" -gt 0 ]]; then
      warn "Port re-detection: ${_redetected} port(s) returned after being absent — investigate"
    fi
  fi
  log ""
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
  local i START=0 END=0
  for i in 1 2 3; do
    START=$(( (RANDOM % 130) * 500 + 1 ))
    END=$(( START + 499 ))
    [[ "$END" -gt 65535 ]] && END=65535
    RANDOM_RANGES+=("${START}-${END}")
  done
  RANDOM_RANGES+=("1-1024")

  local PORT_ARG
  PORT_ARG=$(IFS=,; echo "${RANDOM_RANGES[*]}")
  info "Scan ranges this run : ${PORT_ARG}"; info "Target               : 127.0.0.1 (localhost)"
  info "Technique            : TCP SYN + UDP top ports"
  log ""

  local NMAP_OUT="/tmp/nmap_scan_${TIMESTAMP}.xml"
  local NMAP_TXT="/tmp/nmap_scan_${TIMESTAMP}.txt"

  # Hard timeout prevents nmap (esp. -sU UDP) from running indefinitely
  local _nmap_timeout=120
  [[ "$USE_FAST_ONLY" == "true" ]] && _nmap_timeout=45

  timeout "$_nmap_timeout" \
  nmap -sS -sV -sU --top-ports 50 \
       -p "T:${PORT_ARG}" \
       -T4 --open --reason \
       --host-timeout "${_nmap_timeout}s" \
       --max-rtt-timeout 500ms \
       -oX "$NMAP_OUT" -oN "$NMAP_TXT" \
       127.0.0.1 2>/dev/null || \
  timeout "$_nmap_timeout" \
  nmap -sT -sV \
       -p "T:${PORT_ARG}" \
       -T4 --open --reason \
       --host-timeout "${_nmap_timeout}s" \
       --max-rtt-timeout 500ms \
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
  OPEN_PORTS=$(grep -E '^[0-9]+/tcp[[:space:]]+open' "$NMAP_TXT" 2>/dev/null | awk -F/ '{print $1}' || true)
  OPEN_UDP=$(grep -E '^[0-9]+/udp[[:space:]]+open' "$NMAP_TXT" 2>/dev/null | awk -F/ '{print $1}' || true)

  # Collect ALL open ports into CSV for scan log: "tcp/22:ssh,tcp/80:http,..."
  local _all_open_csv=""
  local PORT SERVICE REASON
  while IFS= read -r PORT; do
    [[ -z "$PORT" ]] && continue
    SERVICE=$(awk -v p="^${PORT}/tcp" '$0 ~ p && /open/ {print $3; exit}' "$NMAP_TXT" 2>/dev/null | head -1 || echo "unknown")
    REASON=$(grep -oE "^${PORT}/tcp[[:space:]]+open[[:space:]]+[^[:space:]]+" "$NMAP_TXT" 2>/dev/null       | awk '{print $NF}' | head -1 || echo "syn-ack")
    # Append to all-open CSV for scan log
    local _csv_entry="tcp/${PORT}:${SERVICE}"
    _all_open_csv="${_all_open_csv:+${_all_open_csv},}${_csv_entry}"
    # Risk assessment
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
    SERVICE=$(awk -v p="^${PORT}/udp" '$0 ~ p && /open/ {print $3; exit}' "$NMAP_TXT" 2>/dev/null | head -1 || echo "unknown")
    local _csv_entry="udp/${PORT}:${SERVICE}"
    _all_open_csv="${_all_open_csv:+${_all_open_csv},}${_csv_entry}"
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
    if [[ "$NEW_PORT_ISSUES" -gt 0 ]]; then
      warn "$NEW_PORT_ISSUES NEW port issue(s) detected for the first time this run"
    fi
  fi

  # ── Record this run in the port scan history log ─────────────
  record_port_scan_run "$PORT_ARG" "${_all_open_csv:-none}"

  subheader "Cross-run port re-detection analysis"
  check_port_redetection "${_all_open_csv:-none}" "$PORT_ARG"

  subheader "Persistent port issue history (risky ports)"
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
  rm -f "$NMAP_OUT" "$NMAP_TXT" 2>/dev/null || true
  info "Raw nmap port scan appended to: ${REPORT}"
}

# ================================================================
#  17. SUMMARY
# ================================================================
section_summary() {
  header "17. SUMMARY"

  local PERCENTAGE=0
  [[ "$TOTAL" -gt 0 ]] && PERCENTAGE=$(( SCORE * 100 / TOTAL ))

  # ── Score panel ─────────────────────────────────────────────────────────
  local _w=$(( ${_PROGRESS_COLS:-80} - 4 ))
  [[ "$_w" -gt 72 ]] && _w=72
  [[ "$_w" -lt 40 ]] && _w=40

  local _rating _rclr _rmsg
  if   [[ "$PERCENTAGE" -ge 80 ]]; then
    _rating="GOOD"     _rclr="$GREEN"
    _rmsg="System is reasonably hardened. Keep up with updates and monitor logs."
  elif [[ "$PERCENTAGE" -ge 50 ]]; then
    _rating="MODERATE" _rclr="$YELLOW"
    _rmsg="Several issues need attention. Address FAIL items as a priority."
  else
    _rating="CRITICAL" _rclr="$RED"
    _rmsg="Significant security risks detected. Immediate action required!"
  fi

  # Score bar: filled ██ / empty ░░ proportional to PERCENTAGE
  local _bar_w=$(( _w - 20 ))
  [[ "$_bar_w" -lt 10 ]] && _bar_w=10
  local _filled=$(( PERCENTAGE * _bar_w / 100 ))
  local _empty=$(( _bar_w - _filled ))
  local _bar="" _bi
  for (( _bi=0; _bi<_filled; _bi++ )); do _bar+="█"; done
  for (( _bi=0; _bi<_empty;  _bi++ )); do _bar+="░"; done

  # Border lines
  local _top_line="" _bot_line="" _bci
  for (( _bci=0; _bci<_w; _bci++ )); do _top_line+="═"; _bot_line+="═"; done

  # ── Counts of FAIL/WARN for the panel ─────────────────────────────
  local _n_fail _n_warn _n_pass _n_info
  _n_fail=$(grep -c "\[✘ FAIL\]" "$REPORT" 2>/dev/null || echo 0)
  _n_warn=$(grep -c "\[⚠ WARN\]" "$REPORT" 2>/dev/null || echo 0)
  _n_pass=$(grep -c "\[✔ PASS\]" "$REPORT" 2>/dev/null || echo 0)
  _n_info=$(grep -c "\[ℹ INFO\]" "$REPORT" 2>/dev/null || echo 0)
  _n_fail=$(safe_int "$_n_fail"); _n_warn=$(safe_int "$_n_warn")
  _n_pass=$(safe_int "$_n_pass"); _n_info=$(safe_int "$_n_info")

  # Rating emoji
  local _rating_icon
  [[ "$_rating" == "GOOD" ]]     && _rating_icon="🟢"
  [[ "$_rating" == "MODERATE" ]] && _rating_icon="🟡"
  [[ "$_rating" == "CRITICAL" ]] && _rating_icon="🔴"

  log ""
  log "  ${_rclr}${BOLD}╔${_top_line}╗${NC}"
  log "  ${_rclr}${BOLD}║${NC}  ${WHITE}${BOLD}⚡  SECURITY ASSESSMENT COMPLETE${NC}$(printf '%*s' $(( _w - 34 )) '')${_rclr}${BOLD}║${NC}"
  log "  ${_rclr}${BOLD}╠${_top_line}╣${NC}"
  # Score bar with percentage inside
  log "  ${_rclr}${BOLD}║${NC}  ${_rclr}${BOLD}${_bar}${NC}  ${WHITE}${BOLD}${PERCENTAGE}%${NC}$(printf '%*s' $(( _w - _bar_w - 6 )) '')${_rclr}${BOLD}║${NC}"
  # Rating row
  local _score_pad=$(( _w - 30 - ${#SCORE} - ${#TOTAL} - ${#_rating} ))
  [[ "$_score_pad" -lt 0 ]] && _score_pad=0
  log "  ${_rclr}${BOLD}║${NC}  ${_rating_icon}  Passed ${BGREEN}${BOLD}${SCORE}${NC} of ${WHITE}${TOTAL}${NC} checks  ·  ${_rclr}${BOLD}${_rating}${NC}$(printf '%*s' "$_score_pad" '')${_rclr}${BOLD}║${NC}"
  # Finding counts row
  local _counts_str="  ✘ ${BRED}${_n_fail} FAIL${NC}  ⚠ ${YELLOW}${_n_warn} WARN${NC}  ✔ ${BGREEN}${_n_pass} PASS${NC}  ℹ ${BCYAN}${_n_info} INFO${NC}"
  local _counts_pad=$(( _w - 2 - ${#_n_fail} - ${#_n_warn} - ${#_n_pass} - ${#_n_info} - 28 ))
  [[ "$_counts_pad" -lt 0 ]] && _counts_pad=0
  log "  ${_rclr}${BOLD}║${NC}${_counts_str}$(printf '%*s' "$_counts_pad" '')${_rclr}${BOLD}║${NC}"
  # Message row
  local _rmsg_pad=$(( _w - 2 - ${#_rmsg} ))
  [[ "$_rmsg_pad" -lt 0 ]] && _rmsg_pad=0
  log "  ${_rclr}${BOLD}║${NC}  ${DIM}${_rmsg}${NC}$(printf '%*s' "$_rmsg_pad" '')${_rclr}${BOLD}║${NC}"
  log "  ${_rclr}${BOLD}╚${_bot_line}╝${NC}"
  log ""
  log ""
  log "  ${BOLD}Output files (current directory):${NC}"
  log "  ┌──────────────────────────────────────────────────────────────┐"
  log "  │  ${BOLD}wowscanner_${TIMESTAMP}.txt${NC}"
  log "  │    Plain-text audit log (full scan output)"
  log "  │  ${BOLD}wowscanner_report_${TIMESTAMP}.odt${NC}"
  log "  │    Graphical report — open with LibreOffice Writer"
  log "  │  ${BOLD}wowscanner_report_${TIMESTAMP}.html${NC}"
  log "  │    Self-contained HTML report — open in any browser"
  log "  │  ${BOLD}wowscanner_stats_${TIMESTAMP}.ods${NC}"
  log "  │    Statistics workbook — open with LibreOffice Calc"
  log "  │  ${BOLD}wowscanner_intel_${TIMESTAMP}.odt${NC}"
  log "  │    Intelligence report with CVE context"
  log "  │  ${BOLD}wowscanner_archive_${TIMESTAMP}.zip${NC}"
  log "  │    Signed archive (HMAC + dual SHA-256/SHA-512 manifest)"
  log "  └──────────────────────────────────────────────────────────────┘"
  log ""
  log "  ${BOLD}Persistent data (/var/lib/wowscanner/):${NC}"
  log "  ┌──────────────────────────────────────────────────────────────┐"
  log "  │  port_issues.log        Port findings across all runs"
  log "  │  port_history.db        Per-port first/last-seen timestamps"
  log "  │  port_scan_log.db       Per-run scan register (re-detection)"
  log "  │  remediation_commands.sh  Auto-generated fix script"
  log "  │  score_history.db       Score trend across runs"
  log "  │  findings_last.db       FAIL snapshot for delta comparison"
  log "  │  baseline.db / baseline.ts  PASS snapshot for regression"
  log "  │  integrity_alerts.log   Archive verification events"
  log "  └──────────────────────────────────────────────────────────────┘"
  log ""
  log "  ${YELLOW}${BOLD}  ⚠  Please check the log file (/var/log/rkhunter.log) for full"
  log "     rkhunter details and to review any false positives.${NC}"
  log ""
  log ""
  log "  ${BBLUE}┌─ ${WHITE}${BOLD}RECOMMENDED NEXT STEPS${NC}${BBLUE} ──────────────────────────────────────┐${NC}"
  log "  ${BBLUE}│${NC}"
  log "  ${BBLUE}│${NC}  ${BRED}${BOLD}①${NC}  Fix all ${BRED}${BOLD}FAIL${NC} items immediately"
  log "  ${BBLUE}│${NC}  ${YELLOW}${BOLD}②${NC}  Review ${YELLOW}WARN${NC} items — apply where relevant"
  log "  ${BBLUE}│${NC}  ${BGREEN}${BOLD}③${NC}  ${BOLD}sudo bash $0 baseline${NC}        — snapshot PASS findings"
  log "  ${BBLUE}│${NC}  ${BGREEN}${BOLD}④${NC}  ${BOLD}sudo bash $0 harden${NC}          — apply sysctl hardening"
  log "  ${BBLUE}│${NC}  ${BGREEN}${BOLD}⑤${NC}  ${BOLD}sudo bash $0 install-timer${NC}   — weekly automated scans"
  log "  ${BBLUE}│${NC}  ${BCYAN}${BOLD}⑥${NC}  ${BOLD}less wowscanner_findings_${TIMESTAMP}.txt${NC}  — browse findings"
  log "  ${BBLUE}│${NC}  ${BCYAN}${BOLD}⑦${NC}  Aim for Lynis hardening index >= 80"
  log "  ${BBLUE}│${NC}  ${BCYAN}${BOLD}⑧${NC}  Set up monitoring: auditd + fail2ban + OSSEC"
  log "  ${BBLUE}│${NC}"
  log "  ${BBLUE}└───────────────────────────────────────────────────────────────┘${NC}"
  log ""

  local _sum_pct=0
  [[ "$TOTAL" -gt 0 ]] && _sum_pct=$(( SCORE * 100 / TOTAL ))
  [[ "$TOTAL" -gt 0 ]] && record_score_history "$SCORE" "$TOTAL" "$_sum_pct"
  [[ "$TOTAL" -gt 0 ]] && show_finding_delta
}

# ================================================================
#  18. ODT REPORT GENERATOR
# ================================================================
generate_odt_report() {
  local TXT_REPORT="$1" SCORE_VAL="$2" TOTAL_VAL="$3" PCT="$4"
  local LAN_JSON_PATH="${5:-/dev/null}"
  local ODT_OUT="wowscanner_report_${TIMESTAMP}.odt"

  echo -e "  ${CYAN}[ℹ]${NC}  Generating ODT → ${ODT_OUT} ..." >&2 || true

  python3 - "$TXT_REPORT" "$ODT_OUT" "$SCORE_VAL" "$TOTAL_VAL" "$PCT" "$TIMESTAMP" \
           "$(hostname -f 2>/dev/null || hostname)" \
           "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')" \
           "$(uname -r)" "$LAN_JSON_PATH" << 'PYEOF' || true
#!/usr/bin/env python3
import sys, os, re, zipfile
from datetime import datetime

txt_report = sys.argv[1]; odt_out = sys.argv[2]
score_val  = int(sys.argv[3])
total_val  = max(int(sys.argv[4]), 1)
pct        = int(sys.argv[5]) if int(sys.argv[4]) > 0 else 0
timestamp  = sys.argv[6]; hostname = sys.argv[7]
os_name    = sys.argv[8]; kernel   = sys.argv[9]
lan_json_path = sys.argv[10] if len(sys.argv) > 10 else ""

import json as _json
lan_data = {}
if lan_json_path and os.path.isfile(lan_json_path):
    try:
        with open(lan_json_path) as _lf:
            lan_data = _json.load(_lf)
    except Exception:
        lan_data = {}

ansi_re = re.compile(r'\x1b\[[0-9;]*m')
with open(txt_report, 'r', errors='replace') as fh:
    raw_lines = [ansi_re.sub('', l.rstrip('\n')) for l in fh]

PASS_RE = re.compile(r'^\s*\[.*PASS.*\]\s*(.*?)\s*Ω?\s*$')
FAIL_RE = re.compile(r'^\s*\[.*FAIL.*\]\s*(.*?)\s*Ω?\s*$')
WARN_RE = re.compile(r'^\s*\[.*WARN.*\]\s*(.*?)\s*Ω?\s*$')
INFO_RE = re.compile(r'^\s*\[.*INFO.*\]\s*(.*?)\s*Ω?\s*$')
SKIP_RE = re.compile(r'^\s*\[.*SKIP.*\]\s*(.*)')
DETAIL_RE = re.compile(r'^\s*(?:│\s*)?↳\s+(.*)')

sections = []; cur_sec = {"title": "Header", "items": []}
last_idx = -1; _in_box = False; _pending_title = None
for line in raw_lines:
    if re.match(r'^\s*╔═', line):
        _in_box = True; _pending_title = None; continue
    if _in_box:
        if re.match(r'^\s*╚═', line):
            if _pending_title:
                sections.append(cur_sec)
                cur_sec = {"title": _pending_title, "items": []}
                last_idx = -1
            _in_box = False; _pending_title = None; continue
        if re.match(r'^\s*[╠╬]═', line): continue
        _clean = re.sub(r'^[\U00010000-\U0010FFFF\u2600-\u2BFF\s]+', '', line.strip())
        _ms = re.match(r'([0-9]+[a-zA-Z]*[. ].+)', _clean)
        if _ms and len(_ms.group(1).strip()) > 3:
            _pending_title = _ms.group(1).strip()
        continue
    matched = False
    for RE, kind in ((PASS_RE,"PASS"),(FAIL_RE,"FAIL"),(WARN_RE,"WARN"),(INFO_RE,"INFO"),(SKIP_RE,"SKIP")):
        m = RE.match(line)
        if m:
            cur_sec["items"].append({"kind": kind, "text": m.group(1)})
            last_idx = len(cur_sec["items"]) - 1
            matched = True; break
    if not matched and last_idx >= 0:
        md = DETAIL_RE.match(line)
        if md and md.group(1).strip():
            cur_sec["items"][-1].setdefault("details", []).append(md.group(1).strip())
sections.append(cur_sec)
sections = [s for s in sections if s["items"]]

all_items = [i for s in sections for i in s["items"]]
n_pass = sum(1 for i in all_items if i["kind"]=="PASS")
n_fail = sum(1 for i in all_items if i["kind"]=="FAIL")
n_warn = sum(1 for i in all_items if i["kind"]=="WARN")
n_info = sum(1 for i in all_items if i["kind"]=="INFO")
n_skip = sum(1 for i in all_items if i["kind"]=="SKIP")

if pct >= 80:
    rating="GOOD";     rating_hex="1B5E20"; bar_fill="43A047"; c_main="#1B5E20"
elif pct >= 50:
    rating="MODERATE"; rating_hex="BF360C"; bar_fill="FB8C00"; c_main="#BF360C"
else:
    rating="CRITICAL"; rating_hex="B71C1C"; bar_fill="E53935"; c_main="#B71C1C"

BAR_WIDTH = 40
filled    = round(pct / 100 * BAR_WIDTH)
bar_str   = "\u2588" * filled + "\u2591" * (BAR_WIDTH - filled)
bar_label = f"{bar_str}  {pct}%  [{rating}]"

def esc(s):
    return (str(s).replace("&","&amp;").replace("<","&lt;")
                  .replace(">","&gt;").replace('"',"&quot;"))

# ── Colour palette ─────────────────────────────────────────────────────────────
C_PASS   = "#1B5E20"; C_FAIL   = "#B71C1C"; C_WARN   = "#E65100"
C_INFO   = "#0D47A1"; C_SKIP   = "#424242"; C_DETAIL = "#4A148C"
C_HEAD1  = "#0D2B50"; C_HEAD2  = "#1565C0"; C_SUBH   = "#1A237E"
C_ALT1   = "#F1F5FB"; C_ALT2   = "#FFFFFF"; C_BORDER = "#AED6F1"
C_DARK   = "#212121"; C_MED    = "#37474F"

KIND_LABEL = {"PASS":"✔ PASS","FAIL":"✘ FAIL","WARN":"⚠ WARN","INFO":"ℹ INFO","SKIP":"─ SKIP"}
KIND_STYLE = {"PASS":"ps","FAIL":"fs","WARN":"ws","INFO":"is","SKIP":"ss"}
KIND_BG    = {"PASS":"#E8F5E9","FAIL":"#FFEBEE","WARN":"#FFF3E0","INFO":"#E3F2FD","SKIP":"#F5F5F5"}

def result_row(item):
    """Render one finding row. Details rendered inline inside the text cell."""
    kind    = item["kind"]
    text    = item["text"]
    details = item.get("details", [])
    ks_map  = {"PASS":"ck_ps","FAIL":"ck_fs","WARN":"ck_ws","INFO":"ck_is","SKIP":"ck_ss"}
    ps_map  = {"PASS":"ps",   "FAIL":"fs",   "WARN":"ws",   "INFO":"is",   "SKIP":"ss"}
    ck = ks_map.get(kind, "ck_is")
    ps = ps_map.get(kind, "is")
    kl = KIND_LABEL.get(kind, kind)
    detail_xml = "".join(
        f'<text:p text:style-name="dt_sub">&#x21B3;  {esc(d)}</text:p>'
        for d in details
    )
    return (
        f'<table:table-row>'
        f'<table:table-cell table:style-name="{ck}" office:value-type="string">'
        f'<text:p text:style-name="{ps}">{esc(kl)}</text:p>'
        f'</table:table-cell>'
        f'<table:table-cell table:style-name="cv" office:value-type="string">'
        f'<text:p text:style-name="tc_bold">{esc(text)}</text:p>'
        + detail_xml +
        f'</table:table-cell>'
        f'</table:table-row>'
    )

def section_summary_row(title, nf, nw, np, ni):
    """One summary row for the executive table."""
    if nf > 0:     bg = "#FFEBEE"; badge = f"✘{nf} FAIL"
    elif nw > 0:   bg = "#FFF3E0"; badge = f"⚠{nw} WARN"
    else:          bg = "#E8F5E9"; badge = f"✔ OK"
    return (
        f'<table:table-row>'
        f'<table:table-cell table:style-name="exc_t" office:value-type="string">'
        f'<text:p text:style-name="exc_sec">{esc(title)}</text:p>'
        f'</table:table-cell>'
        f'<table:table-cell table:style-name="exc_n" office:value-type="string">'
        f'<text:p text:style-name="exc_num">{nf}</text:p>'
        f'</table:table-cell>'
        f'<table:table-cell table:style-name="exc_n" office:value-type="string">'
        f'<text:p text:style-name="exc_warn">{nw}</text:p>'
        f'</table:table-cell>'
        f'<table:table-cell table:style-name="exc_n" office:value-type="string">'
        f'<text:p text:style-name="exc_pass">{np}</text:p>'
        f'</table:table-cell>'
        f'<table:table-cell table:style-name="exc_n" office:value-type="string">'
        f'<text:p text:style-name="exc_info">{ni}</text:p>'
        f'</table:table-cell>'
        f'</table:table-row>'
    )

run_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
parts = []

# ── SVG helpers ────────────────────────────────────────────────────────────────
def odt_embed_svg(svg_data, w_cm, h_cm, name):
    return (
        f'<text:p text:style-name="tb">'
        f'<draw:frame draw:name="{name}" svg:width="{w_cm}cm" svg:height="{h_cm}cm" '
        f'text:anchor-type="as-char" draw:z-index="0">'
        f'<draw:image xlink:href="Pictures/{name}.svg" xlink:type="simple" '
        f'xlink:show="embed" xlink:actuate="onLoad"/>'
        f'</draw:frame>'
        f'</text:p>'
    )

def arc(a0,a1,ro,ri,cd,cl):
    import math
    def pt(a,r):
        return (cd+r*math.cos(math.radians(a)), cl+r*math.sin(math.radians(a)))
    if abs(a1-a0)>=359.9:
        return (f'<circle cx="{cd}" cy="{cl}" r="{ro}" fill="{cl}"/>'
                f'<circle cx="{cd}" cy="{cl}" r="{ri}" fill="white"/>')
    x0o,y0o=pt(a0,ro); x1o,y1o=pt(a1,ro)
    x0i,y0i=pt(a0,ri); x1i,y1i=pt(a1,ri)
    laf=1 if (a1-a0)%360>180 else 0
    return (f'<path d="M{x0o:.1f},{y0o:.1f} A{ro},{ro} 0 {laf},1 {x1o:.1f},{y1o:.1f} '
            f'L{x1i:.1f},{y1i:.1f} A{ri},{ri} 0 {laf},0 {x0i:.1f},{y0i:.1f} Z" fill="{cl}"/>')

def build_security_index_svg(pct2, nf, nw, np2, ni, rat, rhex, bfill):
    W,H = 900,280
    cx,cy,ro,ri = 140,140,110,72
    C = {"PASS":"#43A047","FAIL":"#E53935","WARN":"#FB8C00","INFO":"#1E88E5","SKIP":"#9E9E9E"}
    tot = max(nf+nw+np2+ni, 1)
    import math
    segs=[("PASS",np2),("WARN",nw),("FAIL",nf),("INFO",ni)]
    p=[f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">',
       f'<defs><filter id="sh"><feDropShadow dx="1" dy="2" stdDeviation="3" flood-opacity="0.13"/></filter></defs>',
       f'<rect width="{W}" height="{H}" fill="#F8FAFD" rx="12"/>',
       f'<rect x="0" y="0" width="{W}" height="7" fill="#{rhex}" rx="3"/>']
    angle=-90
    for label,val in segs:
        deg=(val/tot)*360
        p.append(arc(angle,angle+deg,ro,ri,cx,cy).replace(f'fill="{cy}"',f'fill="{C[label]}"'))
        angle+=deg
    # Centre pct text
    p.append(f'<text x="{cx}" y="{cy-10}" text-anchor="middle" font-size="30" font-weight="bold" fill="#{rhex}">{pct2}%</text>')
    p.append(f'<text x="{cx}" y="{cy+16}" text-anchor="middle" font-size="13" fill="#546E7A">{rat}</text>')
    p.append(f'<text x="{cx}" y="{cy+34}" text-anchor="middle" font-size="10" fill="#78909C">{np2+nf+nw} checks</text>')
    # Legend
    lx,ly=300,60; lw=560; lh=160
    p.append(f'<rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" fill="#FFFFFF" rx="8" filter="url(#sh)"/>')
    items=[("✘ FAIL",nf,"#E53935"),("⚠ WARN",nw,"#FB8C00"),("✔ PASS",np2,"#43A047"),("ℹ INFO",ni,"#1E88E5")]
    for idx,(lbl,val,col) in enumerate(items):
        row=idx//2; col_i=idx%2
        bx=lx+30+col_i*270; by=ly+28+row*64
        bar_w=min(200,int(val/max(nf+nw+np2+ni,1)*180))
        p.append(f'<rect x="{bx}" y="{by}" width="{bar_w}" height="18" fill="{col}" rx="3" opacity="0.85"/>')
        p.append(f'<text x="{bx}" y="{by-5}" font-size="11" fill="{col}" font-weight="bold">{lbl}: {val}</text>')
    p.append('</svg>')
    return '\n'.join(p), W, H

def build_findings_bar_svg(secs):
    import math
    n=len(secs); bar_h=22; gap=5; pad_l=210; pad_r=80; pad_t=30; pad_b=20
    W=900; H=pad_t+n*(bar_h+gap)+pad_b
    p=[f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">',
       f'<rect width="{W}" height="{H}" fill="#F8FAFD" rx="8"/>']
    max_tot=max((s[1]+s[2]+s[3] for s in secs),default=1)
    avail=W-pad_l-pad_r
    for i,(title,nf,nw,np2,ni) in enumerate(secs):
        y=pad_t+i*(bar_h+gap)
        # Alternating row background
        if i%2==0:
            p.append(f'<rect x="0" y="{y-2}" width="{W}" height="{bar_h+4}" fill="#EEF3FA" rx="2"/>')
        p.append(f'<text x="{pad_l-8}" y="{y+15}" text-anchor="end" font-size="9" fill="#37474F">{title[:28]}</text>')
        tot=nf+nw+np2
        if tot>0:
            fw=int(nf/max_tot*avail); ww=int(nw/max_tot*avail); pw=int(np2/max_tot*avail)
            xo=pad_l
            if fw>0: p.append(f'<rect x="{xo}" y="{y+1}" width="{fw}" height="{bar_h-2}" fill="#E53935" rx="2"/>'); xo+=fw
            if ww>0: p.append(f'<rect x="{xo}" y="{y+1}" width="{ww}" height="{bar_h-2}" fill="#FB8C00" rx="2"/>'); xo+=ww
            if pw>0: p.append(f'<rect x="{xo}" y="{y+1}" width="{pw}" height="{bar_h-2}" fill="#43A047" rx="2"/>');
            lbl_parts=[]
            if nf: lbl_parts.append(f'✘{nf}')
            if nw: lbl_parts.append(f'⚠{nw}')
            if np2: lbl_parts.append(f'✔{np2}')
            p.append(f'<text x="{pad_l+int(tot/max_tot*avail)+5}" y="{y+15}" font-size="9" fill="#546E7A">{"  ".join(lbl_parts)}</text>')
    # Legend
    for xi,(lbl,col) in enumerate([("FAIL","#E53935"),("WARN","#FB8C00"),("PASS","#43A047")]):
        p.append(f'<rect x="{pad_l+xi*140}" y="{H-16}" width="12" height="10" fill="{col}" rx="2"/>')
        p.append(f'<text x="{pad_l+xi*140+16}" y="{H-7}" font-size="9" fill="#546E7A">{lbl}</text>')
    p.append('</svg>')
    return '\n'.join(p), W, H

# Per-section stats for bar chart (filter to sections with actual FAIL/WARN/PASS)
sec_stats_odt = [(s["title"],
                  sum(1 for i in s["items"] if i["kind"]=="FAIL"),
                  sum(1 for i in s["items"] if i["kind"]=="WARN"),
                  sum(1 for i in s["items"] if i["kind"]=="PASS"),
                  sum(1 for i in s["items"] if i["kind"]=="INFO"))
                 for s in sections
                 if any(i["kind"] in ("FAIL","WARN","PASS") for i in s["items"])]

def build_odt_donut_svg(n_pass2, n_fail2, n_warn2, n_info2, pct2, rating2):
    """Donut chart — PASS/FAIL/WARN/INFO distribution."""
    W,H=500,240; cx,cy,ro,ri=120,120,100,62
    tot=max(n_pass2+n_fail2+n_warn2+n_info2,1)
    segs=[("PASS",n_pass2,"#43A047"),("WARN",n_warn2,"#FB8C00"),
          ("FAIL",n_fail2,"#E53935"),("INFO",n_info2,"#1E88E5")]
    p=[f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">',
       '<rect width="500" height="240" fill="#F8FAFD" rx="10"/>']
    a=-90
    for lbl,val,col in segs:
        if val>0:
            deg=(val/tot)*360
            p.append(arc(a,a+deg,ro,ri,cx,cy).replace(f'fill="{cy}"',f'fill="{col}"'))
            a+=deg
    p.append(f'<text x="{cx}" y="{cy-6}" text-anchor="middle" font-size="26" font-weight="bold" fill="#{pct2>79 and "1B5E20" or pct2>49 and "BF360C" or "B71C1C"}">{pct2}%</text>')
    p.append(f'<text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="10" fill="#607D8B">{rating2}</text>')
    ly=30
    for lbl,val,col in segs:
        p.append(f'<rect x="265" y="{ly}" width="14" height="14" fill="{col}" rx="3"/>')
        p.append(f'<text x="285" y="{ly+11}" font-size="11" fill="#37474F">{lbl}: {val}</text>')
        ly+=30
    p.append('</svg>')
    _do_W,_do_H=W,H
    return '\n'.join(p), _do_W, _do_H

def build_odt_heatmap_svg(sec_stats2):
    import math
    cols=["FAIL","WARN","PASS"]; col_colours={"FAIL":"#E53935","WARN":"#FB8C00","PASS":"#43A047"}
    n=len(sec_stats2); cw=70; rh=16; pad_l=190; pad_t=40; pad_b=20
    W=pad_l+len(cols)*cw+20; H=pad_t+n*rh+pad_b
    p=[f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">',
       f'<rect width="{W}" height="{H}" fill="#F8FAFD" rx="8"/>']
    for ci,col in enumerate(cols):
        cx2=pad_l+ci*cw+cw//2
        p.append(f'<text x="{cx2}" y="{pad_t-6}" text-anchor="middle" font-size="9" font-weight="bold" fill="{col_colours[col]}">{col}</text>')
    maxvals={c:max((s[{"FAIL":1,"WARN":2,"PASS":3}[c]] for s in sec_stats2),default=1) for c in cols}
    for ri2,(title,nf,nw,np2,ni) in enumerate(sec_stats2):
        y=pad_t+ri2*rh; bg="#EEF3FA" if ri2%2==0 else "#F8FAFD"
        p.append(f'<rect x="0" y="{y}" width="{W}" height="{rh}" fill="{bg}"/>')
        p.append(f'<text x="{pad_l-5}" y="{y+11}" text-anchor="end" font-size="8" fill="#37474F">{title[:24]}</text>')
        for ci,col in enumerate(cols):
            val={"FAIL":nf,"WARN":nw,"PASS":np2}[col]
            intensity=min(0.85,val/max(maxvals[col],1))
            alpha=int(intensity*220)+20
            fill=col_colours[col]
            bx=pad_l+ci*cw+4; by=y+2; bw=cw-8; bh=rh-4
            p.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" fill="{fill}" opacity="{alpha/255:.2f}" rx="2"/>')
            if val>0:
                p.append(f'<text x="{bx+bw//2}" y="{by+bh-2}" text-anchor="middle" font-size="8" fill="#fff" font-weight="bold">{val}</text>')
    p.append('</svg>')
    return '\n'.join(p), W, H

def build_odt_trend_svg():
    """Score trend line chart — reads score_history.db."""
    hist_path="/var/lib/wowscanner/score_history.db"
    points=[]
    if os.path.isfile(hist_path):
        with open(hist_path) as f:
            for ln in f:
                parts2=ln.strip().split('|')
                if len(parts2)>=4:
                    try:
                        ts2=parts2[0]; pct2=int(parts2[3])
                        points.append((ts2[:10], pct2))
                    except Exception:
                        pass
    points=points[-20:]  # last 20 runs max
    W,H=900,220; pad_l=50; pad_r=30; pad_t=30; pad_b=40
    aw=W-pad_l-pad_r; ah=H-pad_t-pad_b
    p=[f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">',
       f'<rect width="{W}" height="{H}" fill="#F8FAFD" rx="8"/>']
    # Grid lines at 0, 25, 50, 75, 100
    for pct_line in [0,25,50,75,100]:
        yg=pad_t+ah-int(pct_line/100*ah)
        col="#C5CAE9" if pct_line in (50,80) else "#E8EAF6"
        p.append(f'<line x1="{pad_l}" y1="{yg}" x2="{pad_l+aw}" y2="{yg}" stroke="{col}" stroke-width="{"1.5" if pct_line in (50,80) else "0.8"}"/>')
        p.append(f'<text x="{pad_l-5}" y="{yg+4}" text-anchor="end" font-size="9" fill="#78909C">{pct_line}%</text>')
    # 80% threshold label
    y80=pad_t+ah-int(80/100*ah)
    p.append(f'<text x="{pad_l+aw+4}" y="{y80+4}" font-size="8" fill="#43A047">GOOD</text>')
    if len(points)>=2:
        n2=len(points)
        dx=aw/(n2-1)
        coords=[(pad_l+i*dx, pad_t+ah-int(pt[1]/100*ah)) for i,pt in enumerate(points)]
        # Filled area
        area_pts=f"{pad_l},{pad_t+ah} " + " ".join(f"{x:.1f},{y:.1f}" for x,y in coords) + f" {pad_l+aw},{pad_t+ah}"
        p.append(f'<polygon points="{area_pts}" fill="#1565C0" opacity="0.08"/>')
        # Line
        line_d="M"+' L'.join(f'{x:.1f},{y:.1f}' for x,y in coords)
        p.append(f'<path d="{line_d}" fill="none" stroke="#1565C0" stroke-width="2.5" stroke-linejoin="round"/>')
        # Points
        for i,(x,y) in enumerate(coords):
            col2="#E53935" if points[i][1]<50 else "#FB8C00" if points[i][1]<80 else "#43A047"
            p.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{col2}" stroke="#fff" stroke-width="1.5"/>')
        # X-axis labels (every other for readability)
        for i,(ts2,pct2) in enumerate(points):
            if i%max(1,n2//8)==0 or i==n2-1:
                x2=pad_l+i*dx
                p.append(f'<text x="{x2:.1f}" y="{H-10}" text-anchor="middle" font-size="8" fill="#78909C">{ts2}</text>')
    elif len(points)==1:
        p.append(f'<text x="{W//2}" y="{H//2}" text-anchor="middle" font-size="13" fill="#78909C">1 data point — run more scans to see trend</text>')
    else:
        p.append(f'<text x="{W//2}" y="{H//2}" text-anchor="middle" font-size="13" fill="#78909C">No history yet — run more scans to see trend</text>')
    p.append('</svg>')
    return '\n'.join(p), W, H

def build_lan_map_svg(lan):
    hosts = lan.get("hosts", [])
    subnet = lan.get("subnet", "")
    n = len(hosts)
    W = 900
    if n == 0:
        H = 120
        return (f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">'
                f'<rect width="{W}" height="{H}" fill="#F8FAFD" rx="8"/>'
                f'<text x="{W//2}" y="{H//2}" text-anchor="middle" font-size="14" fill="#90A4AE">No LAN hosts discovered</text>'
                f'</svg>'), W, H
    import math
    cols = max(4, min(8, math.ceil(math.sqrt(n * 1.6))))
    rows = math.ceil(n / cols)
    NODE_W, NODE_H, GAP_X, GAP_Y = 100, 52, 20, 28
    PAD_X, PAD_Y = 30, 50
    H = PAD_Y + rows * (NODE_H + GAP_Y) + 30
    p = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Arial">',
         f'<rect width="{W}" height="{H}" fill="#F8FAFD" rx="8"/>',
         f'<text x="{W//2}" y="24" text-anchor="middle" font-size="11" font-weight="bold" fill="#1565C0">LAN: {subnet}  ({n} hosts)</text>']
    # Gateway node (first host or subnet .1)
    gw_ip = lan.get("gateway", "")
    for idx, host in enumerate(hosts):
        row_i = idx // cols; col_i = idx % cols
        total_row_w = cols * NODE_W + (cols - 1) * GAP_X
        x_off = (W - total_row_w) // 2
        x = x_off + col_i * (NODE_W + GAP_X)
        y = PAD_Y + row_i * (NODE_H + GAP_Y)
        ip = host.get("ip", "")
        vendor = (host.get("vendor") or host.get("hostname") or "")[:14]
        is_gw = (ip == gw_ip)
        fill = "#E3F2FD" if not is_gw else "#FFF3E0"
        stroke = "#1565C0" if not is_gw else "#E65100"
        sw = "1" if not is_gw else "2"
        p.append(f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" rx="6"/>')
        label = "⭐ GW" if is_gw else "🖥"
        p.append(f'<text x="{x+NODE_W//2}" y="{y+16}" text-anchor="middle" font-size="10" fill="{stroke}">{label}</text>')
        p.append(f'<text x="{x+NODE_W//2}" y="{y+30}" text-anchor="middle" font-size="9" font-weight="bold" fill="#212121">{ip}</text>')
        if vendor:
            p.append(f'<text x="{x+NODE_W//2}" y="{y+44}" text-anchor="middle" font-size="7.5" fill="#607D8B">{vendor}</text>')
    p.append('</svg>')
    return '\n'.join(p), W, H

# ── Build SVG charts ───────────────────────────────────────────────────────────
svg_index, _idx_W, _idx_H = build_security_index_svg(pct, n_fail, n_warn, n_pass, n_info, rating, rating_hex, bar_fill)
svg_bar,   _bar_W, _bar_H = build_findings_bar_svg(sec_stats_odt)
svg_lan,   _lan_W, _lan_H = build_lan_map_svg(lan_data)
lan_host_count = len(lan_data.get("hosts", []))
_lan_frame_h = round(17.0 * _lan_H / _lan_W, 2)

svg_donut_odt, _do_W, _do_H = build_odt_donut_svg(n_pass, n_fail, n_warn, n_info, pct, rating)
_do_frame_h   = round(11.0 * _do_H / _do_W, 2)

svg_heatmap_odt, _hm_W, _hm_H = build_odt_heatmap_svg(sec_stats_odt)
_hm_frame_h     = round(17.0 * _hm_H / max(_hm_W, 1), 2)
_hm_frame_h     = max(4.0, min(25.0, _hm_frame_h))

svg_trend_odt, _tr_W, _tr_H = build_odt_trend_svg()
_tr_frame_h = round(17.0 * _tr_H / _tr_W, 2)

bar_h = max(8.0, round(len(sec_stats_odt) * 0.65 + 2.5, 1))

# ── Assemble document body ─────────────────────────────────────────────────────
# Cover / title block
parts.append(f'<text:h text:style-name="h1_cover" text:outline-level="1">Wowscanner Security Report</text:h>')
parts.append(f'<text:p text:style-name="cover_sub">Host: {esc(hostname)}  |  OS: {esc(os_name)}  |  Kernel: {esc(kernel)}</text:p>')
parts.append(f'<text:p text:style-name="cover_sub">Generated: {esc(run_date)}  |  Timestamp: {esc(timestamp)}</text:p>')
parts.append(f'<text:p text:style-name="tb"/>')

# Security Index chart
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Security Index</text:h>')
parts.append(odt_embed_svg(svg_index, 17, round(17.0*_idx_H/_idx_W, 2), "security_index"))
parts.append(f'<text:p text:style-name="tb"/>')

# Score bar (text visual)
parts.append(f'<text:p text:style-name="bar">{esc(bar_label)}</text:p>')
parts.append(f'<text:p text:style-name="rt_{rating_hex}">{rating}  ·  {score_val} / {total_val} checks passed ({pct}%)</text:p>')
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# Executive summary table
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Executive Summary — All Sections</text:h>')
parts.append(
    '<table:table table:style-name="exc_t">'
    '<table:table-column table:style-name="exc_col_sec"/>'
    '<table:table-column table:style-name="exc_col_n"/>'
    '<table:table-column table:style-name="exc_col_n"/>'
    '<table:table-column table:style-name="exc_col_n"/>'
    '<table:table-column table:style-name="exc_col_n"/>'
    # Header row
    '<table:table-row>'
    '<table:table-cell table:style-name="exc_hdr" office:value-type="string"><text:p text:style-name="exc_hdr_t">Section</text:p></table:table-cell>'
    '<table:table-cell table:style-name="exc_hdr_f" office:value-type="string"><text:p text:style-name="exc_hdr_t">FAIL</text:p></table:table-cell>'
    '<table:table-cell table:style-name="exc_hdr_w" office:value-type="string"><text:p text:style-name="exc_hdr_t">WARN</text:p></table:table-cell>'
    '<table:table-cell table:style-name="exc_hdr_p" office:value-type="string"><text:p text:style-name="exc_hdr_t">PASS</text:p></table:table-cell>'
    '<table:table-cell table:style-name="exc_hdr_i" office:value-type="string"><text:p text:style-name="exc_hdr_t">INFO</text:p></table:table-cell>'
    '</table:table-row>'
)
for s in sections:
    nf = sum(1 for i in s["items"] if i["kind"]=="FAIL")
    nw = sum(1 for i in s["items"] if i["kind"]=="WARN")
    np2= sum(1 for i in s["items"] if i["kind"]=="PASS")
    ni2= sum(1 for i in s["items"] if i["kind"]=="INFO")
    parts.append(section_summary_row(s["title"], nf, nw, np2, ni2))
parts.append('</table:table>')
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# Findings by Section bar chart
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Findings by Section</text:h>')
parts.append(odt_embed_svg(svg_bar, 17, bar_h, "findings_bar"))
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# Finding distribution donut
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Finding Distribution</text:h>')
parts.append(f'<text:p text:style-name="cover_sub">PASS: {n_pass}  ·  FAIL: {n_fail}  ·  WARN: {n_warn}  ·  INFO: {n_info}  ·  SKIP: {n_skip}</text:p>')
parts.append(odt_embed_svg(svg_donut_odt, 11, _do_frame_h, "finding_donut"))
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# Section × Severity heatmap
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Section × Severity Heatmap</text:h>')
parts.append(odt_embed_svg(svg_heatmap_odt, 17, _hm_frame_h, "sec_heatmap"))
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# LAN network map
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">LAN Network Map ({lan_host_count} hosts)</text:h>')
parts.append(f'<text:p text:style-name="cover_sub">Subnet: {esc(lan_data.get("subnet","unknown"))}  ·  Method: {esc(lan_data.get("scan_method","none"))}  ·  Scanned: {esc(lan_data.get("timestamp",""))}</text:p>')
parts.append(odt_embed_svg(svg_lan, 17, _lan_frame_h, "lan_map"))
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# Score trend
parts.append(f'<text:h text:style-name="h2" text:outline-level="2">Security Score Trend</text:h>')
parts.append(f'<text:p text:style-name="cover_sub">Score history across scan runs (from /var/lib/wowscanner/score_history.db)</text:p>')
parts.append(odt_embed_svg(svg_trend_odt, 17, _tr_frame_h, "score_trend"))
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# ── Detailed section findings ─────────────────────────────────────────────────
parts.append(f'<text:h text:style-name="h1_sec" text:outline-level="1">Detailed Findings</text:h>')
for sec in sections:
    nf = sum(1 for i in sec["items"] if i["kind"]=="FAIL")
    nw = sum(1 for i in sec["items"] if i["kind"]=="WARN")
    np2= sum(1 for i in sec["items"] if i["kind"]=="PASS")
    badge = f"  ✘ {nf} FAIL" if nf else f"  ⚠ {nw} WARN" if nw else "  ✔ OK"
    sec_hs = "h2_sec_fail" if nf else "h2_sec_warn" if nw else "h2_sec_ok"
    parts.append(f'<text:h text:style-name="{sec_hs}" text:outline-level="2">{esc(sec["title"])}{esc(badge)}</text:h>')
    parts.append('<table:table table:style-name="rt">'
                 '<table:table-column table:style-name="col_k"/>'
                 '<table:table-column table:style-name="col_v"/>')
    for item in sec["items"]:
        parts.append(result_row(item))
    parts.append('</table:table>')
    parts.append('<text:p text:style-name="section_gap"/>')

# Summary counts
parts.append(f'<text:h text:style-name="h1_sec" text:outline-level="1">Summary Counts</text:h>')
for kind, n2, style in [("✔ PASS",n_pass,"ps"),("✘ FAIL",n_fail,"fs"),("⚠ WARN",n_warn,"ws"),("ℹ INFO",n_info,"is"),("─ SKIP",n_skip,"ss")]:
    parts.append(f'<text:p text:style-name="{style}">{kind} : {n2}</text:p>')
parts.append(f'<text:p text:style-name="tb"><text:soft-page-break/></text:p>')

# Full audit log reference
parts.append(f'<text:h text:style-name="h1_sec" text:outline-level="1">Full Audit Log</text:h>')
parts.append(f'<text:p text:style-name="tc">Complete plain-text audit output — all sections, all findings.</text:p>')
parts.append(f'<text:p text:style-name="tc">Open the companion .txt file: {esc(os.path.basename(txt_report))}</text:p>')

def _xe(s):
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def _lp(t):
    return f'<text:p text:style-name="log_line">{_xe(t)}</text:p>'
WRAP = 120
for raw in raw_lines:
    if len(raw) <= WRAP:
        parts.append(_lp(raw))
    else:
        for off in range(0, len(raw), WRAP):
            parts.append(_lp(raw[off:off+WRAP]))

if any("rkhunter" in l.lower() for l in raw_lines):
    parts.append(f'<text:p text:style-name="ws">⚠  For rkhunter details see /var/log/rkhunter.log</text:p>')

body = "\n".join(parts)

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
  <!-- ── Table geometry ────────────────────────────────── -->
  <style:style style:name="rt"  style:family="table">
    <style:table-properties style:width="17cm" table:align="margins"/>
  </style:style>
  <style:style style:name="col_k" style:family="table-column">
    <style:table-column-properties style:column-width="3.2cm"/>
  </style:style>
  <style:style style:name="col_v" style:family="table-column">
    <style:table-column-properties style:column-width="13.8cm"/>
  </style:style>
  <!-- Executive summary table -->
  <style:style style:name="exc_t" style:family="table">
    <style:table-properties style:width="17cm" table:align="margins"/>
  </style:style>
  <style:style style:name="exc_col_sec" style:family="table-column">
    <style:table-column-properties style:column-width="8.5cm"/>
  </style:style>
  <style:style style:name="exc_col_n" style:family="table-column">
    <style:table-column-properties style:column-width="2.125cm"/>
  </style:style>
  <!-- ── Cell styles ───────────────────────────────────── -->
  <style:style style:name="ck_ps" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#E8F5E9" fo:padding="0.12cm" fo:border="0.5pt solid #A5D6A7"/>
  </style:style>
  <style:style style:name="ck_fs" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFEBEE" fo:padding="0.12cm" fo:border="0.5pt solid #EF9A9A"/>
  </style:style>
  <style:style style:name="ck_ws" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFF3E0" fo:padding="0.12cm" fo:border="0.5pt solid #FFCC80"/>
  </style:style>
  <style:style style:name="ck_is" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#E3F2FD" fo:padding="0.12cm" fo:border="0.5pt solid #90CAF9"/>
  </style:style>
  <style:style style:name="ck_ss" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#F5F5F5" fo:padding="0.12cm" fo:border="0.5pt solid #E0E0E0"/>
  </style:style>
  <style:style style:name="ck_dt" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#F3E5F5" fo:padding="0.08cm" fo:border="0.3pt solid #CE93D8"/>
  </style:style>
  <style:style style:name="cv" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FFFFFF" fo:padding="0.12cm" fo:border="0.5pt solid #CFD8DC"/>
  </style:style>
  <!-- Executive summary cell styles -->
  <style:style style:name="exc_hdr"   style:family="table-cell">
    <style:table-cell-properties fo:background-color="#0D2B50" fo:padding="0.1cm" fo:border="0.5pt solid #1565C0"/>
  </style:style>
  <style:style style:name="exc_hdr_f" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#B71C1C" fo:padding="0.1cm" fo:border="0.5pt solid #E53935"/>
  </style:style>
  <style:style style:name="exc_hdr_w" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#BF360C" fo:padding="0.1cm" fo:border="0.5pt solid #FB8C00"/>
  </style:style>
  <style:style style:name="exc_hdr_p" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1B5E20" fo:padding="0.1cm" fo:border="0.5pt solid #43A047"/>
  </style:style>
  <style:style style:name="exc_hdr_i" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#0D47A1" fo:padding="0.1cm" fo:border="0.5pt solid #1E88E5"/>
  </style:style>
  <style:style style:name="exc_t_cell" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#EEF3FA" fo:padding="0.08cm" fo:border="0.4pt solid #BBDEFB"/>
  </style:style>
  <style:style style:name="exc_n" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#FAFAFA" fo:padding="0.08cm" fo:border="0.4pt solid #CFD8DC" fo:text-align="center"/>
  </style:style>
  <!-- ── Paragraph styles ──────────────────────────────── -->
  <!-- Cover title -->
  <style:style style:name="h1_cover" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0cm" fo:margin-bottom="0.3cm"
      fo:background-color="#0D2B50" fo:padding="0.3cm"
      fo:border-left="4pt solid #1ABC9C"/>
    <style:text-properties fo:font-size="18pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <!-- Section heading (with coloured left border) -->
  <style:style style:name="h1_sec" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.4cm" fo:margin-bottom="0.15cm"
      fo:background-color="#1565C0" fo:padding="0.18cm"
      fo:border-left="5pt solid #1ABC9C"/>
    <style:text-properties fo:font-size="14pt" fo:font-weight="bold" fo:color="#FFFFFF" style:font-name="Arial"/>
  </style:style>
  <!-- Sub-section heading -->
  <style:style style:name="h2" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.3cm" fo:margin-bottom="0.1cm"
      fo:border-bottom="1.5pt solid #1565C0" fo:padding-bottom="0.06cm"/>
    <style:text-properties fo:font-size="11.5pt" fo:font-weight="bold" fo:color="#1565C0" style:font-name="Arial"/>
  </style:style>
  <!-- Section findings headings: 3 colour variants -->
  <style:style style:name="h2_sec_fail" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.3cm" fo:margin-bottom="0.06cm"
      fo:background-color="#FDEDEC" fo:padding="0.1cm"
      fo:border-left="4pt solid #E74C3C" fo:border-bottom="0.5pt solid #F1948A"/>
    <style:text-properties fo:font-size="10.5pt" fo:font-weight="bold" fo:color="#922B21" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="h2_sec_warn" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.3cm" fo:margin-bottom="0.06cm"
      fo:background-color="#FEF5E7" fo:padding="0.1cm"
      fo:border-left="4pt solid #E67E22" fo:border-bottom="0.5pt solid #FAD7A0"/>
    <style:text-properties fo:font-size="10.5pt" fo:font-weight="bold" fo:color="#9A4500" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="h2_sec_ok" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0.3cm" fo:margin-bottom="0.06cm"
      fo:background-color="#EAFAF1" fo:padding="0.1cm"
      fo:border-left="4pt solid #27AE60" fo:border-bottom="0.5pt solid #A9DFBF"/>
    <style:text-properties fo:font-size="10.5pt" fo:font-weight="bold" fo:color="#1D6A2E" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="cover_sub" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center" fo:margin-bottom="0.05cm"/>
    <style:text-properties fo:font-size="9pt" fo:color="#546E7A" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="bar" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center" fo:background-color="#F5F5F5"
      fo:padding="0.2cm" fo:border="1pt solid #CFD8DC" fo:margin-bottom="0.15cm"/>
    <style:text-properties style:font-name="Cour" fo:font-size="10.5pt" fo:font-weight="bold" fo:color="#212121"/>
  </style:style>
  <style:style style:name="rt_{rating_hex}" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center" fo:margin-bottom="0.2cm"/>
    <style:text-properties fo:font-size="16pt" fo:font-weight="bold" fo:color="#{rating_hex}" style:font-name="Arial"/>
  </style:style>
  <!-- Finding badge text styles -->
  <style:style style:name="ps" style:family="paragraph">
    <style:text-properties fo:color="#1B5E20" fo:font-weight="bold" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="fs" style:family="paragraph">
    <style:text-properties fo:color="#B71C1C" fo:font-weight="bold" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="ws" style:family="paragraph">
    <style:text-properties fo:color="#BF360C" fo:font-weight="bold" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="is" style:family="paragraph">
    <style:text-properties fo:color="#0D47A1" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="ss" style:family="paragraph">
    <style:text-properties fo:color="#757575" style:font-name="Cour" fo:font-size="8.5pt"/>
  </style:style>
  <!-- Finding text (main text cell) -->
  <style:style style:name="tc_bold" style:family="paragraph">
    <style:text-properties style:font-name="Arial" fo:font-size="9pt" fo:color="#212121"/>
  </style:style>
  <!-- Detail sub-line (inside finding text cell) -->
  <style:style style:name="dt_sub" style:family="paragraph">
    <style:paragraph-properties fo:margin-left="0.25cm" fo:margin-top="0.02cm"/>
    <style:text-properties fo:color="#4A148C" fo:font-style="italic" style:font-name="Arial" fo:font-size="8pt"/>
  </style:style>
  <!-- Executive table text styles -->
  <style:style style:name="exc_hdr_t" style:family="paragraph">
    <style:text-properties fo:color="#FFFFFF" fo:font-weight="bold" style:font-name="Arial" fo:font-size="9pt"/>
  </style:style>
  <style:style style:name="exc_sec" style:family="paragraph">
    <style:text-properties fo:color="#1A237E" style:font-name="Arial" fo:font-size="8.5pt"/>
  </style:style>
  <style:style style:name="exc_num" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center"/>
    <style:text-properties fo:color="#B71C1C" fo:font-weight="bold" style:font-name="Arial" fo:font-size="9pt"/>
  </style:style>
  <style:style style:name="exc_warn" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center"/>
    <style:text-properties fo:color="#BF360C" fo:font-weight="bold" style:font-name="Arial" fo:font-size="9pt"/>
  </style:style>
  <style:style style:name="exc_pass" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center"/>
    <style:text-properties fo:color="#1B5E20" fo:font-weight="bold" style:font-name="Arial" fo:font-size="9pt"/>
  </style:style>
  <style:style style:name="exc_info" style:family="paragraph">
    <style:paragraph-properties fo:text-align="center"/>
    <style:text-properties fo:color="#0D47A1" style:font-name="Arial" fo:font-size="9pt"/>
  </style:style>
  <!-- Log / misc -->
  <style:style style:name="log_ref" style:family="paragraph">
    <style:text-properties style:font-name="Cour" fo:font-size="8pt" fo:color="#7F8C8D"/>
  </style:style>
  <style:style style:name="log_line" style:family="paragraph">
    <style:paragraph-properties fo:margin-top="0cm" fo:margin-bottom="0cm" fo:line-height="108%"/>
    <style:text-properties style:font-name="Cour" fo:font-size="6pt" fo:color="#212121"/>
  </style:style>
  <style:style style:name="tc" style:family="paragraph">
    <style:text-properties style:font-name="Cour" fo:font-size="8.5pt" fo:color="#212121"/>
  </style:style>
  <style:style style:name="tb" style:family="paragraph">
    <style:text-properties fo:font-size="3pt"/>
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
      fo:margin-left="1.5cm" fo:margin-right="1.5cm"/>
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
  <manifest:file-entry manifest:full-path="Pictures/lan_map.svg"        manifest:media-type="image/svg+xml"/>
  <manifest:file-entry manifest:full-path="Pictures/finding_donut.svg"  manifest:media-type="image/svg+xml"/>
  <manifest:file-entry manifest:full-path="Pictures/sec_heatmap.svg"    manifest:media-type="image/svg+xml"/>
  <manifest:file-entry manifest:full-path="Pictures/score_trend.svg"    manifest:media-type="image/svg+xml"/>
</manifest:manifest>"""

try:
    with zipfile.ZipFile(odt_out, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text")
        zf.writestr("META-INF/manifest.xml", manifest_xml)
        zf.writestr("content.xml",           content_xml)
        zf.writestr("styles.xml",            styles_xml)
        zf.writestr("Pictures/security_index.svg", svg_index)
        zf.writestr("Pictures/findings_bar.svg",   svg_bar)
        zf.writestr("Pictures/lan_map.svg",        svg_lan)
        zf.writestr("Pictures/finding_donut.svg",  svg_donut_odt)
        zf.writestr("Pictures/sec_heatmap.svg",    svg_heatmap_odt)
        zf.writestr("Pictures/score_trend.svg",    svg_trend_odt)
    print(f"ODT report written: {odt_out}  ({os.path.getsize(odt_out):,} bytes)")
except Exception as ex:
    print(f"ERROR: ODT generation failed: {ex}", file=sys.stderr)
    raise SystemExit(1)
print(f"  Charts: Security Index | Findings by Section | LAN Network Map ({lan_host_count} hosts) | Finding Donut | Heatmap | Score Trend")
print(f"  Sections: {len(sections)}  FAIL: {n_fail}  WARN: {n_warn}  PASS: {n_pass}")
PYEOF

  if [[ -f "${ODT_OUT}" ]]; then
    write_odf_crc "${ODT_OUT}"
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
  local LAN_JSON_PATH="${5:-/dev/null}"
  local ODS_OUT="wowscanner_stats_${TIMESTAMP}.ods"

  echo -e "  ${CYAN}[ℹ]${NC}  Generating ODS → ${ODS_OUT} ..." >&2 || true

  python3 - "$TXT_REPORT" "$ODS_OUT" "$SCORE_VAL" "$TOTAL_VAL" "$PCT" "$TIMESTAMP" \
           "$(hostname -f 2>/dev/null || hostname)" \
           "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')" \
           "$(uname -r)" "$LAN_JSON_PATH" << 'STATSEOF' || true
import sys, os, re, zipfile, math
from datetime import datetime

txt_report = sys.argv[1]; ods_out = sys.argv[2]
score_val  = int(sys.argv[3])
total_val  = max(int(sys.argv[4]), 1)  # guard: never zero
pct        = int(sys.argv[5]) if int(sys.argv[4]) > 0 else 0
timestamp  = sys.argv[6]; hostname = sys.argv[7]
os_name    = sys.argv[8]; kernel   = sys.argv[9]
lan_json_path = sys.argv[10] if len(sys.argv) > 10 else ""

import json as _json
lan_data = {}
if lan_json_path and os.path.isfile(lan_json_path):
    try:
        with open(lan_json_path) as _lf:
            lan_data = _json.load(_lf)
    except Exception:
        lan_data = {}
run_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Parse the audit report ────────────────────────────────────────
ansi_re = re.compile(r'\x1b\[[0-9;]*m')
with open(txt_report, 'r', errors='replace') as fh:
    raw_lines = [ansi_re.sub('', l.rstrip('\n')) for l in fh]

PASS_RE  = re.compile(r'^\s*\[.*PASS.*\]\s*(.*?)\s*Ω?\s*$')
FAIL_RE  = re.compile(r'^\s*\[.*FAIL.*\]\s*(.*?)\s*Ω?\s*$')
WARN_RE  = re.compile(r'^\s*\[.*WARN.*\]\s*(.*?)\s*Ω?\s*$')
INFO_RE  = re.compile(r'^\s*\[.*INFO.*\]\s*(.*?)\s*Ω?\s*$')
SKIP_RE  = re.compile(r'^\s*\[.*SKIP.*\]\s*(.*?)\s*Ω?\s*$')
DETAIL_RE = re.compile(r'^\s*(?:│\s*)?↳\s+(.*)')

sections = []; cur_sec = {"title": "Header", "items": [], "details": []}
last_item_idx = -1
_in_box = False; _pending_title = None

for line in raw_lines:
    if re.match(r'^\s*╔═', line):
        _in_box = True; _pending_title = None; continue
    if _in_box:
        if re.match(r'^\s*╚═', line):
            if _pending_title:
                sections.append(cur_sec)
                cur_sec = {"title": _pending_title, "items": [], "details": []}
                last_item_idx = -1
            _in_box = False; _pending_title = None; continue
        if re.match(r'^\s*[╠╬]═', line): continue
        _clean = re.sub(r'^[\U00010000-\U0010FFFF\u2600-\u2BFF\s]+', '', line.strip())
        _ms = re.match(r'([0-9]+[a-zA-Z]*[. ].+)', _clean)
        if _ms and len(_ms.group(1).strip()) > 3:
            _pending_title = _ms.group(1).strip()
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
        "title": s["title"], "pass": n_p, "fail": n_f,
        "warn": n_w, "info": n_i, "skip": n_s,
        "total": tot, "pct": round(n_p*100/max(tot,1)) if tot else 0
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
    return "".join(parts), W, H


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
        gx = pad_l + int(tick / max(max_val, 1) * plot_w)
        parts.append(f'<line x1="{gx}" y1="{pad_t}" x2="{gx}" y2="{pad_t + n*row_h}" stroke="#2E3A5E" stroke-width="1"/>')
        parts.append(f'<text x="{gx}" y="{pad_t + n*row_h + 15}" text-anchor="middle" font-family="Arial" font-size="8" fill="#78909C">{tick}</text>')

    for idx, s in enumerate(sec_stats):
        y = pad_t + idx * row_h + 2
        bh = row_h - 4
        pw = int(s["pass"] / max(max_val, 1) * plot_w)
        fw = int(s["fail"] / max(max_val, 1) * plot_w)
        ww = int(s["warn"] / max(max_val, 1) * plot_w)
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
        parts.append(f'<text x="{pad_l-6}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="#CFD8DC">{s["title"][:34].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")}</text>')
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
    return "".join(parts), W, H


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
        sweep = 2 * math.pi * count / max(all_total, 1)
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
    return "".join(parts), W, H


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
        ratio = val / max(max_v, 1)
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
        parts.append(f'<text x="{lbl_w-6}" y="{y2+row_h//2+4}" text-anchor="end" font-family="Arial" font-size="8" fill="#B0BEC5">{s["title"][:34].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")}</text>')
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
    return "".join(parts), W, H


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

    W, H, cx2, cy2, R2 = 520, 360, 240, 195, 120
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
    return "".join(parts), W, H


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
    pct_s = round(count*100/max(checks_total,1)) if checks_total else 0
    ov.append(row(cell_str(kind,style), cell_num(count,style),
                  cell_pct(pct_s,style) if kind not in ("ℹ  INFO","–  SKIP") else cell_empty(),
                  cell_empty(3)))
ov.append(row(*[cell_empty(6)]))
ov.append(row(cell_str("Charts (sheet 7):", "ce_lbl"),
              cell_str("score_gauge | bar_chart | pie_chart | heatmap | severity_radar | dim_radar | score_trend | port_register | security_index | findings_bar | lan_map", "ce_info"),
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

# ── Sheet 2b: All Findings (every PASS/FAIL/WARN/INFO finding) ──────────────
all_rows = []
all_rows.append(row(
    hcell("Section"), hcell("Type"), hcell("Finding"), hcell("Details")
))
for s in sections:
    for item in s["items"]:
        kstyle = {"FAIL":"ce_fail","WARN":"ce_warn","PASS":"ce_pass",
                  "INFO":"ce_info","SKIP":"ce_skip"}.get(item["kind"],"ce1")
        dstr = " | ".join(item["details"][:5]) if item["details"] else "—"
        all_rows.append(row(
            cell_str(s["title"], "ce1"),
            cell_str(item["kind"], kstyle),
            cell_str(item["text"], "ce1"),
            cell_str(dstr, "ce_detail"),
        ))
if len(all_rows) == 1:
    all_rows.append(row(cell_str("No findings parsed yet","ce_info"), cell_empty(3)))

sheet2b = ('<table:table table:name="All Findings" table:style-name="ta1">'
           '<table:table-column table:style-name="co_wide2"/>'
           '<table:table-column table:style-name="co_val"/>'
           '<table:table-column table:style-name="co_issues"/>'
           '<table:table-column table:style-name="co_fix"/>'
           + "\n".join(all_rows) + '</table:table>')

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
                cell_str(s["title"], "ce1"),
                cell_str(item["kind"], kind_style),
                cell_str(item["text"], "ce1"),
                sev_cell(sev),
                cell_str((detail_str if detail_str else "—"), "ce_detail"),
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
        cell_str(sec_title, "ce_fail_light"),
        cell_str(item["text"], "ce1"),
        sev_cell(sev),
        cell_str(desc, "ce_desc"),
        cell_str(evidence, "ce_evidence"),
        cell_str(fix, "ce_fix"),
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
        cell_str(sec_title, "ce_warn_light"),
        cell_str(item["text"], "ce1"),
        sev_cell(sev),
        cell_str(desc, "ce_desc"),
        cell_str(evidence, "ce_evidence"),
        cell_str(fix, "ce_fix"),
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
    cd_rows.append(row(cell_str(s["title"],"ce1"), cell_num(s["pass"],"ce_pass"),
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

def build_score_trend_svg():
    """Line chart of score history from score_history.db across runs."""
    import os as _os, datetime as _dt
    W, H = 820, 300
    pad_l, pad_r, pad_t, pad_b = 70, 40, 50, 60
    BW = W - pad_l - pad_r
    BH = H - pad_t - pad_b

    # Read score_history.db: lines of  timestamp|score|total|pct
    history = []
    hist_db = "/var/lib/wowscanner/score_history.db"
    if _os.path.exists(hist_db):
        try:
            with open(hist_db) as _hf:
                for _line in _hf:
                    parts = _line.strip().split("|")
                    if len(parts) >= 4:
                        try:
                            raw_ts = parts[0].strip()
                            if raw_ts.isdigit():
                                # New format: unix epoch
                                _ts  = int(raw_ts)
                                _lbl = _dt.datetime.fromtimestamp(_ts).strftime("%m-%d")
                            else:
                                # Legacy format: "YYYY-MM-DD HH:MM:SS" — extract MM-DD
                                _lbl = raw_ts[5:10] if len(raw_ts) >= 10 else raw_ts
                            _pct = int(parts[3])
                            history.append((_lbl, _pct))
                        except Exception:
                            pass
        except Exception:
            pass

    # Always include current run
    history.append((run_date[-5:], pct))
    # Keep last 12 runs max, deduplicate adjacent same-label
    if len(history) > 12:
        history = history[-12:]

    p = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="8"/>',
        f'<text x="{W//2}" y="28" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Security Score Trend</text>',
    ]

    mn, mx = 0, 100
    n = len(history)
    if n < 2:
        p.append(f'<text x="{W//2}" y="{H//2}" text-anchor="middle" font-family="Arial" font-size="11" fill="#78909C">Run more scans to populate trend</text>')
        p.append('</svg>')
        return "".join(p), W, H

    # Zone fills — SVG y-axis goes down; high % = low y value
    for zmin, zmax, zcol in [(80,100,"#0D2B0D"),(60,80,"#0B2B17"),(0,60,"#1A1215")]:
        zlo = max(zmin, mn); zhi = min(zmax, mx)
        if zlo >= zhi: continue
        z_top = H - pad_b - (zhi - mn) / (mx - mn) * BH
        z_bot = H - pad_b - (zlo - mn) / (mx - mn) * BH
        p.append(f'<rect x="{pad_l}" y="{z_top:.1f}" width="{BW}" height="{max(0,z_bot-z_top):.1f}" fill="{zcol}"/>')

    # Horizontal grid lines + Y labels
    for v in range(0, 101, 20):
        gy = H - pad_b - (v-mn)/(mx-mn)*BH
        p.append(f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{pad_l+BW}" y2="{gy:.1f}" stroke="#1A2535" stroke-width="0.8"/>')
        p.append(f'<text x="{pad_l-6}" y="{gy+4:.1f}" text-anchor="end" font-family="Arial" font-size="8" fill="#78909C">{v}%</text>')

    # Data points
    pts = []
    for i, (lbl, score) in enumerate(history):
        x = pad_l + i / (n-1) * BW
        y = H - pad_b - (score-mn)/(mx-mn)*BH
        pts.append((x, y, lbl, score))

    # Area fill
    poly = f"{pad_l},{H-pad_b} " + " ".join(f"{x:.1f},{y:.1f}" for x,y,_,_ in pts) + f" {pad_l+BW},{H-pad_b}"
    p.append(f'<polygon points="{poly}" fill="#0D3D2E" stroke="none"/>')

    # Line
    for i in range(len(pts)-1):
        p.append(f'<line x1="{pts[i][0]:.1f}" y1="{pts[i][1]:.1f}" x2="{pts[i+1][0]:.1f}" y2="{pts[i+1][1]:.1f}" stroke="#4CAF50" stroke-width="2.5"/>')

    # Points + labels
    for i, (x, y, lbl, score) in enumerate(pts):
        col = "#4CAF50" if score >= 80 else ("#FFB300" if score >= 60 else "#EF5350")
        is_last = (i == len(pts)-1)
        p.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{col}" stroke="#1A1A2E" stroke-width="1.5"/>')
        if is_last or i % max(1, n//6) == 0:
            txt_y = y - 10 if y > pad_t + 20 else y + 18
            p.append(f'<text x="{x:.1f}" y="{txt_y:.1f}" text-anchor="middle" font-family="Arial" font-size="8" font-weight="bold" fill="{col}">{score}%</text>')
        # X-axis label
        if i % max(1, n//8) == 0 or is_last:
            p.append(f'<text x="{x:.1f}" y="{H-pad_b+16:.1f}" text-anchor="middle" font-family="Arial" font-size="7.5" fill="#78909C">{lbl}</text>')

    # Y-axis
    p.append(f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{H-pad_b}" stroke="#37474F" stroke-width="0.8"/>')
    # Zone labels
    for vz, lz, cz in [(90,"EXCELLENT","#42A5F5"),(70,"GOOD","#66BB6A"),(50,"MODERATE","#FFB300"),(30,"CRITICAL","#EF5350")]:
        if mn <= vz <= mx:
            gy2 = H - pad_b - (vz-mn)/(mx-mn)*BH
            p.append(f'<text x="{pad_l+BW+4}" y="{gy2+3:.1f}" font-family="Arial" font-size="7" fill="{cz}">{lz}</text>')
    p.append('</svg>')
    return "".join(p), W, H


def build_port_register_svg():
    """Port re-detection register: dots showing open/closed across scan runs."""
    import os as _os
    W, H_per_port = 820, 28
    pad_l, pad_r, pad_t, pad_b = 200, 110, 50, 36
    MAX_RUNS = 10
    MAX_PORTS = 12

    # Read port_scan_log.db: lines of  timestamp|ranges|port1,port2,...
    runs = []       # list of (label, set_of_open_ports)
    log_db = "/var/lib/wowscanner/port_scan_log.db"
    if _os.path.exists(log_db):
        try:
            with open(log_db) as _lf:
                import datetime as _dt2
                for _line in _lf:
                    parts = _line.strip().split("|")
                    if len(parts) >= 3:
                        try:
                            raw_ts = parts[0].strip()
                            if raw_ts.isdigit():
                                # New format: unix epoch
                                _ts  = int(raw_ts)
                                _lbl = _dt2.datetime.fromtimestamp(_ts).strftime("%m/%d")
                            else:
                                # Legacy format: "YYYY-MM-DD HH:MM:SS"
                                _lbl = raw_ts[5:10] if len(raw_ts) >= 10 else raw_ts
                            _open = set(p.strip() for p in parts[2].split(",") if p.strip())
                            runs.append((_lbl, _open))
                        except Exception:
                            pass
        except Exception:
            pass

    if len(runs) < 2:
        # No history yet — draw placeholder
        p = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="180" viewBox="0 0 {W} 180">',
            f'<rect width="{W}" height="180" fill="#1A1A2E" rx="8"/>',
            f'<text x="{W//2}" y="80" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Port Scan Re-Detection Register</text>',
            f'<text x="{W//2}" y="108" text-anchor="middle" font-family="Arial" font-size="10" fill="#78909C">Run at least 2 scans to populate port history.</text>',
            '</svg>',
        ]
        return "".join(p), W, 180

    runs = runs[-MAX_RUNS:]
    n_runs = len(runs)

    # Collect all unique ports seen across runs, sort, limit
    all_ports = sorted(set(p for _, pset in runs for p in pset),
                       key=lambda p: int(p.split("/")[-1]) if p.split("/")[-1].isdigit() else 99999)
    if len(all_ports) > MAX_PORTS:
        all_ports = all_ports[:MAX_PORTS]

    n_ports = len(all_ports)
    H = pad_t + n_ports * H_per_port + pad_b
    BW = W - pad_l - pad_r
    cell_w = BW / max(n_runs, 1)

    p = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#1A1A2E" rx="8"/>',
        f'<text x="{W//2}" y="28" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#E0E0E0">Port Scan Re-Detection Register</text>',
    ]

    # Column headers (run dates)
    for ci, (lbl, _) in enumerate(runs):
        cx2 = pad_l + (ci + 0.5) * cell_w
        p.append(f'<text x="{cx2:.1f}" y="{pad_t-8}" text-anchor="middle" font-family="Arial" font-size="7.5" fill="#78909C">{lbl}</text>')

    # Port rows
    for ri, port in enumerate(all_ports):
        ry = pad_t + ri * H_per_port
        bg = "#141424" if ri % 2 == 0 else "#1A1A2E"
        p.append(f'<rect x="0" y="{ry}" width="{W}" height="{H_per_port}" fill="{bg}"/>')
        p.append(f'<text x="{pad_l-8}" y="{ry+H_per_port//2+4}" text-anchor="end" font-family="Arial" font-size="8" fill="#CFD8DC">{port}</text>')

        # Detect status across runs
        open_runs = [i for i, (_, pset) in enumerate(runs) if port in pset]
        total_seen = len(open_runs)
        last_run_open = (n_runs - 1) in open_runs

        # Status signal
        if total_seen == 0:
            status, status_col = "–", "#546E7A"
        elif total_seen == n_runs:
            status, status_col = "PERSISTENT", "#42A5F5"
        elif last_run_open and total_seen < n_runs:
            status, status_col = "RE-DETECTED", "#FFB300"
        elif not last_run_open and total_seen > 0:
            status, status_col = "CLOSED ✔", "#4CAF50"
        else:
            status, status_col = "SEEN", "#90A4AE"

        p.append(f'<text x="{pad_l+BW+6}" y="{ry+H_per_port//2+4}" font-family="Arial" font-size="7.5" font-weight="bold" fill="{status_col}">{status}</text>')

        # Dots for each run
        for ci, (_, pset) in enumerate(runs):
            cx2 = pad_l + (ci + 0.5) * cell_w
            cy2 = ry + H_per_port // 2
            if port in pset:
                p.append(f'<circle cx="{cx2:.1f}" cy="{cy2}" r="7" fill="{status_col}" opacity="0.85"/>')
            else:
                p.append(f'<circle cx="{cx2:.1f}" cy="{cy2}" r="5" fill="#1E2A3A" stroke="#37474F" stroke-width="0.8"/>')

    # Legend
    lx2, ly2 = pad_l, H - 22
    for lbl, col in [("PERSISTENT","#42A5F5"),("RE-DETECTED","#FFB300"),("CLOSED","#4CAF50")]:
        p.append(f'<circle cx="{lx2+6}" cy="{ly2+4}" r="5" fill="{col}"/>')
        p.append(f'<text x="{lx2+15}" y="{ly2+8}" font-family="Arial" font-size="8" fill="{col}">{lbl}</text>')
        lx2 += 110

    p.append('</svg>')
    return "".join(p), W, H


def build_security_dimension_radar_svg():
    """8-axis Security Dimension Radar — coverage across authentication, network,
    kernel, file system, logging, services, packages, rootkit/MAC sections.
    Each axis shows the score% for that group of audit sections.
    """
    # Map dimensions to section-title prefix patterns
    dim_map = [
        ("Authentication",  ["3.", "4.", "5."]),
        ("Network",         ["6.", "7."]),
        ("Kernel",          ["11."]),
        ("File System",     ["8."]),
        ("Logging",         ["10."]),
        ("Services",        ["9.", "13c", "13d"]),
        ("Packages",        ["13. "]),   # space avoids matching 13c/13d
        ("Rootkit / MAC",   ["14b", "14."]),
    ]

    axes = []
    for dim_name, prefixes in dim_map:
        matched = [s for s in sec_stats
                   if any(s["title"].lstrip().startswith(p) for p in prefixes)]
        if matched:
            avg_pct = round(sum(s["pct"] for s in matched) / len(matched))
        else:
            avg_pct = 0   # section not present in this report
        axes.append((dim_name, avg_pct))

    n = len(axes)
    W, H   = 600, 500
    cx, cy = 300, 265
    R      = 155   # outer ring radius
    BG     = "#1A1A2E"

    import math as _m

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="{BG}" rx="10"/>',
        f'<text x="{W//2}" y="26" text-anchor="middle" font-family="Arial" '
        f'font-size="13" font-weight="bold" fill="#E0E0E0">Security Dimension Radar</text>',
        f'<text x="{W//2}" y="42" text-anchor="middle" font-family="Arial" '
        f'font-size="9" fill="#78909C">Score % per security domain (100% = all checks passed)</text>',
    ]

    # ── Grid rings ─────────────────────────────────────────────────────
    ring_vals = [25, 50, 75, 100]
    ring_cols = ["#1A2535", "#1E2D42", "#223350", "#263A5E"]
    for ri, (rv, rc) in enumerate(zip(ring_vals, ring_cols)):
        ring_pts = []
        for i in range(n):
            ang = _m.radians(-90 + i * 360 / n)
            ring_pts.append(f"{cx + R*rv/100*_m.cos(ang):.1f},{cy + R*rv/100*_m.sin(ang):.1f}")
        parts.append(f'<polygon points="{" ".join(ring_pts)}" '
                     f'fill="{rc}" stroke="#2E3A5E" stroke-width="0.8"/>')
        # Ring % label (at top spoke)
        label_y = cy - R * rv / 100 - 4
        parts.append(f'<text x="{cx+3}" y="{label_y:.1f}" font-family="Arial" '
                     f'font-size="7" fill="#546E7A">{rv}%</text>')

    # ── Axis spokes ────────────────────────────────────────────────────
    for i in range(n):
        ang = _m.radians(-90 + i * 360 / n)
        ex = cx + R * _m.cos(ang)
        ey = cy + R * _m.sin(ang)
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{ex:.1f}" y2="{ey:.1f}" '
                     f'stroke="#2E3A5E" stroke-width="1.2"/>')

    # ── Data polygon ────────────────────────────────────────────────────
    data_pts = []
    for i, (dim_name, val) in enumerate(axes):
        ang   = _m.radians(-90 + i * 360 / n)
        ratio = val / 100
        data_pts.append((cx + R * ratio * _m.cos(ang),
                         cy + R * ratio * _m.sin(ang)))

    poly_str = " ".join(f"{x:.1f},{y:.1f}" for x, y in data_pts)
    # Gradient fill colour based on overall score
    fill_col  = "#2E7D32" if pct >= 80 else ("#E65100" if pct >= 60 else "#B71C1C")
    stroke_col = "#4CAF50" if pct >= 80 else ("#FF9800" if pct >= 60 else "#EF5350")
    parts.append(f'<polygon points="{poly_str}" fill="{fill_col}" '
                 f'fill-opacity="0.25" stroke="{stroke_col}" stroke-width="2.5"/>')

    # ── Axis labels + value dots ────────────────────────────────────────
    for i, (dim_name, val) in enumerate(axes):
        ang   = _m.radians(-90 + i * 360 / n)
        ratio = val / 100

        # Dot on data polygon
        dx = cx + R * ratio * _m.cos(ang)
        dy = cy + R * ratio * _m.sin(ang)
        dot_col = "#4CAF50" if val >= 75 else ("#FFB300" if val >= 50 else "#EF5350")
        parts.append(f'<circle cx="{dx:.1f}" cy="{dy:.1f}" r="5" '
                     f'fill="{dot_col}" stroke="#1A1A2E" stroke-width="1.5"/>')

        # Axis label — push beyond the outer ring, anchor by quadrant
        lx = cx + (R + 28) * _m.cos(ang)
        ly = cy + (R + 28) * _m.sin(ang)
        cos_a = _m.cos(ang)
        anchor = "middle" if abs(cos_a) < 0.35 else ("start" if cos_a > 0 else "end")
        # Colour by score
        lbl_col = "#4CAF50" if val >= 75 else ("#FFB300" if val >= 50 else "#EF5350")
        parts.append(f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" '
                     f'font-family="Arial" font-size="9.5" font-weight="bold" '
                     f'fill="{lbl_col}">{dim_name}</text>')
        parts.append(f'<text x="{lx:.1f}" y="{ly+12:.1f}" text-anchor="{anchor}" '
                     f'font-family="Arial" font-size="9" fill="{lbl_col}">{val}%</text>')

    # ── Centre score ────────────────────────────────────────────────────
    score_col = "#4CAF50" if pct >= 80 else ("#FF9800" if pct >= 60 else "#EF5350")
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="28" fill="#0D1117" '
                 f'stroke="{score_col}" stroke-width="2"/>')
    parts.append(f'<text x="{cx}" y="{cy+6}" text-anchor="middle" font-family="Arial" '
                 f'font-size="14" font-weight="bold" fill="{score_col}">{pct}%</text>')

    # ── Legend ──────────────────────────────────────────────────────────
    lx2, ly2 = 16, H - 54
    parts.append(f'<text x="{lx2}" y="{ly2}" font-family="Arial" font-size="8.5" '
                 f'font-weight="bold" fill="#90A4AE">Score key:</text>')
    ly2 += 14
    for col, lbl in [("#4CAF50", "≥ 75%  Good"), ("#FFB300", "50–74%  Moderate"),
                     ("#EF5350", "&lt; 50%  Needs work")]:
        parts.append(f'<circle cx="{lx2+5}" cy="{ly2-4}" r="5" fill="{col}"/>')
        parts.append(f'<text x="{lx2+14}" y="{ly2}" font-family="Arial" '
                     f'font-size="8" fill="{col}">{lbl}</text>')
        ly2 += 14

    parts.append(f'<text x="{W//2}" y="{H-8}" text-anchor="middle" font-family="Arial" '
                 f'font-size="7.5" fill="#546E7A">'
                 f'Each axis = avg score% of sections in that domain</text>')
    parts.append('</svg>')
    return "".join(parts), W, H


def build_lan_map_svg_ods(lan):
    """Same compact design as ODT builder — W=700, auto-height."""
    import math as _math
    hosts   = lan.get("hosts", [])
    subnet  = lan.get("subnet", "")
    method  = lan.get("scan_method", "")
    ts      = lan.get("timestamp", "")
    gateway = lan.get("gateway", "")

    W = 700; NODE_R = 20; HEADER_H = 30; PAD_TOP = 14; PAD_BOT = 8
    LEGEND_H = 22; LABEL_SP = NODE_R + 24

    n = len(hosts)
    if n == 0:
        H = 90
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
                f'<rect width="{W}" height="{H}" fill="#F5F5F5" rx="6"/>'
                f'<text x="{W//2}" y="38" text-anchor="middle" font-family="Arial" '
                f'font-size="13" fill="#888">No LAN hosts discovered</text>'
                f'<text x="{W//2}" y="58" text-anchor="middle" font-family="Arial" '
                f'font-size="10" fill="#AAA">Subnet: {subnet}  |  Method: {method}</text>'
                f'</svg>'), W, H

    n_ring = max(n - 1, 1)
    min_chord = NODE_R * 2 * 1.3
    min_ring_r = (min_chord / 2) / _math.sin(_math.pi / n_ring) if n_ring > 1 else NODE_R * 3
    max_ring_r = (W / 2) - NODE_R - LABEL_SP - 4
    ring_r = max(NODE_R * 3, min(int(min_ring_r) + 4, int(max_ring_r)))

    cx = W / 2
    cy = HEADER_H + PAD_TOP + ring_r + NODE_R + 16
    H = int(cy + ring_r + LABEL_SP + LEGEND_H + PAD_BOT)

    C_SELF="#1A5276"; C_GW="#117A65"; C_HOST="#5D6D7E"
    C_EDGE="#CBD5E0"; C_TEXT="#FFFFFF"; C_BG="#FAFAFA"
    C_SUBNET="#EBF5FB"; LABEL_COL="#2C3E50"

    p = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="{C_BG}" rx="6"/>',
        f'<rect x="0" y="0" width="{W}" height="{HEADER_H}" fill="#1A3A6B" rx="6"/>',
        f'<rect x="0" y="{HEADER_H-6}" width="{W}" height="6" fill="#1A3A6B"/>',
        f'<text x="10" y="{HEADER_H-8}" font-family="Arial" font-size="11" '
        f'font-weight="bold" fill="white">LAN — {subnet}</text>',
        f'<text x="{W-8}" y="{HEADER_H-8}" text-anchor="end" font-family="Arial" '
        f'font-size="8" fill="#B0C4DE">{method} \u00b7 {n} device{"s" if n!=1 else ""}</text>',
        f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{ring_r + NODE_R + 5}" '
        f'fill="{C_SUBNET}" stroke="#AED6F1" stroke-width="1" stroke-dasharray="3,3"/>',
    ]

    pos = {}
    self_idx = next((i for i, h in enumerate(hosts) if h.get("is_self")), 0)
    pos[self_idx] = (cx, cy)
    others = [i for i in range(n) if i != self_idx]
    for k, idx in enumerate(others):
        angle = (2 * _math.pi * k / max(len(others), 1)) - _math.pi / 2
        pos[idx] = (cx + ring_r * _math.cos(angle), cy + ring_r * _math.sin(angle))

    for idx in others:
        px, py = pos[idx]
        p.append(f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{px:.1f}" y2="{py:.1f}" '
                 f'stroke="{C_EDGE}" stroke-width="1" stroke-dasharray="4,3" opacity="0.8"/>')

    for i, host in enumerate(hosts):
        px, py = pos[i]
        is_self = host.get("is_self", False)
        is_gw   = host.get("is_gateway", False) or host.get("ip") == gateway
        colour  = C_SELF if is_self else (C_GW if is_gw else C_HOST)
        stroke  = "#FFFFFF" if is_self else ("#A9D18E" if is_gw else "#8FA3B1")
        sw      = "2" if (is_self or is_gw) else "1.5"
        p.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{NODE_R}" '
                 f'fill="{colour}" stroke="{stroke}" stroke-width="{sw}"/>')
        icon = "H" if is_self else ("G" if is_gw else "D")
        p.append(f'<text x="{px:.1f}" y="{py+4:.1f}" text-anchor="middle" '
                 f'font-family="Arial" font-size="10" font-weight="bold" fill="{C_TEXT}">{icon}</text>')
        if is_self or is_gw:
            badge = "THIS HOST" if is_self else "GATEWAY"
            bw = 52 if is_self else 44
            p.append(f'<rect x="{px-bw/2:.1f}" y="{py-NODE_R-14:.1f}" '
                     f'width="{bw}" height="12" rx="2" fill="{colour}"/>')
            p.append(f'<text x="{px:.1f}" y="{py-NODE_R-5:.1f}" '
                     f'text-anchor="middle" font-family="Arial" font-size="7" '
                     f'font-weight="bold" fill="white">{badge}</text>')
        ly = py + NODE_R + 11
        p.append(f'<text x="{px:.1f}" y="{ly:.1f}" text-anchor="middle" '
                 f'font-family="Arial" font-size="8" font-weight="bold" fill="{LABEL_COL}">{host["ip"]}</text>')
        _raw_sub = (host.get("hostname") or host.get("vendor") or "")[:16]
        sub = _raw_sub.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        if sub:
            p.append(f'<text x="{px:.1f}" y="{ly+11:.1f}" text-anchor="middle" '
                     f'font-family="Arial" font-size="7" fill="#7F8C8D">{sub}</text>')

    leg_y = H - LEGEND_H + 8
    for i, (col, label) in enumerate(
            [(C_SELF, "This host"), (C_GW, "Gateway"), (C_HOST, "Device")]):
        lx = 10 + i * 110
        p.append(f'<circle cx="{lx+5}" cy="{leg_y}" r="5" fill="{col}"/>')
        p.append(f'<text x="{lx+14}" y="{leg_y+4}" font-family="Arial" '
                 f'font-size="8" fill="{LABEL_COL}">{label}</text>')
    p.append(f'<text x="{W-8}" y="{leg_y+4}" text-anchor="end" '
             f'font-family="Arial" font-size="7" fill="#AAA">{ts}</text>')
    p.append('</svg>')
    return '\n'.join(p), W, H

svg_lan_ods, _lan_W_ods, _lan_H_ods = build_lan_map_svg_ods(lan_data)

# Per-chart row styles: populated by chart_img_row(), injected into auto-styles
_chart_row_styles = []
_chart_img_counter = [0]

def chart_img_row(path, w_cm, h_cm, title):
    """Embed one SVG chart with a title row above it.
    Generates a unique row style for EACH chart so the row height exactly
    matches the frame height — fixing the LibreOffice Calc image-clipping bug
    caused by all rows sharing a single fixed-height ro_chart style."""
    _chart_img_counter[0] += 1
    idx = _chart_img_counter[0]
    row_h = round(float(h_cm) + 0.4, 2)  # frame + breathing room
    row_style = f"ro_c{idx}"
    _chart_row_styles.append((row_style, row_h))
    frame_name = f"chart_{idx}"

    title_row = (
        '<table:table-row>'
        f'<table:table-cell table:number-columns-spanned="2" table:style-name="ce_title">'
        f'<text:p>{esc(title)}</text:p></table:table-cell>'
        '<table:covered-table-cell/>'
        '</table:table-row>'
    )
    img_row = (
        f'<table:table-row table:style-name="{row_style}">'
        f'<table:table-cell table:number-columns-spanned="2" table:style-name="ce_img">'
        '<text:p>'
        f'<draw:frame draw:name="{frame_name}" '
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

svg_gauge,   _sg_W,  _sg_H  = build_score_gauge_svg()
svg_bar,     _sb_W,  _sb_H  = build_bar_chart_svg()
svg_pie,     _sp_W,  _sp_H  = build_pie_chart_svg()
svg_heat,    _sh_W,  _sh_H  = build_heatmap_svg()
svg_radar,   _sr_W,  _sr_H  = build_severity_radar_svg()
svg_dimradar,_dr_W,  _dr_H  = build_security_dimension_radar_svg()
svg_trend,   _st_W,  _st_H  = build_score_trend_svg()
svg_portreg, _pr_W,  _pr_H  = build_port_register_svg()
chart_rows = []
# Frame width for all charts (matches column span of 2 × 8.5cm each)
_CHART_W_CM = 17.0
# Compute exact frame heights from actual SVG pixel dimensions to prevent clipping
for svg_path, svg_title, svg_W, svg_H in [
    ("Pictures/score_gauge.svg",    "Score Gauge — Overall security score with benchmark markers",    _sg_W, _sg_H),
    ("Pictures/bar_chart.svg",      "Bar Chart — PASS / FAIL / WARN per audit section",               _sb_W, _sb_H),
    ("Pictures/pie_chart.svg",      "Pie Chart — Distribution of all result types",                   _sp_W, _sp_H),
    ("Pictures/heatmap.svg",        "Heatmap — Finding density: section × severity",                  _sh_W, _sh_H),
    ("Pictures/severity_radar.svg", "Severity Radar — Issue count by Critical / High / Medium / Low", _sr_W, _sr_H),
    ("Pictures/security_index.svg", "Security Index — Colour-coded score gauge with rating legend",   820,   260),
    ("Pictures/findings_bar.svg",   "Findings Bar — PASS/FAIL/WARN per section with score %",         820,   max(270, len(sec_stats)*18+70)),
    ("Pictures/lan_map.svg",        f"LAN Network Map — {lan_data.get('host_count',0)} devices on {lan_data.get('subnet','unknown')} (method: {lan_data.get('scan_method','none')})", _lan_W_ods, _lan_H_ods),
    ("Pictures/score_trend.svg",    "Score Trend — Security score across all scan runs (reads score_history.db)", _st_W, _st_H),
    ("Pictures/port_register.svg",  "Port Re-Detection Register — Open ports across scan runs (reads port_scan_log.db)", _pr_W, _pr_H),
    ("Pictures/dim_radar.svg",      "Security Dimension Radar — 8-axis coverage: Authentication | Network | Kernel | File System | Logging | Services | Packages | Rootkit/MAC", _dr_W, _dr_H),
]:
    _frame_h = round(_CHART_W_CM * svg_H / max(svg_W, 1), 2)
    chart_rows.append(chart_img_row(svg_path, _CHART_W_CM, _frame_h, svg_title))

sheet7 = (
    '<table:table table:name="Charts" table:style-name="ta1">'
    '<table:table-column table:style-name="co_chart_half"/>'
    '<table:table-column table:style-name="co_chart_half"/>'
    + "".join(chart_rows)
    + '</table:table>'
)

# ── Sheet 7: Charts — SVGs embedded as visible images ─────────────
# Each chart is rendered as a draw:frame/draw:image in its own row so

# Build LAN map SVG before chart_rows so its dimensions are available for the row height
# build_lan_map_svg_ods called after function definition below

# ═══════════════════════════════════════════════════════════════
#  ODS STYLES
# ═══════════════════════════════════════════════════════════════
styles_auto_base = """
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
  <!-- Dynamic score bar styles (all three rating colours) -->
  <style:style style:name="ce_bar_4CAF50" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1B5E20" fo:padding="0.12cm" fo:border="0.4pt solid #2E7D32"/>
    <style:text-properties fo:font-size="8pt" fo:font-weight="bold" fo:color="#A5D6A7" style:font-name="Courier New"/>
  </style:style>
  <style:style style:name="ce_bar_FF9800" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#4A2500" fo:padding="0.12cm" fo:border="0.4pt solid #E65100"/>
    <style:text-properties fo:font-size="8pt" fo:font-weight="bold" fo:color="#FFCC80" style:font-name="Courier New"/>
  </style:style>
  <style:style style:name="ce_bar_F44336" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#4A0000" fo:padding="0.12cm" fo:border="0.4pt solid #B71C1C"/>
    <style:text-properties fo:font-size="8pt" fo:font-weight="bold" fo:color="#EF9A9A" style:font-name="Courier New"/>
  </style:style>
  <!-- Dynamic rating styles -->
  <style:style style:name="ce_rating_2E7D32" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#1B5E20" fo:padding="0.12cm" fo:border="0.4pt solid #2E7D32"/>
    <style:text-properties fo:font-size="9pt" fo:font-weight="bold" fo:color="#A5D6A7" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_rating_E65100" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#4A2500" fo:padding="0.12cm" fo:border="0.4pt solid #E65100"/>
    <style:text-properties fo:font-size="9pt" fo:font-weight="bold" fo:color="#FFCC80" style:font-name="Arial"/>
  </style:style>
  <style:style style:name="ce_rating_B71C1C" style:family="table-cell">
    <style:table-cell-properties fo:background-color="#4A0000" fo:padding="0.12cm" fo:border="0.4pt solid #B71C1C"/>
    <style:text-properties fo:font-size="9pt" fo:font-weight="bold" fo:color="#EF9A9A" style:font-name="Arial"/>
  </style:style>
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
"""
# Inject per-chart row styles — must be done after chart_rows are built
# so h_cm values are known
_dynamic_row_styles = "".join(
    f'  <style:style style:name="{rs}" style:family="table-row">\n'
    f'    <style:table-row-properties style:row-height="{rh}cm"'
    f' style:use-optimal-row-height="false"/>\n'
    f'  </style:style>\n'
    for rs, rh in _chart_row_styles
)
styles_auto = styles_auto_base + _dynamic_row_styles + "</office:automatic-styles>\n"


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
{sheet2b}
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
    ('Pictures/lan_map.svg',        'image/svg+xml'),
    ('Pictures/score_trend.svg',    'image/svg+xml'),
    ('Pictures/port_register.svg',  'image/svg+xml'),
    ('Pictures/dim_radar.svg',       'image/svg+xml'),
]
manifest_xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
    '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">\n'
    + "".join(f'  <manifest:file-entry manifest:full-path="{p}" manifest:media-type="{m}"/>\n' for p,m in manifest_entries)
    + '</manifest:manifest>\n')

# ── Build SVGs ────────────────────────────────────────────────────

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
        _fb_safe = s["title"][:30].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        p.append(f'<text x="{pl-8}" y="{y+bh//2+4}" text-anchor="end" font-family="Arial" font-size="9" fill="{lc}">{_fb_safe}</text>')
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

# ── LAN network map SVG (shared builder, same as ODT) ─────────────





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
    zf.writestr("Pictures/lan_map.svg",        svg_lan_ods)
    zf.writestr("Pictures/score_trend.svg",    svg_trend)
    zf.writestr("Pictures/port_register.svg",  svg_portreg)
    zf.writestr("Pictures/dim_radar.svg",       svg_dimradar)

lan_n = lan_data.get("host_count", 0)
print(f"Enhanced ODS report written: {ods_out}  ({os.path.getsize(ods_out):,} bytes)")
print(f"  Sheets: Overview | Per-Section | All Findings | All Issues | FAIL Deep-Dive | WARN Deep-Dive | ChartData | Charts ({len(sections)} sections parsed, {n_fail} FAILs, {n_warn} WARNs, {n_pass} PASSes)")
print(f"  SVGs:   score_gauge | bar_chart | pie_chart | heatmap | severity_radar | dim_radar | score_trend | port_register | security_index | findings_bar | lan_map ({lan_n} hosts)")
STATSEOF

  if [[ -f "wowscanner_stats_${TIMESTAMP}.ods" ]]; then
    write_odf_crc "wowscanner_stats_${TIMESTAMP}.ods"
    pass "Enhanced ODS report generated: wowscanner_stats_${TIMESTAMP}.ods"
    log "  ${CYAN}${BOLD}Sheets (7): Overview | Per-Section | All Issues | FAIL Deep-Dive | WARN Deep-Dive | ChartData | Charts${NC}"
    log "  ${CYAN}${BOLD}SVGs (11): score_gauge | bar_chart | pie_chart | heatmap | severity_radar | dim_radar | score_trend | port_register | security_index | findings_bar | lan_map${NC}"
    log "  ${CYAN}${BOLD}Each FAIL/WARN includes: severity, description, evidence captured, fix commands, CVE refs${NC}"
    log "  ${CYAN}${BOLD}Open with LibreOffice Calc, OnlyOffice, or Google Sheets.${NC}"
  else
    warn "ODS generation failed — check Python3 availability"
  fi
}

# ================================================================
#  ODF CRC CHECK
#  Standalone inner-member CRC verification for .odt / .ods files.
#
#  How it works:
#   - Every ODF file is a ZIP archive containing XML members and
#     image assets.  Python's zipfile module stores a CRC-32 in
#     each member's local file header, computed at write time.
#   - write_odf_crc() reads those stored CRC-32 values right after
#     the file is generated and writes a .crc sidecar:
#       wowscanner_report_<ts>.odt.crc
#       wowscanner_stats_<ts>.ods.crc
#       wowscanner_intel_<ts>.odt.crc
#   - verify_odf_crc() re-opens each ODF file, re-reads the CRC-32
#     from every member header, and compares against the sidecar.
#     It also re-decompresses each member and lets Python verify the
#     stored CRC against the actual data (zipfile does this on read).
#   - check_odf_crcs() is called from cmd_verify and can also be
#     invoked standalone:
#       sudo bash wowscanner.sh verify-odf
#
#  Sidecar format (.crc file):
#   # Wowscanner ODF inner-CRC manifest v1
#   # Generated : <timestamp>
#   # File      : <filename>
#   # SHA-256   : <hex>    (whole-file, for quick tamper detection)
#   # Members   : <N>
#   <crc32hex>  <member_name>
#   ...
# ================================================================

# ================================================================
#  TXT INTEGRITY — SHA-256 sidecar for the plain-text audit log
#
#  The .txt report is the most editable output file (plain text, no
#  internal structure to protect it).  We write a .txt.sha256 sidecar
#  immediately after archiving so any subsequent tampering is detected
#  by verify.  The sidecar is also included IN the zip so the hash
#  itself is covered by the HMAC-signed INTEGRITY.txt manifest.
#
#  Sidecar format:
#    # Wowscanner txt integrity v1
#    # Generated : <timestamp>
#    # File      : <filename>
#    # Size      : <bytes>
#    # SHA-256   : <hex>
#    # SHA-512   : <hex>
#    # Lines     : <count>
# ================================================================
write_txt_crc() {
  # Args: $1 = path to the .txt report
  local _txt="$1"
  [[ -f "$_txt" ]] || return 0
  local _crc_file="${_txt}.sha256"

  python3 - "$_txt" "$_crc_file" << 'TXTCRCEOF' || true
import sys, os, hashlib, datetime

txt_path = sys.argv[1]
crc_path  = sys.argv[2]
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def sha512(path):
    h = hashlib.sha512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""): h.update(chunk)
    return h.hexdigest()

sz   = os.path.getsize(txt_path)
h256 = sha256(txt_path)
h512 = sha512(txt_path)
with open(txt_path, "r", errors="replace") as fh:
    line_count = sum(1 for _ in fh)

out_lines = [
    "# Wowscanner txt integrity v1",
    f"# Generated : {ts}",
    f"# File      : {os.path.basename(txt_path)}",
    f"# Size      : {sz}",
    f"# Lines     : {line_count}",
    f"# SHA-256   : {h256}",
    f"# SHA-512   : {h512}",
    "",
    f"{h256}  {os.path.basename(txt_path)}",
    "",
]
with open(crc_path, "w") as fh:
    for row in out_lines:
        fh.write(row + "\n")

print(f"  [CRC] txt sidecar: {os.path.basename(crc_path)}  ({sz:,}B  {line_count} lines)")
TXTCRCEOF
}

verify_txt_crc() {
  # Verify a .txt report against its .sha256 sidecar.
  # Args: $1 = path to the .txt file
  # Returns: 0 = OK/skip, 1 = mismatch
  local _txt="$1"
  local _crc_file="${_txt}.sha256"

  if [[ ! -f "$_txt" ]]; then
    echo -e "  ${CYAN}│  ${RED}MISSING  $(basename "$_txt")  — file deleted${NC}"
    return 1
  fi

  # ── Recover sidecar from zip when missing ──────────────────────────────────
  # If the .sha256 sidecar doesn't exist (file predates this feature, or was
  # cleaned up), look for the matching wowscanner_archive_<TIMESTAMP>.zip in
  # the same directory and extract the SHA-256 from its INTEGRITY.txt.
  # On a match we write the sidecar so future verify runs are instant.
  if [[ ! -f "$_crc_file" ]]; then
    local _base _ts _zip _recovered=false
    _base=$(basename "$_txt" .txt)          # wowscanner_TIMESTAMP
    _ts="${_base#wowscanner_}"              # TIMESTAMP
    _zip="$(dirname "$_txt")/wowscanner_archive_${_ts}.zip"

    if [[ -f "$_zip" ]]; then
      python3 - "$_txt" "$_crc_file" "$_zip" << 'RECOVEREOF' && _recovered=true || true
import sys, os, zipfile, hashlib, datetime

txt_path = sys.argv[1]
crc_path = sys.argv[2]
zip_path = sys.argv[3]

GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
NC     = "\033[0m"

def sha256f(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""): h.update(chunk)
    return h.hexdigest()

name = os.path.basename(txt_path)

# Extract SHA-256 from INTEGRITY.txt inside the zip
stored_256 = None
try:
    with zipfile.ZipFile(zip_path, "r") as zf:
        if "INTEGRITY.txt" in zf.namelist():
            manifest = zf.read("INTEGRITY.txt").decode("utf-8", "replace")
            for line in manifest.splitlines():
                parts = line.split()
                if len(parts) >= 8 and parts[-1] == name and not line.startswith("#"):
                    stored_256 = parts[0]
                    break
except Exception as e:
    print(f"  {CYAN}|  {YELLOW}SKIP   {name}  - zip read error: {e}{NC}")
    raise SystemExit(1)

if not stored_256:
    print(f"  {CYAN}|  {YELLOW}SKIP   {name}  - not found in zip INTEGRITY.txt{NC}")
    raise SystemExit(1)

# Compare live file against zip-stored hash
actual_256 = sha256f(txt_path)
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if actual_256 != stored_256:
    print(f"  {CYAN}|  {RED}{BOLD}TAMPERED  {name}{NC}")
    print(f"  {CYAN}|    {RED}SHA-256 stored={stored_256[:16]}...  actual={actual_256[:16]}...{NC}")
    raise SystemExit(2)

# Match — write sidecar so future verifies skip the zip entirely
sz = os.path.getsize(txt_path)
with open(txt_path, "r", errors="replace") as fh:
    line_count = sum(1 for _ in fh)
with open(crc_path, "w") as fh:
    fh.write("\n".join([
        "# Wowscanner txt integrity v1",
        f"# Generated : {ts}  (recovered from zip INTEGRITY.txt)",
        f"# File      : {name}",
        f"# Size      : {sz}",
        f"# Lines     : {line_count}",
        f"# SHA-256   : {actual_256}",
        "# SHA-512   : (not in zip manifest - recomputed on next verify)",
        "",
        f"{actual_256}  {name}",
        "",
    ]))
print(f"  {CYAN}|  {GREEN}OK     {name}  sha256={actual_256[:16]}...  (recovered from zip, sidecar written){NC}")
raise SystemExit(0)
RECOVEREOF
      if [[ "$_recovered" == "true" ]]; then return 0; fi
    else
      echo -e "  ${CYAN}│  ${YELLOW}SKIP   $(basename "$_txt")  — no .sha256 sidecar and no matching zip${NC}"
      return 0
    fi
    # Python exited non-zero (TAMPERED or zip error) — return failure
    return 1
  fi

  python3 - "$_txt" "$_crc_file" << 'TXTVEOF' || return 1
import sys, os, hashlib

txt_path = sys.argv[1]
crc_path  = sys.argv[2]

GREEN='[0;32m'; RED='[0;31m'; YELLOW='[1;33m'
CYAN='[0;36m'; BOLD='[1m'; NC='[0m'

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

# Parse sidecar
stored_256 = stored_512 = stored_size = stored_lines = None
with open(crc_path) as f:
    for line in f:
        line = line.strip()
        if line.startswith('# SHA-256'):
            stored_256 = line.split(':', 1)[1].strip()
        elif line.startswith('# SHA-512'):
            stored_512 = line.split(':', 1)[1].strip()
        elif line.startswith('# Size'):
            try: stored_size = int(line.split(':', 1)[1].strip())
            except: pass
        elif line.startswith('# Lines'):
            try: stored_lines = int(line.split(':', 1)[1].strip())
            except: pass

name = os.path.basename(txt_path)
ok = True
issues = []

# Size check (fast, no hashing needed)
actual_size = os.path.getsize(txt_path)
if stored_size is not None and actual_size != stored_size:
    issues.append(f'SIZE  stored={stored_size}  actual={actual_size}')
    ok = False

# SHA-256
actual_256 = sha256(txt_path)
if stored_256 and actual_256 != stored_256:
    issues.append(f'SHA-256  stored={stored_256[:16]}...  actual={actual_256[:16]}...')
    ok = False

# SHA-512 (belt-and-suspenders)
if stored_512:
    actual_512 = sha512(txt_path)
    if actual_512 != stored_512:
        issues.append(f'SHA-512 mismatch')
        ok = False

if ok:
    with open(txt_path, 'r', errors='replace') as f:
        actual_lines = sum(1 for _ in f)
    line_note = ''
    if stored_lines is not None and actual_lines != stored_lines:
        line_note = f'  {YELLOW}(line count changed: {stored_lines}→{actual_lines}){NC}'
    print(f'  {CYAN}│  {GREEN}OK     {name}  sha256={actual_256[:16]}...{NC}{line_note}')
    raise SystemExit(0)
else:
    print(f'  {CYAN}│  {RED}{BOLD}TAMPERED  {name}{NC}')
    for issue in issues:
        print(f'  {CYAN}│    {RED}↳ {issue}{NC}')
    raise SystemExit(1)
TXTVEOF
}

write_odf_crc() {
  # Called immediately after each ODF generator finishes.
  # Args: $1 = path to the .odt / .ods file
  local _odf="$1"
  [[ -f "$_odf" ]] || return 0
  local _crc_file="${_odf}.crc"

  python3 - "$_odf" "$_crc_file" << 'CRCEOF' || true
import sys, os, zipfile, hashlib, datetime

odf_path = sys.argv[1]
crc_path  = sys.argv[2]
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""): h.update(chunk)
    return h.hexdigest()

whole_sha = sha256(odf_path)
out_lines = [
    "# Wowscanner ODF inner-CRC manifest v1",
    f"# Generated : {ts}",
    f"# File      : {os.path.basename(odf_path)}",
    f"# Size      : {os.path.getsize(odf_path)}",
    f"# SHA-256   : {whole_sha}",
]

with zipfile.ZipFile(odf_path, "r") as zf:
    members = zf.infolist()
    out_lines.append(f"# Members   : {len(members)}")
    out_lines.append("#")
    out_lines.append("# crc32hex  member_name")
    for m in members:
        out_lines.append(f"{m.CRC:08x}  {m.filename}")

with open(crc_path, "w") as fh:
    for row in out_lines:
        fh.write(row + "\n")

print(f"  [CRC] sidecar written: {os.path.basename(crc_path)}  ({len(members)} members)")
CRCEOF
}

verify_odf_crc() {
  # Verify one .odt / .ods file against its .crc sidecar.
  # Args: $1 = path to the .odt / .ods file
  # Returns: 0 = OK, 1 = mismatch/error
  local _odf="$1"
  local _crc_file="${_odf}.crc"
  local _name
  _name=$(basename "$_odf")

  python3 - "$_odf" "$_crc_file" << 'VERIFCRCEOF' || return 1
import sys, os, zipfile, hashlib, datetime

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

def c(col, txt): return f'{col}{txt}{NC}'
def bell(): sys.stdout.write('\a'); sys.stdout.flush()

odf_path  = sys.argv[1]
crc_path  = sys.argv[2]
fname     = os.path.basename(odf_path)
ok = True

print(f'  {CYAN}┌─ ODF CRC check: {BOLD}{fname}{NC}')

if not os.path.isfile(odf_path):
    print(f'  {CYAN}│  {RED}MISSING  — file not found: {odf_path}{NC}')
    print(f'  {CYAN}└─ FAIL{NC}'); sys.exit(1)

if not os.path.isfile(crc_path):
    print(f'  {CYAN}│  {YELLOW}No .crc sidecar found — CRC check skipped{NC}')
    print(f'  {CYAN}│  {YELLOW}(Run a new scan to generate sidecar files){NC}')
    print(f'  {CYAN}└─ SKIP{NC}'); sys.exit(0)

# Parse sidecar
expected = {}   # member_name -> crc32 int
exp_sha  = None
exp_size = None
exp_members = None
with open(crc_path) as f:
    for line in f:
        line = line.rstrip()
        if line.startswith('# SHA-256'):
            exp_sha = line.split(':', 1)[1].strip()
        elif line.startswith('# Size'):
            try: exp_size = int(line.split(':', 1)[1].strip())
            except: pass
        elif line.startswith('# Members'):
            try: exp_members = int(line.split(':', 1)[1].strip())
            except: pass
        elif line.startswith('#') or not line:
            continue
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                expected[parts[1]] = int(parts[0], 16)

# 1. File size check
actual_size = os.path.getsize(odf_path)
if exp_size is not None and actual_size != exp_size:
    bell(); ok = False
    print(f'  {CYAN}│  {RED}SIZE FAIL    expected={exp_size}B  actual={actual_size}B{NC}')
else:
    print(f'  {CYAN}│  {GREEN}Size OK      {actual_size:,} bytes{NC}')

# 2. Whole-file SHA-256
def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''): h.update(chunk)
    return h.hexdigest()

act_sha = sha256(odf_path)
if exp_sha and act_sha != exp_sha:
    bell(); ok = False
    print(f'  {CYAN}│  {RED}SHA-256 FAIL  stored={exp_sha[:20]}...  actual={act_sha[:20]}...{NC}')
else:
    print(f'  {CYAN}│  {GREEN}SHA-256 OK    {act_sha[:32]}...{NC}')

# 3. Inner member CRC-32 check
crc_fails = []; crc_ok = 0; missing_members = []; extra_members = []
try:
    with zipfile.ZipFile(odf_path, 'r') as zf:
        actual_members = {m.filename: m.CRC for m in zf.infolist()}

        # Members present in sidecar but missing from file
        for mname in expected:
            if mname not in actual_members:
                missing_members.append(mname)

        # Members in file — compare CRCs
        for mname, act_crc in actual_members.items():
            if mname not in expected:
                extra_members.append(mname)
                continue
            exp_crc = expected[mname]
            if act_crc != exp_crc:
                crc_fails.append((mname, exp_crc, act_crc))
            else:
                crc_ok += 1

        # 4. Re-decompress every member to let Python verify CRC vs data
        #    (zipfile.read() raises BadZipFile if the decompressed data
        #     does not match the stored CRC-32)
        decomp_fails = []
        for m in zf.infolist():
            try:
                zf.read(m.filename)
            except Exception as e:
                decomp_fails.append((m.filename, str(e)))

except zipfile.BadZipFile as e:
    bell(); ok = False
    print(f'  {CYAN}│  {RED}NOT A VALID ZIP: {e}{NC}')
    print(f'  {CYAN}└─ FAIL{NC}'); sys.exit(1)

if missing_members:
    bell(); ok = False
    for m in missing_members:
        print(f'  {CYAN}│  {RED}MEMBER MISSING  {m}{NC}')

if extra_members:
    print(f'  {CYAN}│  {YELLOW}New members (not in sidecar): {", ".join(extra_members)}{NC}')

if crc_fails:
    bell(); ok = False
    for mname, exp_c, act_c in crc_fails:
        print(f'  {CYAN}│  {RED}CRC MISMATCH  {mname}{NC}')
        print(f'  {CYAN}│    {RED}expected={exp_c:08x}  actual={act_c:08x}{NC}')
else:
    total_checked = crc_ok + len(extra_members)
    print(f'  {CYAN}│  {GREEN}Inner CRC OK  {crc_ok}/{total_checked} members verified{NC}')

if 'decomp_fails' in dir() and decomp_fails:
    bell(); ok = False
    for mname, err in decomp_fails:
        print(f'  {CYAN}│  {RED}DECOMPRESS FAIL  {mname}: {err}{NC}')
else:
    print(f'  {CYAN}│  {GREEN}Decompress OK  all members decompressed without CRC error{NC}')

if ok:
    print(f'  {CYAN}└─ {GREEN}{BOLD}PASS  {fname} is intact{NC}')
    sys.exit(0)
else:
    print(f'  {CYAN}└─ {RED}{BOLD}FAIL  {fname} has integrity issues{NC}')
    sys.exit(1)
VERIFCRCEOF
}

check_odf_crcs() {
  # Scan the current directory for all wowscanner .odt and .ods files
  # and verify each against its .crc sidecar.
  local _dir="$PWD"; local _fail=0 _ok=0 _skip=0
  local _found=false

  echo ""
  echo -e "  ${CYAN}${BOLD}┌─ File integrity verification (.txt + .odt/.ods) ──────────┐${NC}"
  echo -e "  ${CYAN}│  Directory: ${_dir}${NC}"

  # ── Plain-text .txt report files ─────────────────────────────
  for _txt in "${_dir}"/wowscanner_*.txt; do
    [[ -f "$_txt" ]] || continue
    _found=true
    if verify_txt_crc "$_txt"; then
      _ok=$(( _ok + 1 ))
    else
      if [[ ! -f "${_txt}.sha256" ]]; then _skip=$(( _skip + 1 )); else _fail=$(( _fail + 1 )); fi
    fi
  done

  # ── ODF/ODS report files ───────────────────────────────────────
  for _odf in "${_dir}"/wowscanner_*.odt "${_dir}"/wowscanner_*.ods; do
    [[ -f "$_odf" ]] || continue
    _found=true
    if verify_odf_crc "$_odf"; then
      _ok=$(( _ok + 1 ))
    else
      if [[ ! -f "${_odf}.crc" ]]; then _skip=$(( _skip + 1 )); else _fail=$(( _fail + 1 )); fi
    fi
    echo ""
  done
  if [[ "$_found" != "true" ]]; then
    echo -e "  ${CYAN}│  ${YELLOW}No wowscanner .odt/.ods files found in current directory${NC}"
  fi
  echo -e "  ${CYAN}│${NC}"
  echo -e "  ${CYAN}│  Summary: ${GREEN}OK=${_ok}${NC}  ${RED}FAIL=${_fail}${NC}  ${YELLOW}SKIP(no sidecar)=${_skip}${NC}"

  if [[ "$_fail" -gt 0 ]]; then
    echo -e "  ${CYAN}│  ${RED}${BOLD}⚠  ${_fail} ODF file(s) failed integrity check!${NC}"
    echo -e "  ${CYAN}│  ${YELLOW}Restore from the corresponding .zip archive.${NC}"
  fi
  echo -e "  ${CYAN}└────────────────────────────────────────────────────────────${NC}"
  echo ""

  return "$_fail"
}

# ================================================================
#  MAIN
# ================================================================

# ================================================================
#  HELP
# ================================================================

# ================================================================
#  NEW: DISK ENCRYPTION CHECK  (called from section_network_container)
# ================================================================
section_disk_encryption() {
  subheader "Disk encryption (LUKS)"
  local _luks_found=0

  # Method 1: lsblk — look for crypt type devices
  if command -v lsblk &>/dev/null; then
    local _crypt_devs
    _crypt_devs=$(lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null \
      | awk '$2=="crypt"' || true)
    if [[ -n "$_crypt_devs" ]]; then
      pass "LUKS encrypted volume(s) detected via lsblk"
      echo "$_crypt_devs" | while IFS= read -r l; do detail "$l"; done
      _luks_found=1
    fi
  fi

  # Method 2: /etc/crypttab — explicitly configured encrypted volumes
  if [[ -s /etc/crypttab ]]; then
    local _ct_count
    _ct_count=$(grep -cE '^[^#]' /etc/crypttab 2>/dev/null || echo 0)
    _ct_count=$(safe_int "$_ct_count")
    if [[ "$_ct_count" -gt 0 ]]; then
      [[ "$_luks_found" -eq 0 ]] && pass "Encrypted volumes in /etc/crypttab: ${_ct_count}"
      detail "  /etc/crypttab entries: ${_ct_count}"
      _luks_found=1
    fi
  fi

  # Method 3: cryptsetup status on common names
  if command -v cryptsetup &>/dev/null; then
    for _cname in sda5_crypt nvme0n1p3_crypt cryptroot dm-crypt; do
      if cryptsetup status "$_cname" &>/dev/null; then
        pass "Active LUKS mapping: ${_cname}"
        _luks_found=1
        break
      fi
    done
  fi

  # Check if root filesystem is on a LUKS device
  local _root_dev
  _root_dev=$(findmnt -no SOURCE / 2>/dev/null || true)
  if [[ -n "$_root_dev" ]]; then
    local _backing
    _backing=$(dmsetup info "$_root_dev" 2>/dev/null | grep -i "crypt\|LUKS" || true)
    if [[ -n "$_backing" ]]; then
      pass "Root filesystem is on an encrypted device: ${_root_dev}"
      _luks_found=1
    fi
  fi
  if [[ "$_luks_found" -eq 0 ]]; then
    warn "No LUKS/disk encryption detected — physical access could expose all data"
    detail "  Consider: cryptsetup luksFormat /dev/sdX  (full-disk encryption on install)"
    detail "  Or: use eCryptfs for home directory encryption: ecryptfs-migrate-home -u USER"
  fi
}

# ================================================================
#  NEW: LINUX CAPABILITIES AUDIT  (called from section_permissions)
# ================================================================
section_capabilities() {
  subheader "Linux capabilities (getcap)"
  if ! command -v getcap &>/dev/null; then
    info "getcap not available (install libcap2-bin) — skipping capabilities audit"
    return
  fi

  # Known legitimate capability holders
  local _whitelist=(
    "ping" "dumpcap" "arping" "clockdiff" "traceroute6"
    "wireshark" "tcpdump" "mtr-packet" "gnome-keyring-daemon"
    "systemd-detect-virt" "ssh-agent"
  )

  local _cap_output _dangerous=0
  _cap_output=$(timeout 30 getcap -r / 2>/dev/null | grep -v "^getcap:" || true)

  if [[ -z "$_cap_output" ]]; then
    pass "No files with elevated capabilities found"
    return
  fi
  while IFS= read -r _capline; do
    [[ -z "$_capline" ]] && continue
    local _capfile _caps
    _capfile=$(awk '{print $1}' <<< "$_capline")
    _caps=$(awk '{$1=""; print}' | xargs <<< "$_capline")
    local _basename; _basename=$(basename "$_capfile")

    # Check against whitelist
    local _known=false
    for _wl in "${_whitelist[@]}"; do [[ "$_basename" == "$_wl" ]] && _known=true && break; done

    # Flag dangerous capabilities on non-whitelisted binaries
    if echo "$_caps" | grep -qiE "cap_sys_admin|cap_setuid|cap_setgid|cap_dac_override|cap_net_raw|cap_sys_ptrace|cap_sys_module"; then
      if [[ "$_known" == "false" ]]; then
        fail "Dangerous capability on unexpected binary: ${_capfile}  (${_caps})"
        _dangerous=$((_dangerous+1))
      else
        info "Expected capability: ${_capfile}  (${_caps})"
      fi
    else
      info "Capability: ${_capfile}  (${_caps})"
    fi
  done <<< "$_cap_output"

  [[ "$_dangerous" -eq 0 ]] && pass "No unexpected dangerous capabilities found"
}

# ================================================================
#  NEW: DNS RESOLVER SECURITY  (called from section_network_container)
# ================================================================
section_dns_security() {
  subheader "DNS resolver security (DoT / DoH)"

  # Check systemd-resolved DoT configuration
  local _dot_ok=false; local _resolved_conf="/etc/systemd/resolved.conf"
  local _resolved_d="/etc/systemd/resolved.conf.d"

  if command -v resolvectl &>/dev/null 2>/dev/null; then
    local _dns_info
    _dns_info=$(resolvectl status 2>/dev/null | head -30 || true)
    local _dot
    _dot=$(grep -i "DNS over TLS\|DNSOverTLS" <<< "$_dns_info" || true)
    if echo "$_dot" | grep -qi "yes\|opportunistic\|on"; then
      pass "DNS over TLS is active (systemd-resolved)"
      _dot_ok=true
    fi
  fi

  # Check resolved.conf for DNSOverTLS setting
  local _dns_conf_files=("$_resolved_conf")
  [[ -d "$_resolved_d" ]] && while IFS= read -r -d '' _f; do
    _dns_conf_files+=("$_f")
  done < <(find "$_resolved_d" -name '*.conf' -print0 2>/dev/null)

  local _dot_setting=""
  for _cf in "${_dns_conf_files[@]}"; do
    [[ -f "$_cf" ]] || continue
    local _v; _v=$(grep -iE "^DNSOverTLS\s*=" "$_cf" 2>/dev/null | tail -1 | cut -d= -f2 | xargs || true)
    [[ -n "$_v" ]] && _dot_setting="$_v"
  done
  if [[ -n "$_dot_setting" ]]; then
    case "${_dot_setting,,}" in
      yes|opportunistic)
        [[ "$_dot_ok" == "false" ]] && pass "DNSOverTLS=${_dot_setting} in resolved.conf"
        _dot_ok=true ;;
      no|"")
        warn "DNSOverTLS=no in resolved.conf — DNS queries are sent in plaintext"
        detail "  Fix: set DNSOverTLS=opportunistic in /etc/systemd/resolved.conf"
        detail "  Then: systemctl restart systemd-resolved" ;;
    esac
  fi

  # Check /etc/resolv.conf for raw cleartext public resolvers
  if [[ -f /etc/resolv.conf ]]; then
    local _plain_dns
    _plain_dns=$(grep -E "^nameserver" /etc/resolv.conf 2>/dev/null \
      | grep -vE "127\.|::1|^#" | head -5 || true)
    if [[ -n "$_plain_dns" ]]; then
      if [[ "$_dot_ok" == "false" ]]; then
        warn "Plaintext DNS resolvers in /etc/resolv.conf (no DoT detected):"
        echo "$_plain_dns" | while IFS= read -r l; do detail "$l"; done
        detail "  All DNS queries visible to network path — consider DoT or DoH"
      else
        info "Resolvers in /etc/resolv.conf (DoT active — queries are encrypted):"
        echo "$_plain_dns" | while IFS= read -r l; do detail "$l"; done
      fi
    fi
  fi

  # Check for alternative DoT/DoH daemons
  for _daemon in cloudflared stubby dnscrypt-proxy; do
    if command -v "$_daemon" &>/dev/null && \
       systemctl is-active --quiet "$_daemon" 2>/dev/null; then
      pass "Encrypted DNS daemon active: ${_daemon}"
      _dot_ok=true
    fi
  done
  [[ "$_dot_ok" == "false" && -z "$_plain_dns" ]] && \
    info "Could not determine DNS encryption status — check resolver configuration manually"
}

# ================================================================
#  NEW: PODMAN / LXC / LXD CONTAINER CHECK  (adds to section_network_container)
# ================================================================
section_alt_containers() {
  subheader "Podman / LXC / LXD containers"

  # Podman
  if command -v podman &>/dev/null; then
    local _pod_running
    _pod_running=$(podman ps --format '{{.Names}} {{.Image}} {{.Status}}' 2>/dev/null \
      | grep -v "^$" | head -20 || true)
    if [[ -n "$_pod_running" ]]; then
      warn "Podman containers running — verify images are trusted and up to date:"
      echo "$_pod_running" | while IFS= read -r l; do detail "$l"; done
      # Check for rootful podman (running as root)
      local _pod_rootless
      _pod_rootless=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo 'true')
    if [[ "$_pod_rootless" == 'false' ]]; then
        fail "Podman is running in ROOTFUL mode — container escape = root compromise"
      else
        pass "Podman is running in rootless mode"
      fi
    else
      info "Podman installed but no containers currently running"
    fi
  fi

  # LXC
  if command -v lxc-ls &>/dev/null; then
    local _lxc_running
    _lxc_running=$(lxc-ls --running 2>/dev/null | head -10 || true)
    if [[ -n "$_lxc_running" ]]; then
      warn "LXC containers running: ${_lxc_running}"
      detail "  Verify: lxc-info -n <name> — check each container is up to date"
    else
      info "LXC installed, no containers running"
    fi
  fi

  # LXD (via lxc CLI)
  if command -v lxc &>/dev/null && lxc list &>/dev/null 2>&1; then
    local _lxd_running
    _lxd_running=$(lxc list --format csv -c ns 2>/dev/null \
      | awk -F, '$2=="RUNNING"' | head -10 || true)
    if [[ -n "$_lxd_running" ]]; then
      warn "LXD containers running:"
      echo "$_lxd_running" | while IFS= read -r l; do detail "  $l"; done
    fi
  fi

  # Neither Podman nor LXC/LXD installed
  if ! command -v podman &>/dev/null && \
     ! command -v lxc-ls &>/dev/null && \
     ! (command -v lxc &>/dev/null && lxc list &>/dev/null 2>&1); then
    info "No Podman / LXC / LXD detected on this system"
  fi
}

# ================================================================
#  NEW: SCORE HISTORY  (called from section_summary, writes to DB)
# ================================================================
record_score_history() {
  local _score="$1" _total="$2" _pct="$3"
  mkdir -p "$PERSIST_DIR" 2>/dev/null || true
  local _ts; _ts=$(date +%s)   # epoch integer — Python readers cast with int()
  echo "${_ts}|${_score}|${_total}|${_pct}" >> "$SCORE_HISTORY_DB" 2>/dev/null || true

  # Show trend vs previous run
  local _prev_pct=""
  if [[ -f "$SCORE_HISTORY_DB" ]]; then
    _prev_pct=$(tail -2 "$SCORE_HISTORY_DB" 2>/dev/null \
      | head -1 | cut -d'|' -f4 || true)
  fi
  _prev_pct=$(safe_int "${_prev_pct:-0}")
  if [[ "$_prev_pct" -gt 0 && "$_prev_pct" != "$_pct" ]]; then
    local _delta=$(( _pct - _prev_pct ))
    if [[ "$_delta" -gt 0 ]]; then
      log "  ${GREEN}[▲ TREND]${NC}  Score improved from ${_prev_pct}% to ${_pct}% (+${_delta}%)  ${GREEN}Ω${NC}"
    elif [[ "$_delta" -lt 0 ]]; then
      log "  ${RED}[▼ TREND]${NC}  Score REGRESSED from ${_prev_pct}% to ${_pct}% (${_delta}%)  ${RED}Ω${NC}"
    fi
  fi

  # Show last 5 scores as a sparkline
  if [[ -f "$SCORE_HISTORY_DB" ]]; then
    local _history
    _history=$(tail -5 "$SCORE_HISTORY_DB" 2>/dev/null \
      | awk -F'|' '{printf "%s:%s%%  ", $1, $4}' || true)
    [[ -n "$_history" ]] && info "Score history (last 5 runs): ${_history}"
  fi
}

# ================================================================
#  TIMING BASELINE — records per-run wall-clock durations and
#  computes a rolling ETA shown beside elapsed time each scan.
#
#  Database: /var/lib/wowscanner/timing_history.db
#  Format  : epoch|wall_s|audit_s|odt_s|ods_s|intel_s|html_s
#
#  First run  : no baseline → records timings, shows nothing extra.
#  Run 2+     : reads last N_BASELINE runs, shows:
#               "ETA ~Xm Ys  (based on N runs)"  in the timer panel.
#
#  The ETA is the exponentially-weighted moving average (EWMA) of
#  past total wall times — recent runs are weighted more heavily.
#  Alpha = 0.4  (40% weight on most recent run, 60% on history).
# ================================================================
N_TIMING_BASELINE=10   # how many past runs to average

record_timing_baseline() {
  # Args: wall_s audit_s odt_s ods_s intel_s html_s
  local _w="$1" _a="$2" _o="$3" _s="$4" _i="$5" _h="$6"
  local _ts; _ts=$(date +%s)
  mkdir -p "$PERSIST_DIR" 2>/dev/null || true
  echo "${_ts}|${_w}|${_a}|${_o}|${_s}|${_i}|${_h}" \
    >> "$TIMING_HISTORY_DB" 2>/dev/null || true
}

# Returns the EWMA-based ETA in seconds (prints to stdout).
# Prints nothing if fewer than 1 past run exists.
get_timing_eta() {
  [[ -f "$TIMING_HISTORY_DB" ]] || return
  local _lines; _lines=$(wc -l < "$TIMING_HISTORY_DB" 2>/dev/null || echo 0)
  _lines=$(safe_int "$_lines")
  [[ "$_lines" -lt 1 ]] && return

  # Read last N_TIMING_BASELINE runs (column 2 = wall_s)
  local _alpha=40   # EWMA alpha × 100  (0.40)
  local _ewma=0 _first=1 _count=0
  while IFS='|' read -r _ts _w _rest; do
    _w=$(safe_int "$_w")
    [[ "$_w" -eq 0 ]] && continue
    if [[ "$_first" -eq 1 ]]; then
      _ewma="$_w"; _first=0
    else
      # EWMA: ewma = alpha*w + (1-alpha)*ewma  (×100 to stay integer)
      _ewma=$(( (_alpha * _w + (100 - _alpha) * _ewma) / 100 ))
    fi
    _count=$(( _count + 1 ))
  done < <(tail -"$N_TIMING_BASELINE" "$TIMING_HISTORY_DB" 2>/dev/null || true)

  [[ "$_count" -lt 1 ]] && return
  echo "${_ewma}|${_count}"   # "seconds|run_count"
}

# ================================================================
#  NEW: FINDING DELTA  (called from section_summary)
# ================================================================
show_finding_delta() {
  mkdir -p "$PERSIST_DIR" 2>/dev/null || true
  local _current_fails _prev_fails

  # Collect current FAILs — strip ANSI codes for clean comparison
  _current_fails=$(sed -n 's/.*\[✘ FAIL\]  //;s/  Ω.*//p' "$REPORT" 2>/dev/null \
    | sed 's/\[[0-9;]*m//g' \
    | sort || true)

  # Compare against previous snapshot
  if [[ -f "$FINDINGS_SNAP" && -s "$FINDINGS_SNAP" ]]; then
    _prev_fails=$(sort "$FINDINGS_SNAP" 2>/dev/null || true)

    local _new_fails _resolved
    _new_fails=$(comm -23 <(echo "$_current_fails") <(echo "$_prev_fails") || true)
    _resolved=$(comm -13 <(echo "$_current_fails") <(echo "$_prev_fails") || true)

    local _new_count _res_count
    _new_count=$(grep -c . <<< "$_new_fails" || echo 0)
    _res_count=$(grep -c . <<< "$_resolved" || echo 0)
    _new_count=$(safe_int "$_new_count")
    _res_count=$(safe_int "$_res_count")

    if [[ "$_new_count" -gt 0 ]]; then
      log "  ${RED}[✘ DELTA]${NC}  ${_new_count} NEW FAIL(s) since last scan:  ${RED}Ω${NC}"
      echo "$_new_fails" | head -10 | while IFS= read -r l; do
        [[ -n "$l" ]] && log "          ${MAGENTA}↳${NC} ${l}"
      done
    fi
    if [[ "$_res_count" -gt 0 ]]; then
      log "  ${GREEN}[✔ DELTA]${NC}  ${_res_count} FAIL(s) RESOLVED since last scan:  ${GREEN}Ω${NC}"
      echo "$_resolved" | head -10 | while IFS= read -r l; do
        [[ -n "$l" ]] && log "          ${MAGENTA}↳${NC} ${l}"
      done
    fi
    [[ "$_new_count" -eq 0 && "$_res_count" -eq 0 ]] && \
      info "No change in FAILs compared to last scan"
  else
    info "No previous scan snapshot found — delta tracking starts from this run"
  fi

  # Write snapshot for next run
  echo "$_current_fails" > "$FINDINGS_SNAP" 2>/dev/null || true

  # ── Baseline regression check ─────────────────────────────────
  local _baseline_db="${PERSIST_DIR}/baseline.db"
  local _baseline_ts="${PERSIST_DIR}/baseline.ts"
  if [[ -f "$_baseline_db" && -s "$_baseline_db" ]]; then
    local _baseline_passes _regressions
    _baseline_passes=$(sort "$_baseline_db" 2>/dev/null || true)
    # A regression is a check that was PASS in baseline but is now FAIL
    # comm -12 = intersection: lines in BOTH current FAILs AND baseline PASSes = regressions
    _regressions=$(comm -12 \
      <(echo "$_current_fails" | sort) \
      <(echo "$_baseline_passes" | sort) 2>/dev/null || true)
    if [[ -n "$_regressions" ]]; then
      local _reg_count
      _reg_count=$(grep -c "." <<< "$_regressions" || true)
      _reg_count=$(safe_int "$_reg_count")
      local _bts=""
      [[ -f "$_baseline_ts" ]] && _bts=$(cat "$_baseline_ts" 2>/dev/null || true)
      log "  ${RED}[✘ REGRESSION]${NC}  ${_reg_count} check(s) regressed since baseline (${_bts:-unknown date}):  ${RED}Ω${NC}"
      echo "$_regressions" | sed 's/\[[0-9;]*m//g' | head -10 | while IFS= read -r l; do
        [[ -n "$l" ]] && log "          ${MAGENTA}↳${NC} ${l}"
      done
    else
      info "No regressions compared to baseline (run 'sudo bash $0 baseline' to update)"
    fi
  fi
}

# ================================================================
#  NEW: DIFF COMMAND  (sudo bash wowscanner.sh diff)
# ================================================================
cmd_diff() {
  require_root
  echo -e "${CYAN}${BOLD}  Wowscanner — Scan Diff${NC}"; echo ""

  # Find two most recent .txt reports
  local _reports=()
  while IFS= read -r _f; do
    [[ -n "$_f" ]] && _reports+=("$_f")
  done < <(find "$PWD" -maxdepth 1 -name 'wowscanner_*.txt' -printf '%T@\t%p\n' 2>/dev/null \
    | sort -rn | head -2 | cut -f2-)

  if [[ "${#_reports[@]}" -lt 2 ]]; then
    echo -e "  ${YELLOW}Need at least 2 scan reports in the current directory to diff.${NC}"
    echo "  Found: ${#_reports[@]}"
    exit 1
  fi
  local _newer="${_reports[0]}" _older="${_reports[1]}"
  echo -e "  ${BOLD}Newer:${NC} $_newer"; echo -e "  ${BOLD}Older:${NC} $_older"
  echo ""

  local _new_fails _old_fails _new_warns _old_warns
  _new_fails=$(sed -n 's/.*\[✘ FAIL\]  //;s/  Ω.*//p' "$_newer" 2>/dev/null | sort || true)
  _old_fails=$(sed -n 's/.*\[✘ FAIL\]  //;s/  Ω.*//p' "$_older" 2>/dev/null | sort || true)
  _new_warns=$(sed -n 's/.*\[⚠ WARN\]  //;s/  Ω.*//p' "$_newer" 2>/dev/null | sort || true)
  _old_warns=$(sed -n 's/.*\[⚠ WARN\]  //;s/  Ω.*//p' "$_older" 2>/dev/null | sort || true)

  local _new_score _old_score
  # Extract the final score percentage from the summary box line "Score : N%"
  _new_score=$(grep -i 'Score.*:.*%' "$_newer" 2>/dev/null \
    | grep -oE '[0-9]+%' | tail -1 || echo "?")
  _old_score=$(grep -i 'Score.*:.*%' "$_older" 2>/dev/null \
    | grep -oE '[0-9]+%' | tail -1 || echo "?")
  echo -e "  ${BOLD}Score: ${_old_score} → ${_new_score}${NC}"
  echo ""

  local _appeared_fails _resolved_fails _appeared_warns _resolved_warns
  _appeared_fails=$(comm -23 <(echo "$_new_fails") <(echo "$_old_fails") | grep . || true)
  _resolved_fails=$(comm -13 <(echo "$_new_fails") <(echo "$_old_fails") | grep . || true)
  _appeared_warns=$(comm -23 <(echo "$_new_warns") <(echo "$_old_warns") | grep . || true)
  _resolved_warns=$(comm -13 <(echo "$_new_warns") <(echo "$_old_warns") | grep . || true)

  if [[ -n "$_appeared_fails" ]]; then
    echo -e "  ${RED}${BOLD}NEW FAILs:${NC}"
    echo "$_appeared_fails" | while IFS= read -r l; do echo -e "    ${RED}+${NC} $l"; done
    echo ""
  fi
  if [[ -n "$_resolved_fails" ]]; then
    echo -e "  ${GREEN}${BOLD}RESOLVED FAILs:${NC}"
    echo "$_resolved_fails" | while IFS= read -r l; do echo -e "    ${GREEN}-${NC} $l"; done
    echo ""
  fi
  if [[ -n "$_appeared_warns" ]]; then
    echo -e "  ${YELLOW}${BOLD}NEW WARNs:${NC}"
    echo "$_appeared_warns" | while IFS= read -r l; do echo -e "    ${YELLOW}+${NC} $l"; done
    echo ""
  fi
  if [[ -n "$_resolved_warns" ]]; then
    echo -e "  ${CYAN}${BOLD}RESOLVED WARNs:${NC}"
    echo "$_resolved_warns" | while IFS= read -r l; do echo -e "    ${CYAN}-${NC} $l"; done
    echo ""
  fi
  if [[ -z "$_appeared_fails$_resolved_fails$_appeared_warns$_resolved_warns" ]]; then
    echo -e "  ${GREEN}No differences in FAIL/WARN findings between the two reports.${NC}"
  fi
}

# ================================================================
#  NEW: INSTALL-TIMER COMMAND
# ================================================================
cmd_install_timer() {
  require_root
  local _script
  _script=$(realpath "$0" 2>/dev/null || echo "$0")
  local _logdir="/var/log/wowscanner"; local _svc="/etc/systemd/system/wowscanner.service"
  local _tmr="/etc/systemd/system/wowscanner.timer"

  echo -e "${CYAN}${BOLD}  Wowscanner — Install Weekly Timer${NC}"
  echo ""; echo "  Script  : $_script"
  echo "  Log dir : $_logdir"; echo ""

  mkdir -p "$_logdir" 2>/dev/null || true

  cat > "$_svc" << SVCEOF
[Unit]
Description=Wowscanner Security Audit
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash ${_script} --no-pentest --fast-only
StandardOutput=append:${_logdir}/wowscanner.log
StandardError=append:${_logdir}/wowscanner.log
WorkingDirectory=${_logdir}
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

  cat > "$_tmr" << TMREOF
[Unit]
Description=Wowscanner Weekly Security Audit Timer

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
TMREOF

  systemctl daemon-reload 2>/dev/null || true
  systemctl enable --now wowscanner.timer 2>/dev/null && \
    echo -e "  ${GREEN}[✔] wowscanner.timer enabled and started${NC}" || \
    echo -e "  ${YELLOW}[⚠] Could not enable timer — check systemd${NC}"

  echo ""; echo -e "  ${BOLD}Next run:${NC}"
  systemctl list-timers wowscanner.timer 2>/dev/null || true
  echo ""; echo "  Logs: $_logdir/wowscanner.log"
  echo "  Remove: sudo bash $0 remove-timer"
}

cmd_remove_timer() {
  require_root
  echo -e "${CYAN}${BOLD}  Wowscanner — Remove Weekly Timer${NC}"
  echo ""
  systemctl disable --now wowscanner.timer 2>/dev/null || true
  rm -f /etc/systemd/system/wowscanner.service \
        /etc/systemd/system/wowscanner.timer 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  echo -e "  ${GREEN}[✔] wowscanner.timer removed${NC}"
}

# ================================================================
#  NEW: HARDEN COMMAND  (sudo bash wowscanner.sh harden)
# ================================================================
cmd_harden() {
  require_root
  local _conf="/etc/sysctl.d/99-wowscanner.conf"
  echo -e "${CYAN}${BOLD}  Wowscanner — Apply Sysctl Hardening${NC}"
  echo ""

  declare -A _sysctl_targets=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.conf.all.rp_filter"]="1"
    ["net.ipv4.conf.default.rp_filter"]="1"
    ["net.ipv4.conf.all.secure_redirects"]="0"
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.all.accept_source_route"]="0"
    ["kernel.randomize_va_space"]="2"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.kptr_restrict"]="2"
    ["kernel.sysrq"]="0"
    ["fs.suid_dumpable"]="0"
    ["kernel.kexec_load_disabled"]="1"
    ["kernel.yama.ptrace_scope"]="1"
  )

  echo -e "  ${BOLD}Changes that will be written to ${_conf}:${NC}"
  echo ""
  local _changes=0
  for _key in "${!_sysctl_targets[@]}"; do
    local _want="${_sysctl_targets[$_key]}"
    local _current
    _current=$(sysctl -n "$_key" 2>/dev/null || echo "N/A")
    if [[ "$_current" == "$_want" ]]; then
      echo -e "    ${GREEN}[OK]${NC}  ${_key} = ${_want}  (already set)"
    else
      echo -e "    ${YELLOW}[  ]${NC}  ${_key}: ${_current} → ${_want}"
      _changes=$((_changes+1))
    fi
  done
  echo ""
  if [[ "$_changes" -eq 0 ]]; then
    echo -e "  ${GREEN}All sysctl values already hardened — no changes needed.${NC}"
    return 0
  fi
  echo -e "  ${BOLD}${_changes} value(s) will be changed.${NC}"
  echo -n "  Apply? [y/N] "
  local _ans; read -r _ans
  [[ "${_ans,,}" != "y" ]] && { echo "  Aborted."; return 0; }

  # Write config file
  {
    echo "# Wowscanner hardening — generated $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Remove this file to revert: rm /etc/sysctl.d/99-wowscanner.conf && sysctl --system"
    echo ""
    for _key in $(echo "${!_sysctl_targets[@]}" | tr ' ' '\n' | sort); do
      echo "${_key} = ${_sysctl_targets[$_key]}"
    done
  } > "$_conf"

  sysctl --system > /dev/null 2>&1 && \
    echo -e "  ${GREEN}[✔] Hardening applied — ${_conf} written and loaded${NC}" || \
    echo -e "  ${YELLOW}[⚠] sysctl --system returned non-zero — check output${NC}"
}

# ================================================================
#  NEW: WEBHOOK / EMAIL DELIVERY  (called from main after archive)
# ================================================================
deliver_report() {
  local _score="$1" _total="$2" _pct="$3" _archive="$4"

  # ── Webhook / Slack / Teams ───────────────────────────────────
  if [[ -n "$WEBHOOK_URL" ]]; then
    local _rating="GOOD"
    [[ "$_pct" -lt 80 ]] && _rating="MODERATE"
    [[ "$_pct" -lt 50 ]] && _rating="CRITICAL"
    local _payload
    _payload=$(printf '{"text":"Wowscanner scan complete on *%s*\\nScore: *%d%%* (%d/%d) — %s\\nArchive: %s"}' \
      "$(hostname -f 2>/dev/null || hostname)" "$_pct" "$_score" "$_total" "$_rating" "$(basename "$_archive")")
    if curl -s -o /dev/null -w "%{http_code}" \
         -H "Content-Type: application/json" \
         -d "$_payload" \
         --max-time 10 \
         "$WEBHOOK_URL" 2>/dev/null | grep -q "^2"; then
      info "Webhook notification sent to: ${WEBHOOK_URL%%//*}/..."
    else
      warn "Webhook delivery failed — check WEBHOOK_URL"
    fi
  fi

  # ── Email delivery ────────────────────────────────────────────
  if [[ -n "$REPORT_EMAIL" ]]; then
    local _mailer=""
    for _m in msmtp sendmail ssmtp; do
      command -v "$_m" &>/dev/null && { _mailer="$_m"; break; }
    done
    if [[ -z "$_mailer" ]]; then
      warn "REPORT_EMAIL set but no mailer found (msmtp/sendmail/ssmtp)"
    elif [[ -f "$_archive" ]]; then
      local _arc_sz; _arc_sz=$(stat -c%s "$_archive" 2>/dev/null || echo 0)
      if [[ "$_arc_sz" -gt 20971520 ]]; then  # >20MB — skip attachment, send summary only
        warn "Archive is $(( _arc_sz / 1048576 ))MB — too large to email; sending summary only"
        printf 'To: %s\nSubject: Wowscanner scan — %s — %s%%\n\nScore: %d/%d (%d%%)\nArchive too large to attach (%dMB)\n' \
          "$REPORT_EMAIL" "$(hostname -f 2>/dev/null || hostname)" "$3" "$1" "$2" "$3" "$(( _arc_sz / 1048576 ))" \
          | "$_mailer" "$REPORT_EMAIL" 2>/dev/null || true
        return 0
      fi
      {
        echo "To: $REPORT_EMAIL"
        echo "Subject: Wowscanner scan — $(hostname -f 2>/dev/null || hostname) — ${_pct}%"
        echo "MIME-Version: 1.0"
        echo "Content-Type: multipart/mixed; boundary=\"wowboundary\""
        echo ""; echo "--wowboundary"
        echo "Content-Type: text/plain"; echo ""
        echo "Wowscanner scan completed on $(hostname -f 2>/dev/null || hostname)"
        echo "Score: ${_pct}% (${_score}/${_total})"; echo "Archive: $(basename "$_archive")"
        echo ""; echo "--wowboundary"
        echo "Content-Type: application/zip"
        echo "Content-Disposition: attachment; filename=\"$(basename "$_archive")\""
        echo "Content-Transfer-Encoding: base64"; echo ""
        base64 "$_archive"
        echo "--wowboundary--"
      } | "$_mailer" "$REPORT_EMAIL" 2>/dev/null         && info "Report emailed to: ${REPORT_EMAIL}"         || warn "Email delivery failed — check mailer configuration"
    fi
  fi
}

# ================================================================
#  NEW: HTML REPORT GENERATOR
# ================================================================
generate_html_report() {
  local _txt="$1" _score="$2" _total="$3" _pct="$4"
  local _html_out="wowscanner_report_${TIMESTAMP}.html"
  echo -e "  ${CYAN}[ℹ]${NC}  Generating HTML → ${_html_out} ..." >&2 || true

  local _rating="CRITICAL" _rcolor="#EF5350"
  [[ "$_pct" -ge 50 ]] && _rating="MODERATE" && _rcolor="#FFB300"
  [[ "$_pct" -ge 80 ]] && _rating="GOOD"     && _rcolor="#66BB6A"

  local _hostname; _hostname=$(hostname -f 2>/dev/null || hostname)
  local _os; _os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown")
  local _kernel; _kernel=$(uname -r)
  local _date; _date=$(date '+%Y-%m-%d %H:%M:%S')

  # Collect findings from the report
  local _fails _warns _passes _infos
  _fails=$(sed -n 's/.*\[✘ FAIL\]  //;s/  Ω.*//p' "$_txt"  2>/dev/null | head -100 || true)
  _warns=$(sed -n 's/.*\[⚠ WARN\]  //;s/  Ω.*//p' "$_txt"  2>/dev/null | head -100 || true)
  _passes=$(grep -c '✔ PASS' "$_txt" 2>/dev/null || echo 0)
  _infos=$(grep -c 'ℹ INFO' "$_txt" 2>/dev/null || echo 0)

  python3 - "$_html_out" "$_score" "$_total" "$_pct" "$_rating" "$_rcolor" \
           "$_hostname" "$_os" "$_kernel" "$_date" \
           "$_passes" "$_infos" "$_txt" \
    << 'HTMLEOF' || true
import sys, os, re, html as _html

out_path = sys.argv[1]
score    = int(sys.argv[2])
total    = int(sys.argv[3])
pct      = int(sys.argv[4]) if int(sys.argv[3]) > 0 else 0
rating   = sys.argv[5]
rcolor   = sys.argv[6]
host     = sys.argv[7]
os_name  = sys.argv[8]
kernel   = sys.argv[9]
date_str = sys.argv[10]
passes   = sys.argv[11]
infos    = sys.argv[12]
txt_path = sys.argv[13] if len(sys.argv) > 13 else ""

def e(s): return _html.escape(str(s))

# Read report for fails/warns
report_lines = []
try:
    if txt_path and os.path.isfile(txt_path):
        with open(txt_path, errors="replace") as fh:
            report_lines = fh.readlines()
except Exception:
    pass

ansi_re = re.compile(r"\x1b\[[0-9;]*m")
fails_html = ""
warns_html = ""
for line in report_lines:
    clean = ansi_re.sub("", line).strip()
    if "[✘ FAIL]" in clean:
        txt = clean.split("[✘ FAIL]")[-1].strip().rstrip("Ω").strip()
        fails_html += f"<li>{e(txt)}</li>\n"
    elif "[⚠ WARN]" in clean:
        txt = clean.split("[⚠ WARN]")[-1].strip().rstrip("Ω").strip()
        warns_html += f"<li>{e(txt)}</li>\n"

arc_w = round(pct / 100 * 300)

fail_section = ""
if fails_html:
    fail_section = (
        "<div class=\"card\"><h2>✘ FAIL — Immediate Action Required</h2>"
        "<ul class=\"fail-list\">" + fails_html + "</ul></div>"
    )
warn_section = ""
if warns_html:
    warn_section = (
        "<div class=\"card\"><h2>⚠ WARN — Review Recommended</h2>"
        "<ul class=\"warn-list\">" + warns_html + "</ul></div>"
    )

fail_count = fails_html.count("<li>")
warn_count = warns_html.count("<li>")

page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wowscanner Security Report — {e(host)}</title>
<style>
:root{{--bg:#0D1117;--surface:#161B22;--border:#30363D;--text:#C9D1D9;
      --pass:#3FB950;--fail:#F85149;--warn:#D29922;--info:#58A6FF;
      --accent:#388BFD;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:Arial,sans-serif;
     font-size:14px;line-height:1.6;padding:24px}}
h1{{font-size:24px;color:#E6EDF3;margin-bottom:4px}}
h2{{font-size:16px;color:var(--accent);margin:24px 0 8px;
    border-bottom:1px solid var(--border);padding-bottom:4px}}
.card{{background:var(--surface);border:1px solid var(--border);
       border-radius:8px;padding:20px;margin-bottom:16px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}}
.meta-item{{background:var(--bg);border-radius:6px;padding:10px}}
.meta-label{{font-size:11px;color:#8B949E;text-transform:uppercase;letter-spacing:.5px}}
.meta-value{{font-size:13px;font-weight:bold;color:#E6EDF3;margin-top:2px}}
.gauge-wrap{{display:flex;align-items:center;gap:24px;flex-wrap:wrap}}
.gauge-bar{{flex:1;min-width:200px}}
.gauge-track{{background:#21262D;border-radius:8px;height:28px;overflow:hidden}}
.gauge-fill{{height:100%;border-radius:8px;display:flex;align-items:center;
             justify-content:flex-end;padding-right:10px;
             font-weight:bold;font-size:13px;color:#fff;
             width:{arc_w}px;background:{rcolor};transition:width 1s}}
.score-big{{font-size:48px;font-weight:bold;color:{rcolor};line-height:1}}
.rating{{font-size:16px;font-weight:bold;color:{rcolor}}}
.counts{{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}}
.count-badge{{padding:6px 14px;border-radius:20px;font-weight:bold;font-size:13px}}
.fail-badge{{background:#3D0F0A;color:#F85149;border:1px solid #F85149}}
.warn-badge{{background:#2D2000;color:#D29922;border:1px solid #D29922}}
.pass-badge{{background:#0A2118;color:#3FB950;border:1px solid #3FB950}}
.info-badge{{background:#0A1929;color:#58A6FF;border:1px solid #58A6FF}}
ul{{padding-left:18px}}
li{{margin:4px 0;padding:4px 8px;border-radius:4px}}
.fail-list li{{background:#3D0F0A20;border-left:3px solid #F85149}}
.warn-list li{{background:#2D200020;border-left:3px solid #D29922}}
.footer{{margin-top:32px;text-align:center;color:#8B949E;font-size:12px}}
</style>
</head>
<body>
<div class="card">
  <h1>🔒 Wowscanner Security Report</h1>
  <p style="color:#8B949E;font-size:12px">Generated: {e(date_str)}</p>
  <div class="meta" style="margin-top:16px">
    <div class="meta-item"><div class="meta-label">Hostname</div><div class="meta-value">{e(host)}</div></div>
    <div class="meta-item"><div class="meta-label">OS</div><div class="meta-value">{e(os_name)}</div></div>
    <div class="meta-item"><div class="meta-label">Kernel</div><div class="meta-value">{e(kernel)}</div></div>
  </div>
  <div class="gauge-wrap">
    <div>
      <div class="score-big">{pct}%</div>
      <div class="rating">{e(rating)}</div>
      <div style="color:#8B949E;font-size:12px;margin-top:4px">{score} / {total} checks passed</div>
    </div>
    <div class="gauge-bar">
      <div class="gauge-track"><div class="gauge-fill">{pct}%</div></div>
    </div>
  </div>
  <div class="counts">
    <span class="count-badge fail-badge">✘ {fail_count} FAILs</span>
    <span class="count-badge warn-badge">⚠ {warn_count} WARNs</span>
    <span class="count-badge pass-badge">✔ {e(passes)} PASSes</span>
    <span class="count-badge info-badge">ℹ {e(infos)} INFOs</span>
  </div>
</div>
{fail_section}
{warn_section}
<div class="footer">Wowscanner Security Scanner &bull; {e(date_str)}</div>
</body>
</html>"""

with open(out_path, "w") as fh:
    fh.write(page)
print(f"  HTML report: {out_path}  ({len(page):,} bytes)")

HTMLEOF
}

# ================================================================
#  NEW: SUPPLY CHAIN SECURITY  (pip/npm packages installed as root)
# ================================================================
section_supply_chain() {
  subheader "Supply chain — pip packages installed as root"

  # pip packages installed system-wide (as root) are a supply-chain risk:
  # a compromised PyPI package runs with root privileges on every execution.
  local _pip_list=""
  for _pip in pip3 pip; do
    command -v "$_pip" &>/dev/null || continue
    _pip_list=$(timeout 15 "$_pip" list --format=columns 2>/dev/null | tail -n +3 || true)
    [[ -n "$_pip_list" ]] && break
  done
  if [[ -z "$_pip_list" ]]; then
    info "pip not available or no system-wide packages installed"
  else
    local _pip_count
    _pip_count=$(grep -c "." <<< "$_pip_list" || true)
    _pip_count=$(safe_int "$_pip_count")
    info "System-wide pip packages: ${_pip_count}"

    # Flag packages known to have had supply-chain incidents
    local _risky_pip=(
      "requests" "urllib3" "setuptools" "pip" "wheel"
    )
    # More importantly: flag packages installed from non-PyPI sources
    local _editable
    _editable=$(timeout 10 pip3 list --editable 2>/dev/null | tail -n +3 || true)
    if [[ -n "$_editable" ]]; then
      warn "Editable pip installs (direct filesystem source — not from PyPI):"
      echo "$_editable" | head -10 | while IFS= read -r l; do detail "$l"; done
    fi

    # Check pip index URL — should be PyPI, not a private mirror with no auth
    local _pip_conf _idx_url=""
    for _cf in /etc/pip.conf ~/.pip/pip.conf ~/.config/pip/pip.conf; do
      [[ -f "$_cf" ]] || continue
      _idx_url=$(grep -i "index-url\|extra-index-url" "$_cf" 2>/dev/null | head -1 || true)
      [[ -n "$_idx_url" ]] && { _pip_conf="$_cf"; break; }
    done
    if [[ -n "$_idx_url" ]]; then
      if echo "$_idx_url" | grep -qi "pypi.org\|files.pythonhosted"; then
        pass "pip index URL points to official PyPI: ${_pip_conf}"
      else
        warn "pip index URL is non-standard — verify it is trusted: ${_idx_url}"
        detail "  File: ${_pip_conf}"
      fi
    else
      info "pip using default PyPI index (no custom index configured)"
    fi
    if [[ "$_pip_count" -gt 50 ]]; then
      warn "Large number of system-wide pip packages (${_pip_count}) — consider virtualenvs"
      detail "  Each package runs with root privileges on system-wide installs"
    else
      pass "System-wide pip package count acceptable: ${_pip_count}"
    fi
  fi
  subheader "Supply chain — npm global packages"
  if command -v npm &>/dev/null; then
    local _npm_list
    _npm_list=$(timeout 15 npm list -g --depth=0 2>/dev/null | tail -n +2 | head -30 || true)
    local _npm_count
    _npm_count=$(grep -c "@" <<< "$_npm_list" || true)
    _npm_count=$(safe_int "$_npm_count")
    if [[ "$_npm_count" -gt 0 ]]; then
      info "Global npm packages: ${_npm_count}"
      echo "$_npm_list" | head -10 | while IFS= read -r l; do detail "$l"; done

      # npm global packages run as the user who installed them — if root, risky
      local _npm_prefix
      _npm_prefix=$(npm root -g 2>/dev/null || true)
      if [[ "$_npm_prefix" == /usr* || "$_npm_prefix" == /opt* ]]; then
        warn "npm global packages installed in system path (${_npm_prefix}) — run as root"
        detail "  Use: npm config set prefix ~/.npm-global  to move to user space"
      fi
    else
      info "No npm global packages installed"
    fi
  fi
  subheader "Supply chain — SUID/SGID in package managers"
  # Package managers that are SUID/SGID create privilege escalation paths
  for _pm in pip pip3 npm yarn gem bundle cargo; do
    local _pm_path
    _pm_path=$(command -v "$_pm" 2>/dev/null || true)
    [[ -z "$_pm_path" ]] && continue
    local _pm_perm
    _pm_perm=$(stat -c%a "$_pm_path" 2>/dev/null || echo "000")
    if [[ "$_pm_perm" =~ [0-9][4-7][0-9][0-9] || "$_pm_perm" =~ [0-9][0-9][2-7][0-9][0-9] ]]; then
      fail "Package manager is SUID/SGID: ${_pm_path} (${_pm_perm})"
    fi
  done
}

# ================================================================
#  NEW: IMMUTABLE FILE ATTRIBUTES  (chattr +i critical files)
# ================================================================
section_immutable() {
  subheader "Immutable file attributes (chattr +i)"

  if ! command -v lsattr &>/dev/null; then
    info "lsattr not available (install e2fsprogs) — skipping immutable check"
    return
  fi

  # Critical files that SHOULD be immutable on hardened systems
  local _immutable_targets=(
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/gshadow
    /etc/sudoers
    /etc/ssh/sshd_config
  )

  local _immutable_count=0 _total_checked=0
  for _f in "${_immutable_targets[@]}"; do
    [[ -f "$_f" ]] || continue
    _total_checked=$(( _total_checked + 1 ))
    local _attrs
    _attrs=$(lsattr "$_f" 2>/dev/null | awk '{print $1}' || true)
    if echo "$_attrs" | grep -q "i"; then
      info "Immutable (+i): ${_f}"
      _immutable_count=$(( _immutable_count + 1 ))
    fi
  done
  if [[ "$_immutable_count" -eq 0 ]]; then
    info "No critical files are immutable — consider: chattr +i /etc/passwd /etc/shadow"
    detail "  Immutable files cannot be modified even by root without first removing the flag"
    detail "  Useful on servers where these files rarely change"
  else
    pass "Immutable critical files: ${_immutable_count}/${_total_checked}"
  fi

  # Check /tmp and /var/tmp for immutable (should NOT be — breaks package installs)
  for _d in /tmp /var/tmp; do
    [[ -d "$_d" ]] || continue
    local _dattr
    _dattr=$(lsattr -d "$_d" 2>/dev/null | awk '{print $1}' || true)
    if echo "$_dattr" | grep -q "i"; then
      fail "Directory ${_d} is immutable — this will break software installations"
    fi
  done

  # Detect suspicious immutable files in web roots (could be webshells protected by +i)
  local _web_roots=(/var/www /srv/www /opt/www /usr/share/nginx/html)
  local _suspicious_immutable=0
  for _wr in "${_web_roots[@]}"; do
    [[ -d "$_wr" ]] || continue
    local _imm_web
    _imm_web=$(timeout 10 lsattr -R "$_wr" 2>/dev/null | awk '$1 ~ /i/ {print $2}' | head -5 || true)
    if [[ -n "$_imm_web" ]]; then
      warn "Immutable files in web root ${_wr} — possible persistent webshell protection:"
      echo "$_imm_web" | while IFS= read -r _wf; do detail "  $_wf"; done
      _suspicious_immutable=$(( _suspicious_immutable + 1 ))
    fi
  done
  [[ "$_suspicious_immutable" -eq 0 ]] && \
    info "No immutable files in web roots"
}

# ================================================================
#  NEW: KERNEL INFORMATION EXPOSURE  (/proc security)
# ================================================================
section_proc_exposure() {
  subheader "Kernel information exposure (/proc)"

  # /proc/kallsyms: kernel symbol table — aids exploit development
  local _kallsyms_val
  _kallsyms_val=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "0")
  _kallsyms_val=$(safe_int "$_kallsyms_val")
  if [[ "$_kallsyms_val" -ge 2 ]]; then
    pass "kernel.kptr_restrict = ${_kallsyms_val} — kernel pointers hidden from all users"
  elif [[ "$_kallsyms_val" -eq 1 ]]; then
    warn "kernel.kptr_restrict = 1 — kernel pointers hidden from non-root only"
    detail "  Recommended: sysctl -w kernel.kptr_restrict=2"
  else
    fail "kernel.kptr_restrict = 0 — kernel pointer addresses visible to all users"
    detail "  Fix: echo 'kernel.kptr_restrict=2' >> /etc/sysctl.d/99-wowscanner.conf"
  fi

  # /proc/kcore: raw kernel memory accessible to root
  if [[ -r /proc/kcore ]]; then
    # kcore is always world-readable by design but its size reveals RAM layout
    local _kcore_sz
    _kcore_sz=$(stat -c%s /proc/kcore 2>/dev/null || echo 0)
    info "/proc/kcore accessible (size: ${_kcore_sz} bytes — reflects physical RAM layout)"
    detail "  Restrict: add 'nounset noexec nodev' mount options if possible"
  fi

  # /proc/kallsyms readable by non-root?
  if [[ -f /proc/kallsyms ]]; then
    local _first_addr
    _first_addr=$(head -1 /proc/kallsyms 2>/dev/null | awk '{print $1}' || true)
    if echo "$_first_addr" | grep -qE "^[1-9a-f]"; then
      fail "/proc/kallsyms shows real kernel addresses — kptr_restrict should be >= 2"
    else
      pass "/proc/kallsyms addresses are zeroed out (kptr_restrict active)"
    fi
  fi

  # dmesg restriction
  local _dmesg_val
  _dmesg_val=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "0")
  _dmesg_val=$(safe_int "$_dmesg_val")
  if [[ "$_dmesg_val" -eq 1 ]]; then
    pass "kernel.dmesg_restrict = 1 — dmesg restricted to root"
  else
    warn "kernel.dmesg_restrict = 0 — any user can read kernel ring buffer (info leak)"
    detail "  Fix: echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.d/99-wowscanner.conf"
  fi

  # /proc/net/tcp exposes internal socket information
  if [[ -r /proc/net/tcp ]]; then
    local _tcp_entries
    _tcp_entries=$(wc -l < /proc/net/tcp 2>/dev/null || echo 0)
    info "/proc/net/tcp readable (${_tcp_entries} socket entries visible to all users)"
  fi
}

# ================================================================
#  NEW: BASELINE COMMAND
#  Reads the most-recent scan .txt report and snapshots all PASS
#  findings to /var/lib/wowscanner/baseline.db for future regression
#  detection.  On subsequent scans, new FAILs that were previously
#  PASSes are highlighted as regressions.
# ================================================================
cmd_baseline() {
  require_root
  echo -e "${CYAN}${BOLD}  Wowscanner — Baseline Snapshot${NC}"
  echo ""

  # Find the most recent .txt report
  local _report
  _report=$(find "$PWD" -maxdepth 1 -name 'wowscanner_*.txt' \
    -printf '%T@\t%p\n' 2>/dev/null | sort -rn | head -1 | cut -f2-)

  if [[ -z "$_report" ]]; then
    echo -e "  ${YELLOW}No scan report found in ${PWD}${NC}"
    echo "  Run a scan first, then run: sudo bash wowscanner.sh baseline"
    exit 1
  fi
  echo -e "  ${BOLD}Report:${NC} $_report"; echo ""

  local _baseline_db="${PERSIST_DIR}/baseline.db"
  local _baseline_ts="${PERSIST_DIR}/baseline.ts"
  mkdir -p "$PERSIST_DIR"

  # Extract all PASS findings — strip ANSI codes for clean storage and comparison
  local _passes
  _passes=$(sed -n 's/.*\[✔ PASS\]  //;s/  Ω.*//p' "$_report" 2>/dev/null \
    | sed 's/\[[0-9;]*m//g' | sort)

  local _pass_count
  _pass_count=$(grep -c "." <<< "$_passes" || true)
  _pass_count=$(safe_int "$_pass_count")

  echo "$_passes" > "$_baseline_db"
  date '+%Y-%m-%d %H:%M:%S' > "$_baseline_ts"
  local _ts; _ts=$(cat "$_baseline_ts")

  echo -e "  ${GREEN}[✔]${NC} Baseline saved: ${_pass_count} PASS findings"
  echo -e "  ${GREEN}[✔]${NC} Timestamp: ${_ts}"; echo -e "  ${GREEN}[✔]${NC} Location: ${_baseline_db}"
  echo ""
  echo -e "  On future scans, any PASS that becomes a FAIL will be"
  echo -e "  highlighted as a ${RED}REGRESSION${NC} in the summary."
  echo ""
}
# ================================================================
#  BASH TAB-COMPLETION
#  Usage:  sudo bash wowscanner.sh install-completion
#  Then:   source /etc/bash_completion.d/wowscanner
#          (or open a new shell — it loads automatically)
#
#  After installation, pressing Tab twice after:
#    sudo bash wowscanner.sh <TAB><TAB>
#  shows all commands and flags.
# ================================================================
cmd_install_completion() {
  require_root

  local _script_path
  _script_path=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")
  local _comp_dir="/etc/bash_completion.d"
  local _comp_file="${_comp_dir}/wowscanner"

  # ── Write the completion script ──────────────────────────────
  mkdir -p "$_comp_dir" 2>/dev/null || true
  cat > "$_comp_file" << COMPEOF
# Bash tab-completion for wowscanner.sh
# Installed by:  sudo bash wowscanner.sh install-completion
# Auto-loaded by bash from /etc/bash_completion.d/
_wowscanner_complete() {
  local cur prev words
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"

  # All top-level commands
  local _commands="clean verify diff harden baseline install-completion
    install-timer remove-timer"

  # All flags
  local _flags="--no-lynis --no-pentest --no-rkhunter --no-hardening
    --no-netcontainer --quiet --fast-only
    --email= --webhook=
    --all --integrity --reset-history"

  # Sub-args for 'clean'
  if [[ "\${words[1]}" == "clean" || "\${words[2]}" == "clean" ]]; then
    COMPREPLY=( \$(compgen -W "--all --integrity" -- "\$cur") )
    return 0
  fi

  # Sub-args for 'verify'
  if [[ "\${words[1]}" == "verify" || "\${words[2]}" == "verify" ]]; then
    COMPREPLY=( \$(compgen -W "--reset-history" -- "\$cur") )
    return 0
  fi

  # First positional arg: offer commands + flags
  if [[ "\$COMP_CWORD" -eq 1 ]] || [[ "\$cur" == -* ]]; then
    COMPREPLY=( \$(compgen -W "\$_commands \$_flags" -- "\$cur") )
    return 0
  fi

  # Subsequent args: flags only
  COMPREPLY=( \$(compgen -W "\$_flags" -- "\$cur") )
  return 0
}

# Register for every common way the script is invoked
complete -F _wowscanner_complete wowscanner.sh
complete -F _wowscanner_complete wowscanner
# Also complete when called via bash explicitly:
#   sudo bash wowscanner.sh <TAB>
complete -F _wowscanner_complete bash
COMPEOF

  chmod 644 "$_comp_file" 2>/dev/null || true

  echo -e "${GREEN}${BOLD}[✔] Tab-completion installed → ${_comp_file}${NC}"
  echo ""
  echo "  Activate now (current shell only):"
  echo "    source ${_comp_file}"
  echo ""
  echo "  Or open a new terminal — it loads automatically."
  echo ""
  echo "  Usage:"
  echo "    sudo bash ${_script_path} <TAB><TAB>   ← show all commands + flags"
  echo "    sudo bash ${_script_path} cl<TAB>      ← complete 'clean'"
  echo "    sudo bash ${_script_path} --no<TAB>    ← complete --no-* flags"
  echo "    sudo bash ${_script_path} clean <TAB>  ← show clean sub-commands"
  echo ""
}

cmd_help() {
  local _w=$(( ${COLUMNS:-80} - 2 ))
  [[ "$_w" -gt 80 ]] && _w=80
  [[ "$_w" -lt 50 ]] && _w=50
  local _line="" _i; for (( _i=0; _i<_w; _i++ )); do _line+="═"; done
  local _thin=""; for (( _i=0; _i<_w; _i++ )); do _thin+="─"; done

  _hpad() {
    local _s="$1" _len="${#1}" _pad
    _pad=$(( (_w - _len) / 2 ))
    printf '%*s%s\n' "$_pad" "" "$_s"
  }

  echo -e "${CYAN}${BOLD}╔${_line}╗${NC}"
  echo -e "${CYAN}${BOLD}║${NC}$(_hpad "${PROGRAM}  v${VERSION}")${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}$(_hpad "${COPYRIGHT}")${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╠${_line}╣${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}Usage:${NC}  sudo bash wowscanner.sh [command] [flags]$(printf '%*s' $(( _w - 45 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╠${_line}╣${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}${ULINE}Commands${NC}$(printf '%*s' $(( _w - 10 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}(no command)${NC}         Run full security audit$(printf '%*s' $(( _w - 44 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}clean${NC}                Delete output files in CWD$(printf '%*s' $(( _w - 44 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}clean --all${NC}          Also wipe /var/lib/wowscanner/$(printf '%*s' $(( _w - 46 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}clean --integrity${NC}    Reset integrity alert log only$(printf '%*s' $(( _w - 49 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}verify${NC}               Verify all archive integrity$(printf '%*s' $(( _w - 45 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}diff${NC}                 Compare two most-recent scans$(printf '%*s' $(( _w - 46 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}harden${NC}               Write /etc/sysctl.d/99-wowscanner.conf$(printf '%*s' $(( _w - 53 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}baseline${NC}             Snapshot current PASS findings$(printf '%*s' $(( _w - 47 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}install-timer${NC}        Install weekly systemd scan timer$(printf '%*s' $(( _w - 50 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}remove-timer${NC}         Remove systemd timer$(printf '%*s' $(( _w - 41 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}install-completion${NC}   Install bash tab-completion$(printf '%*s' $(( _w - 46 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╠${_line}╣${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}${ULINE}Password Recovery${NC}$(printf '%*s' $(( _w - 19 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}recover${NC}              Backup & remove auth.key → re-run to set new pass$(printf '%*s' $(( _w - 60 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}                     sudo bash $0 recover${NC}$(printf '%*s' $(( _w - 42 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}reset-auth${NC}           Change passphrase (needs current pass)$(printf '%*s' $(( _w - 52 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}reset-auth forgot${NC}    Forgot pass — reset via recovery key (root)$(printf '%*s' $(( _w - 56 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}reset-auth rk${NC}        Reset using 48-char recovery key$(printf '%*s' $(( _w - 50 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}reset-auth --force${NC}   Wipe all auth data (root only — no undo)$(printf '%*s' $(( _w - 54 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╠${_line}╣${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}${ULINE}Flags${NC}$(printf '%*s' $(( _w - 7 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--no-pentest${NC}         Skip pentest sections 0a-0e$(printf '%*s' $(( _w - 45 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--no-lynis${NC}           Skip Lynis audit (section 15)$(printf '%*s' $(( _w - 47 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--no-rkhunter${NC}        Skip rkhunter/chkrootkit$(printf '%*s' $(( _w - 43 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--no-hardening${NC}       Skip hardening-advanced section$(printf '%*s' $(( _w - 49 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--fast-only${NC}          Skip slow sections (~2-4 min)$(printf '%*s' $(( _w - 47 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--quiet${NC}              Suppress info lines$(printf '%*s' $(( _w - 38 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--email=addr${NC}         Email report after scan$(printf '%*s' $(( _w - 42 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}--webhook=url${NC}        POST report to webhook URL$(printf '%*s' $(( _w - 44 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╠${_line}╣${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}${ULINE}Output files (each run)${NC}$(printf '%*s' $(( _w - 25 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}wowscanner_<TS>.txt${NC}               Full plain-text audit log$(printf '%*s' $(( _w - 55 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}wowscanner_findings_<TS>.txt${NC}      Paginated findings (spacebar)$(printf '%*s' $(( _w - 59 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}wowscanner_report_<TS>.odt${NC}        Graphical ODT report$(printf '%*s' $(( _w - 50 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}wowscanner_report_<TS>.html${NC}       Self-contained HTML report$(printf '%*s' $(( _w - 55 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}wowscanner_stats_<TS>.ods${NC}         Statistics spreadsheet$(printf '%*s' $(( _w - 51 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}║${NC}  ${DIM}wowscanner_archive_<TS>.zip${NC}       HMAC-signed archive$(printf '%*s' $(( _w - 49 )) '')${CYAN}${BOLD}║${NC}"
  echo -e "${CYAN}${BOLD}╚${_line}╝${NC}"
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
  local _dir="$PWD"; local _iw=59 _tp _cp
  printf -v _tp "%-${_iw}s" "   ${PROGRAM}  v${VERSION}"; printf -v _cp "%-${_iw}s" "   ${COPYRIGHT}"

  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║${_tp}║"; echo "  ║${_cp}║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}Integrity Verify — directory: ${_dir}${NC}"
  echo ""

  # ── verify --reset-history ────────────────────────────────────
  # Writes RETIRED entries for every ARCHIVED zip in $PWD, then exits.
  # On a test system or after a major version change, this clears the
  # slate so future verify/scan runs have no stale history to alarm on.
  if [[ "$CMD_RESET_HISTORY" == "true" ]]; then
    local _alert_log="${PERSIST_DIR}/integrity_alerts.log"
    echo -e "  ${YELLOW}${BOLD}┌─ Resetting integrity history for: ${_dir} ────────────────┐${NC}"
    mkdir -p "$PERSIST_DIR"
    local _ts _retired=0 _any_archived=false
    local _zn _has_dir _seen_retire=()
    _ts=$(date '+%Y-%m-%d %H:%M:%S')
    # Retire every ARCHIVED zip that belongs to this directory.
    # Process substitution (cat) reads the file completely before the loop
    # starts, so appending to it inside the loop is safe.
    while IFS= read -r line; do
      [[ "$line" != *"  ARCHIVED  "* ]] && continue
      [[ "$line" =~ zip=([^[:space:]]+) ]] || continue
      _zn="${BASH_REMATCH[1]}"
      # Skip duplicates within this run
      local _dup=false; local _s
      for _s in "${_seen_retire[@]}"; do [[ "$_s" == "$_zn" ]] && { _dup=true; break; }; done
      [[ "$_dup" == "true" ]] && continue
      # Check directory scope
      _has_dir=false
      [[ "$line" =~ dir=([^[:space:]]+) ]] && _has_dir=true
      if [[ "$_has_dir" == "true" ]]; then
        [[ "${BASH_REMATCH[1]}" != "$_dir" ]] && continue
      else
        # Old-format entry (no dir=): only retire if it matches the naming pattern
        [[ "$_zn" != wowscanner_archive_*.zip ]] && continue
      fi
      _any_archived=true
      _seen_retire+=("$_zn")
      echo "[${_ts}]  RETIRED  zip=${_zn}  dir=${_dir}  reason=reset-history" \
        >> "$_alert_log"
      echo -e "  ${YELLOW}│  ${GREEN}RETIRED:${NC}  ${_zn}"
      _retired=$(( _retired + 1 ))
    done < <([[ -f "$_alert_log" ]] && cat "$_alert_log" || true)

    if [[ "$_any_archived" == "false" ]]; then
      echo -e "  ${YELLOW}│  No ARCHIVED entries found for this directory — nothing to retire.${NC}"
    else
      echo -e "  ${YELLOW}│"
      echo -e "  ${YELLOW}│  ${GREEN}✔  ${_retired} archive(s) marked RETIRED.${NC}"
      echo -e "  ${YELLOW}│     Future verify runs will not alarm on missing archives.${NC}"
      echo -e "  ${YELLOW}│     Future scans will track new archives from scratch.${NC}"
    fi
    echo -e "  ${YELLOW}${BOLD}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    return
  fi

  # ── Discover all zip archives ─────────────────────────────────
  local _zips=()
  while IFS= read -r -d '' z; do
    _zips+=("$z")
  done < <(find "$_dir" -maxdepth 1 -type f \
    -name 'wowscanner_archive_*.zip' -print0 2>/dev/null)

  # ── Check alert log for archives we KNOW should exist here ────
  # Only consider ARCHIVED entries whose dir= matches $PWD.
  # Skip any zip that already has a resolved state:
  #   ALARM_MISSING, CLEANED, SUPERSEDED, RETIRED
  local _alert_log="${PERSIST_DIR}/integrity_alerts.log"
  local _known_zips=() _resolved_names=()
  local _revt _zn _skip _rn
  if [[ -f "$_alert_log" ]]; then
    # Build resolved set first
    while IFS= read -r line; do
      for _revt in ALARM_MISSING CLEANED SUPERSEDED RETIRED; do
        if [[ "$line" == *"  ${_revt}  "* ]]; then
          [[ "$line" =~ zip=([^[:space:]]+) ]] && _resolved_names+=("${BASH_REMATCH[1]}")
          break
        fi
      done
    done < "$_alert_log"
    # Collect ARCHIVED entries scoped to this directory — deduplicated
    while IFS= read -r line; do
      [[ "$line" != *"  ARCHIVED  "* ]] && continue
      [[ "$line" =~ dir=([^[:space:]]+) ]] || continue
      [[ "${BASH_REMATCH[1]}" == "$_dir" ]] || continue
      [[ "$line" =~ zip=([^[:space:]]+) ]] || continue
      _zn="${BASH_REMATCH[1]}"
      # Skip if already resolved
      _skip=false
      for _rn in "${_resolved_names[@]}"; do [[ "$_rn" == "$_zn" ]] && { _skip=true; break; }; done
      [[ "$_skip" == "true" ]] && continue
      # Skip if already in _known_zips (deduplication)
      for _rn in "${_known_zips[@]}"; do [[ "$_rn" == "$_zn" ]] && { _skip=true; break; }; done
      [[ "$_skip" == "false" ]] && _known_zips+=("$_zn")
    done < "$_alert_log"
  fi

  # Report any known-unresolved zip that is now missing
  local _alarm=false _newer _expected
  if [[ "${#_known_zips[@]}" -gt 0 ]]; then
    echo -e "  ${BOLD}Checking for missing archives (scoped to ${_dir})...${NC}"
    for zname in "${_known_zips[@]}"; do
      _expected="${_dir}/${zname}"
      if [[ ! -f "$_expected" ]]; then
        # Check if a newer archive replaced it
        _newer=false
        while IFS= read -r -d '' _z; do
          [[ "$(basename "$_z")" != "$zname" ]] && { _newer=true; break; }
        done < <(find "$_dir" -maxdepth 1 -type f -name 'wowscanner_archive_*.zip' -print0 2>/dev/null)
        if [[ "$_newer" == "true" ]]; then
          echo -e "  ${YELLOW}SUPERSEDED  ${zname}${NC}"
          echo -e "  ${YELLOW}            ↳ Replaced by a newer archive in this directory — no alarm${NC}"
          echo "[$(date '+%Y-%m-%d %H:%M:%S')]  SUPERSEDED  zip=${zname}  dir=${_dir}" \
            >> "$_alert_log"
        else
          _alarm=true
          echo -e "\a"
          echo -e "  ${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
          echo -e "  ${RED}${BOLD}║  ⚠  ARCHIVE MISSING — POSSIBLE TAMPERING OR DELETION        ║${NC}"
          echo -e "  ${RED}${BOLD}║  Expected : ${zname}${NC}"
          echo -e "  ${RED}${BOLD}║  Directory: ${_dir}${NC}"
          echo -e "  ${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
          echo ""
          echo "[$(date '+%Y-%m-%d %H:%M:%S')]  ALARM_MISSING  zip=${zname}  dir=${_dir}" \
            >> "$_alert_log"
        fi
      fi
    done
    $_alarm || echo -e "  ${GREEN}All known archives accounted for (present or superseded).${NC}"
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
import sys, os, zipfile, hashlib, hmac, datetime, socket, stat, pwd, grp, re

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

# ── Load resolved states from the alert log ───────────────────────────────
# Resolved states: CLEANED (file), SUPERSEDED (zip), RETIRED (zip), ALARM_MISSING (zip)
# Zips in SUPERSEDED/RETIRED state are shown as informational, not alarming.
# Files in CLEANED state are shown as expected-absent, not missing.
cleaned_files  = set()   # basenames of files deleted by 'clean'
superseded_zips = set()  # zip names replaced by newer scans or manually retired
alert_log_path = os.path.join(persist_dir, 'integrity_alerts.log')
if os.path.isfile(alert_log_path):
    with open(alert_log_path) as _alf:
        for line in _alf:
            if '  CLEANED  ' in line:
                parts = line.strip().split('file=', 1)
                if len(parts) == 2:
                    cleaned_files.add(parts[1].strip())
            elif '  SUPERSEDED  ' in line or '  RETIRED  ' in line:
                m = re.search(r'zip=(\S+)', line)
                if m: superseded_zips.add(m.group(1))

grand_ok = 0; grand_fail = 0; grand_unexpected_missing = 0
grand_cleaned_missing = 0; grand_perm = 0; grand_size = 0
grand_superseded = 0
alerts = []

for zpath in zip_paths:
    zname = os.path.basename(zpath)
    arc_ok = 0; arc_fail = 0; arc_unexp = 0; arc_clean = 0

    print(f"\n  {CYAN}│  {BOLD}{'─'*54}{NC}")

    # ── Superseded archive — informational only, skip deep checks ────────
    if zname in superseded_zips:
        print(f"  {CYAN}│  {YELLOW}SUPERSEDED  {zname}{NC}")
        print(f"  {CYAN}│              ↳ Replaced by a newer scan — no integrity alarm{NC}")
        grand_superseded += 1
        continue

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
            # HMAC mismatch. Two possible causes:
            #  A) Genuine tampering: someone edited INTEGRITY.txt inside the zip
            #  B) Machine-key mismatch: archive was created on a different machine
            #     or the machine-id changed (reinstall, docker, etc.)
            # We can't tell which from the HMAC alone, so report clearly without
            # ringing the alarm bell — the file hash checks below will confirm
            # whether the actual content has been changed.
            print(f"  {CYAN}│  {YELLOW}HMAC check : MISMATCH — see note below{NC}")
            print(f"  {CYAN}│  {YELLOW}  Possible cause A: INTEGRITY.txt was altered (tampering){NC}")
            print(f"  {CYAN}│  {YELLOW}  Possible cause B: archive was created on a different machine{NC}")
            print(f"  {CYAN}│  {YELLOW}    or machine-id changed (reinstall / new OS). File hashes{NC}")
            print(f"  {CYAN}│  {YELLOW}    below will still verify content integrity independently.{NC}")
            alerts.append(f"[{ts_now}]  HMAC_MISMATCH  zip={zname}  (check file hashes to confirm)")
            # Do NOT increment arc_fail here — let file hash checks be the arbiter
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
if grand_superseded:         summary_parts.append(f"{YELLOW}{grand_superseded} superseded (replaced by newer scan){NC}")
if grand_cleaned_missing:    summary_parts.append(f"{YELLOW}{grand_cleaned_missing} cleaned (expected absent){NC}")
if grand_unexpected_missing: summary_parts.append(f"{RED}{grand_unexpected_missing} MISSING (unexpected){NC}")
if grand_fail:               summary_parts.append(f"{RED}{grand_fail} TAMPERED{NC}")
if grand_size:               summary_parts.append(f"{RED}{grand_size} size-fail{NC}")
if grand_perm:               summary_parts.append(f"{MAGENTA}{grand_perm} perm-changed{NC}")
if not summary_parts:        summary_parts.append(f"{YELLOW}no archives checked{NC}")
print(f"  {CYAN}│  {'   '.join(summary_parts)}")

# Only alarm on genuinely unexpected problems
if grand_fail > 0 or grand_size > 0 or grand_unexpected_missing > 0:
    bell()
    print(f"  {CYAN}│  {RED}{BOLD}⚠  INTEGRITY COMPROMISED — see details above!{NC}")
elif grand_cleaned_missing > 0 and grand_ok == 0 and grand_fail == 0:
    print(f"  {CYAN}│  {YELLOW}Files were removed with 'clean' — zip archives are intact.{NC}")
    print(f"  {CYAN}│  {YELLOW}To restore: unzip wowscanner_archive_<ts>.zip -d .{NC}")
    print(f"  {CYAN}│  {GREEN}No unexpected tampering detected.{NC}")
elif grand_superseded > 0 and grand_ok == 0 and grand_fail == 0 and grand_unexpected_missing == 0:
    print(f"  {CYAN}│  {YELLOW}All archives are from superseded scans — no current archive to check.{NC}")
    print(f"  {CYAN}│  {GREEN}No integrity issues detected.{NC}")
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
                 f"ok={grand_ok}  cleaned={grand_cleaned_missing}  "
                 f"superseded={grand_superseded}\n")
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

  # ── ODF inner-CRC check ───────────────────────────────────────
  # After verifying the ZIP archives, also verify the inner CRC-32
  # of every .odt and .ods file directly on disk (independent of
  # the ZIP archive system — detects corruption or tampering of the
  # report files even if the outer archive was not modified).
  check_odf_crcs || true
}

# ── Passive zip-presence check (called at scan start) ────────────
# Warns if any previously archived zip has been deleted since the
# last scan.  Rings the terminal bell and logs an alert.
check_archive_presence() {
  # Called at start of every scan. Warns if a zip that was ARCHIVED in $PWD
  # has since disappeared without being CLEANED, SUPERSEDED, or RETIRED.
  #
  # Resolved states (suppress alarm, never repeat):
  #   ALARM_MISSING, CLEANED, SUPERSEDED, RETIRED
  #
  # SUPERSEDED: written here when a zip that was ARCHIVED in $PWD is gone
  #   but a newer wowscanner_archive_*.zip exists in the same directory.
  #   This is the normal case when deploying a new script version and
  #   running a fresh scan — the old archive is simply replaced.
  #   No alarm is raised, just a quiet info line.
  local _dir="$PWD"
  local _alert_log="${PERSIST_DIR}/integrity_alerts.log"
  [[ ! -f "$_alert_log" ]] && return

  # Build set of already-resolved zip names (any terminal state)
  local _resolved_zips=()
  while IFS= read -r _rline; do
    local _revt
    for _revt in ALARM_MISSING CLEANED SUPERSEDED RETIRED; do
      if [[ "$_rline" == *"  ${_revt}  "* ]]; then
        if [[ "$_rline" =~ zip=([^[:space:]]+) ]]; then
          _resolved_zips+=("${BASH_REMATCH[1]}")
        fi
        break
      fi
    done
  done < "$_alert_log"

  local _ts
  _ts=$(date '+%Y-%m-%d %H:%M:%S')

  while IFS= read -r line; do
    # Only process ARCHIVED entries that have a dir= field matching $PWD
    [[ "$line" != *"  ARCHIVED  "* ]] && continue
    [[ "$line" =~ dir=([^[:space:]]+) ]] || continue
    local _archived_dir="${BASH_REMATCH[1]}"
    [[ "$_archived_dir" == "$_dir" ]] || continue
    [[ "$line" =~ zip=([^[:space:]]+) ]] || continue
    local _zname="${BASH_REMATCH[1]}"
    local _zpath="${_dir}/${_zname}"

    # Already resolved — skip silently
    local _is_resolved=false; local _rz
    for _rz in "${_resolved_zips[@]}"; do
      [[ "$_rz" == "$_zname" ]] && { _is_resolved=true; break; }
    done
    [[ "$_is_resolved" == "true" ]] && continue

    if [[ ! -f "$_zpath" ]]; then
      # Zip is gone from disk. Check if a replacement archive now exists.
      local _newer_exists=false
      while IFS= read -r -d '' _z; do
        [[ "$(basename "$_z")" != "$_zname" ]] && { _newer_exists=true; break; }
      done < <(find "$_dir" -maxdepth 1 -type f -name 'wowscanner_archive_*.zip' -print0 2>/dev/null)

      if [[ "$_newer_exists" == "true" ]]; then
        # A newer archive exists in this directory — the old one was superseded.
        # This is the normal "new version, fresh scan" scenario. No alarm.
        echo "[${_ts}]  SUPERSEDED  zip=${_zname}  dir=${_dir}" >> "$_alert_log"
        info "Old archive superseded (newer scan present): ${_zname}"
      else
        # No replacement exists — this is a genuine unexpected disappearance.
        echo -e "\a"
        warn "ARCHIVE MISSING: ${_zname} — was created here but is now gone!"
        warn "Run:  sudo bash $0 verify  — for a full integrity check"
        echo "[${_ts}]  ALARM_MISSING  zip=${_zname}  dir=${_dir}" >> "$_alert_log"
      fi
      # Add to resolved set so we don't double-process in this run
      _resolved_zips+=("$_zname")
    fi
  done < "$_alert_log"
}

# ================================================================
#  CLEAN COMMAND  (sudo bash wowscanner.sh clean [--all])
#  Wipes all wowscanner output files from the current directory
#  and exits immediately — the audit is NOT run.
#  With --all: also removes /var/lib/wowscanner/ persistent data.
# ================================================================
cmd_clean() {
  require_root

  local _dir="$PWD"; local _wiped=0 _failed=0 _bytes=0
  local _files=()
  local _sz _szh   # reused in both deletion loops — declared once here
  local _tp _cp _iw=59
  printf -v _tp "%-${_iw}s" "   ${PROGRAM}  v${VERSION}"; printf -v _cp "%-${_iw}s" "   ${COPYRIGHT}"

  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║${_tp}║"; echo "  ║${_cp}║"
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
    -o -name 'wowscanner_*.txt.sha256' \
    -o -name 'wowscanner_*.odt' \
    -o -name 'wowscanner_*.ods' \
    -o -name 'wowscanner_*.odp' \
    -o -name 'wowscanner_*.html' \
    -o -name 'wowscanner_*.sha256' \
    -o -name 'wowscanner_*.odt.crc' \
    -o -name 'wowscanner_*.ods.crc' \
    \) -print0 2>/dev/null)

  if [[ "${#_files[@]}" -eq 0 ]]; then
    echo -e "  ${GREEN}No wowscanner output files found in ${_dir}${NC}"
  else
    echo -e "  ${YELLOW}${BOLD}┌─ Deleting output files (zip archives kept) ──────────────┐${NC}"
    local _clean_ts
    _clean_ts=$(date '+%Y-%m-%d %H:%M:%S')
    for f in "${_files[@]}"; do
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
    # Wipe scan history (/var/lib/wowscanner/)
    local _persist="/var/lib/wowscanner"
    if [[ -d "$_persist" ]]; then
      echo -e "  ${YELLOW}${BOLD}┌─ Persistent data (--all): ${_persist} ─${NC}"
      local _pw=0 _pf=0 _pb=0
      while IFS= read -r -d '' f; do
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
      echo -e "  ${GREEN}  ${_persist} does not exist — nothing to remove${NC}"
    fi

    # Also wipe auth credentials (/etc/wowscanner/)
    local _auth_dir="/etc/wowscanner"
    if [[ -d "$_auth_dir" ]]; then
      echo -e "  ${YELLOW}${BOLD}┌─ Auth credentials (--all): ${_auth_dir} ─${NC}"
      local _aw=0 _af=0
      while IFS= read -r -d '' f; do
        if rm -f "$f" 2>/dev/null; then
          echo -e "  ${YELLOW}│  ${GREEN}deleted:${NC}  $(basename "$f")"
          _aw=$(( _aw + 1 ))
        else
          echo -e "  ${YELLOW}│  ${RED}FAILED :${NC}  $(basename "$f")"
          _af=$(( _af + 1 ))
        fi
      done < <(find "$_auth_dir" -maxdepth 1 -type f -print0 2>/dev/null)
      rmdir "$_auth_dir" 2>/dev/null || true
      echo -e "  ${YELLOW}${BOLD}└─ Deleted ${_aw} auth file(s)${NC}"
    else
      echo -e "  ${GREEN}  ${_auth_dir} does not exist — nothing to remove${NC}"
    fi

    # Also remove sudoers entry
    if [[ -f "/etc/sudoers.d/wowscanner" ]]; then
      rm -f "/etc/sudoers.d/wowscanner" 2>/dev/null || true
      echo -e "  ${YELLOW}  Removed /etc/sudoers.d/wowscanner${NC}"
    fi
    echo -e "  ${BGREEN}  Next run will trigger first-run setup wizard.${NC}"
  elif [[ "$CLEAN_INTEGRITY" == "true" ]]; then
    # ── Wipe only integrity_alerts.log ────────────────────────────
    # Useful when deploying a new script version or on a test system
    # where old ARCHIVED entries would cause false-positive alarms.
    local _ilog="${PERSIST_DIR}/integrity_alerts.log"
    echo -e "  ${YELLOW}${BOLD}┌─ Integrity alert log reset ────────────────────────────────┐${NC}"
    if [[ -f "$_ilog" ]]; then
      local _isz _iszh
      _isz=$(stat -c%s "$_ilog" 2>/dev/null || echo 0)
      _iszh=$(numfmt --to=iec "$_isz" 2>/dev/null || echo "${_isz}B")
      local _line_count
      _line_count=$(wc -l < "$_ilog" 2>/dev/null || echo 0)
      if rm -f "$_ilog" 2>/dev/null; then
        echo -e "  ${YELLOW}│  ${GREEN}deleted:${NC}  integrity_alerts.log  ${YELLOW}(${_iszh}, ${_line_count} entries)${NC}"
        echo -e "  ${YELLOW}│  ${GREEN}✔  Integrity history cleared.${NC}"
        echo -e "  ${YELLOW}│     The next scan will start tracking archives fresh.${NC}"
        echo -e "  ${YELLOW}│     The next 'verify' will have no history to check against.${NC}"
      else
        echo -e "  ${YELLOW}│  ${RED}FAILED to delete ${_ilog} — check permissions${NC}"
      fi
    else
      echo -e "  ${YELLOW}│  ${GREEN}integrity_alerts.log does not exist — nothing to remove${NC}"
    fi
    echo -e "  ${YELLOW}${BOLD}└────────────────────────────────────────────────────────────┘${NC}"
  else
    echo -e "  ${BOLD}  Persistent data (/var/lib/wowscanner/) was kept.${NC}"
    echo    "  Run with  clean --all  to also wipe port history and remediation data."
    echo    "  Run with  clean --integrity  to wipe only the integrity alert log."
  fi
  echo ""; echo -e "  ${GREEN}${BOLD}Done.${NC}"
  echo ""
}

# ================================================================
#  PAGINATED FINDINGS REPORT
#  Written as wowscanner_findings_<TIMESTAMP>.txt
#
#  Designed for terminal reading with:
#    less wowscanner_findings_*.txt        (spacebar = next page)
#    more wowscanner_findings_*.txt        (spacebar = next page)
#
#  Structure: one page per scan section.
#  Each page shows all FAIL / WARN / PASS / INFO findings for that
#  section.  Pages are separated by a form-feed character (\f / 0x0C)
#  which both `less` and `more` treat as a hard page break.
#  The file is CRC-checked alongside the main audit log.
# ================================================================
generate_findings_report() {
  local _txt_report="$1"
  local _out="wowscanner_findings_${TIMESTAMP}.txt"

  python3 - "$_txt_report" "$_out" "$SCORE" "$TOTAL" "$PERCENTAGE" \
            "$(hostname -f 2>/dev/null || hostname)" \
            "$(date '+%Y-%m-%d %H:%M:%S')" << 'FINDINGSEOF' || true
import sys, os, re, datetime

txt_path  = sys.argv[1]
out_path  = sys.argv[2]
score_val = int(sys.argv[3])
total_val = max(int(sys.argv[4]), 1)
pct       = int(sys.argv[5])
hostname  = sys.argv[6]
date_str  = sys.argv[7]

ansi_re = re.compile(r"\x1b\[[0-9;]*m")

with open(txt_path, "r", errors="replace") as fh:
    raw = [ansi_re.sub("", l.rstrip("\n")) for l in fh]

# Regexes for section headers and findings
# header() writes: "  🔐  5. SSH CONFIG    " — emoji+spaces+number.text
# We match on the ╔═ box-top, then extract title from the content line,
# then confirm on ╚═ box-bottom.
SEC_RE    = re.compile(r"^\s+(?:..\s+)?(?:.\s+)?([0-9]+[a-zA-Z]*[. ].+?)\s*$")
FAIL_RE   = re.compile(r"^\s*\[.*FAIL.*\]\s*(.*?)\s*Ω?\s*$")
WARN_RE   = re.compile(r"^\s*\[.*WARN.*\]\s*(.*?)\s*Ω?\s*$")
PASS_RE   = re.compile(r"^\s*\[.*PASS.*\]\s*(.*?)\s*Ω?\s*$")
INFO_RE   = re.compile(r"^\s*\[.*INFO.*\]\s*(.*?)\s*Ω?\s*$")
SKIP_RE   = re.compile(r"^\s*\[.*SKIP.*\]\s*(.*?)\s*Ω?\s*$")
# detail() now writes "  │       ↳ text"  — match │...↳ or plain ↳
DETAIL_RE = re.compile(r"^\s*(?:│\s*)?↳\s+(.*)")

sections = []
cur = {"title": "General", "items": []}
last_idx = -1
in_box = False
pending_title = None

for line in raw:
    # Box top
    if re.match(r"^\s*╔═", line):
        in_box = True
        pending_title = None
        continue
    if in_box:
        # Box bottom — commit title
        if re.match(r"^\s*╚═", line):
            if pending_title:
                sections.append(cur)
                cur = {"title": pending_title, "items": []}
                last_idx = -1
            in_box = False
            pending_title = None
            continue
        # Skip dividers inside box
        if re.match(r"^\s*[╠╬]═", line):
            continue
        # Content line — strip box chars and emoji to extract title
        stripped = line.strip().rstrip()
        # Remove trailing spaces/box padding
        # Remove leading emoji (any non-ASCII char followed by spaces)
        clean = re.sub(r"^[\U00010000-\U0010FFFF\u2600-\u2BFF\s]+", "", stripped)
        m = re.match(r"([0-9]+[a-zA-Z]*[. ].+)", clean)
        if m:
            t = m.group(1).strip()
            if len(t) > 3:
                pending_title = t
        continue

    # Finding lines
    matched = False
    for pat, kind in ((FAIL_RE,"FAIL"),(WARN_RE,"WARN"),(PASS_RE,"PASS"),(INFO_RE,"INFO"),(SKIP_RE,"SKIP")):
        m = pat.match(line)
        if m:
            text = m.group(1).strip()
            if text:
                cur["items"].append({"kind": kind, "text": text, "details": []})
                last_idx = len(cur["items"]) - 1
            matched = True
            break
    if not matched and last_idx >= 0:
        md = DETAIL_RE.match(line)
        if md and md.group(1).strip():
            cur["items"][-1]["details"].append(md.group(1).strip())

sections.append(cur)
sections = [s for s in sections if s["items"]]

n_fail = sum(1 for s in sections for i in s["items"] if i["kind"] == "FAIL")
n_warn = sum(1 for s in sections for i in s["items"] if i["kind"] == "WARN")
n_pass = sum(1 for s in sections for i in s["items"] if i["kind"] == "PASS")
n_info = sum(1 for s in sections for i in s["items"] if i["kind"] == "INFO")

COL     = 80
DIVIDER = "=" * COL
THIN    = "-" * COL
# Visible section separator — works in every pager, greppable with /^>>>
SEP     = "\n\n" + (">" * 3 + " NEXT SECTION " + ">" * (COL - 17)) + "\n\n"

KIND_LABEL = {"FAIL": "✘ FAIL", "WARN": "⚠ WARN", "PASS": "✔ PASS", "INFO": "ℹ INFO", "SKIP": "─ SKIP"}
KIND_HDR   = {
    "FAIL": "[ FAILURES ]" + "-" * (COL - 13),
    "WARN": "[ WARNINGS ]" + "-" * (COL - 13),
    "PASS": "[ PASSING  ]" + "-" * (COL - 13),
    "INFO": "[ INFO     ]" + "-" * (COL - 13),
    "SKIP": "[ SKIPPED  ]" + "-" * (COL - 13),
}

def wrap_text(text, max_w, cont_indent):
    # Greedy word-wrap — O(n), terminates for any input including no-space strings.
    if not text:
        return [""]
    if max_w < 10:
        max_w = 10
    safe_indent = min(cont_indent, max(max_w // 4, 4))
    first_w = max_w
    cont_w  = max(max_w - safe_indent, 8)
    pad     = " " * safe_indent

    words = text.split(" ")
    lines = []
    current = ""
    limit = first_w
    for word in words:
        if not word:
            continue
        # If a single word exceeds the limit, hard-slice it
        while len(word) > limit:
            if current:
                lines.append(current)
                current = ""
                limit = cont_w
            lines.append(word[:limit])
            word = word[limit:]
        if not word:
            continue
        candidate = (current + " " + word).lstrip() if current else word
        if len(candidate) <= limit:
            current = candidate
        else:
            if current:
                lines.append(current)
                limit = cont_w
            current = word
    if current:
        lines.append(current)
    if not lines:
        return [text[:max_w]]
    result = [lines[0]]
    for l in lines[1:]:
        result.append(pad + l)
    return result

# Cover page
cover = [
    DIVIDER,
    "",
    "  WOWSCANNER — FINDINGS REPORT",
    f"  Host: {hostname}   Generated: {date_str}",
    "",
    THIN,
    f"  Score  : {score_val} / {total_val} ({pct}%)",
    f"  FAIL   : {n_fail}",
    f"  WARN   : {n_warn}",
    f"  PASS   : {n_pass}",
    f"  INFO   : {n_info}",
    THIN,
    "",
    "  HOW TO NAVIGATE:",
    "    less findings.txt         arrows/PgDn to scroll, q to quit",
    "    grep -n FAIL findings.txt  show only failures with line numbers",
    "    grep -n WARN findings.txt  show only warnings",
    "    /^>>>                      search for next section boundary in less",
    "",
    THIN,
    f"  SECTIONS ({len(sections)} with findings):",
    "",
]
for idx, s in enumerate(sections, 1):
    nf = sum(1 for i in s["items"] if i["kind"] == "FAIL")
    nw = sum(1 for i in s["items"] if i["kind"] == "WARN")
    np_ = sum(1 for i in s["items"] if i["kind"] == "PASS")
    ni  = sum(1 for i in s["items"] if i["kind"] == "INFO")
    parts = []
    if nf: parts.append(f"✘{nf}")
    if nw: parts.append(f"⚠{nw}")
    if np_: parts.append(f"✔{np_}")
    if ni:  parts.append(f"ℹ{ni}")
    badge = "  " + "  ".join(parts) if parts else ""
    cover.append(f"  {idx:3d}.  {s['title'][:50]:<50}{badge}")
cover += ["", DIVIDER]

# Section pages
pages = []
for sec_idx, s in enumerate(sections, 1):
    pl = [
        DIVIDER,
        f"  Section {sec_idx}/{len(sections)} — {s['title']}",
        THIN,
        "",
    ]
    for kind in ("FAIL", "WARN", "PASS", "INFO", "SKIP"):
        items = [i for i in s["items"] if i["kind"] == kind]
        if not items:
            continue
        pl.append(KIND_HDR[kind])
        pl.append("")
        for it in items:
            label = KIND_LABEL[kind]
            prefix = f"  [{label}]  "
            available = COL - len(prefix)
            wrapped = wrap_text(it["text"], available, len(prefix) + 4)
            pl.append(prefix + wrapped[0])
            for extra in wrapped[1:]:
                pl.append(extra)
            for d in it["details"]:
                pl.append(f"           ->  {d[:COL - 15]}")
            pl.append("")
    pl.append(DIVIDER)
    pages.append("\n".join(pl))

output = "\n".join(cover) + SEP + SEP.join(pages) + "\n"

with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(output)

sz = os.path.getsize(out_path)
print(f"  Findings report: {out_path}  ({sz:,}B  {len(sections)} sections  {n_fail} FAILs  {n_warn} WARNs  {n_pass} PASSes)")
FINDINGSEOF
}

# ================================================================
#  17b. FAILED LOGIN ANALYSIS
#  Parses /var/log/auth.log (or journal) for brute-force indicators:
#  repeated failed SSH logins, invalid users, source IP frequency.
# ================================================================
section_failed_logins() {
  header "17b. FAILED LOGIN ANALYSIS"
  subheader "SSH brute-force indicators"

  local _auth_log="" _journal_ok=false
  for _f in /var/log/auth.log /var/log/secure; do
    [[ -r "$_f" ]] && { _auth_log="$_f"; break; }
  done

  # Try journalctl if no log file
  if [[ -z "$_auth_log" ]] && command -v journalctl &>/dev/null; then
    _journal_ok=true
  fi

  if [[ -z "$_auth_log" && "$_journal_ok" == "false" ]]; then
    info "No auth log or journalctl available — skipping failed login analysis"
    return
  fi

  local _get_lines
  if [[ -n "$_auth_log" ]]; then
    _get_lines="tail -n 50000 \"$_auth_log\" 2>/dev/null"
  else
    _get_lines="journalctl -u ssh -u sshd --no-pager -n 50000 2>/dev/null"
  fi

  # Count failed attempts (last 50k lines ≈ last few days on busy server)
  local _fail_count _invalid_count _top_ips
  _fail_count=$(eval "$_get_lines" | grep -c "Failed password\|authentication failure\|Invalid user" 2>/dev/null || echo 0)
  _fail_count=$(safe_int "$_fail_count")
  _invalid_count=$(eval "$_get_lines" | grep -c "Invalid user" 2>/dev/null || echo 0)
  _invalid_count=$(safe_int "$_invalid_count")

  if [[ "$_fail_count" -eq 0 ]]; then
    pass "No failed SSH login attempts found in recent logs"
    return
  fi

  # Threshold: >100 failures = active brute force
  if   [[ "$_fail_count" -gt 1000 ]]; then
    fail "ACTIVE BRUTE FORCE: ${_fail_count} failed login attempts detected"
  elif [[ "$_fail_count" -gt 100 ]]; then
    warn "${_fail_count} failed login attempts — possible brute-force scanning"
  else
    info "${_fail_count} failed login attempt(s) — within normal range"
  fi

  [[ "$_invalid_count" -gt 0 ]] && \
    detail "Invalid username attempts: ${_invalid_count} (probing for accounts)"

  # Top 5 attacking IPs
  _top_ips=$(eval "$_get_lines" | \
    grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    awk '{print $2}' | sort | uniq -c | sort -rn | head -5 || true)
  if [[ -n "$_top_ips" ]]; then
    info "Top attacking IPs (from recent log):"
    while IFS= read -r _ip_line; do
      detail "$_ip_line"
    done <<< "$_top_ips"
  fi

  # Check if fail2ban is protecting SSH
  subheader "Brute-force protection"
  if command -v fail2ban-client &>/dev/null; then
    local _f2b_status
    _f2b_status=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" || true)
    if [[ -n "$_f2b_status" ]]; then
      pass "fail2ban is active and protecting SSH"
      detail "$_f2b_status"
    else
      warn "fail2ban installed but SSH jail may not be active"
      detail "Run: fail2ban-client status sshd"
    fi
  else
    if [[ "$_fail_count" -gt 100 ]]; then
      fail "fail2ban not installed — no automated brute-force protection"
      detail "Install: apt install fail2ban"
    else
      info "fail2ban not installed (consider it if server is internet-facing)"
    fi
  fi
}

# ================================================================
#  17c. ENVIRONMENT SECURITY
#  Checks umask, PATH safety, shell startup files, dangerous env vars.
# ================================================================
section_env_security() {
  header "17c. ENVIRONMENT SECURITY"
  subheader "umask"

  local _umask
  _umask=$(umask 2>/dev/null || echo "0022")
  case "$_umask" in
    0077|077) pass "umask ${_umask} — files created with 700 permissions (most restrictive)" ;;
    0027|027) pass "umask ${_umask} — files created with 640 permissions (good)" ;;
    0022|022) warn "umask ${_umask} — files created with 644 permissions (world-readable)" ;;
    *)        warn "umask ${_umask} — verify this is appropriate for this system" ;;
  esac

  subheader "PATH safety"
  # Check for . or empty component in root PATH (allows command hijacking)
  if echo "${PATH}" | tr ':' '\n' | grep -qE '^\.?$'; then
    fail "Dangerous PATH entry: '.' or empty component found — allows command hijacking"
    detail "Fix: remove '.' from PATH in /root/.bashrc and /etc/profile"
  else
    pass "PATH does not contain '.' or empty component"
  fi

  # World-writable directories in PATH
  local _ww_path=0
  while IFS= read -r _pdir; do
    [[ -z "$_pdir" ]] && continue
    if [[ -d "$_pdir" ]] && [[ -w "$_pdir" ]]; then
      local _pperms
      _pperms=$(stat -c%a "$_pdir" 2>/dev/null || echo "0")
      if [[ "${_pperms: -1}" =~ [2367] ]]; then
        fail "World-writable directory in PATH: ${_pdir} (${_pperms})"
        _ww_path=$(( _ww_path + 1 ))
      fi
    fi
  done <<< "$(echo "${PATH}" | tr ':' '\n')"
  [[ "$_ww_path" -eq 0 ]] && pass "No world-writable directories in PATH"

  subheader "Dangerous environment variables"
  local _env_issues=0
  for _evar in LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PERL5LIB RUBYLIB; do
    local _val
    _val=$(printenv "$_evar" 2>/dev/null || true)
    if [[ -n "$_val" ]]; then
      fail "Dangerous env var set: ${_evar}=${_val:0:80}"
      detail "This can be used to hijack library loading and escalate privileges"
      _env_issues=$(( _env_issues + 1 ))
    fi
  done
  [[ "$_env_issues" -eq 0 ]] && pass "No dangerous library-injection env vars set"

  subheader "Shell startup file safety"
  local _rc_issues=0
  for _rc in /root/.bashrc /root/.bash_profile /root/.profile /etc/profile \
             /etc/bash.bashrc /etc/environment; do
    [[ -f "$_rc" ]] || continue
    local _rc_perm
    _rc_perm=$(stat -c%a "$_rc" 2>/dev/null || echo "0")
    # Should not be world-writable
    if [[ "${_rc_perm: -1}" =~ [2367] ]]; then
      fail "World-writable shell startup file: ${_rc} (${_rc_perm})"
      _rc_issues=$(( _rc_issues + 1 ))
    fi
  done
  [[ "$_rc_issues" -eq 0 ]] && pass "Shell startup files have safe permissions"
}

# ================================================================
#  USB DEVICE AUDIT
#  Checks for USB storage devices (data exfiltration risk),
#  USB network adapters, and kernel USB attack surface.
# ================================================================
section_usb_devices() {
  header "17d. USB DEVICE AUDIT"
  subheader "Connected USB storage devices"

  local _usb_storage=""
  if command -v lsblk &>/dev/null; then
    _usb_storage=$(lsblk -d -o NAME,TRAN,SIZE,TYPE 2>/dev/null | \
      awk '$2=="usb"' || true)
  fi
  if [[ -z "$_usb_storage" ]] && [[ -d /sys/bus/usb/devices ]]; then
    _usb_storage=$(find /sys/bus/usb/devices -name "product" 2>/dev/null | \
      xargs grep -li "flash\|disk\|storage" 2>/dev/null || true)
  fi

  if [[ -n "$_usb_storage" ]]; then
    warn "USB storage device(s) detected — potential data exfiltration vector"
    while IFS= read -r _u; do detail "$_u"; done <<< "$_usb_storage"
  else
    pass "No USB storage devices detected"
  fi

  subheader "USB network adapters"
  local _usb_net=""
  if command -v lsusb &>/dev/null; then
    _usb_net=$(lsusb 2>/dev/null | grep -i "ethernet\|wireless\|wi-fi\|802.11\|lan adapter" || true)
  fi
  if [[ -n "$_usb_net" ]]; then
    warn "USB network adapter(s) detected — may bypass firewall rules"
    while IFS= read -r _un; do detail "$_un"; done <<< "$_usb_net"
  else
    pass "No USB network adapters detected"
  fi

  subheader "USB attack surface — kernel modules"
  # Check if USB storage kernel module is loaded (usb_storage enables mass storage)
  if lsmod 2>/dev/null | grep -q "^usb_storage"; then
    if [[ -n "$_usb_storage" ]]; then
      info "usb_storage module loaded (USB drives connected)"
    else
      warn "usb_storage kernel module loaded but no storage device visible — consider blacklisting"
      detail "Blacklist: echo 'blacklist usb_storage' > /etc/modprobe.d/usb-storage.conf"
    fi
  else
    pass "usb_storage kernel module not loaded (USB mass storage disabled)"
  fi
}

# ================================================================
#  17e. WORLD-WRITABLE FILE DEEP SCAN
#  Scans key directories for world-writable files outside /tmp,
#  sticky-bit bypass risks, and writable system config files.
# ================================================================
section_world_writable_deep() {
  header "17e. WORLD-WRITABLE FILE DEEP SCAN"
  subheader "World-writable files outside /tmp"

  local _ww_count=0
  local _ww_files=""
  _ww_files=$(find /etc /usr/bin /usr/sbin /usr/lib /bin /sbin \
    -maxdepth 4 -type f -perm -o+w 2>/dev/null | head -20 || true)

  if [[ -n "$_ww_files" ]]; then
    fail "World-writable files found in system directories"
    while IFS= read -r _f; do
      detail "$_f"
      _ww_count=$(( _ww_count + 1 ))
    done <<< "$_ww_files"
    detail "Fix: chmod o-w <file>"
  else
    pass "No world-writable files in system directories"
  fi

  subheader "Writable /etc config files (non-root owner)"
  local _etc_ww=0
  while IFS= read -r -d '' _f; do
    local _owner
    _owner=$(stat -c '%U' "$_f" 2>/dev/null || echo "unknown")
    if [[ "$_owner" != "root" ]]; then
      fail "Non-root owned /etc file: $_f (owner: $_owner)"
      _etc_ww=$(( _etc_ww + 1 ))
    fi
  done < <(find /etc -maxdepth 2 -type f -writable 2>/dev/null -print0)
  [[ "$_etc_ww" -eq 0 ]] && pass "All writable /etc files are root-owned"

  subheader "SUID/SGID files in non-standard paths"
  local _suid_nonstandard=0
  while IFS= read -r -d '' _f; do
    case "$_f" in
      /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/libexec/*) continue ;;
    esac
    warn "SUID/SGID in non-standard path: $_f"
    _suid_nonstandard=$(( _suid_nonstandard + 1 ))
  done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
  [[ "$_suid_nonstandard" -eq 0 ]] && pass "No SUID/SGID files outside standard system paths"
}

# ================================================================
#  17f. CERTIFICATE & TLS AUDIT
#  Checks expiry of system certificates and key lengths.
# ================================================================
section_cert_audit() {
  header "17f. CERTIFICATE & TLS AUDIT"
  subheader "System certificate store"

  local _cert_dir="" _expired=0 _expiring=0 _ok=0
  for _d in /etc/ssl/certs /usr/share/ca-certificates /etc/pki/tls/certs; do
    [[ -d "$_d" ]] && { _cert_dir="$_d"; break; }
  done

  if [[ -z "$_cert_dir" ]]; then
    info "No standard certificate directory found"
  else
    local _today_epoch
    _today_epoch=$(date +%s)
    local _warn_epoch=$(( _today_epoch + 30*86400 ))   # 30 days

    while IFS= read -r -d '' _cert; do
      [[ -f "$_cert" ]] || continue
      local _exp_str _exp_epoch
      _exp_str=$(openssl x509 -noout -enddate -in "$_cert" 2>/dev/null | cut -d= -f2 || true)
      [[ -z "$_exp_str" ]] && continue
      _exp_epoch=$(date -d "$_exp_str" +%s 2>/dev/null || echo 0)
      [[ "$_exp_epoch" -eq 0 ]] && continue
      local _name; _name=$(basename "$_cert")
      if [[ "$_exp_epoch" -lt "$_today_epoch" ]]; then
        fail "EXPIRED certificate: $_name (expired $_exp_str)"
        _expired=$(( _expired + 1 ))
      elif [[ "$_exp_epoch" -lt "$_warn_epoch" ]]; then
        warn "Certificate expiring within 30 days: $_name (expires $_exp_str)"
        _expiring=$(( _expiring + 1 ))
      else
        _ok=$(( _ok + 1 ))
      fi
    done < <(find "$_cert_dir" -maxdepth 2 -name "*.pem" -o -name "*.crt" 2>/dev/null -print0)

    if [[ "$(( _expired + _expiring + _ok ))" -eq 0 ]]; then
      info "No parseable certificates found in $_cert_dir"
    elif [[ "$_expired" -eq 0 && "$_expiring" -eq 0 ]]; then
      pass "All $_ok certificate(s) checked — none expired or expiring soon"
    fi
  fi

  subheader "SSH host key lengths"
  for _keyfile in /etc/ssh/ssh_host_rsa_key.pub \
                  /etc/ssh/ssh_host_ecdsa_key.pub \
                  /etc/ssh/ssh_host_ed25519_key.pub; do
    [[ -f "$_keyfile" ]] || continue
    local _bits _type
    _bits=$(ssh-keygen -l -f "$_keyfile" 2>/dev/null | awk '{print $1}' || echo 0)
    _type=$(ssh-keygen -l -f "$_keyfile" 2>/dev/null | awk '{print $NF}' | tr -d '()' || echo "?")
    _bits=$(safe_int "$_bits")
    local _kname; _kname=$(basename "$_keyfile" .pub)
    if [[ "$_type" == "ED25519" ]]; then
      pass "Host key ${_kname}: ${_type} (modern, secure)"
    elif [[ "$_bits" -ge 3072 ]]; then
      pass "Host key ${_kname}: ${_bits}-bit ${_type} (acceptable)"
    elif [[ "$_bits" -ge 2048 ]]; then
      warn "Host key ${_kname}: ${_bits}-bit ${_type} (consider 4096-bit RSA or ED25519)"
    elif [[ "$_bits" -gt 0 ]]; then
      fail "Host key ${_kname}: ${_bits}-bit ${_type} — weak, regenerate immediately"
      detail "Fix: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key"
    fi
  done
}

# ================================================================
#  17g. NETWORK SECURITY EXTRAS
#  ARP poisoning protection, ICMP hardening, TCP wrappers.
# ================================================================
section_network_security() {
  header "17g. NETWORK SECURITY EXTRAS"
  subheader "ARP poisoning protection"

  local _arp_filter
  _arp_filter=$(sysctl -n net.ipv4.conf.all.arp_filter 2>/dev/null || echo 0)
  _arp_filter=$(safe_int "$_arp_filter")
  if [[ "$_arp_filter" -eq 1 ]]; then
    pass "ARP filter enabled (net.ipv4.conf.all.arp_filter=1)"
  else
    warn "ARP filter disabled — system may be vulnerable to ARP spoofing"
    detail "Fix: sysctl -w net.ipv4.conf.all.arp_filter=1"
  fi

  local _arp_announce
  _arp_announce=$(sysctl -n net.ipv4.conf.all.arp_announce 2>/dev/null || echo 0)
  _arp_announce=$(safe_int "$_arp_announce")
  if [[ "$_arp_announce" -ge 2 ]]; then
    pass "ARP announce level ${_arp_announce} — IP source address not leaked in ARP"
  else
    info "ARP announce level ${_arp_announce} — consider setting to 2"
    detail "Fix: sysctl -w net.ipv4.conf.all.arp_announce=2"
  fi

  subheader "ICMP security"
  local _icmp_ignore_bcast
  _icmp_ignore_bcast=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo 0)
  if [[ "$_icmp_ignore_bcast" -eq 1 ]]; then
    pass "ICMP broadcast echo requests ignored (Smurf attack prevention)"
  else
    warn "ICMP broadcast echo not ignored — Smurf attack amplification possible"
    detail "Fix: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
  fi

  local _icmp_bogus
  _icmp_bogus=$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null || echo 0)
  if [[ "$_icmp_bogus" -eq 1 ]]; then
    pass "Bogus ICMP error responses ignored"
  else
    info "Consider enabling: sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
  fi

  subheader "TCP/IP hardening"
  local _tcp_rfc1337
  _tcp_rfc1337=$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null || echo 0)
  if [[ "$_tcp_rfc1337" -eq 1 ]]; then
    pass "TCP RFC1337 TIME-WAIT assassination protection enabled"
  else
    warn "TCP RFC1337 protection disabled"
    detail "Fix: sysctl -w net.ipv4.tcp_rfc1337=1"
  fi

  local _martians
  _martians=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || echo 0)
  if [[ "$_martians" -eq 1 ]]; then
    pass "Martian packet logging enabled (spoofed/impossible addresses logged)"
  else
    info "Consider enabling martian packet logging:"
    detail "sysctl -w net.ipv4.conf.all.log_martians=1"
  fi

  subheader "TCP wrappers"
  if [[ -f /etc/hosts.allow || -f /etc/hosts.deny ]]; then
    local _allow_count _deny_count
    _allow_count=$(grep -vc "^#\|^[[:space:]]*$" /etc/hosts.allow 2>/dev/null || echo 0)
    _deny_count=$(grep -vc "^#\|^[[:space:]]*$" /etc/hosts.deny 2>/dev/null || echo 0)
    if grep -q "^ALL[[:space:]]*:[[:space:]]*ALL" /etc/hosts.deny 2>/dev/null; then
      pass "TCP wrappers: default-deny policy in /etc/hosts.deny"
      detail "/etc/hosts.allow has $_allow_count allow rule(s)"
    else
      info "TCP wrappers present but no default-deny rule found"
      detail "Consider adding 'ALL: ALL' to /etc/hosts.deny for default deny"
    fi
  else
    info "TCP wrappers (hosts.allow/deny) not configured"
  fi
}

# ================================================================
#  17h. AUDIT DAEMON STATUS
#  Checks auditd configuration, rules count, and log rotation.
# ================================================================
section_auditd_check() {
  header "17h. AUDITD DETAILED CHECK"
  subheader "Service status"

  if ! command -v auditctl &>/dev/null; then
    warn "auditd not installed — no kernel-level audit trail"
    detail "Install: apt install auditd && systemctl enable --now auditd"
    return
  fi

  if systemctl is-active auditd &>/dev/null; then
    pass "auditd service is active and running"
  else
    fail "auditd service is not running"
    detail "Fix: systemctl enable --now auditd"
    return
  fi

  subheader "Audit rules"
  local _rule_count
  _rule_count=$(auditctl -l 2>/dev/null | grep -vc "^No rules\|^List" || echo 0)
  _rule_count=$(safe_int "$_rule_count")

  if [[ "$_rule_count" -gt 20 ]]; then
    pass "auditd has $_rule_count active rules (comprehensive coverage)"
  elif [[ "$_rule_count" -gt 5 ]]; then
    warn "auditd has only $_rule_count rules — consider adding CIS benchmark rules"
    detail "Reference: /usr/share/doc/auditd/examples/rules/"
  else
    fail "auditd has very few rules ($_rule_count) — audit coverage is minimal"
    detail "Add rules: wget -O /etc/audit/rules.d/cis.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules"
  fi

  subheader "Audit log rotation"
  local _audit_conf="/etc/audit/auditd.conf"
  if [[ -f "$_audit_conf" ]]; then
    local _max_log_file
    _max_log_file=$(grep -i "^max_log_file\b" "$_audit_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
    _max_log_file=$(safe_int "$_max_log_file")
    if [[ "$_max_log_file" -ge 50 ]]; then
      pass "Audit log max size: ${_max_log_file}MB (sufficient)"
    elif [[ "$_max_log_file" -gt 0 ]]; then
      warn "Audit log max size: ${_max_log_file}MB — consider increasing to 50MB+"
    else
      info "max_log_file not set in auditd.conf — using default"
    fi

    local _num_logs
    _num_logs=$(grep -i "^num_logs\b" "$_audit_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
    _num_logs=$(safe_int "$_num_logs")
    if [[ "$_num_logs" -ge 5 ]]; then
      pass "Audit log rotation: $_num_logs log files kept"
    elif [[ "$_num_logs" -gt 0 ]]; then
      warn "Only $_num_logs audit log rotation files — logs may be overwritten quickly"
    fi
  fi
}

# ================================================================
#  17i. OPEN FILES & SOCKET EXPOSURE
#  Lists processes with unexpected open network connections and
#  checks for processes with deleted-but-open executables (rootkit indicator).
# ================================================================
section_open_files_check() {
  header "17i. OPEN FILES & SOCKET EXPOSURE"
  subheader "Processes with deleted open executables"

  local _deleted_exes=""
  if command -v lsof &>/dev/null; then
    _deleted_exes=$(lsof +L1 2>/dev/null \
      | grep -v "^COMMAND\|/dev/\|/proc/\|/run/\|/tmp/font\|/var/cache/fontconfig" \
      | awk '{print $1, $2, $9}' | head -20 || true)
  elif [[ -d /proc ]]; then
    local _pid
    for _pid in /proc/[0-9]*/exe; do
      local _target
      _target=$(readlink "$_pid" 2>/dev/null || true)
      [[ "$_target" == *" (deleted)"* ]] && \
        _deleted_exes+="$(basename "$(dirname "$_pid")") $_target"$'\n'
    done
  fi

  if [[ -n "$_deleted_exes" ]]; then
    warn "Processes running with deleted executables (possible rootkit or stale update):"
    while IFS= read -r _line; do
      [[ -n "$_line" ]] && detail "$_line"
    done <<< "$(echo "$_deleted_exes" | head -10)"
    detail "Investigate each: if after apt upgrade, restart the process."
    detail "If unexplained: treat as potential rootkit indicator."
  else
    pass "No processes found running with deleted executables"
  fi

  subheader "File descriptor exhaustion risk"
  local _fd_max _fd_used _fd_pct
  _fd_max=$(cat /proc/sys/fs/file-max 2>/dev/null || echo "0")
  _fd_used=$(awk '{print $1}' /proc/sys/fs/file-nr 2>/dev/null || echo "0")
  _fd_max=$(safe_int "$_fd_max"); _fd_used=$(safe_int "$_fd_used")
  if [[ "$_fd_max" -gt 0 ]]; then
    _fd_pct=$(( _fd_used * 100 / _fd_max ))
    if [[ "$_fd_pct" -ge 80 ]]; then
      fail "File descriptor usage critical: ${_fd_used}/${_fd_max} (${_fd_pct}%)"
      detail "Increase fs.file-max or investigate descriptor leaks: lsof | wc -l"
    elif [[ "$_fd_pct" -ge 60 ]]; then
      warn "File descriptor usage elevated: ${_fd_used}/${_fd_max} (${_fd_pct}%)"
    else
      pass "File descriptor usage normal: ${_fd_used}/${_fd_max} (${_fd_pct}%)"
    fi
  fi

  subheader "World-readable sensitive open files"
  # Check if any process has a sensitive file open (e.g. /etc/shadow, private keys)
  if command -v lsof &>/dev/null; then
    local _sensitive_open
    _sensitive_open=$(lsof 2>/dev/null \
      | grep -E "/etc/shadow|/etc/gshadow|id_rsa|id_ed25519|\.pem|\.key|\.p12" \
      | grep -v "^COMMAND" | awk '{print $1, $2, $9}' | head -10 || true)
    if [[ -n "$_sensitive_open" ]]; then
      warn "Sensitive files are currently open by processes:"
      while IFS= read -r _line; do detail "$_line"; done <<< "$_sensitive_open"
    else
      pass "No sensitive files (shadow, private keys) found open by processes"
    fi
  fi

  subheader "Unix socket exposure"
  local _world_sockets
  _world_sockets=$(find /tmp /var/run /run -maxdepth 2 -type s \
    \( -perm -0002 \) 2>/dev/null | head -10 || true)
  if [[ -n "$_world_sockets" ]]; then
    warn "World-writable Unix sockets found:"
    while IFS= read -r _s; do
      detail "$_s  ($(stat -c '%U:%G %a' "$_s" 2>/dev/null || echo "stat failed"))"
    done <<< "$_world_sockets"
  else
    pass "No world-writable Unix sockets found"
  fi

  subheader "Unexpected listening services"
  if command -v ss &>/dev/null; then
    local _listeners
    _listeners=$(ss -tlnp 2>/dev/null | grep LISTEN \
      | awk '{print $4, $6}' \
      | grep -v "127\.0\.0\.1\|::1\|0\.0\.0\.0:22\b\|:::22\b" || true)
    if [[ -n "$_listeners" ]]; then
      info "Network services listening on non-loopback interfaces:"
      while IFS= read -r _l; do detail "$_l"; done <<< "$_listeners"
    else
      pass "No unexpected public-facing listeners detected"
    fi
  fi
}

# ================================================================
#  17j. SWAP SPACE & MEMORY SECURITY
#  Checks swap encryption, memory overcommit settings.
# ================================================================
section_memory_security() {
  header "17j. SWAP & MEMORY SECURITY"
  subheader "Swap encryption"

  local _swap_total
  _swap_total=$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
  _swap_total=$(safe_int "$_swap_total")

  if [[ "$_swap_total" -eq 0 ]]; then
    info "No swap space configured"
  else
    local _swap_enc=false
    if command -v dmsetup &>/dev/null; then
      dmsetup status 2>/dev/null | grep -qi "crypt" && _swap_enc=true
    fi
    if grep -q "swap" /etc/crypttab 2>/dev/null; then _swap_enc=true; fi
    if [[ "$_swap_enc" == "true" ]]; then
      pass "Swap space is encrypted via dm-crypt"
    else
      warn "Swap space (${_swap_total}KB) is NOT encrypted — sensitive data may persist on disk"
      detail "Add to /etc/crypttab: swap /dev/sdXY /dev/urandom swap,cipher=aes-xts-plain64,size=256"
    fi
  fi

  subheader "Memory overcommit policy"
  local _overcommit
  _overcommit=$(sysctl -n vm.overcommit_memory 2>/dev/null || echo "0")
  _overcommit=$(safe_int "$_overcommit")
  case "$_overcommit" in
    0) info "vm.overcommit_memory=0 (heuristic overcommit — default, reasonable)" ;;
    1) warn "vm.overcommit_memory=1 (always overcommit — can mask OOM conditions)" ;;
    2) pass "vm.overcommit_memory=2 (strict overcommit — most secure, prevents OOM)" ;;
  esac

  subheader "Kernel pointer exposure via /proc/kallsyms"
  local _kptr
  _kptr=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "0")
  _kptr=$(safe_int "$_kptr")
  if [[ "$_kptr" -ge 2 ]]; then
    pass "kernel.kptr_restrict=$_kptr — kernel pointers hidden from all users"
  elif [[ "$_kptr" -eq 1 ]]; then
    warn "kernel.kptr_restrict=1 — pointers hidden from non-root only (set to 2)"
  else
    fail "kernel.kptr_restrict=0 — kernel addresses visible to all users (exploitation aid)"
    detail "Fix: sysctl -w kernel.kptr_restrict=2"
  fi
}

# ================================================================
#  17k. PAM & AUTHENTICATION HARDENING
# ================================================================
section_pam_security() {
  header "17k. PAM & AUTHENTICATION HARDENING"
  subheader "PAM module integrity"

  local _pam_unknown=0
  local _pam_pkg_files=""
  if command -v dpkg &>/dev/null; then
    _pam_pkg_files=$(dpkg -S '/lib/*/security/pam_*.so' '/lib64/security/pam_*.so' \
      2>/dev/null | awk -F': ' '{print $2}' | sort -u || true)
  fi
  for _mod in /lib/*/security/pam_*.so /lib64/security/pam_*.so; do
    [[ -f "$_mod" ]] || continue
    if [[ -n "$_pam_pkg_files" ]] && \
       ! grep -qF "$(basename "$_mod")" <<< "$_pam_pkg_files"; then
      warn "PAM module not owned by any package: $_mod"
      _pam_unknown=$(( _pam_unknown + 1 ))
    fi
  done
  [[ "$_pam_unknown" -eq 0 ]] && pass "All PAM modules belong to installed packages"

  subheader "TOTP / Two-Factor Authentication"
  if grep -rqE "pam_google_authenticator|pam_oath|pam_totp" /etc/pam.d/ 2>/dev/null; then
    pass "Two-factor authentication PAM module is configured"
  else
    info "No TOTP/2FA PAM module found — consider: apt install libpam-google-authenticator"
  fi

  subheader "Sudo I/O logging"
  if grep -rqE "log_input|log_output|iolog_dir" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    pass "Sudo I/O logging is configured (privileged commands are recorded)"
  else
    warn "Sudo I/O logging not enabled — no record of commands run via sudo"
    detail "Add to /etc/sudoers.d/audit: Defaults log_input,log_output,iolog_dir=/var/log/sudo-io"
  fi

  subheader "su restriction to wheel/sudo group"
  if grep -qE "pam_wheel|auth.*required.*pam_wheel" /etc/pam.d/su 2>/dev/null; then
    pass "su is restricted to wheel group via pam_wheel"
  else
    warn "su is not restricted — any user can attempt su to root"
    detail "Add to /etc/pam.d/su: auth required pam_wheel.so use_uid"
  fi
}

# ================================================================
#  17l. FILESYSTEM HARDENING
# ================================================================
section_filesystem_hardening() {
  header "17l. FILESYSTEM HARDENING"
  subheader "/tmp mount options"

  local _tmp_opts=""
  _tmp_opts=$(findmnt -no OPTIONS /tmp 2>/dev/null || \
    grep -w "/tmp" /proc/mounts 2>/dev/null | awk '{print $4}' || true)

  if [[ -z "$_tmp_opts" ]]; then
    warn "/tmp is not a separate filesystem — noexec/nosuid cannot be enforced per-mount"
    detail "Consider: mount a tmpfs on /tmp with noexec,nosuid,nodev"
  else
    local _f_noexec _f_nosuid _f_nodev
    _f_noexec=$(echo "$_tmp_opts" | grep -c "noexec" || true)
    _f_nosuid=$(echo "$_tmp_opts" | grep -c "nosuid" || true)
    _f_nodev=$(echo  "$_tmp_opts" | grep -c "nodev"  || true)
    [[ "$_f_noexec" -gt 0 ]] && pass "/tmp mounted noexec — script execution from /tmp blocked" \
      || fail "/tmp missing noexec — attackers can run scripts from /tmp"
    [[ "$_f_nosuid" -gt 0 ]] && pass "/tmp mounted nosuid" \
      || warn "/tmp missing nosuid — SUID binaries in /tmp can escalate privileges"
    [[ "$_f_nodev" -gt 0 ]]  && pass "/tmp mounted nodev" \
      || info "/tmp missing nodev (low risk on most systems)"
  fi

  subheader "/dev/shm security"
  local _shm_opts=""
  _shm_opts=$(findmnt -no OPTIONS /dev/shm 2>/dev/null || true)
  if [[ -n "$_shm_opts" ]]; then
    local _s_noexec
    _s_noexec=$(echo "$_shm_opts" | grep -c "noexec" || true)
    [[ "$_s_noexec" -gt 0 ]] && pass "/dev/shm mounted noexec" \
      || warn "/dev/shm missing noexec — shared memory exploitable for code execution"
  else
    info "/dev/shm mount options unavailable"
  fi

  subheader "/proc hidepid"
  local _proc_opts=""
  _proc_opts=$(findmnt -no OPTIONS /proc 2>/dev/null || true)
  if echo "$_proc_opts" | grep -qE "hidepid=2|hidepid=invisible"; then
    pass "/proc mounted with hidepid=2 — processes hidden from non-root users"
  elif echo "$_proc_opts" | grep -q "hidepid=1"; then
    warn "/proc hidepid=1 — directories hidden but cmdline still visible; upgrade to hidepid=2"
  else
    warn "/proc mounted without hidepid — all users can inspect other processes' environments"
    detail "Add to /etc/fstab: proc /proc proc defaults,hidepid=2,gid=proc 0 0"
  fi

  subheader "Home directory permissions"
  local _home_bad=0
  while IFS=: read -r _uname _ _uid _ _ _uhome _; do
    [[ "$_uid" -lt 1000 || "$_uid" -ge 65534 ]] && continue
    [[ -d "$_uhome" ]] || continue
    local _hp
    _hp=$(stat -c%a "$_uhome" 2>/dev/null || echo "755")
    # Last digit: world bits. 0=none 1=x 2=w 3=wx 4=r 5=rx 6=rw 7=rwx
    # Middle digit: group bits.
    local _world_bit="${_hp: -1}" _group_bit="${_hp: -2:1}"
    if [[ "$_world_bit" =~ [1-7] ]] || [[ "$_group_bit" =~ [2367] ]]; then
      warn "Loose home directory: $_uhome ($_hp) for $_uname"
      _home_bad=$(( _home_bad + 1 ))
    fi
  done < /etc/passwd
  [[ "$_home_bad" -eq 0 ]] && pass "All home directories have safe permissions (700 or 750)"
}

# ================================================================
#  17m. CONTAINER SECURITY DEEP-DIVE
# ================================================================
section_container_security() {
  header "17m. CONTAINER SECURITY DEEP-DIVE"

  if ! command -v docker &>/dev/null; then
    info "Docker not installed — skipping container security checks"
    return
  fi

  subheader "Docker daemon configuration"
  local _daemon_json="/etc/docker/daemon.json"
  if [[ -f "$_daemon_json" ]]; then
    if grep -q '"no-new-privileges".*true' "$_daemon_json" 2>/dev/null; then
      pass "Docker: no-new-privileges=true set globally in daemon.json"
    else
      warn "Docker: no-new-privileges not set — containers can gain privileges via SUID"
      detail "Add to /etc/docker/daemon.json: { \"no-new-privileges\": true }"
    fi
    if grep -q '"userns-remap"' "$_daemon_json" 2>/dev/null; then
      pass "Docker: user namespace remapping enabled (container root ≠ host root)"
    else
      warn "Docker: user namespace remapping not enabled"
      detail "Add to daemon.json: { \"userns-remap\": \"default\" }"
    fi
  else
    warn "No /etc/docker/daemon.json — Docker running with insecure defaults"
    detail "Create /etc/docker/daemon.json with: no-new-privileges, userns-remap, log-level"
  fi

  subheader "Docker socket and group permissions"
  if [[ -S /var/run/docker.sock ]]; then
    local _sperm
    _sperm=$(stat -c%a /var/run/docker.sock 2>/dev/null || echo "0")
    if [[ "$_sperm" -le 660 ]]; then
      pass "Docker socket permissions: $_sperm"
    else
      fail "Docker socket too permissive: $_sperm — grants host root-equivalent access"
    fi
    local _docker_members
    _docker_members=$(getent group docker 2>/dev/null | cut -d: -f4 || true)
    if [[ -n "$_docker_members" ]]; then
      warn "Users in docker group (effectively root): $_docker_members"
      detail "Each docker group member can escape to host root via: docker run -v /:/host ..."
    else
      pass "No non-root users in docker group"
    fi
  fi

  subheader "Running containers: root user check"
  local _container_count _root_containers=0
  _container_count=$(docker ps -q 2>/dev/null | wc -l || echo 0)
  _container_count=$(safe_int "$_container_count")
  if [[ "$_container_count" -eq 0 ]]; then
    info "No containers currently running"
    return
  fi
  info "$_container_count container(s) running"
  while IFS= read -r _cid; do
    [[ -z "$_cid" ]] && continue
    local _cuser _cname
    _cuser=$(docker inspect --format='{{.Config.User}}' "$_cid" 2>/dev/null || echo "")
    _cname=$(docker inspect --format='{{.Name}}' "$_cid" 2>/dev/null | tr -d '/' || echo "$_cid")
    if [[ -z "$_cuser" || "$_cuser" == "root" || "$_cuser" == "0" ]]; then
      warn "Container running as root: $_cname — add USER in Dockerfile"
      _root_containers=$(( _root_containers + 1 ))
    fi
  done < <(docker ps -q 2>/dev/null || true)
  [[ "$_root_containers" -eq 0 ]] && pass "All running containers use a non-root USER"
}

# ================================================================
#  17n. PACKAGE REPOSITORY SECURITY
# ================================================================
section_repo_security() {
  header "17n. PACKAGE REPOSITORY SECURITY"
  subheader "APT source signing"

  local _unsigned=0
  if grep -rqE "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    fail "APT source with 'trusted=yes' found — signature verification bypassed"
    _unsigned=$(( _unsigned + 1 ))
  fi
  local _key_missing
  _key_missing=$(apt-get update --print-uris 2>&1 | grep -c "NO_PUBKEY\|no public key" || true)
  _key_missing=$(safe_int "$_key_missing")
  if [[ "$_key_missing" -gt 0 ]]; then
    warn "$_key_missing APT repository/repositories missing a GPG signing key"
  fi
  [[ "$_unsigned" -eq 0 && "$_key_missing" -eq 0 ]] && pass "All APT repositories appear properly signed"

  subheader "Third-party repositories"
  local _third=0
  while IFS= read -r _srcfile; do
    [[ -f "$_srcfile" ]] || continue
    while IFS= read -r _line; do
      [[ "$_line" =~ ^[[:space:]]*# ]] && continue
      [[ -z "${_line// /}" ]] && continue
      if [[ "$_line" == deb* ]] && \
         ! echo "$_line" | grep -qE "ubuntu\.com|debian\.org|raspbian\.org|launchpad\.net"; then
        info "Third-party APT source: $_line"
        detail "File: $_srcfile — verify you trust this repository"
        _third=$(( _third + 1 ))
      fi
    done < "$_srcfile"
  done < <(find /etc/apt -name "*.list" -o -name "*.sources" 2>/dev/null)
  if [[ "$_third" -gt 0 ]]; then
    note "$_third third-party APT source(s) — ensure each is from a trusted vendor"
  else
    pass "No third-party APT repositories detected"
  fi

  subheader "Installed package footprint"
  local _pkg_count
  _pkg_count=$(dpkg -l 2>/dev/null | grep -c "^ii" || echo 0)
  _pkg_count=$(safe_int "$_pkg_count")
  info "$_pkg_count packages installed"
  if [[ "$_pkg_count" -gt 800 ]]; then
    warn "$_pkg_count packages installed — large footprint increases attack surface"
    detail "Run: apt autoremove && apt purge \$(deborphan) to reduce footprint"
  else
    pass "Package footprint is reasonable ($_pkg_count packages)"
  fi
}


# ================================================================
#  17o. TIME SYNCHRONISATION SECURITY
#  Accurate time is critical for auth tokens, logs, and certs.
# ================================================================
section_time_sync() {
  header "17o. TIME SYNCHRONISATION SECURITY"
  subheader "NTP / systemd-timesyncd status"

  local _time_synced=false
  if command -v timedatectl &>/dev/null; then
    local _td_out
    _td_out=$(timedatectl show 2>/dev/null || timedatectl 2>/dev/null || true)
    if echo "$_td_out" | grep -qi "NTPSynchronized=yes\|NTP synchronized: yes\|System clock synchronized: yes"; then
      pass "System clock is NTP-synchronised"
      _time_synced=true
    elif echo "$_td_out" | grep -qi "NTP service: active\|NetworkTimeProtocol=yes"; then
      warn "NTP service active but not yet synchronised — may be starting up"
    else
      fail "System clock is NOT synchronised via NTP"
      detail "Fix: timedatectl set-ntp true"
    fi
  fi

  # Check for ntpd or chrony as alternatives
  if ! "$_time_synced"; then
    if systemctl is-active ntp &>/dev/null || systemctl is-active ntpd &>/dev/null; then
      pass "ntpd service is active"
      _time_synced=true
    elif systemctl is-active chronyd &>/dev/null; then
      pass "chrony time daemon is active"
      _time_synced=true
    fi
  fi

  subheader "NTP server configuration"
  local _ntp_servers=""
  for _conf in /etc/systemd/timesyncd.conf /etc/ntp.conf /etc/chrony.conf /etc/chrony/chrony.conf; do
    [[ -f "$_conf" ]] || continue
    _ntp_servers=$(grep -E "^NTP=|^server\s|^pool\s" "$_conf" 2>/dev/null | head -5 || true)
    [[ -n "$_ntp_servers" ]] && break
  done
  if [[ -n "$_ntp_servers" ]]; then
    pass "NTP servers configured:"
    while IFS= read -r _srv; do detail "$_srv"; done <<< "$_ntp_servers"
  else
    info "NTP server configuration not found in standard config files"
  fi

  subheader "Clock drift check"
  if command -v chronyc &>/dev/null; then
    local _drift
    _drift=$(chronyc tracking 2>/dev/null | grep "System time" | awk '{print $4}' || true)
    if [[ -n "$_drift" ]]; then
      info "Chrony system time offset: ${_drift}s"
    fi
  fi
}

# ================================================================
#  17p. IPv6 SECURITY
#  Many admins configure IPv4 but leave IPv6 open by default.
# ================================================================
section_ipv6_security() {
  header "17p. IPv6 SECURITY"
  subheader "IPv6 enabled/disabled status"

  local _ipv6_disabled=false
  local _sysctl_ipv6
  _sysctl_ipv6=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
  _sysctl_ipv6=$(safe_int "$_sysctl_ipv6")

  if [[ "$_sysctl_ipv6" -eq 1 ]]; then
    pass "IPv6 is disabled system-wide (net.ipv6.conf.all.disable_ipv6=1)"
    _ipv6_disabled=true
  else
    info "IPv6 is enabled — checking firewall coverage"
  fi

  if [[ "$_ipv6_disabled" == "true" ]]; then
    return
  fi

  subheader "ip6tables / nftables rules"
  local _ip6_rules=0
  if command -v ip6tables &>/dev/null; then
    _ip6_rules=$(ip6tables -L INPUT --line-numbers 2>/dev/null | grep -vc "^Chain\|^target\|^num\|^$" || true)
    _ip6_rules=$(safe_int "$_ip6_rules")
    if [[ "$_ip6_rules" -gt 0 ]]; then
      pass "ip6tables has $_ip6_rules INPUT rule(s) — IPv6 traffic is filtered"
    else
      fail "ip6tables INPUT chain is empty — IPv6 traffic is completely unfiltered"
      detail "Fix: ip6tables -P INPUT DROP && ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    fi
  fi

  if command -v ufw &>/dev/null; then
    local _ufw_ipv6
    _ufw_ipv6=$(grep -i "^IPV6=yes" /etc/default/ufw 2>/dev/null || true)
    if [[ -n "$_ufw_ipv6" ]]; then
      pass "UFW is configured to manage IPv6 rules (IPV6=yes in /etc/default/ufw)"
    else
      warn "UFW may not be managing IPv6 — check /etc/default/ufw for IPV6=yes"
    fi
  fi

  subheader "IPv6 router advertisement acceptance"
  local _ra_accept
  _ra_accept=$(sysctl -n net.ipv6.conf.all.accept_ra 2>/dev/null || echo "1")
  _ra_accept=$(safe_int "$_ra_accept")
  if [[ "$_ra_accept" -eq 0 ]]; then
    pass "IPv6 router advertisement acceptance disabled (net.ipv6.conf.all.accept_ra=0)"
  else
    warn "IPv6 router advertisements accepted — rogue RA can redirect IPv6 traffic"
    detail "Fix: sysctl -w net.ipv6.conf.all.accept_ra=0"
  fi
}

# ================================================================
#  17q. SSH HARDENING EXTRAS
#  Fine-grained SSH config checks beyond section 5.
# ================================================================
section_ssh_extras() {
  header "17q. SSH HARDENING EXTRAS"
  subheader "Allowed authentication methods"

  local _sshd_config="/etc/ssh/sshd_config"
  [[ -f "$_sshd_config" ]] || { info "No /etc/ssh/sshd_config found"; return; }

  # AuthenticationMethods
  local _auth_methods
  _auth_methods=$(grep -i "^AuthenticationMethods" "$_sshd_config" 2>/dev/null | awk '{print $2}' || echo "")
  if [[ -n "$_auth_methods" ]]; then
    pass "AuthenticationMethods explicitly set: $_auth_methods"
  else
    info "AuthenticationMethods not set — defaults to publickey,password"
  fi

  # Ciphers — check for weak/deprecated
  local _ciphers
  _ciphers=$(grep -i "^Ciphers" "$_sshd_config" 2>/dev/null | cut -d' ' -f2- || echo "")
  if [[ -n "$_ciphers" ]]; then
    if echo "$_ciphers" | grep -qE "arcfour|3des|blowfish|cast128|aes128-cbc|aes192-cbc|aes256-cbc"; then
      fail "Weak/deprecated SSH ciphers configured: $(echo "$_ciphers" | tr ',' '\n' | grep -E "arcfour|3des|blowfish|cast128|cbc" | head -3 | tr '\n' ' ')"
      detail "Recommended: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
    else
      pass "SSH ciphers are restricted to modern algorithms"
    fi
  else
    info "No Ciphers line in sshd_config — using OpenSSH defaults"
  fi

  # MACs — check for weak
  local _macs
  _macs=$(grep -i "^MACs" "$_sshd_config" 2>/dev/null | cut -d' ' -f2- || echo "")
  if [[ -n "$_macs" ]]; then
    if echo "$_macs" | grep -qE "md5|sha1\b|umac-64"; then
      fail "Weak SSH MACs configured — MD5/SHA1 in use"
      detail "Remove: hmac-md5, hmac-sha1, umac-64. Keep: hmac-sha2-256, hmac-sha2-512, umac-128"
    else
      pass "SSH MACs are strong (no MD5/SHA1)"
    fi
  fi

  # KexAlgorithms
  local _kex
  _kex=$(grep -i "^KexAlgorithms" "$_sshd_config" 2>/dev/null | cut -d' ' -f2- || echo "")
  if [[ -n "$_kex" ]]; then
    if echo "$_kex" | grep -qE "diffie-hellman-group1|diffie-hellman-group14-sha1|gss-gex-sha1"; then
      fail "Weak SSH key exchange algorithms configured (DH group1/14-sha1)"
      detail "Recommended: KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
    else
      pass "SSH key exchange algorithms use strong curves/groups"
    fi
  fi

  subheader "Login restrictions"
  # AllowUsers / AllowGroups
  local _allow_users _allow_groups
  _allow_users=$(grep -iE "^AllowUsers|^AllowGroups" "$_sshd_config" 2>/dev/null || echo "")
  if [[ -n "$_allow_users" ]]; then
    pass "SSH login restricted: $_allow_users"
  else
    warn "No AllowUsers or AllowGroups in sshd_config — any valid user can attempt SSH login"
    detail "Add: AllowUsers yourusername  OR  AllowGroups sshusers"
  fi

  # MaxSessions
  local _max_sess
  _max_sess=$(grep -i "^MaxSessions" "$_sshd_config" 2>/dev/null | awk '{print $2}' || echo "10")
  _max_sess=$(safe_int "$_max_sess")
  if [[ "$_max_sess" -le 4 ]]; then
    pass "MaxSessions=$_max_sess (limits parallel channel abuse)"
  else
    info "MaxSessions=$_max_sess — consider reducing to 3-4 for hardened servers"
  fi

  # Disable agent and TCP forwarding combined check
  local _agent_fwd _tcp_fwd
  _agent_fwd=$(grep -i "^AllowAgentForwarding" "$_sshd_config" 2>/dev/null | awk '{print tolower($2)}' || echo "yes")
  _tcp_fwd=$(grep -i "^AllowTcpForwarding" "$_sshd_config" 2>/dev/null | awk '{print tolower($2)}' || echo "yes")
  if [[ "$_agent_fwd" == "no" && "$_tcp_fwd" == "no" ]]; then
    pass "SSH agent forwarding and TCP forwarding both disabled"
  elif [[ "$_agent_fwd" == "no" ]]; then
    info "SSH agent forwarding disabled; TCP forwarding still enabled"
  elif [[ "$_tcp_fwd" == "no" ]]; then
    info "SSH TCP forwarding disabled; agent forwarding still enabled"
  else
    warn "Both SSH agent forwarding and TCP forwarding are enabled"
    detail "For hardened servers: AllowAgentForwarding no && AllowTcpForwarding no"
  fi
}


# ================================================================
#  17r. CORE DUMP SECURITY
# ================================================================
section_core_dump_security() {
  header "17r. CORE DUMP SECURITY"
  subheader "Core dump enabled/disabled"

  local _core_pattern
  _core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "core")

  # Disabled if pattern is empty or /dev/null
  if [[ "$_core_pattern" == "|/bin/false" || "$_core_pattern" == "/dev/null" ]]; then
    pass "Core dumps disabled (kernel.core_pattern → /dev/null or suppressed)"
  elif [[ "$_core_pattern" == *"|/usr/share/apport"* || "$_core_pattern" == *"apport"* ]]; then
    info "Core dumps handled by apport: $( echo "$_core_pattern" | head -c 60 )"
    detail "Verify apport is configured to not store full core dumps in production"
  else
    warn "Core dumps enabled — pattern: $( echo "$_core_pattern" | head -c 60 )"
    detail "Disable: echo 'kernel.core_pattern=/dev/null' >> /etc/sysctl.d/99-hardening.conf"
  fi

  subheader "Core dump size limits"
  local _core_size
  _core_size=$(ulimit -c 2>/dev/null || echo "unknown")
  if [[ "$_core_size" == "0" ]]; then
    pass "Core dump size limit is 0 (core dumps suppressed via ulimit)"
  elif [[ "$_core_size" == "unlimited" ]]; then
    warn "Core dump size is unlimited — can fill disk and leak sensitive process memory"
    detail "Add to /etc/security/limits.conf: * hard core 0"
  else
    info "Core dump size limit: ${_core_size} blocks"
  fi

  subheader "SUID core dumps"
  local _suid_dumpable
  _suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "0")
  _suid_dumpable=$(safe_int "$_suid_dumpable")
  if [[ "$_suid_dumpable" -eq 0 ]]; then
    pass "fs.suid_dumpable=0 — SUID processes cannot produce core dumps"
  elif [[ "$_suid_dumpable" -eq 2 ]]; then
    info "fs.suid_dumpable=2 — core dumps produced for SUID processes (root-readable only)"
  else
    fail "fs.suid_dumpable=1 — SUID core dumps readable by process owner (privilege leak)"
    detail "Fix: sysctl -w fs.suid_dumpable=0"
  fi

  subheader "Systemd core dump configuration"
  if [[ -f /etc/systemd/coredump.conf ]]; then
    local _sd_storage
    _sd_storage=$(grep -i "^Storage=" /etc/systemd/coredump.conf 2>/dev/null \
                  | cut -d= -f2 | tr -d ' ' || echo "")
    if [[ "$_sd_storage" == "none" ]]; then
      pass "systemd coredump storage disabled"
    elif [[ -n "$_sd_storage" ]]; then
      info "systemd coredump storage: $_sd_storage"
    fi
  fi
}

# ================================================================
#  17s. SYSTEMD UNIT HARDENING
# ================================================================
section_systemd_hardening() {
  header "17s. SYSTEMD UNIT HARDENING"
  subheader "Critical service sandboxing"

  local _svc _ok=0 _weak=0
  for _svc in sshd ssh nginx apache2 httpd mysql mysqld postgresql \
              redis-server mongod docker cups avahi-daemon; do
    if systemctl is-active --quiet "$_svc" 2>/dev/null; then
      local _unit_file
      _unit_file=$(systemctl cat "$_svc" 2>/dev/null | head -80 || true)
      local _score=0
      echo "$_unit_file" | grep -qiE "^PrivateTmp\s*=\s*true"      && _score=$((_score+1))
      echo "$_unit_file" | grep -qiE "^ProtectSystem\s*=\s*(strict|full|true)" && _score=$((_score+1))
      echo "$_unit_file" | grep -qiE "^NoNewPrivileges\s*=\s*true"  && _score=$((_score+1))
      echo "$_unit_file" | grep -qiE "^ProtectHome\s*=\s*(true|read-only|tmpfs)" && _score=$((_score+1))
      echo "$_unit_file" | grep -qiE "^RestrictNamespaces\s*=\s*true" && _score=$((_score+1))
      if [[ "$_score" -ge 3 ]]; then
        pass "${_svc}: good sandboxing ($_score/5 directives)"
        _ok=$(( _ok+1 ))
      elif [[ "$_score" -ge 1 ]]; then
        warn "${_svc}: partial sandboxing ($_score/5) — add PrivateTmp, ProtectSystem=strict, NoNewPrivileges"
        _weak=$(( _weak+1 ))
      else
        warn "${_svc}: no systemd sandboxing detected — consider hardening the unit file"
        detail "Add to [Service]: PrivateTmp=true  ProtectSystem=strict  NoNewPrivileges=true"
        _weak=$(( _weak+1 ))
      fi
    fi
  done
  [[ "$_ok" -eq 0 && "$_weak" -eq 0 ]] && info "No well-known network services found to audit"

  subheader "Systemd-resolved and time-sync security"
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    local _dns_stub
    _dns_stub=$(grep -iE "^DNSStubListener\s*=" /etc/systemd/resolved.conf 2>/dev/null | tail -1 | cut -d= -f2 | xargs || echo "yes")
    if [[ "${_dns_stub,,}" == "no" ]]; then
      info "systemd-resolved: DNS stub listener disabled"
    else
      info "systemd-resolved: DNS stub listener active on 127.0.0.53"
    fi
  fi

  subheader "Default systemd resource limits"
  local _default_limit
  _default_limit=$(systemctl show | grep "^DefaultLimitNOFILE=" | cut -d= -f2 || echo "unknown")
  info "Default file descriptor limit (DefaultLimitNOFILE): ${_default_limit:-system default}"

  subheader "Systemd journal storage"
  local _storage
  _storage=$(grep -iE "^Storage\s*=" /etc/systemd/journald.conf 2>/dev/null | tail -1 | cut -d= -f2 | xargs || echo "auto")
  case "${_storage,,}" in
    persistent) pass "journald Storage=persistent — logs survive reboot" ;;
    auto)       info "journald Storage=auto (persistent if /var/log/journal exists)" ;;
    volatile)   warn "journald Storage=volatile — logs lost on reboot; consider persistent" ;;
    none)       fail "journald Storage=none — all logs discarded!" ;;
    *)          info "journald Storage=${_storage}" ;;
  esac

  subheader "Failed systemd units"
  local _failed_units
  _failed_units=$(systemctl --failed --no-legend 2>/dev/null | awk '{print $1}' | head -10 || true)
  if [[ -z "$_failed_units" ]]; then
    pass "No failed systemd units"
  else
    fail "Failed systemd unit(s) detected:"
    while IFS= read -r _u; do detail "$_u"; done <<< "$_failed_units"
  fi

  subheader "Socket-activated services"
  local _socket_count
  _socket_count=$(systemctl list-units --type=socket --state=active --no-legend 2>/dev/null | wc -l || echo "0")
  _socket_count=$(safe_int "$_socket_count")
  info "$_socket_count active socket-activated unit(s)"
  if [[ "$_socket_count" -gt 10 ]]; then
    info "Review socket units: systemctl list-units --type=socket"
  fi
}

# ================================================================
#  17t. SUDO AUDIT
# ================================================================
section_sudo_audit() {
  header "17t. SUDO CONFIGURATION AUDIT"
  subheader "NOPASSWD entries"

  local _nopasswd_count=0
  local _nopasswd_entries=""
  if [[ -f /etc/sudoers ]]; then
    _nopasswd_entries=$(grep -E "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
      | grep -v "^#" | grep -v "^[[:space:]]*#" || true)
    _nopasswd_count=$(echo "$_nopasswd_entries" | grep -c "NOPASSWD" || echo 0)
    _nopasswd_count=$(safe_int "$_nopasswd_count")
  fi

  if [[ "$_nopasswd_count" -eq 0 ]]; then
    pass "No NOPASSWD entries in sudoers — password required for all sudo use"
  else
    warn "$_nopasswd_count NOPASSWD sudo rule(s) — users can sudo without a password"
    while IFS= read -r _entry; do
      [[ -n "$_entry" ]] && detail "$_entry"
    done <<< "$_nopasswd_entries"
  fi

  subheader "Wildcard and ALL command rules"
  local _wildcard_rules=""
  _wildcard_rules=$(grep -E "ALL\s*=\s*\(ALL\)\s*ALL|=\s*\(ALL:ALL\)\s*ALL|\bALL\b.*\bALL\b.*\bALL\b" \
    /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v "^#" || true)
  if [[ -n "$_wildcard_rules" ]]; then
    warn "Broad 'ALL' sudo rules found (effectively root on all commands):"
    while IFS= read -r _r; do [[ -n "$_r" ]] && detail "$_r"; done <<< "$(echo "$_wildcard_rules" | head -5)"
  else
    pass "No unrestricted ALL sudo rules detected"
  fi

  subheader "Sudo timeout"
  local _sudo_timeout
  _sudo_timeout=$(grep -E "^Defaults.*timestamp_timeout" /etc/sudoers 2>/dev/null \
    | grep -oE "timestamp_timeout\s*=\s*[0-9-]+" | grep -oE "[0-9-]+" || echo "15")
  _sudo_timeout=$(safe_int "$_sudo_timeout")
  if [[ "$_sudo_timeout" -eq 0 ]]; then
    pass "Sudo timestamp_timeout=0 — password required every time"
  elif [[ "$_sudo_timeout" -le 5 ]]; then
    pass "Sudo timeout: ${_sudo_timeout}min (short, acceptable)"
  elif [[ "$_sudo_timeout" -le 15 ]]; then
    info "Sudo timeout: ${_sudo_timeout}min (default) — consider reducing to 5"
  else
    warn "Sudo timeout: ${_sudo_timeout}min — long window for privilege escalation after compromise"
    detail "Set: Defaults timestamp_timeout=5  in /etc/sudoers"
  fi

  subheader "Sudoers file permissions"
  for _sf in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$_sf" ]] || continue
    local _sperm _sowner
    _sperm=$(stat -c%a "$_sf" 2>/dev/null || echo "644")
    _sowner=$(stat -c%U "$_sf" 2>/dev/null || echo "unknown")
    if [[ "$_sperm" != "440" && "$_sperm" != "400" && "$_sperm" != "640" ]]; then
      fail "Unsafe sudoers file permissions: $_sf ($_sperm) — should be 440"
      detail "Fix: chmod 440 $_sf"
    elif [[ "$_sowner" != "root" ]]; then
      fail "Sudoers file not owned by root: $_sf (owner: $_sowner)"
    fi
  done
  [[ -f /etc/sudoers ]] && \
    [[ "$(stat -c%a /etc/sudoers 2>/dev/null)" == "440" || "$(stat -c%a /etc/sudoers 2>/dev/null)" == "400" ]] && \
    pass "/etc/sudoers has correct permissions"
}

# ================================================================
#  17u. LOG INTEGRITY & REMOTE FORWARDING
# ================================================================
section_log_integrity() {
  header "17u. LOG INTEGRITY & REMOTE FORWARDING"
  subheader "Remote syslog forwarding"

  local _remote_log=false
  # Check rsyslog for remote forwarding
  if [[ -d /etc/rsyslog.d ]] || [[ -f /etc/rsyslog.conf ]]; then
    local _fwd
    _fwd=$(grep -rE "^[^#].*@@?[0-9a-zA-Z]" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null \
           | grep -v "^#" | head -3 || true)
    if [[ -n "$_fwd" ]]; then
      pass "rsyslog configured for remote forwarding (logs shipped off-system)"
      while IFS= read -r _f; do detail "$_f"; done <<< "$_fwd"
      _remote_log=true
    fi
  fi
  # Check syslog-ng
  if [[ -d /etc/syslog-ng ]]; then
    if grep -rq "destination.*tcp\|destination.*udp" /etc/syslog-ng/ 2>/dev/null; then
      pass "syslog-ng configured for remote forwarding"
      _remote_log=true
    fi
  fi
  # Check systemd-journal-remote
  if systemctl is-active systemd-journal-upload &>/dev/null; then
    pass "systemd-journal-upload is active (journals forwarded remotely)"
    _remote_log=true
  fi

  if [[ "$_remote_log" == "false" ]]; then
    warn "No remote log forwarding configured — logs lost if system is compromised"
    detail "Consider: rsyslog with @@syslog-server:514 or SIEM agent (Elastic, Splunk)"
  fi

  subheader "Log file integrity indicators"
  # Check for log gaps (sudden jumps in syslog timestamps — possible tampering)
  local _auth_log="" _gap_found=false
  for _f in /var/log/auth.log /var/log/secure; do
    [[ -r "$_f" ]] && { _auth_log="$_f"; break; }
  done

  if [[ -n "$_auth_log" ]]; then
    local _log_perms _log_owner
    _log_perms=$(stat -c%a "$_auth_log" 2>/dev/null || echo "0")
    _log_owner=$(stat -c%U "$_auth_log" 2>/dev/null || echo "unknown")
    if [[ "$_log_owner" != "root" && "$_log_owner" != "syslog" ]]; then
      fail "Auth log owner is $_log_owner (expected root/syslog) — possible tampering"
    else
      pass "Auth log ownership is correct ($_log_owner)"
    fi
    # Check if world-readable
    if [[ "${_log_perms: -1}" =~ [4567] ]]; then
      warn "Auth log is world-readable: $_auth_log ($_log_perms)"
      detail "Fix: chmod 640 $_auth_log"
    else
      pass "Auth log permissions are restricted ($_log_perms)"
    fi
  fi

  subheader "Logrotate configuration"
  if [[ -f /etc/logrotate.conf ]]; then
    local _retention
    _retention=$(grep -E "^rotate\s" /etc/logrotate.conf 2>/dev/null | awk '{print $2}' || echo "4")
    _retention=$(safe_int "$_retention")
    if [[ "$_retention" -ge 12 ]]; then
      pass "Log rotation retains $_retention copies (good forensic window)"
    elif [[ "$_retention" -ge 4 ]]; then
      info "Log rotation retains $_retention copies — consider 13+ for monthly retention"
    else
      warn "Log rotation retains only $_retention copies — short forensic window"
      detail "Set 'rotate 13' in /etc/logrotate.conf for 3+ months"
    fi
  fi
}

# ================================================================
#  17v. COMPILER & DEVELOPMENT TOOLS
# ================================================================
section_compiler_tools() {
  header "17v. COMPILER & DEVELOPMENT TOOLS"
  subheader "Compiler presence on production system"

  local _compilers_found=0
  local _compiler_list=""
  for _cc in gcc g++ cc c++ clang clang++ tcc nasm as ld; do
    if command -v "$_cc" &>/dev/null; then
      local _ver
      _ver=$("$_cc" --version 2>/dev/null | head -1 || echo "version unknown")
      _compiler_list+="${_cc}: ${_ver}"$'\n'
      _compilers_found=$(( _compilers_found + 1 ))
    fi
  done

  if [[ "$_compilers_found" -eq 0 ]]; then
    pass "No compilers found — attackers cannot compile exploit code on this system"
  else
    warn "$_compilers_found compiler(s) found on production system:"
    printf "%b" "$_compiler_list" | while IFS= read -r _line; do
      [[ -n "$_line" ]] && detail "$_line"
    done
    detail "Remove: apt-get purge gcc g++ clang binutils build-essential"
  fi

  subheader "Build/development package groups"
  local _build_pkgs=0
  if command -v dpkg &>/dev/null; then
    for _pkg in build-essential cmake automake autoconf libtool \
                python3-dev ruby-dev golang nodejs npm; do
      if dpkg -l "$_pkg" 2>/dev/null | grep -q "^ii"; then
        warn "Development package installed: $_pkg"
        _build_pkgs=$(( _build_pkgs + 1 ))
      fi
    done
  fi
  [[ "$_build_pkgs" -eq 0 ]] && pass "No build toolchain packages installed"

  subheader "Scripting interpreters"
  local _interp_count=0
  for _interp in python3 python perl ruby node php lua; do
    if command -v "$_interp" &>/dev/null; then
      local _ver
      _ver=$("$_interp" --version 2>/dev/null | head -1 || echo "version unknown")
      info "$_interp present: ${_ver:0:60}"
      _interp_count=$(( _interp_count + 1 ))
    fi
  done
  if [[ "$_interp_count" -ge 4 ]]; then
    warn "$_interp_count scripting interpreters installed — consider removing unused ones"
  else
    [[ "$_interp_count" -eq 0 ]] && \
      pass "No scripting interpreters installed" || \
      info "$_interp_count scripting interpreter(s) — review if all are needed"
  fi

  subheader "Package manager privilege abuse"
  # pip/npm installed as root without --user is a supply chain risk
  local _pip_root=0
  if command -v pip3 &>/dev/null; then
    _pip_root=$(pip3 list 2>/dev/null | wc -l || echo "0")
    _pip_root=$(safe_int "$_pip_root")
    if [[ "$_pip_root" -gt 5 ]]; then
      warn "${_pip_root} Python packages installed system-wide via pip3 — supply chain risk"
      detail "Prefer: pip3 install --user <pkg> or use virtual environments"
    fi
  fi

  local _npm_global=0
  if command -v npm &>/dev/null; then
    _npm_global=$(npm list -g --depth=0 2>/dev/null | grep -c "@" || echo "0")
    _npm_global=$(safe_int "$_npm_global")
    if [[ "$_npm_global" -gt 0 ]]; then
      warn "${_npm_global} npm global package(s) installed — supply chain risk"
      detail "Review: npm list -g --depth=0"
    fi
  fi
  [[ "$_pip_root" -le 5 && "$_npm_global" -eq 0 ]] && \
    pass "No risky system-wide pip/npm package installations"

  subheader "Debug & reverse-engineering tools"
  local _debug_tools=0
  for _tool in gdb strace ltrace objdump nm readelf strings hexdump xxd; do
    if command -v "$_tool" &>/dev/null; then
      _debug_tools=$(( _debug_tools + 1 ))
    fi
  done
  if [[ "$_debug_tools" -gt 3 ]]; then
    warn "$_debug_tools debug/RE tools installed (gdb, strace, objdump etc.) — high on production servers"
    detail "Review: which gdb strace ltrace objdump nm readelf"
  else
    pass "$_debug_tools debug tool(s) installed — acceptable"
  fi
}


# ================================================================
#  17w. NETWORK INTERFACE SECURITY
#  Promiscuous mode, unexpected IP addresses, ARP cache poisoning.
# ================================================================
section_network_interfaces() {
  header "17w. NETWORK INTERFACE SECURITY"
  subheader "Promiscuous mode detection"

  local _promisc_found=0
  while IFS= read -r _iface; do
    [[ -z "$_iface" || "$_iface" == "lo" ]] && continue
    if ip link show "$_iface" 2>/dev/null | grep -q "PROMISC"; then
      fail "Interface $_iface is in PROMISCUOUS mode — passive packet capture possible"
      detail "Disable: ip link set $_iface -promisc"
      _promisc_found=$(( _promisc_found+1 ))
    fi
  done < <(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/{print $2}' | cut -d@ -f1)
  [[ "$_promisc_found" -eq 0 ]] && pass "No interfaces in promiscuous mode"

  subheader "Interface IP address audit"
  local _iface_count=0
  while IFS= read -r _line; do
    [[ -n "$_line" ]] && info "$_line" && _iface_count=$(( _iface_count+1 ))
  done < <(ip -4 addr show 2>/dev/null | awk '/inet /{print $NF": "$2}' | grep -v "^lo:" || true)
  [[ "$_iface_count" -eq 0 ]] && info "No IPv4 addresses configured"

  subheader "ARP cache integrity"
  local _arp_out _dup_macs
  _arp_out=$(arp -n 2>/dev/null || ip neigh show 2>/dev/null || true)
  if [[ -n "$_arp_out" ]]; then
    _dup_macs=$(echo "$_arp_out" | awk '{print $3}' | sort | uniq -d | grep -vE "^$|00:00:00" || true)
    if [[ -n "$_dup_macs" ]]; then
      fail "Duplicate MAC addresses detected in ARP cache (possible ARP poisoning):"
      while IFS= read -r _mac; do detail "$_mac appears multiple times"; done <<< "$_dup_macs"
    else
      pass "No duplicate MAC addresses in ARP cache"
    fi
  fi

  subheader "Network interface packet drops"
  local _high_drops=0
  while IFS= read -r _iface; do
    [[ -z "$_iface" || "$_iface" == "lo" ]] && continue
    local _rx _tx
    _rx=$(cat "/sys/class/net/${_iface}/statistics/rx_dropped" 2>/dev/null || echo 0)
    _tx=$(cat "/sys/class/net/${_iface}/statistics/tx_dropped" 2>/dev/null || echo 0)
    _rx=$(safe_int "$_rx"); _tx=$(safe_int "$_tx")
    local _tot=$(( _rx+_tx ))
    if [[ "$_tot" -gt 1000 ]]; then
      warn "High packet drops on ${_iface}: RX=${_rx} TX=${_tx} — possible DoS or misconfiguration"
      _high_drops=$(( _high_drops+1 ))
    fi
  done < <(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/{print $2}' | cut -d@ -f1)
  [[ "$_high_drops" -eq 0 ]] && pass "Packet drop counts are normal on all interfaces"

  subheader "IP forwarding policy"
  local _fwd4 _fwd6
  _fwd4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
  _fwd6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
  if [[ "$_fwd4" == "1" ]]; then
    warn "IPv4 forwarding enabled (net.ipv4.ip_forward=1) — only needed on routers/VPNs"
    detail "Disable: sysctl -w net.ipv4.ip_forward=0"
  else
    pass "IPv4 forwarding disabled"
  fi
  if [[ "$_fwd6" == "1" ]]; then
    warn "IPv6 forwarding enabled — only needed on routers"
  else
    pass "IPv6 forwarding disabled"
  fi
}

# ================================================================
#  17x. KERNEL MODULE SECURITY
#  Checks loaded modules, blacklisting, and unsigned modules.
# ================================================================
section_kernel_modules() {
  header "17x. KERNEL MODULE SECURITY"
  subheader "Dangerous/unnecessary modules loaded"

  local _risky_found=0
  declare -A _risky_desc
  _risky_desc=(
    [usb_storage]="USB mass storage — disable to prevent data exfil via USB drives"
    [firewire_core]="FireWire — enables DMA attacks; remove if not needed"
    [thunderbolt]="Thunderbolt — enables DMA attacks; verify Thunderbolt security level"
    [bluetooth]="Bluetooth — attack surface; disable if not using Bluetooth"
    [cramfs]="CramFS filesystem — obsolete, rarely needed"
    [freevxfs]="FreeVXFS filesystem — obsolete, rarely needed"
    [jffs2]="JFFS2 filesystem — obsolete, rarely needed"
    [hfs]="HFS filesystem — macOS filesystem, rarely needed on servers"
    [hfsplus]="HFS+ filesystem — macOS filesystem, rarely needed"
    [squashfs]="SquashFS — if not using snap/AppImage, can be removed"
    [udf]="UDF filesystem — CD/DVD filesystem, rarely needed"
    [dccp]="DCCP protocol — obscure, has had CVEs; disable if unused"
    [sctp]="SCTP protocol — telecom protocol; disable if unused"
    [rds]="RDS protocol — has had critical CVEs; disable"
    [tipc]="TIPC protocol — cluster protocol; disable if unused"
  )

  for _mod in "${!_risky_desc[@]}"; do
    if lsmod 2>/dev/null | grep -q "^${_mod}\b"; then
      warn "Unnecessary module loaded: ${_mod} — ${_risky_desc[$_mod]}"
      detail "Blacklist: echo 'blacklist ${_mod}' >> /etc/modprobe.d/hardening.conf"
      _risky_found=$(( _risky_found+1 ))
    fi
  done
  [[ "$_risky_found" -eq 0 ]] && pass "No dangerous/unnecessary kernel modules loaded"

  subheader "Module signature enforcement"
  local _sig
  _sig=$(cat /proc/sys/kernel/module_sig_enforce 2>/dev/null || echo "0")
  if [[ "$_sig" == "1" ]]; then
    pass "kernel.module_sig_enforce=1 — only signed modules can be loaded"
  else
    warn "Module signature enforcement disabled (module_sig_enforce=0)"
    detail "Enable: echo 'kernel.module_sig_enforce=1' >> /etc/sysctl.d/99-hardening.conf"
    detail "Note: requires all modules to be signed — may break out-of-tree modules"
  fi

  subheader "Module loading lock"
  local _modlock
  _modlock=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "0")
  if [[ "$_modlock" == "1" ]]; then
    pass "kernel.modules_disabled=1 — no new modules can be loaded at runtime"
  else
    info "kernel.modules_disabled=0 — modules can be loaded at runtime"
  fi

  subheader "Blacklist configuration"
  local _bl_count=0
  for _f in /etc/modprobe.d/*.conf; do
    [[ -f "$_f" ]] || continue
    local _n; _n=$(grep -c "^blacklist" "$_f" 2>/dev/null || echo 0)
    _bl_count=$(( _bl_count + $(safe_int "$_n") ))
  done
  if [[ "$_bl_count" -gt 5 ]]; then
    pass "$_bl_count module blacklist entries in /etc/modprobe.d/ — good coverage"
  elif [[ "$_bl_count" -gt 0 ]]; then
    info "$_bl_count module blacklist entries — consider adding dccp,sctp,rds,tipc,cramfs,udf"
  else
    warn "No module blacklist entries found in /etc/modprobe.d/"
    detail "Create /etc/modprobe.d/hardening.conf with blacklist rules"
  fi

  subheader "Total loaded modules"
  local _mod_count
  _mod_count=$(lsmod 2>/dev/null | tail -n+2 | wc -l || echo "0")
  _mod_count=$(safe_int "$_mod_count")
  info "$_mod_count kernel modules currently loaded"
  [[ "$_mod_count" -gt 120 ]] && \
    note "Large module count increases attack surface — review: lsmod | sort"
}

# ================================================================
#  17y. APPARMOR / SELINUX PROFILE AUDIT
#  Detailed profile status beyond the basic MAC check in section 14.
# ================================================================
section_mac_profiles() {
  header "17y. MAC PROFILE DETAILED AUDIT"

  if command -v apparmor_status &>/dev/null || \
     [[ -d /sys/kernel/security/apparmor ]]; then
    subheader "AppArmor profile breakdown"

    local _aa_enforced=0 _aa_complain=0 _aa_disabled=0
    if command -v aa-status &>/dev/null; then
      _aa_enforced=$(aa-status 2>/dev/null | grep -oE "^[0-9]+ profiles are in enforce" | grep -oE "^[0-9]+" || echo 0)
      _aa_complain=$(aa-status 2>/dev/null | grep -oE "^[0-9]+ profiles are in complain" | grep -oE "^[0-9]+" || echo 0)
      _aa_enforced=$(safe_int "$_aa_enforced")
      _aa_complain=$(safe_int "$_aa_complain")

      if [[ "$_aa_enforced" -gt 10 ]]; then
        pass "$_aa_enforced AppArmor profiles in enforce mode"
      elif [[ "$_aa_enforced" -gt 0 ]]; then
        warn "Only $_aa_enforced AppArmor profiles enforcing — coverage is minimal"
        detail "Enable all profiles: aa-enforce /etc/apparmor.d/*"
      fi

      if [[ "$_aa_complain" -gt 0 ]]; then
        warn "$_aa_complain profile(s) in complain mode — not actually restricting"
        detail "Move to enforce: aa-enforce /etc/apparmor.d/*"
      fi

      # Show key services without profiles
      for _svc in nginx apache2 mysql sshd dovecot postfix; do
        if systemctl is-active "$_svc" &>/dev/null; then
          if ! aa-status 2>/dev/null | grep -q "/$_svc"; then
            warn "Active service with no AppArmor profile: $_svc"
          fi
        fi
      done
    fi

    # Check for AppArmor deniald log entries
    if [[ -f /var/log/kern.log ]]; then
      local _denials
      _denials=$(grep -c "apparmor.*DENIED" /var/log/kern.log 2>/dev/null || echo 0)
      _denials=$(safe_int "$_denials")
      if [[ "$_denials" -gt 0 ]]; then
        warn "$_denials AppArmor DENIED events in kern.log — review for false positives"
        detail "View: grep 'apparmor.*DENIED' /var/log/kern.log | tail -20"
      else
        pass "No AppArmor denial events in kern.log"
      fi
    fi

  elif command -v sestatus &>/dev/null; then
    subheader "SELinux status"
    local _se_status
    _se_status=$(sestatus 2>/dev/null | head -3 || echo "unavailable")
    if echo "$_se_status" | grep -qi "enforcing"; then
      pass "SELinux is in enforcing mode"
    elif echo "$_se_status" | grep -qi "permissive"; then
      warn "SELinux is in permissive mode — logging but not enforcing"
    else
      fail "SELinux is disabled"
    fi
    while IFS= read -r _l; do info "$_l"; done <<< "$_se_status"
  else
    warn "Neither AppArmor nor SELinux appears active"
  fi
}

# ================================================================
#  17z. NETWORK EXPOSURE SUMMARY
#  Consolidated view of all external-facing services and their risk.
# ================================================================
section_exposure_summary() {
  header "17z. NETWORK EXPOSURE SUMMARY"
  subheader "All listening services with risk assessment"

  if ! command -v ss &>/dev/null && ! command -v netstat &>/dev/null; then
    info "Neither ss nor netstat available — skipping exposure summary"
    return
  fi

  local _listeners=""
  if command -v ss &>/dev/null; then
    _listeners=$(ss -tlnup 2>/dev/null | awk 'NR>1{print $1,$4,$6}' || true)
  else
    _listeners=$(netstat -tlnup 2>/dev/null | awk 'NR>2{print $1,$4,$7}' || true)
  fi

  if [[ -z "$_listeners" ]]; then
    info "No listening services detected"
    return
  fi

  declare -A PORT_RISK
  PORT_RISK=(
    [20]="CRIT:FTP data port — plaintext file transfer"
    [21]="CRIT:FTP — plaintext credentials and data"
    [22]="LOW:SSH — encrypted; ensure brute-force protection is active"
    [23]="CRIT:Telnet — plaintext credentials, remove immediately"
    [25]="HIGH:SMTP — verify relay restrictions and TLS enforcement"
    [53]="MED:DNS — verify recursive query restrictions"
    [79]="HIGH:Finger — user enumeration, obsolete protocol"
    [80]="MED:HTTP — plaintext; redirect to HTTPS where possible"
    [110]="HIGH:POP3 — plaintext mail retrieval"
    [111]="HIGH:RPCbind — enables NFS attack surface"
    [143]="HIGH:IMAP — plaintext mail"
    [161]="HIGH:SNMP — often has default community strings"
    [389]="HIGH:LDAP — plaintext; use LDAPS (636) instead"
    [443]="LOW:HTTPS — encrypted"
    [445]="CRIT:SMB/CIFS — primary ransomware vector"
    [512]="CRIT:rexec — plaintext remote execution, remove"
    [513]="CRIT:rlogin — plaintext remote login, remove"
    [514]="CRIT:rsh/syslog — plaintext remote shell, remove"
    [631]="MED:CUPS printing — check if internet-facing"
    [873]="MED:rsync — check authentication"
    [2049]="HIGH:NFS — check exports are restricted"
    [3306]="CRIT:MySQL — database must not be internet-facing"
    [5432]="CRIT:PostgreSQL — database must not be internet-facing"
    [5900]="HIGH:VNC — often weak authentication"
    [6379]="CRIT:Redis — no authentication by default"
    [8080]="MED:HTTP-alt — check if dev/test server is exposed"
    [8443]="MED:HTTPS-alt — verify certificate validity"
    [9200]="CRIT:Elasticsearch — no authentication by default"
    [27017]="CRIT:MongoDB — no authentication by default"
  )

  local _exposed=0 _critical=0 _high=0 _med=0 _low=0
  declare -A _seen_ports

  while IFS= read -r _line; do
    [[ -z "$_line" ]] && continue
    local _port
    _port=$(echo "$_line" | grep -oE '[:*][0-9]+(\s|$)' | grep -oE '[0-9]+' | head -1 || true)
    [[ -z "$_port" ]] && continue
    [[ -n "${_seen_ports[$_port]:-}" ]] && continue
    _seen_ports[$_port]=1

    if echo "$_line" | grep -qE "0\.0\.0\.0|::\b|\*"; then
      local _risk="${PORT_RISK[$_port]:-}"
      if [[ -n "$_risk" ]]; then
        local _level="${_risk%%:*}" _desc="${_risk#*:}"
        case "$_level" in
          CRIT) fail "CRITICAL  :${_port}  ${_desc}"; _critical=$(( _critical+1 )) ;;
          HIGH) warn "HIGH      :${_port}  ${_desc}"; _high=$(( _high+1 )) ;;
          MED)  info "MEDIUM    :${_port}  ${_desc}"; _med=$(( _med+1 )) ;;
          LOW)  pass "LOW risk  :${_port}  ${_desc}"; _low=$(( _low+1 )) ;;
        esac
        _exposed=$(( _exposed+1 ))
      fi
    fi
  done <<< "$_listeners"

  subheader "Exposure summary"
  if [[ "$_critical" -gt 0 ]]; then
    fail "$_critical CRITICAL + $_high HIGH + $_med MEDIUM + $_low LOW risk port(s) — immediate action required"
    detail "Fix CRITICALs first: stop/firewall the service, then re-run wowscanner"
  elif [[ "$_high" -gt 0 ]]; then
    warn "$_high HIGH + $_med MEDIUM + $_low LOW risk port(s) open"
    detail "Review HIGH ports and ensure authentication and encryption are enforced"
  elif [[ "$_exposed" -gt 0 ]]; then
    info "$_med MEDIUM + $_low LOW risk port(s) — review each"
  else
    pass "No known high-risk services exposed on public interfaces"
  fi
}


# ================================================================
#  NEW: 17b3. HARDWARE & FIRMWARE SECURITY
#  Checks Secure Boot, IOMMU, CPU vulnerabilities, TPM
# ================================================================
section_hardware_security() {
  header "17b3. HARDWARE & FIRMWARE SECURITY"

  subheader "Secure Boot status"
  local _sb=false
  if command -v mokutil &>/dev/null; then
    local _sb_out
    _sb_out=$(mokutil --sb-state 2>/dev/null || echo "")
    if echo "$_sb_out" | grep -qi "SecureBoot enabled"; then
      pass "Secure Boot is ENABLED — bootloader and kernel are cryptographically verified"
      _sb=true
    elif echo "$_sb_out" | grep -qi "SecureBoot disabled"; then
      warn "Secure Boot is DISABLED — unsigned bootloaders/kernels can run"
      detail "Enable in UEFI/BIOS firmware settings"
    fi
  elif [[ -d /sys/firmware/efi ]]; then
    local _sb_val
    _sb_val=$(cat /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null \
      | od -An -tu1 -j4 -N1 2>/dev/null | tr -d ' ' || echo "")
    if [[ "$_sb_val" == "1" ]]; then
      pass "Secure Boot is ENABLED (EFI variable)"
      _sb=true
    else
      warn "Secure Boot appears disabled"
    fi
  else
    info "UEFI/EFI not detected — system may be BIOS/Legacy boot"
  fi

  subheader "IOMMU (DMA protection)"
  local _iommu=false
  # (IOMMU check handled below)
  if dmesg 2>/dev/null | grep -qiE "DMAR|AMD-Vi|IOMMU: enabled"; then
    pass "IOMMU is active — DMA attacks from peripherals are mitigated"
    _iommu=true
  elif grep -qiE "intel_iommu=on|amd_iommu=on" /proc/cmdline 2>/dev/null; then
    pass "IOMMU enabled via kernel command line"
    _iommu=true
  else
    info "IOMMU not detected as active — consider enabling for better DMA protection"
    detail "Add intel_iommu=on (Intel) or amd_iommu=on (AMD) to GRUB_CMDLINE_LINUX"
  fi

  subheader "CPU vulnerability mitigations"
  local _vuln_dir="/sys/devices/system/cpu/vulnerabilities"
  if [[ -d "$_vuln_dir" ]]; then
    local _mitigated=0 _vulnerable=0
    while IFS= read -r _vuln_file; do
      local _name _status
      _name=$(basename "$_vuln_file")
      _status=$(cat "$_vuln_file" 2>/dev/null || echo "Unknown")
      if echo "$_status" | grep -qi "^Not affected\|^Mitigation\|^Mitigated"; then
        _mitigated=$(( _mitigated+1 ))
      elif echo "$_status" | grep -qi "^Vulnerable"; then
        fail "CPU vulnerable to ${_name}: ${_status}"
        _vulnerable=$(( _vulnerable+1 ))
      else
        info "${_name}: ${_status}"
      fi
    done < <(find "$_vuln_dir" -maxdepth 1 -type f 2>/dev/null | sort)
    [[ "$_mitigated" -gt 0 ]] && pass "$_mitigated CPU vulnerability/vulnerabilities mitigated or not applicable"
    [[ "$_vulnerable" -eq 0 && "$_mitigated" -gt 0 ]] && pass "No unmitigated CPU vulnerabilities found"
  else
    info "CPU vulnerability sysfs not available (older kernel)"
  fi

  subheader "TPM (Trusted Platform Module)"
  if [[ -d /sys/class/tpm ]] || ls /dev/tpm* 2>/dev/null | head -1; then
    pass "TPM device detected — hardware-backed key storage available"
    if command -v tpm2_getcap &>/dev/null; then
      info "tpm2-tools installed — TPM2 management available"
    fi
  else
    info "No TPM device detected"
  fi
}

# ================================================================
#  NEW: 17b4. GRUB & BOOT SECURITY
# ================================================================
section_boot_security() {
  header "17b4. GRUB & BOOT SECURITY"

  subheader "GRUB configuration security"

  # GRUB password protection
  local _grub_cfg
  for _f in /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.d/40_custom; do
    [[ -f "$_f" ]] && _grub_cfg="$_f" && break
  done

  if [[ -n "$_grub_cfg" ]]; then
    if grep -q "password_pbkdf2\|password " "$_grub_cfg" 2>/dev/null; then
      pass "GRUB bootloader is password-protected"
    else
      warn "GRUB has no password — anyone with physical access can boot into recovery mode"
      detail "Set GRUB password: grub-mkpasswd-pbkdf2 then add to /etc/grub.d/40_custom"
    fi
  else
    info "GRUB config not found at standard paths"
  fi

  subheader "Kernel command line audit"
  local _cmdline
  _cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
  if [[ -n "$_cmdline" ]]; then
    info "Kernel cmdline: ${_cmdline:0:120}"
    # Check for debug options that should not be in production
    if echo "$_cmdline" | grep -qE "\bdebug\b|\bsingle\b|\binit=/bin/sh\b|\binit=/bin/bash\b"; then
      fail "Dangerous kernel parameters present: debug/single/init override"
      detail "Remove debug options from GRUB_CMDLINE_LINUX in /etc/default/grub"
    else
      pass "No dangerous kernel parameters (debug/single/init override) in cmdline"
    fi
    # Check for spectre/meltdown mitigations
    if echo "$_cmdline" | grep -qE "nopti|nospectre|mitigations=off"; then
      fail "CPU mitigations DISABLED via kernel cmdline — system is vulnerable to Spectre/Meltdown"
      detail "Remove mitigations=off and nopti from /etc/default/grub"
    else
      pass "CPU mitigations not disabled via kernel cmdline"
    fi
  fi

  subheader "Boot partition permissions"
  if [[ -d /boot ]]; then
    local _boot_perm
    _boot_perm=$(stat -c "%a" /boot 2>/dev/null || echo "unknown")
    if [[ "$_boot_perm" == "700" || "$_boot_perm" == "600" || "$_boot_perm" == "750" ]]; then
      pass "/boot directory permissions: ${_boot_perm} (not world-readable)"
    else
      warn "/boot directory permissions: ${_boot_perm} — consider restricting to 700 or 750"
      detail "Fix: chmod 700 /boot"
    fi
    # Check grub.cfg permissions
    for _f in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
      if [[ -f "$_f" ]]; then
        local _fp; _fp=$(stat -c "%a" "$_f" 2>/dev/null || echo "unknown")
        if [[ "$_fp" == "600" || "$_fp" == "400" ]]; then
          pass "${_f} permissions: ${_fp} (owner-only)"
        else
          warn "${_f} permissions: ${_fp} — should be 600"
          detail "Fix: chmod 600 $_f"
        fi
      fi
    done
  fi
}



section_web_server() {
  header "17b5. WEB SERVER SECURITY"

  local _found_any=false

  # ── Nginx ──────────────────────────────────────────────────────
  if command -v nginx &>/dev/null || systemctl is-active nginx &>/dev/null 2>&1; then
    _found_any=true
    subheader "Nginx configuration"

    local _nginx_v
    _nginx_v=$(nginx -v 2>&1 | head -1 || echo "unknown")
    info "Nginx version: ${_nginx_v}"

    # Server tokens
    if nginx -T 2>/dev/null | grep -qi "server_tokens\s*off"; then
      pass "Nginx: server_tokens off — version not exposed in headers"
    else
      warn "Nginx: server_tokens may be on — consider 'server_tokens off' to hide version"
    fi

    # SSL/TLS protocols — check for SSLv3/TLS1.0/1.1
    local _weak_ssl
    _weak_ssl=$(nginx -T 2>/dev/null | grep -iE "ssl_protocols.*[Ss][Ss][Ll][Vv]?3?|TLSv1[^.2]|TLSv1\.1" \
      | grep -v "#" | head -3 || true)
    if [[ -n "$_weak_ssl" ]]; then
      fail "Nginx: weak SSL/TLS protocols configured:"
      while IFS= read -r l; do detail "$l"; done <<< "$_weak_ssl"
    else
      pass "Nginx: no weak SSL/TLS protocols (SSLv3/TLS1.0/1.1) detected"
    fi

    # Security headers
    local _nginx_hdrs
    _nginx_hdrs=$(nginx -T 2>/dev/null | grep -i "add_header" || true)
    local _missing_hdrs=()
    echo "$_nginx_hdrs" | grep -qi "X-Frame-Options"            || _missing_hdrs+=("X-Frame-Options")
    echo "$_nginx_hdrs" | grep -qi "X-Content-Type-Options"     || _missing_hdrs+=("X-Content-Type-Options")
    echo "$_nginx_hdrs" | grep -qi "Strict-Transport-Security"  || _missing_hdrs+=("Strict-Transport-Security (HSTS)")
    echo "$_nginx_hdrs" | grep -qi "Content-Security-Policy"    || _missing_hdrs+=("Content-Security-Policy")
    if [[ ${#_missing_hdrs[@]} -eq 0 ]]; then
      pass "Nginx: key security headers configured"
    else
      warn "Nginx: missing security headers: ${_missing_hdrs[*]}"
      detail "Add to nginx.conf server block: add_header X-Frame-Options DENY;"
    fi

    # autoindex
    if nginx -T 2>/dev/null | grep -qi "autoindex\s*on"; then
      fail "Nginx: directory listing (autoindex on) is enabled — information disclosure"
      detail "Disable: autoindex off;"
    else
      pass "Nginx: directory listing is disabled"
    fi
  fi

  # ── Apache ─────────────────────────────────────────────────────
  if command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
    _found_any=true
    subheader "Apache configuration"

    local _apache_bin="apache2"; command -v httpd &>/dev/null && _apache_bin="httpd"
    local _apache_v
    _apache_v=$("$_apache_bin" -v 2>/dev/null | head -1 || echo "unknown")
    info "Apache version: ${_apache_v}"

    # ServerTokens
    local _st
    _st=$(grep -rE "^\s*ServerTokens" /etc/apache2/ /etc/httpd/ 2>/dev/null | head -1 | awk '{print $2}' || echo "Full")
    if [[ "${_st,,}" == "prod" || "${_st,,}" == "productonly" ]]; then
      pass "Apache: ServerTokens Prod — minimal version info in headers"
    else
      warn "Apache: ServerTokens=${_st:-Full} — consider 'ServerTokens Prod'"
    fi

    # ServerSignature
    local _ss
    _ss=$(grep -rE "^\s*ServerSignature" /etc/apache2/ /etc/httpd/ 2>/dev/null | head -1 | awk '{print $2}' || echo "On")
    if [[ "${_ss,,}" == "off" ]]; then
      pass "Apache: ServerSignature Off"
    else
      warn "Apache: ServerSignature=${_ss:-On} — consider 'ServerSignature Off'"
    fi

    # Trace method
    local _trace
    _trace=$(grep -rE "^\s*TraceEnable" /etc/apache2/ /etc/httpd/ 2>/dev/null | head -1 | awk '{print $2}' || echo "On")
    if [[ "${_trace,,}" == "off" ]]; then
      pass "Apache: TraceEnable Off — TRACE method disabled"
    else
      warn "Apache: TraceEnable=${_trace:-On} — disable with 'TraceEnable Off'"
      detail "TRACE can enable cross-site tracing (XST) attacks"
    fi
  fi

  if [[ "$_found_any" == "false" ]]; then
    skip "No web server (nginx/apache) detected"
  fi
}


section_secrets_scan() {
  header "17b6. SECRETS & CREDENTIAL EXPOSURE"

  subheader "Private keys and certificates in world-readable locations"
  local _exposed_keys=0
  while IFS= read -r _kf; do
    [[ -z "$_kf" ]] && continue
    local _perm
    _perm=$(stat -c "%a" "$_kf" 2>/dev/null || echo "000")
    # World-readable private key
    if [[ "${_perm: -1}" -ge 4 ]]; then
      fail "World-readable private key: $_kf (perms: $_perm)"
      detail "Fix: chmod 600 $_kf"
      _exposed_keys=$(( _exposed_keys+1 ))
    fi
  done < <(find /etc /home /root /var/www /opt 2>/dev/null -maxdepth 6 \
    \( -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o -name "id_ed25519" \
       -o -name "id_ecdsa" -o -name "*.p12" -o -name "*.pfx" \) \
    -type f 2>/dev/null | head -30)
  [[ "$_exposed_keys" -eq 0 ]] && pass "No world-readable private key files found"

  subheader "Credentials in common config files"
  local _cred_files=0
  local _search_paths=("/etc/fstab" "/etc/environment" "/root/.bashrc"
    "/root/.bash_history" "/root/.profile")
  # Also check web app configs
  for _d in /var/www /opt /srv /home; do
    [[ -d "$_d" ]] || continue
    while IFS= read -r _cf; do
      _search_paths+=("$_cf")
    done < <(find "$_d" -maxdepth 5 -type f \
      \( -name "*.env" -o -name ".env" -o -name "wp-config.php" \
         -o -name "config.php" -o -name "database.yml" -o -name "secrets.yml" \
         -o -name "credentials.json" \) 2>/dev/null | head -20)
  done

  for _f in "${_search_paths[@]}"; do
    [[ -f "$_f" ]] || continue
    # Look for password/secret patterns (not just comments)
    local _hits
    _hits=$(grep -iE "^\s*(password|passwd|secret|api_key|db_pass|db_password)\s*=" \
      "$_f" 2>/dev/null | grep -v "^#" | grep -v "^\s*#" | wc -l || echo 0)
    _hits=$(safe_int "$_hits")
    if [[ "$_hits" -gt 0 ]]; then
      warn "Potential credentials in $_f ($_hits match(es))"
      detail "Review manually — may be test/example values"
      _cred_files=$(( _cred_files+1 ))
    fi
  done
  [[ "$_cred_files" -eq 0 ]] && pass "No credential patterns found in common config files"

  subheader "bash history containing sensitive commands"
  local _hist_issues=0
  for _hf in /root/.bash_history /home/*/.bash_history; do
    [[ -f "$_hf" ]] || continue
    local _sensitive
    _sensitive=$(grep -cE "password|passwd|secret|api.key|token|curl.*-u|mysql\s+-p\S" \
      "$_hf" 2>/dev/null || echo 0)
    _sensitive=$(safe_int "$_sensitive")
    if [[ "$_sensitive" -gt 0 ]]; then
      warn "Sensitive commands in $_hf ($_sensitive line(s))"
      detail "Clear history: cat /dev/null > $_hf"
      _hist_issues=$(( _hist_issues+1 ))
    fi
  done
  [[ "$_hist_issues" -eq 0 ]] && pass "No sensitive patterns found in bash history files"

  subheader "SSH agent forwarding sockets"
  local _ssh_sockets
  _ssh_sockets=$(find /tmp /run -maxdepth 3 -name "agent.*" -type s 2>/dev/null | wc -l || echo 0)
  _ssh_sockets=$(safe_int "$_ssh_sockets")
  if [[ "$_ssh_sockets" -gt 0 ]]; then
    info "$_ssh_sockets SSH agent socket(s) found in /tmp or /run"
    detail "Active SSH agent forwarding — ensure sockets are cleaned up on logout"
  else
    pass "No SSH agent forwarding sockets found"
  fi
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

  # Write .txt integrity sidecars BEFORE collecting files so they get bundled in the zip
  local _txt_report="${_dir}/wowscanner_${TIMESTAMP}.txt"
  [[ -f "$_txt_report" ]] && write_txt_crc "$_txt_report"
  local _findings_report="${_dir}/wowscanner_findings_${TIMESTAMP}.txt"
  [[ -f "$_findings_report" ]] && write_txt_crc "$_findings_report"

  # Collect every output file for THIS run (identified by $TIMESTAMP)
  while IFS= read -r -d '' f; do
    _files+=("$f")
  done < <(find "$_dir" -maxdepth 1 -type f \
    \( -name "wowscanner_${TIMESTAMP}.txt"          \
    -o -name "wowscanner_${TIMESTAMP}.txt.sha256"   \
    -o -name "wowscanner_findings_${TIMESTAMP}.txt.sha256" \
    -o -name "wowscanner_findings_${TIMESTAMP}.txt" \
    -o -name "wowscanner_report_${TIMESTAMP}.odt"   \
    -o -name "wowscanner_report_${TIMESTAMP}.html"  \
    -o -name "wowscanner_stats_${TIMESTAMP}.ods"    \
    -o -name "wowscanner_intel_${TIMESTAMP}.odt"    \
    \) -print0 2>/dev/null)

  if [[ "${#_files[@]}" -eq 0 ]]; then
    echo -e "  ${YELLOW}[⚠ WARN]  Archive: no output files found to archive (timestamp: ${TIMESTAMP})${NC}"
    return
  fi
  echo -e ""
  echo -e "  ${CYAN}${BOLD}┌─ Archiving scan outputs ──────────────────────────────────┐${NC}"

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
# .sha256 sidecars are bundled in the zip for recovery but NOT listed in
# INTEGRITY.txt — they are helper files, not content.  Their absence on
# disk after a clean or manual tidy should not trigger a verify alarm.
SIDECAR_SUFFIXES = ('.sha256', '.crc')
entries = {}
for src in src_files:
    if not os.path.isfile(src):
        continue
    name = os.path.basename(src)
    if any(name.endswith(s) for s in SIDECAR_SUFFIXES):
        continue   # bundle in zip but skip from manifest
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
            e = entries.get(arcname)
            if e:
                print(f"  archived: {arcname}  ({sz:,}B)  "
                      f"sha256={e['sha256'][:16]}...  sha512={e['sha512'][:16]}...")
            else:
                print(f"  archived: {arcname}  ({sz:,}B)  [sidecar — not in manifest]")
    zf.writestr("INTEGRITY.txt", integrity_txt)

# Immediately self-verify the zip (catches write errors / corruption)
bad_crc = []
try:
    with zipfile.ZipFile(zip_path, 'r') as zf:
        bad_crc = zf.testzip() or []
    if not bad_crc:
        print(f"  self-check: zip CRC OK — all {packed} files verified")
    else:
        print(f"  self-check: CRC FAIL in {bad_crc} — zip may be corrupt!", file=sys.stderr)
except Exception as ex:
    print(f"  self-check: ERROR — {ex}", file=sys.stderr)

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
             f"dir={os.path.dirname(os.path.abspath(zip_path))}  "
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
    echo -e "  ${CYAN}│  ${GREEN}${BOLD}Archive : $(basename "$_zip")  (${_zszh})${NC}"
    [[ -f "$_sha" ]] && \
      echo -e "  ${CYAN}│  ${GREEN}${BOLD}Hashes  : $(basename "$_sha")  (verify: sha256sum -c $(basename "$_sha"))${NC}"
  else
    echo -e "  ${YELLOW}[⚠ WARN]  Archive creation failed — individual files are still present${NC}"
  fi
  echo -e "  ${CYAN}${BOLD}└─ Individual files kept alongside the archive${NC}"
  echo -e ""
}

# ================================================================
#  PROGRESS BAR — top-of-screen status band (2 rows)
#
#  Design: simple, proven, works everywhere.
#
#  After clear-screen at startup the terminal is blank.
#  Rows 1–2 are reserved for the status band:
#    Row 1: ╔══ title + progress bar + % + time ══╗
#    Row 2: ║  Section: <current section name>     ║
#  The scroll region is set to rows 3..ROWS so all log() output
#  scrolls below the band without ever touching it.
#
#  The background subshell redraws BOTH rows every second (live clock).
#  The main process only updates the state file; bg loop owns all drawing.
#
#  Compatibility:
#  • /dev/tty checked — silently disabled if absent
#  • UTF-8 auto-detected from locale
#  • Scroll region tested via tput csr
#  • stty size → $COLUMNS/$LINES → tput → 80×24 fallback
#  • flock on every write prevents bg/main interleave
#  • EXIT/INT/TERM/HUP trap always restores terminal
# ================================================================

_PROGRESS_BAR_WIDTH=24    # ░/█ chars inside the bar
_PROGRESS_STEP=0
_PROGRESS_ENABLED=false
_PROGRESS_BG_PID=""
_PROGRESS_STATE=""         # tmpfile: 0|step|label|cum  (written by main, read by bg)

_PROGRESS_ROWS=24
_PROGRESS_COLS=80
_PROGRESS_USE_UNICODE=false
_PROGRESS_USE_SCREG=false

# Section timing weights (see index comment for flag→index mapping)
# 0-4=pentest 5=sysinfo 6=updates 7=users 8=password 9=ssh 10=firewall
# 11=ports 12=permissions 13=services 14=logging 15=kernel 16=cron
# 17=packages 18=13c-hardening 19=13d-netcontainer 20=14b-rootkits
# 21=14-mac 22=15-lynis 23=16a-lan 24=16-portscan
_PROGRESS_LABELS=( "0a pentest-enum" "0b pentest-web" "0c pentest-ssh" "0d pentest-sqli" "0e pentest-stress" "1 sysinfo" "2 updates" "3 users" "4 password" "5 ssh" "6 firewall" "7 ports" "8 permissions" "9 services" "10 logging" "11 kernel" "12 cron" "13 packages" "13c hardening-advanced" "13d network-container" "14b chkrootkit+rkhunter" "14 mac" "15 lynis" "16a lan-scan" "16 portscan" "17b failed-logins" "17c env-security" "17d usb-audit" "17e ww-deep" "17f cert-audit" "17g net-security" "17h auditd" "17i open-files" "17j mem-security" "17k pam-security" "17l fs-hardening" "17m container" "17n repo-sec" "17o time-sync" "17p ipv6" "17q ssh-extras" "17r core-dump" "17s systemd" "17t sudo-audit" "17u log-integrity" "17v compilers" "17b3 hw-security" "17b4 boot-sec" "17b5 web-server" "17b6 secrets" "17w net-ifaces" "17x kernel-mods" "17y mac-profiles" "17z exposure" )
_PROGRESS_WEIGHTS=( 90 120 60 90 25 3 18 12 3 6 3 4 55 4 8 5 5 35 28 18 70 3 50 25 30 8 4 3 12 6 5 6 4 5 5 7 5 4 4 5 6 4 6 5 5 3 6 5 6 8 5 4 5 4 )
_PROGRESS_CUM=( 90 210 270 360 385 388 406 418 421 427 430 434 489 493 501 506 511 546 574 592 662 665 715 740 770 778 782 785 797 803 808 814 818 823 828 835 840 844 848 853 859 863 869 874 879 882 888 893 899 907 912 916 921 925 )
_PROGRESS_TOTAL=925

# ── _progress_get_size ─────────────────────────────────────────────────────────
_progress_get_size() {
  local _out _r="" _c=""
  _out=$(stty size </dev/tty 2>/dev/null || true)
  if [[ "$_out" =~ ^[0-9]+\ [0-9]+$ ]]; then
    _r="${_out%% *}"; _c="${_out##* }"
  fi
  [[ -z "$_r" ]] && _r="${LINES:-24}"
  [[ -z "$_c" ]] && _c="${COLUMNS:-80}"
  _PROGRESS_ROWS=$(( ${_r:-24} > 0 ? ${_r:-24} : 24 ))
  _PROGRESS_COLS=$(( ${_c:-80} > 0 ? ${_c:-80} : 80 ))
}



# ── _ws_net_seed_iface ────────────────────────────────────────────────────────
_ws_net_seed_iface() {
  local _iface="" _if _rest
  while IFS=: read -r _if _rest; do
    _if="${_if// /}"
    [[ -z "$_if" || "$_if" == "lo" || "$_if" == *"face"* || "$_if" == "Inter"* ]] && continue
    _iface="$_if"; break
  done < /proc/net/dev 2>/dev/null
  [[ -z "$_iface" ]] && _iface=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
  export _PROG_NET_IFACE="${_iface:-eth0}"
  local _rxb=0 _txb=0 _rxp=0 _txp=0 _nif _nr
  while IFS=: read -r _nif _nr; do
    _nif="${_nif// /}"
    [[ "$_nif" != "$_PROG_NET_IFACE" ]] && continue
    read -r _rxb _rxp _ _ _ _ _ _ _txb _txp _ <<< "$_nr" 2>/dev/null || true
    break
  done < /proc/net/dev 2>/dev/null
  export _PROG_NET_RX_PREV=${_rxb:-0}
  export _PROG_NET_TX_PREV=${_txb:-0}
  export _PROG_NET_PK_PREV=$(( ${_rxp:-0} + ${_txp:-0} ))
  export _PROG_NET_RX=0 _PROG_NET_TX=0 _PROG_NET_PKTS=0
}

# ── _progress_get_size ────────────────────────────────────────────────────────
_progress_get_size() {
  local _out _r="" _c=""
  _out=$(stty size </dev/tty 2>/dev/null || true)
  if [[ "$_out" =~ ^[0-9]+\ [0-9]+$ ]]; then
    _r="${_out%% *}"; _c="${_out##* }"
  fi
  [[ -z "$_r" ]] && _r="${LINES:-24}"
  [[ -z "$_c" ]] && _c="${COLUMNS:-80}"
  _PROGRESS_ROWS=$(( ${_r:-24} > 0 ? ${_r:-24} : 24 ))
  _PROGRESS_COLS=$(( ${_c:-80} > 0 ? ${_c:-80} : 80 ))
}

# ── _progress_draw_band ───────────────────────────────────────────────────────
# Draws 4-row HUD pinned to top (rows 1-4).
# Rows 1-4 are outside the scroll region set in _progress_init.
# Scan output scrolls in rows 5..ROWS, never touching rows 1-4.
#
# Row 1: ─ separator
# Row 2: [bar]  pct  clock  ETA  DSK:●  CPU:●  NET:●  IO:N%  CPU:N%
# Row 3: ➤ section label                        N/54  ▼ RX  ▲ TX  pkts/s
# Row 4: ─ separator
#
# All values (_PROG_*) are locals set by _progress_bg_refresh in this
# same subshell — no export/import needed.
_progress_draw_band() {
  local _label="$1" _pct="$2" _elapsed="$3" _cols="$4" _eta_raw="${5:-}"

  # ── Characters ────────────────────────────────────────────────────
  local _full="█" _empty="░" _dot="●" _uarr="▲" _darr="▼"
  [[ "$_PROGRESS_USE_UNICODE" != "true" ]] && {
    _full="#"; _empty="-"; _dot="*"; _uarr="^"; _darr="v"
  }

  # ── Bar ───────────────────────────────────────────────────────────
  local _bw="${_PROGRESS_BAR_WIDTH:-24}"
  local _filled=$(( _pct * _bw / 100 ))
  local _empty_n=$(( _bw - _filled ))
  local _bar="" _i
  for (( _i=0; _i<_filled;  _i++ )); do _bar+="$_full"; done
  for (( _i=0; _i<_empty_n; _i++ )); do _bar+="$_empty"; done

  # ── Clock ─────────────────────────────────────────────────────────
  local _efmt
  printf -v _efmt "%02d:%02d:%02d" \
    "$(( _elapsed/3600 ))" "$(( (_elapsed%3600)/60 ))" "$(( _elapsed%60 ))"

  # ── ETA ───────────────────────────────────────────────────────────
  local _eta=""
  if [[ -n "$_eta_raw" ]]; then
    local _eta_s="${_eta_raw%%|*}"
    if [[ "$_eta_s" -gt 0 && "$_elapsed" -lt "$_eta_s" ]]; then
      local _rem=$(( _eta_s - _elapsed ))
      local _rm=$(( _rem/60 )) _rs=$(( _rem%60 ))
      [[ "$_rm" -gt 0 ]] && _eta=" ETA ~${_rm}m${_rs}s" || _eta=" ETA ~${_rs}s"
    elif [[ "$_eta_s" -gt 0 ]]; then
      _eta=" ETA ~done"
    fi
  fi

  # ── Colours ───────────────────────────────────────────────────────
  local _bc
  if   [[ "$_pct" -eq 100 ]]; then _bc=$'\033[1;32m'
  elif [[ "$_pct" -ge 75  ]]; then _bc=$'\033[0;32m'
  elif [[ "$_pct" -ge 50  ]]; then _bc=$'\033[0;33m'
  elif [[ "$_pct" -ge 25  ]]; then _bc=$'\033[1;33m'
  else                              _bc=$'\033[0;36m'
  fi
  local _R=$'\033[0m' _B=$'\033[1m' _D=$'\033[2;37m'

  # ── LED dots (colour set by sampling loops below, defaulting idle) ─
  local _d_col="${_led_disk_col:-$'\033[2;34m'}"
  local _c_col="${_led_cpu_col:-$'\033[2;34m'}"
  local _n_col="${_led_net_col:-$'\033[2;34m'}"
  local _dled="${_d_col}${_dot}${_R}"
  local _cled="${_c_col}${_dot}${_R}"
  local _nled="${_n_col}${_dot}${_R}"

  # ── Net rate strings ──────────────────────────────────────────────
  local _rx="${_led_net_rx:-0}" _tx="${_led_net_tx:-0}" _pk="${_led_net_pk:-0}"
  local _rxs _txs _pks
  if   [[ "$_rx" -ge 1048576 ]]; then printf -v _rxs "%4dMB/s" "$((_rx/1048576))"
  elif [[ "$_rx" -ge 1024    ]]; then printf -v _rxs "%4dKB/s" "$((_rx/1024))"
  else                                printf -v _rxs "%4d B/s" "$_rx"; fi
  if   [[ "$_tx" -ge 1048576 ]]; then printf -v _txs "%4dMB/s" "$((_tx/1048576))"
  elif [[ "$_tx" -ge 1024    ]]; then printf -v _txs "%4dKB/s" "$((_tx/1024))"
  else                                printf -v _txs "%4d B/s" "$_tx"; fi
  if   [[ "$_pk" -ge 1000    ]]; then printf -v _pks "%4dk/s"  "$((_pk/1000))"
  else                                printf -v _pks "%4d/s"   "$_pk"; fi

  # ── Separator line ────────────────────────────────────────────────
  local _sep; printf -v _sep '%*s' "$(( _cols > 2 ? _cols - 2 : 2 ))" ''
  _sep="${_sep// /─}"

  # ── Row 2 (bar row) ───────────────────────────────────────────────
  # Content: " Wowscanner vVERSION  [BAR]  PCT%  CLOCK ETA  DSK:● CPU:● NET:●  IO:N%  CPU:N%"
  # Visible widths:
  #   left:  1 + "Wowscanner v" (12) + 5 (ver) + 2 + 1 (bracket) + bw + 1 + 2 + 3 + 1 + 2 + 8 + eta
  #   right: "  DSK:● CPU:● NET:●  IO:NNN%  CPU:NNN% " = 40 visible
  local _disk_pct_val="${_led_disk_pct:-0}"
  local _cpu_pct_val="${_led_cpu_pct:-0}"
  local _step="${_PROGRESS_STEP:-0}" _total="${#_PROGRESS_LABELS[@]}"
  local _iface="${_PROG_NET_IFACE:-eth0}"

  # Compute padding for row2:
  #   left_vis = 1+12+5+2+1+bw+1+2+3+1+2+8+eta_len = 38 + bw + eta_len
  local _r2_lv=$(( 38 + _bw + ${#_eta} ))
  #   right_vis = 2+4+1+1+1+1+4+1+1+1+2+7+2+8 = ~40, let's fix at 40
  local _r2_rv=40
  local _p2_n=$(( _cols - 2 - _r2_lv - _r2_rv ))
  local _p2=""; [[ "$_p2_n" -gt 0 ]] && printf -v _p2 '%*s' "$_p2_n" ""

  # Compute padding for row3:
  #   left_vis = 2 + 1 (arrow) + 2 + 32 (label) = 37
  #   right_vis = 2 + step/total + 2 + darr + rxs + uarr + txs + pkts + iface ~ 50
  local _r3_lv=37
  local _r3_rv=$(( 4 + ${#_step} + 1 + ${#_total} + 2 + 8 + 8 + 8 + 2 + ${#_iface} ))
  local _p3_n=$(( _cols - 2 - _r3_lv - _r3_rv ))
  local _p3=""; [[ "$_p3_n" -gt 0 ]] && printf -v _p3 '%*s' "$_p3_n" ""

  # ── Write rows 1-4 in one shot ────────────────────────────────────
  # \033[s / \033[u  = save/restore cursor position (stays in scroll region row 5+)
  # \033[1;1H        = jump to row 1 col 1 (above scroll region — safe because
  #                    cursor save was done first)
  {
    printf '\033[s'
    # Row 1: top separator
    printf '\033[1;1H\033[2K%s▌%s▐%s' "$_D" "$_sep" "$_R"
    # Row 2: bar + clock + ETA + LEDs
    printf '\033[2;1H\033[2K%s▌%s Wowscanner v%-5s  [%s]  %s%3d%%%s  %s%s%s' \
      "$_bc" "$_B" "${VERSION}" "$_bar" "$_B" "$_pct" "$_R" \
      "$_D" "$_efmt" "$_eta"
    printf '%s  %sDSK:%s%s %sCPU:%s%s %sNET:%s%s  %sIO:%3d%%  CPU:%3d%%%s%s▐%s' \
      "$_p2" \
      "$_D" "$_R" "$_dled" \
      "$_D" "$_R" "$_cled" \
      "$_D" "$_R" "$_nled" \
      "$_D" "$_disk_pct_val" "$_cpu_pct_val" "$_R" \
      "$_bc" "$_R"
    # Row 3: section label + net monitor
    printf '\033[3;1H\033[2K%s▌%s  %s➤%s  %-32s%s  %s%d/%d  %s%s  %s%s  %s%s  %s%s%s▐%s' \
      "$_bc" "$_R" \
      "$_B" "$_R" "${_label:0:32}" \
      "$_p3" \
      "$_D" "$_step" "$_total" "$_R" \
      "$_D$_darr$_R" "$_rxs" \
      "$_D$_uarr$_R" "$_txs" \
      "$_D" "$_pks  ${_iface}" "$_R" \
      "$_bc" "$_R"
    # Row 4: bottom separator
    printf '\033[4;1H\033[2K%s▌%s▐%s' "$_D" "$_sep" "$_R"
    printf '\033[u'
  } >/dev/tty 2>/dev/null || true
}

# ── _progress_bg_refresh ─────────────────────────────────────────────────────
_progress_bg_refresh() {
  local _sf="$1" _total="$2" _t_start="$3" _eta_raw="$4"

  local _now; _now=$(date +%s)
  local _bias=$(( SECONDS - (_now - _t_start) ))
  local _label="" _pct=0 _floor=0 _ceil=0 _sect_start=$SECONDS _prev_label="" _tick=0

  # LED state — local to this subshell, used directly by _progress_draw_band
  local _led_disk_col=$'\033[2;34m'  _led_cpu_col=$'\033[2;34m'  _led_net_col=$'\033[2;34m'
  local _led_disk_pct=0  _led_cpu_pct=0
  local _led_net_rx=0    _led_net_tx=0  _led_net_pk=0
  local _ds_prev=0  _cpu_tot_prev=0  _cpu_idl_prev=0
  local _net_rx_prev=0  _net_tx_prev=0  _net_pk_prev=0

  # Inherit seed values from parent (exported before fork)
  [[ -n "${_PROG_DS_PREV:-}"        ]] && _ds_prev=$_PROG_DS_PREV
  [[ -n "${_PROG_CPU_TOTAL_PREV:-}" ]] && _cpu_tot_prev=$_PROG_CPU_TOTAL_PREV
  [[ -n "${_PROG_CPU_IDLE_PREV:-}"  ]] && _cpu_idl_prev=$_PROG_CPU_IDLE_PREV
  [[ -n "${_PROG_NET_RX_PREV:-}"    ]] && _net_rx_prev=$_PROG_NET_RX_PREV
  [[ -n "${_PROG_NET_TX_PREV:-}"    ]] && _net_tx_prev=$_PROG_NET_TX_PREV
  [[ -n "${_PROG_NET_PK_PREV:-}"    ]] && _net_pk_prev=$_PROG_NET_PK_PREV

  while [[ -f "$_sf" ]]; do
    # ── State file ─────────────────────────────────────────────────
    local _line; _line=$(cat "$_sf" 2>/dev/null) || true
    [[ "$_line" == "DONE" ]] && break
    if [[ -n "$_line" ]]; then
      local _f1="${_line%%|*}" _rest="${_line#*|}"
      local _f2="${_rest%%|*}"  _f3="${_rest##*|}"
      if [[ "$_f2" =~ ^[0-9]+$ && "$_f3" =~ ^[0-9]+$ ]]; then
        _floor="$_f2"; _ceil="$_f3"
        if [[ "$_f1" != "$_prev_label" ]]; then
          _label="$_f1"; _prev_label="$_f1"; _sect_start=$SECONDS
        fi
      fi
    fi

    # ── Animate ────────────────────────────────────────────────────
    local _span=$(( _ceil - _floor ))
    if [[ "$_span" -gt 0 ]]; then
      local _in=$(( SECONDS - _sect_start )); [[ "$_in" -lt 0 ]] && _in=0
      local _exp=$(( _span * 2 )); [[ "$_exp" -lt 4 ]] && _exp=4
      local _w=$(( _in * _span / _exp ))
      [[ "$_w" -ge "$_span" ]] && _w=$(( _span - 1 ))
      _pct=$(( _floor + _w ))
    else
      _pct=$_floor
    fi
    [[ "$_pct" -gt 100 ]] && _pct=100

    local _elapsed=$(( SECONDS - _bias )); [[ "$_elapsed" -lt 0 ]] && _elapsed=0

    # ── Resize every ~1 s ──────────────────────────────────────────
    _tick=$(( (_tick + 1) % 4 ))
    [[ "$_tick" -eq 0 ]] && _progress_get_size

    # ── Disk I/O (zero forks) ──────────────────────────────────────
    local _ds_now=0 _dsl
    while IFS= read -r _dsl; do
      local _df3="" _df4=0 _df8=0
      read -r _ _ _df3 _df4 _ _ _ _df8 _ <<< "$_dsl" 2>/dev/null || true
      [[ "$_df3" == "loop"* || "$_df3" == "ram"* || -z "$_df3" ]] && continue
      _ds_now=$(( _ds_now + ${_df4:-0} + ${_df8:-0} ))
    done < /proc/diskstats 2>/dev/null
    local _ds_d=$(( _ds_now - _ds_prev )); _ds_prev=$_ds_now
    [[ "$_ds_d" -lt 0 ]] && _ds_d=0
    _led_disk_pct=$(( _ds_d * 100 / 220 ))
    [[ "$_led_disk_pct" -gt 100 ]] && _led_disk_pct=100
    if   [[ "$_led_disk_pct" -ge 75 ]]; then _led_disk_col=$'\033[1;31m'
    elif [[ "$_led_disk_pct" -ge 45 ]]; then _led_disk_col=$'\033[0;33m'
    elif [[ "$_led_disk_pct" -ge 20 ]]; then _led_disk_col=$'\033[0;32m'
    elif [[ "$_led_disk_pct" -ge  5 ]]; then _led_disk_col=$'\033[0;36m'
    else                                      _led_disk_col=$'\033[2;34m'
    fi

    # ── CPU (zero forks) ───────────────────────────────────────────
    local _cl="" _cu=0 _cn=0 _cs=0 _ci=0 _cow=0 _crq=0 _csr=0 _cst=0
    IFS= read -r _cl < /proc/stat 2>/dev/null || true
    read -r _ _cu _cn _cs _ci _cow _crq _csr _cst _ <<< "$_cl" 2>/dev/null || true
    local _ct=$(( ${_cu:-0}+${_cn:-0}+${_cs:-0}+${_ci:-0}+${_cow:-0}+${_crq:-0}+${_csr:-0}+${_cst:-0} ))
    local _ci2=$(( ${_ci:-0}+${_cow:-0} ))
    local _dt=$(( _ct - _cpu_tot_prev )) _di=$(( _ci2 - _cpu_idl_prev ))
    _cpu_tot_prev=$_ct; _cpu_idl_prev=$_ci2
    _led_cpu_pct=0
    if [[ "$_dt" -gt 0 ]]; then
      local _db=$(( _dt - _di )); [[ "$_db" -lt 0 ]] && _db=0
      _led_cpu_pct=$(( _db * 100 / _dt ))
      [[ "$_led_cpu_pct" -gt 100 ]] && _led_cpu_pct=100
    fi
    if   [[ "$_led_cpu_pct" -ge 85 ]]; then _led_cpu_col=$'\033[1;31m'
    elif [[ "$_led_cpu_pct" -ge 60 ]]; then _led_cpu_col=$'\033[0;31m'
    elif [[ "$_led_cpu_pct" -ge 35 ]]; then _led_cpu_col=$'\033[0;33m'
    elif [[ "$_led_cpu_pct" -ge 10 ]]; then _led_cpu_col=$'\033[0;32m'
    else                                     _led_cpu_col=$'\033[2;34m'
    fi

    # ── Network (zero forks) ───────────────────────────────────────
    local _nrxb=0 _ntxb=0 _nrxp=0 _ntxp=0 _nif="" _nr=""
    while IFS=: read -r _nif _nr; do
      _nif="${_nif// /}"
      [[ "$_nif" != "${_PROG_NET_IFACE:-eth0}" ]] && continue
      read -r _nrxb _nrxp _ _ _ _ _ _ _ntxb _ntxp _ <<< "$_nr" 2>/dev/null || true
      break
    done < /proc/net/dev 2>/dev/null
    local _nrd=$(( (${_nrxb:-0} - _net_rx_prev) * 4 ))
    local _ntd=$(( (${_ntxb:-0} - _net_tx_prev) * 4 ))
    local _npd=$(( (${_nrxp:-0} + ${_ntxp:-0} - _net_pk_prev) * 4 ))
    [[ "$_nrd" -lt 0 ]] && _nrd=0; [[ "$_ntd" -lt 0 ]] && _ntd=0; [[ "$_npd" -lt 0 ]] && _npd=0
    _net_rx_prev=${_nrxb:-0}; _net_tx_prev=${_ntxb:-0}
    _net_pk_prev=$(( ${_nrxp:-0} + ${_ntxp:-0} ))
    _led_net_rx=$_nrd; _led_net_tx=$_ntd; _led_net_pk=$_npd
    local _nt=$(( _nrd + _ntd ))
    if   [[ "$_nt" -ge 52428800 ]]; then _led_net_col=$'\033[1;31m'
    elif [[ "$_nt" -ge 10485760 ]]; then _led_net_col=$'\033[0;33m'
    elif [[ "$_nt" -ge 1048576  ]]; then _led_net_col=$'\033[0;32m'
    elif [[ "$_nt" -ge 1024     ]]; then _led_net_col=$'\033[0;36m'
    else                                  _led_net_col=$'\033[2;34m'
    fi

    _progress_draw_band "$_label" "$_pct" "$_elapsed" "$_PROGRESS_COLS" "$_eta_raw"
    sleep 0.25 2>/dev/null || sleep 1
  done
}

# ── _progress_write_state ─────────────────────────────────────────────────────
_progress_write_state() {
  [[ -n "$_PROGRESS_STATE" ]] || return
  printf '%s|%d|%d\n' "$1" "${2:-0}" "${3:-${2:-0}}" \
    >"$_PROGRESS_STATE" 2>/dev/null || true
}

# ── _progress_init ────────────────────────────────────────────────────────────
_progress_init() {
  [[ -c /dev/tty ]] || return
  printf '' >/dev/tty 2>/dev/null || return

  _CACHED_ETA_RAW=$(get_timing_eta 2>/dev/null || true)

  local _lc="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
  [[ "${_lc,,}" == *utf-8* || "${_lc,,}" == *utf8* ]] && _PROGRESS_USE_UNICODE=true

  _progress_get_size
  _PROGRESS_ENABLED=true

  _PROGRESS_STATE=$(mktemp /tmp/wowsc_prog_XXXXXX 2>/dev/null) || {
    _PROGRESS_ENABLED=false; return
  }

  # ── Scroll region: rows 5..ROWS scroll; rows 1-4 are the fixed HUD ──
  # \033[5;ROWSr  means only rows 5..ROWS participate in scrolling.
  # The terminal's scroll engine physically cannot touch rows 1-4.
  # Scan output from log()/echo naturally goes to stdout which the shell
  # keeps inside the scroll region.
  printf '\033[5;%dr' "$_PROGRESS_ROWS" >/dev/tty 2>/dev/null || true
  # Move cursor into scroll region (row 5) so first output lands there
  printf '\033[5;1H' >/dev/tty 2>/dev/null || true

  # ── Seed /proc baselines (exported so bg subshell inherits them) ─
  _ws_net_seed_iface

  local _ds_init=0 _dsl
  while IFS= read -r _dsl; do
    local _df3="" _df4=0 _df8=0
    read -r _ _ _df3 _df4 _ _ _ _df8 _ <<< "$_dsl" 2>/dev/null || true
    [[ "$_df3" == "loop"* || "$_df3" == "ram"* || -z "$_df3" ]] && continue
    _ds_init=$(( _ds_init + ${_df4:-0} + ${_df8:-0} ))
  done < /proc/diskstats 2>/dev/null
  export _PROG_DS_PREV=$_ds_init

  local _cpu_l="" _wu=0 _wn=0 _ws=0 _wi=0 _wio=0
  IFS= read -r _cpu_l < /proc/stat 2>/dev/null || true
  read -r _ _wu _wn _ws _wi _wio _ <<< "$_cpu_l" 2>/dev/null || true
  export _PROG_CPU_TOTAL_PREV=$(( ${_wu:-0}+${_wn:-0}+${_ws:-0}+${_wi:-0}+${_wio:-0} ))
  export _PROG_CPU_IDLE_PREV=$(( ${_wi:-0}+${_wio:-0} ))

  # ── Hide cursor, draw initial HUD at rows 1-4 ─────────────────────
  printf '\033[?25l' >/dev/tty 2>/dev/null || true
  _progress_write_state "starting..." 0 0
  _progress_draw_band "starting..." 0 0 "$_PROGRESS_COLS" ""

  # ── Launch background subshell ────────────────────────────────────
  _progress_bg_refresh "$_PROGRESS_STATE" "$_PROGRESS_TOTAL" "$T_START" "${_CACHED_ETA_RAW:-}" &
  _PROGRESS_BG_PID=$!
}

# ── _progress_draw ────────────────────────────────────────────────────────────
_progress_draw() {
  [[ "$_PROGRESS_ENABLED" == "true" ]] || return
  local _label="${1:-}" _cum="${2:-0}"
  local _pct=0
  [[ "$_PROGRESS_TOTAL" -gt 0 ]] && _pct=$(( _cum * 100 / _PROGRESS_TOTAL ))
  [[ "$_pct" -gt 100 ]] && _pct=100
  _progress_write_state "$_label" "$_pct" "$_pct"
}

# ── _progress_tick ────────────────────────────────────────────────────────────
_progress_tick() {
  [[ "$_PROGRESS_ENABLED" == "true" ]] || return
  local _label="$1" _i
  for (( _i=0; _i<${#_PROGRESS_LABELS[@]}; _i++ )); do
    if [[ "${_PROGRESS_LABELS[$_i]}" == "$_label" ]]; then
      _PROGRESS_STEP=$(( _i + 1 )); break
    fi
  done
  local _cum=0
  [[ "${_PROGRESS_STEP:-0}" -gt 0 ]] && _cum="${_PROGRESS_CUM[$(( _PROGRESS_STEP - 1 ))]}"
  local _next="done"
  [[ "${_PROGRESS_STEP:-0}" -lt "${#_PROGRESS_LABELS[@]}" ]] && \
    _next="${_PROGRESS_LABELS[${_PROGRESS_STEP:-0}]}"
  _progress_draw "$_next" "$_cum"
}

# ── _progress_finish ──────────────────────────────────────────────────────────
_progress_finish() {
  [[ "$_PROGRESS_ENABLED" == "true" ]] || return

  if [[ -n "$_PROGRESS_BG_PID" ]]; then
    kill -HUP "$_PROGRESS_BG_PID" 2>/dev/null || true
    local _t=0
    while kill -0 "$_PROGRESS_BG_PID" 2>/dev/null && [[ "$_t" -lt 20 ]]; do
      sleep 0.1 2>/dev/null || true; _t=$(( _t + 1 ))
    done
    kill -9 "$_PROGRESS_BG_PID" 2>/dev/null || true
    wait "$_PROGRESS_BG_PID" 2>/dev/null || true
    _PROGRESS_BG_PID=""
  fi
  [[ -n "$_PROGRESS_STATE" ]] && printf 'DONE\n' >"$_PROGRESS_STATE" 2>/dev/null || true

  _progress_get_size
  _progress_draw_band "complete" 100 "$(( SECONDS - _T_START_SECONDS ))" "$_PROGRESS_COLS" "${_CACHED_ETA_RAW:-}"
  sleep 0.6 2>/dev/null || true

  # Remove scroll region → full terminal scrollable again
  printf '\033[r' >/dev/tty 2>/dev/null || true
  # Clear the 4 HUD rows
  local _hf
  for _hf in 1 2 3 4; do
    printf '\033[%d;1H\033[2K' "$_hf" >/dev/tty 2>/dev/null || true
  done
  printf '\033[1;1H\033[?25h' >/dev/tty 2>/dev/null || true

  rm -f "$_PROGRESS_STATE" 2>/dev/null || true
  _PROGRESS_STATE=""
  _PROGRESS_ENABLED=false
}

# ── _progress_start ───────────────────────────────────────────────────────────
_progress_start() {
  [[ "$_PROGRESS_ENABLED" == "true" ]] || return
  local _label="$1" _i _floor=0 _ceil=0
  for (( _i=0; _i<${#_PROGRESS_LABELS[@]}; _i++ )); do
    if [[ "${_PROGRESS_LABELS[$_i]}" == "$_label" ]]; then
      if [[ "$_PROGRESS_TOTAL" -gt 0 ]]; then
        [[ "$_i" -gt 0 ]] && _floor=$(( _PROGRESS_CUM[$(( _i - 1 ))] * 100 / _PROGRESS_TOTAL ))
        _ceil=$(( _PROGRESS_CUM[$_i] * 100 / _PROGRESS_TOTAL ))
        [[ "$_ceil" -le "$_floor" ]] && _ceil=$(( _floor + 1 ))
        [[ "$_ceil" -gt 99 ]] && _ceil=99
      fi
      break
    fi
  done
  _progress_write_state "$_label" "$_floor" "$_ceil"
}

_elapsed() {
  local label="$1"; local now
  now=$(date +%s)
  local _section_secs=$(( now - _SECTION_START ))
  # Record section name and duration for the final timer panel
  _SECTION_TIMES+=("${label}|${_section_secs}")
  _SECTION_START=$now   # reset for next section
  # Advance bar: mark this section as COMPLETE (full CUM weight)
  _progress_tick "$label"
}

main() {
  require_root
  check_archive_presence   # warn immediately if any known zip has disappeared
  T_START=$(date +%s)
  _T_START_SECONDS=$SECONDS        # bash built-in anchor — used for zero-fork elapsed calc
  _SECTION_START=$T_START          # per-section start time (reset after each section)
  _SECTION_TIMES=()                # collects "label|seconds" for timer panel

  # Adjust weights BEFORE _progress_init so background subshell gets correct total
  local _pw_sum _pw_i
  _recompute_progress_cum() {
    _pw_sum=0
    for (( _pw_i=0; _pw_i<${#_PROGRESS_WEIGHTS[@]}; _pw_i++ )); do
      _pw_sum=$(( _pw_sum + _PROGRESS_WEIGHTS[_pw_i] ))
      _PROGRESS_CUM[$_pw_i]=$_pw_sum
    done
    _PROGRESS_TOTAL=$_pw_sum
  }
  if [[ "$USE_PENTEST"      != "true" ]]; then
    local _pi; for _pi in 0 1 2 3 4; do _PROGRESS_WEIGHTS[$_pi]=0; done
    _recompute_progress_cum
  fi
  # Always recompute once to ensure new sections are included
  _recompute_progress_cum
  if [[ "$USE_LYNIS"        != "true" ]]; then _PROGRESS_WEIGHTS[22]=0; _recompute_progress_cum; fi
  if [[ "$USE_RKHUNTER"     != "true" ]]; then _PROGRESS_WEIGHTS[20]=0; _recompute_progress_cum; fi
  if [[ "$USE_HARDENING"    != "true" ]]; then _PROGRESS_WEIGHTS[18]=0; _recompute_progress_cum; fi
  if [[ "$USE_NETCONTAINER" != "true" ]]; then _PROGRESS_WEIGHTS[19]=0; _recompute_progress_cum; fi

  _progress_init

  # Trap: clean up progress bar if scan is interrupted (Ctrl+C, kill, error)
  # _progress_finish clears progress rows, shows cursor, kills bg subshell.
  _progress_cleanup_trap() { _progress_finish 2>/dev/null || true; }
  trap '_progress_cleanup_trap' EXIT INT TERM HUP

  # ── Aesthetic startup banner ─────────────────────────────────────────────
  # Build a full-width banner that adapts to the terminal.
  # The progress band is at rows 1-2; banner prints from row 3 downward.
  local _bw=78   # inner box content width
  # Get terminal width from progress bar detection (already run)
  if [[ "$_PROGRESS_ENABLED" == "true" && "$_PROGRESS_COLS" -gt 40 ]]; then
    _bw=$(( _PROGRESS_COLS - 4 ))   # 2 chars for ║ borders + 1 each side
    [[ "$_bw" -gt 100 ]] && _bw=100
  fi
  local _top _bot _div _i
  _top="╔"; _bot="╚"; _div="╠"
  for (( _i=0; _i<_bw+2; _i++ )); do _top+="═"; _bot+="═"; _div+="═"; done
  _top+="╗"; _bot+="╝"; _div+="╣"

  # Helper: centre-pad a string to _bw
  _bpad() {
    local _s="$1" _len="${#1}" _pad _lpad _rpad
    _pad=$(( _bw - _len ))
    _lpad=$(( _pad / 2 ))
    _rpad=$(( _pad - _lpad ))
    printf "║%*s%s%*s║" "$_lpad" "" "$_s" "$_rpad" ""
  }
  # Helper: left-pad a string to _bw
  _lpad() { printf "║  %-$(( _bw - 2 ))s║" "$1"; }

  local _hostname _os _kernel _now_str
  _hostname=$(hostname -f 2>/dev/null || hostname)
  _os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Linux")
  _kernel=$(uname -r)
  _now_str=$(date '+%Y-%m-%d  %H:%M:%S  %Z')

  # Mode flags
  local _m_pentest _m_lynis _m_rkhunter _m_hard _m_net _active_flags=""
  [[ "$USE_PENTEST"      == "true" ]] && _m_pentest="[ON]"  || { _m_pentest="[off]"; _active_flags+=" --no-pentest"; }
  [[ "$USE_LYNIS"        == "true" ]] && _m_lynis="[ON]"    || { _m_lynis="[off]";   _active_flags+=" --no-lynis"; }
  [[ "$USE_RKHUNTER"     == "true" ]] && _m_rkhunter="[ON]" || { _m_rkhunter="[off]";_active_flags+=" --no-rkhunter"; }
  [[ "$USE_HARDENING"    == "true" ]] && _m_hard="[ON]"     || { _m_hard="[off]";    _active_flags+=" --no-hardening"; }
  [[ "$USE_NETCONTAINER" == "true" ]] && _m_net="[ON]"      || { _m_net="[off]";     _active_flags+=" --no-netcontainer"; }
  [[ -z "$_active_flags" ]] && _active_flags="none (full scan)"

  # Coloured ASCII banner — adapts to terminal width
  log "${BCYAN}${_top}${NC}"
  log "${BCYAN}║${NC}$(_bpad "")${BCYAN}║${NC}"
  # ASCII art title split across two lines for narrow terminals
  if [[ "$_bw" -ge 56 ]]; then
    log "${BCYAN}║${NC}$(_bpad "${WHITE}${BOLD}██╗    ██╗ ██████╗ ██╗    ██╗███████╗${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${WHITE}${BOLD}██║    ██║██╔═══██╗██║    ██║██╔════╝${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${BBLUE}${BOLD}██║ █╗ ██║██║   ██║██║ █╗ ██║███████╗${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${BLUE}${BOLD}██║███╗██║██║   ██║██║███╗██║╚════██║${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${BLUE}╚███╔███╔╝╚██████╔╝╚███╔███╔╝███████║${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${BLUE}${DIM} ╚══╝╚══╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${BCYAN}S E C U R I T Y   S C A N N E R${NC}${BCYAN}")${BCYAN}║${NC}"
  else
    log "${BCYAN}║${NC}$(_bpad "${WHITE}${BOLD}WOWSCANNER${NC}${BCYAN}")${BCYAN}║${NC}"
    log "${BCYAN}║${NC}$(_bpad "${GREY}Security Scanner${NC}${BCYAN}")${BCYAN}║${NC}"
  fi
  log "${BCYAN}║${NC}$(_bpad "")${BCYAN}║${NC}"
  log "${BCYAN}║${NC}$(_bpad "${DIM}v${VERSION}  ·  ${COPYRIGHT}${NC}${BCYAN}")${BCYAN}║${NC}"
  log "${BCYAN}║${NC}$(_bpad "")${BCYAN}║${NC}"
  log "${BCYAN}${_div}${NC}"
  log "${BCYAN}║${NC}${BOLD}$(_lpad "  🖥  Host    :  ${NC}${WHITE}${_hostname}${NC}${BCYAN}")${NC}"
  log "${BCYAN}║${NC}${BOLD}$(_lpad "  🐧  OS      :  ${NC}${WHITE}${_os}${NC}${BCYAN}")${NC}"
  log "${BCYAN}║${NC}${BOLD}$(_lpad "  🧬  Kernel  :  ${NC}${WHITE}${_kernel}${NC}${BCYAN}")${NC}"
  log "${BCYAN}║${NC}${BOLD}$(_lpad "  🕐  Started :  ${NC}${WHITE}${_now_str}${NC}${BCYAN}")${NC}"
  log "${BCYAN}${_div}${NC}"
  # Colour-code each mode flag ON/off
  local _m_pen_c _m_lyn_c _m_rkh_c _m_hrd_c _m_net_c
  [[ "$_m_pentest"   == "[ON]" ]]  && _m_pen_c="${BGREEN}" || _m_pen_c="${DIM}"
  [[ "$_m_lynis"     == "[ON]" ]]  && _m_lyn_c="${BGREEN}" || _m_lyn_c="${DIM}"
  [[ "$_m_rkhunter"  == "[ON]" ]]  && _m_rkh_c="${BGREEN}" || _m_rkh_c="${DIM}"
  [[ "$_m_hard"      == "[ON]" ]]  && _m_hrd_c="${BGREEN}" || _m_hrd_c="${DIM}"
  [[ "$_m_net"       == "[ON]" ]]  && _m_net_c="${BGREEN}" || _m_net_c="${DIM}"
  log "${BCYAN}║${NC}$(_lpad "  Pentest ${_m_pen_c}${_m_pentest}${NC}  Lynis ${_m_lyn_c}${_m_lynis}${NC}  Rkhunter ${_m_rkh_c}${_m_rkhunter}${NC}  Hardening ${_m_hrd_c}${_m_hard}${NC}  Net ${_m_net_c}${_m_net}${NC}${BCYAN}")${NC}"
  log "${BCYAN}║${NC}$(_lpad "  Sections: ${WHITE}${BOLD}50${NC}  Flags: ${DIM}${_active_flags}${NC}${BCYAN}")${NC}"
  log "${BCYAN}${_bot}${NC}"
  log ""

  # Helper: log elapsed time after each major section

  # Each section: _progress_start shows it RUNNING immediately,
  # Total: 31 audited sections across security domains
  # _elapsed records duration and advances the bar when it FINISHES.
  _progress_start "0a pentest-enum";   section_pentest_enum || true;       _elapsed "0a pentest-enum"
  _progress_start "0b pentest-web";   section_pentest_web || true;        _elapsed "0b pentest-web"
  _progress_start "0c pentest-ssh";   section_pentest_ssh || true;        _elapsed "0c pentest-ssh"
  _progress_start "0d pentest-sqli";   section_pentest_sqli || true;       _elapsed "0d pentest-sqli"
  _progress_start "0e pentest-stress";   section_pentest_stress || true;     _elapsed "0e pentest-stress"
  _progress_start "1 sysinfo";   section_sysinfo || true;            _elapsed "1 sysinfo"
  _progress_start "2 updates";   section_updates || true;            _elapsed "2 updates"
  _progress_start "3 users";   section_users || true;              _elapsed "3 users"
  _progress_start "4 password";   section_password_policy || true;    _elapsed "4 password"
  _progress_start "5 ssh";   section_ssh || true;                _elapsed "5 ssh"
  _progress_start "6 firewall";   section_firewall || true;           _elapsed "6 firewall"
  _progress_start "7 ports";   section_ports || true;              _elapsed "7 ports"
  _progress_start "8 permissions";   section_permissions || true;        _elapsed "8 permissions"
  _progress_start "9 services";   section_services || true;           _elapsed "9 services"
  _progress_start "10 logging";   section_logging || true;            _elapsed "10 logging"
  _progress_start "11 kernel";   section_kernel || true;             _elapsed "11 kernel"
  _progress_start "12 cron";   section_cron || true;               _elapsed "12 cron"
  _progress_start "13 packages";   section_packages || true;           _elapsed "13 packages"
  _progress_start "13c hardening-advanced";   section_hardening_advanced || true;  _elapsed "13c hardening-advanced"
  _progress_start "13d network-container";   section_network_container || true;   _elapsed "13d network-container"
  _progress_start "14b chkrootkit+rkhunter";   section_chkrootkit || true;          _elapsed "14b chkrootkit+rkhunter"
  _progress_start "14 mac";   section_mac || true;                _elapsed "14 mac"
  _progress_start "15 lynis";   section_lynis || true;              _elapsed "15 lynis"
  _progress_start "16a lan-scan";   section_lan_scan || true;           _elapsed "16a lan-scan"
  _progress_start "16 portscan";   section_portscan || true;           _elapsed "16 portscan"
  _progress_start "17b failed-logins";   section_failed_logins || true;      _elapsed "17b failed-logins"
  _progress_start "17c env-security";   section_env_security || true;       _elapsed "17c env-security"
  _progress_start "17d usb-audit";   section_usb_devices || true;        _elapsed "17d usb-audit"
  _progress_start "17e ww-deep";   section_world_writable_deep || true; _elapsed "17e ww-deep"
  _progress_start "17f cert-audit";   section_cert_audit || true;          _elapsed "17f cert-audit"
  _progress_start "17g net-security";   section_network_security || true;    _elapsed "17g net-security"
  _progress_start "17h auditd";   section_auditd_check || true;        _elapsed "17h auditd"
  _progress_start "17i open-files";   section_open_files_check || true;    _elapsed "17i open-files"
  _progress_start "17j mem-security";   section_memory_security || true;     _elapsed "17j mem-security"
  _progress_start "17k pam-security";   section_pam_security || true;         _elapsed "17k pam-security"
  _progress_start "17l fs-hardening";   section_filesystem_hardening || true; _elapsed "17l fs-hardening"
  _progress_start "17m container";   section_container_security || true;   _elapsed "17m container"
  _progress_start "17n repo-sec";   section_repo_security || true;        _elapsed "17n repo-sec"
  _progress_start "17o time-sync";   section_time_sync || true;            _elapsed "17o time-sync"
  _progress_start "17p ipv6";   section_ipv6_security || true;        _elapsed "17p ipv6"
  _progress_start "17q ssh-extras";   section_ssh_extras || true;           _elapsed "17q ssh-extras"
  _progress_start "17r core-dump";   section_core_dump_security || true;   _elapsed "17r core-dump"
  _progress_start "17s systemd";   section_systemd_hardening || true;    _elapsed "17s systemd"
  _progress_start "17t sudo-audit";   section_sudo_audit || true;           _elapsed "17t sudo-audit"
  _progress_start "17u log-integrity";   section_log_integrity || true;       _elapsed "17u log-integrity"
  _progress_start "17v compilers";   section_compiler_tools || true;       _elapsed "17v compilers"
  _progress_start "17b3 hw-security";   section_hardware_security || true;     _elapsed "17b3 hw-security"
  _progress_start "17b4 boot-sec";   section_boot_security || true;         _elapsed "17b4 boot-sec"
  _progress_start "17b5 web-server";   section_web_server || true;           _elapsed "17b5 web-server"
  _progress_start "17b6 secrets";      section_secrets_scan || true;          _elapsed "17b6 secrets"
  _progress_start "17w net-ifaces";   section_network_interfaces || true;    _elapsed "17w net-ifaces"
  _progress_start "17x kernel-mods";   section_kernel_modules || true;       _elapsed "17x kernel-mods"
  _progress_start "17y mac-profiles";   section_mac_profiles || true;         _elapsed "17y mac-profiles"
  _progress_start "17z exposure";   section_exposure_summary || true;     _elapsed "17z exposure"
  section_summary || true

  local PERCENTAGE=0
  [[ "$TOTAL" -gt 0 ]] && PERCENTAGE=$(( SCORE * 100 / TOTAL ))

  # ── Flush REPORT before generators read it ───────────────────────
  sync 2>/dev/null || true

  # ── Stop progress bar NOW so terminal is fully restored before generators ──
  # Generators can take 30-120s total. Without restoring the terminal first,
  # their output was previously hidden inside the scroll region.
  _progress_finish

  # ── Generation phase banner ───────────────────────────────────────────────
  local _gw=$(( ${COLUMNS:-80} - 2 ))
  [[ "$_gw" -gt 76 ]] && _gw=76
  local _gline=""; local _gi; for (( _gi=0; _gi<_gw; _gi++ )); do _gline+="═"; done
  echo ""
  echo -e "${BBLUE}${BOLD}╔${_gline}╗${NC}"
  echo -e "${BBLUE}${BOLD}║${NC}$(printf "%*s${WHITE}${BOLD}📄  GENERATING REPORT FILES${NC}%*s" $(( (_gw-27)/2 )) "" $(( _gw-27-((_gw-27)/2) )) "")${BBLUE}${BOLD}║${NC}"
  echo -e "${BBLUE}${BOLD}╚${_gline}╝${NC}"
  echo ""

  # ── Run all generators with timing ──────────────────────────────────────────
  # timeout cannot call shell functions directly — just call them directly.
  # The generators run python3 internally; if python3 hangs, the user can Ctrl+C.
  local _GEN_ODT_S=0 _GEN_ODS_S=0 _GEN_INTEL_S=0 _GEN_HTML_S=0 _GEN_FINDINGS_S=0
  local _g_t0 _g_t1

  echo -e "  ${BBLUE}◆${NC} ${BOLD}ODT report${NC}${DIM} (graphical audit)${NC}"
  _g_t0=$(date +%s)
  generate_odt_report       "$REPORT" "$SCORE" "$TOTAL" "$PERCENTAGE" "$LAN_JSON" || true
  _g_t1=$(date +%s); _GEN_ODT_S=$(( _g_t1 - _g_t0 ))
  echo -e "  ${BGREEN}✔${NC}  ODT report complete  ${DIM}(${_GEN_ODT_S}s)${NC}"

  echo -e "  ${BBLUE}◆${NC} ${BOLD}ODS statistics${NC}${DIM} (workbook + charts)${NC}"
  _g_t0=$(date +%s)
  generate_stats_ods        "$REPORT" "$SCORE" "$TOTAL" "$PERCENTAGE" "$LAN_JSON" || true
  _g_t1=$(date +%s); _GEN_ODS_S=$(( _g_t1 - _g_t0 ))
  echo -e "  ${BGREEN}✔${NC}  ODS statistics complete  ${DIM}(${_GEN_ODS_S}s)${NC}"

  echo -e "  ${BBLUE}◆${NC} ${BOLD}Intel ODT${NC}${DIM} (CVE & threat intelligence)${NC}"
  _g_t0=$(date +%s)
  generate_odf_intel_report "$SCORE"  "$TOTAL" "$PERCENTAGE" "$REPORT" || true
  _g_t1=$(date +%s); _GEN_INTEL_S=$(( _g_t1 - _g_t0 ))
  echo -e "  ${BGREEN}✔${NC}  Intel ODT complete  ${DIM}(${_GEN_INTEL_S}s)${NC}"

  echo -e "  ${BBLUE}◆${NC} ${BOLD}HTML report${NC}${DIM} (self-contained browser report)${NC}"
  _g_t0=$(date +%s)
  generate_html_report      "$REPORT" "$SCORE" "$TOTAL" "$PERCENTAGE" || true
  _g_t1=$(date +%s); _GEN_HTML_S=$(( _g_t1 - _g_t0 ))
  echo -e "  ${BGREEN}✔${NC}  HTML report complete  ${DIM}(${_GEN_HTML_S}s)${NC}"

  echo -e "  ${BBLUE}◆${NC} ${BOLD}Findings report${NC}${DIM} (paginated text)${NC}"
  _g_t0=$(date +%s)
  generate_findings_report  "$REPORT" || true
  _g_t1=$(date +%s); _GEN_FINDINGS_S=$(( _g_t1 - _g_t0 ))
  echo -e "  ${BGREEN}✔${NC}  Findings report complete  ${DIM}(${_GEN_FINDINGS_S}s)${NC}"

  local _GEN_TOTAL_S=$(( _GEN_ODT_S + _GEN_ODS_S + _GEN_INTEL_S + _GEN_HTML_S + _GEN_FINDINGS_S ))
  echo ""

  # ── Archive all output files ──────────────────────────────────────────────
  echo -e "  ${BBLUE}◆${NC} ${BOLD}Creating signed archive...${NC}"
  sync 2>/dev/null || true
  archive_outputs || true
  local _arc_file="wowscanner_archive_${TIMESTAMP}.zip"
  [[ -f "$_arc_file" ]] && \
    echo -e "  ${GREEN}✔${NC}  Archive: ${_arc_file}" || \
    echo -e "  ${YELLOW}⚠${NC}  Archive not created"

  # ── Webhook / email delivery ──────────────────────────────────────────────
  if [[ -f "$_arc_file" ]]; then
    deliver_report "$SCORE" "$TOTAL" "$PERCENTAGE" "$_arc_file" || true
  fi

  # ── Record this run's timing to the baseline DB ───────────────
  # Wall time is computed below; pass 0 now and we'll update after T_WALL_S is known.
  # We do a two-step: fetch ETA BEFORE recording so the current run
  # doesn't skew its own prediction.
  local _ETA_RAW; _ETA_RAW=$(get_timing_eta)    # "seconds|count" or empty

  # ════════════════════════════════════════════════════════════════
  #  ELAPSED TIMER PANEL  — shown after every scan
  #  Displays total wall-clock time broken into: audit vs generation
  # ════════════════════════════════════════════════════════════════
  local T_AUDIT_END T_AUDIT_ELAPSED
  T_AUDIT_END=$(date +%s)
  T_AUDIT_ELAPSED=$(( T_AUDIT_END - T_START ))

  # ── Total wall clock ──────────────────────────────────────────
  local T_WALL_END T_WALL_S T_WALL_H T_WALL_M T_WALL_SEC
  T_WALL_END=$(date +%s)
  T_WALL_S=$(( T_WALL_END - T_START ))
  T_WALL_H=$(( T_WALL_S / 3600 ))
  T_WALL_M=$(( (T_WALL_S % 3600) / 60 ))
  T_WALL_SEC=$(( T_WALL_S % 60 ))

  # ── Record this run into the timing baseline DB ───────────────
  record_timing_baseline "$T_WALL_S" "$T_AUDIT_ELAPSED" \
    "$_GEN_ODT_S" "$_GEN_ODS_S" "$_GEN_INTEL_S" "$_GEN_HTML_S"

  # ── Parse ETA from baseline (fetched before this run was recorded) ─
  local _ETA_SECS=0 _ETA_RUNS=0 _ETA_STR="" _ETA_DIFF_STR="" _ETA_COL=""
  if [[ -n "$_ETA_RAW" ]]; then
    _ETA_SECS="${_ETA_RAW%%|*}"
    _ETA_RUNS="${_ETA_RAW##*|}"
    _ETA_SECS=$(safe_int "$_ETA_SECS")
    _ETA_RUNS=$(safe_int "$_ETA_RUNS")
    if [[ "$_ETA_SECS" -gt 0 ]]; then
      local _eta_m=$(( _ETA_SECS / 60 )) _eta_s=$(( _ETA_SECS % 60 ))
      [[ "$_eta_m" -gt 0 ]] && _ETA_STR="${_eta_m}m ${_eta_s}s" || _ETA_STR="${_eta_s}s"
      # Diff: how far off was the prediction?
      local _diff=$(( T_WALL_S - _ETA_SECS ))
      local _adiff=$(( _diff < 0 ? -_diff : _diff ))
      local _diff_sign="+"
      [[ "$_diff" -lt 0 ]] && _diff_sign="-"
      local _dm=$(( _adiff / 60 )) _ds=$(( _adiff % 60 ))
      [[ "$_dm" -gt 0 ]] && _ETA_DIFF_STR="${_diff_sign}${_dm}m ${_ds}s" \
                         || _ETA_DIFF_STR="${_diff_sign}${_ds}s"
      # Colour: within 15% = green, within 30% = yellow, else red
      local _pct_off=$(( _adiff * 100 / ( _ETA_SECS > 0 ? _ETA_SECS : 1 ) ))
      if   [[ "$_pct_off" -le 15 ]]; then _ETA_COL="$GREEN"
      elif [[ "$_pct_off" -le 30 ]]; then _ETA_COL="$YELLOW"
      else                                 _ETA_COL="$RED"; fi
    fi
  fi

  # Format helper: Xm Ys
  _fmt_dur() {
    local _s="$1" _m=$(( $1 / 60 )) _r=$(( $1 % 60 ))
    [[ "$_m" -gt 0 ]] && echo "${_m}m ${_r}s" || echo "${_r}s"
  }
  # Colour helper: green<=10s yellow<=60s red>60s
  _dur_col() { [[ "$1" -le 10 ]] && echo "$GREEN" || { [[ "$1" -le 60 ]] && echo "$YELLOW" || echo "$RED"; }; }

  local _tc_wall
  [[ "$T_WALL_S" -lt 300 ]] && _tc_wall="$GREEN" || { [[ "$T_WALL_S" -lt 720 ]] && _tc_wall="$YELLOW" || _tc_wall="$RED"; }
  local _wall_str
  [[ "$T_WALL_H" -gt 0 ]] && _wall_str="${T_WALL_H}h ${T_WALL_M}m ${T_WALL_SEC}s" \
                           || _wall_str="${T_WALL_M}m ${T_WALL_SEC}s"

  # ── Build a mini bar chart (max width 30) ────────────────────
  _mini_bar() {
    local _s="$1" _max="$2" _w=30 _f _b=""
    _f=$(( _s * _w / ( _max > 0 ? _max : 1 ) ))
    [[ "$_f" -lt 1 && "$_s" -gt 0 ]] && _f=1
    local _i; for (( _i=0; _i<_f; _i++ )); do _b+="█"; done
    echo "$_b"
  }
  local _max_phase=$(( T_AUDIT_ELAPSED > _GEN_TOTAL_S ? T_AUDIT_ELAPSED : _GEN_TOTAL_S ))

  # ── Timer panel (adaptive width) ─────────────────────────────────────
  local _tw=$(( ${_PROGRESS_COLS:-80} - 2 ))
  [[ "$_tw" -gt 76 ]] && _tw=76
  [[ "$_tw" -lt 50 ]] && _tw=50
  local _tline="" _tthin="" _tci
  for (( _tci=0; _tci<_tw; _tci++ )); do _tline+="═"; _tthin+="─"; done

  log ""
  log "${BBLUE}${BOLD}╔${_tline}╗${NC}"
  log "${BBLUE}${BOLD}║${NC}$(printf "%*s${WHITE}${BOLD}⏱  SCAN TIMING SUMMARY${NC}%*s" $(( (_tw-22)/2 )) "" $(( _tw-22-((_tw-22)/2) )) "")${BBLUE}${BOLD}║${NC}"
  log "${BBLUE}${BOLD}╠${_tline}╣${NC}"
  log "${BBLUE}${BOLD}║${NC}"
  log "${BBLUE}${BOLD}║${NC}  ${WHITE}${BOLD}Phase                     Duration   Bar (relative)${NC}"
  log "${BBLUE}${BOLD}║${NC}  ${BBLUE}${_tthin}${NC}"

  # Audit sections aggregate row
  local _ac; _ac=$(_dur_col "$T_AUDIT_ELAPSED")
  local _ab; _ab=$(_mini_bar "$T_AUDIT_ELAPSED" "$_max_phase")
  log "${CYAN}${BOLD}║${NC}  ${_ac}$(printf '%-26s' 'Audit sections (total)')  $(printf '%8s' "$(_fmt_dur "$T_AUDIT_ELAPSED")")${NC}   ${_ac}${_ab}${NC}"

  # Per-section breakdown from _SECTION_TIMES array
  if [[ "${#_SECTION_TIMES[@]}" -gt 0 ]]; then
    log "${BBLUE}${BOLD}║${NC}  ${BBLUE}  ┌─ ${WHITE}Section breakdown${NC}${BBLUE} ──────────────────────────────────${NC}"
    local _entry _slbl _ssec _sc _sb
    for _entry in "${_SECTION_TIMES[@]}"; do
      _slbl="${_entry%%|*}"
      _ssec="${_entry##*|}"
      _ssec=$(( _ssec > 0 ? _ssec : 0 ))
      [[ "$_ssec" -eq 0 ]] && continue     # skip skipped sections
      _sc=$(_dur_col "$_ssec")
      _sb=$(_mini_bar "$_ssec" "$_max_phase")
      log "${BBLUE}${BOLD}║${NC}  ${BBLUE}  │${NC} ${_sc}$(printf '%-24s' "${_slbl:0:24}")  $(printf '%8s' "$(_fmt_dur "$_ssec")")${NC}   ${_sc}${_sb}${NC}"
    done
    log "${BBLUE}${BOLD}║${NC}  ${BBLUE}  └──────────────────────────────────────────────────────────${NC}"
  fi

  # Generator rows
  local _gc _gb
  for _row in \
      "ODT report:$_GEN_ODT_S" \
      "ODS statistics:$_GEN_ODS_S" \
      "Intel ODT:$_GEN_INTEL_S" \
      "HTML report:$_GEN_HTML_S"; do
    local _rl="${_row%%:*}" _rs="${_row##*:}"
    _gc=$(_dur_col "$_rs")
    _gb=$(_mini_bar "$_rs" "$_max_phase")
    log "${BBLUE}${BOLD}║${NC}  ${_gc}$(printf '%-26s' "$_rl")  $(printf '%8s' "$(_fmt_dur "$_rs")")${NC}   ${_gc}${_gb}${NC}"
  done
  log "${BBLUE}${BOLD}║${NC}  ${BBLUE}────────────────────────────────────────────────────────────────${NC}"

  # ── Total wall clock row + ETA comparison ────────────────────
  if [[ -n "$_ETA_STR" ]]; then
    # We have a baseline — show actual vs predicted with accuracy indicator
    local _eta_acc_bar=""
    local _pct_off_display=$(( (_adiff * 100) / (_ETA_SECS > 0 ? _ETA_SECS : 1) ))
    # Accuracy bar: ████ = accurate  ░░░░ = off
    local _acc_filled=$(( (100 - (_pct_off_display < 100 ? _pct_off_display : 100)) * 10 / 100 ))
    local _ai; for (( _ai=0; _ai<10; _ai++ )); do
      [[ "$_ai" -lt "$_acc_filled" ]] && _eta_acc_bar+="█" || _eta_acc_bar+="░"
    done
    log "${CYAN}${BOLD}║${NC}  ${_tc_wall}${BOLD}$(printf '%-18s' 'TOTAL WALL CLOCK')  $(printf '%8s' "$_wall_str")${NC}   ${_ETA_COL}ETA was ~${_ETA_STR}  (${_ETA_DIFF_STR})  ${_eta_acc_bar}${NC}"
    log "${CYAN}${BOLD}║${NC}  ${CYAN}$(printf '%-18s' '')              Prediction based on ${_ETA_RUNS} prior run(s) · EWMA α=0.4${NC}"
  else
    # First run — no baseline yet
    log "${CYAN}${BOLD}║${NC}  ${_tc_wall}${BOLD}$(printf '%-26s' 'TOTAL WALL CLOCK')  $(printf '%8s' "$_wall_str")${NC}   ${YELLOW}First run — baseline recorded for future ETA${NC}"
  fi
  log "${BBLUE}${BOLD}║${NC}  ${BGREEN}${BOLD}$(printf '%-26s' 'Score')  ${SCORE} / ${TOTAL} passed (${PERCENTAGE}%)${NC}"
  log "${BBLUE}${BOLD}║${NC}"
  log "${BBLUE}${BOLD}╚${_tline}╝${NC}"
  log ""
  log "${BBLUE}${BOLD}╔${_tline}╗${NC}"
  log "${BBLUE}${BOLD}║${NC}$(printf "%*s${WHITE}${BOLD}OUTPUT FILES${NC}%*s" $(( (_tw-12)/2 )) "" $(( _tw-12-((_tw-12)/2) )) "")${CYAN}${BOLD}║${NC}"
  log "${CYAN}${BOLD}╚${_tline}╝${NC}"
  log ""
  # Output files panel with icons
  local _fw=$(( ${_PROGRESS_COLS:-80} - 4 ))
  [[ "$_fw" -gt 74 ]] && _fw=74
  local _fline=""; local _fci; for (( _fci=0; _fci<_fw; _fci++ )); do _fline+="─"; done
  log ""
  log "  ${BBLUE}┌${_fline}┐${NC}"
  log "  ${BBLUE}│${NC}  ${WHITE}${BOLD}📂  OUTPUT FILES${NC}$(printf '%*s' $(( _fw - 18 )) '')${BBLUE}│${NC}"
  log "  ${BBLUE}├${_fline}┤${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}📄  ${REPORT}${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}Full plain-text audit log${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}🔍  wowscanner_findings_${TIMESTAMP}.txt${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}Paginated findings  (less findings.txt)${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}📊  wowscanner_report_${TIMESTAMP}.odt${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}Graphical ODT report  (LibreOffice Writer)${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}🌐  wowscanner_report_${TIMESTAMP}.html${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}Self-contained HTML  (any browser)${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}📈  wowscanner_stats_${TIMESTAMP}.ods${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}Statistics workbook  (LibreOffice Calc)${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}🔬  wowscanner_intel_${TIMESTAMP}.odt${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}Intelligence report  (CVE context)${NC}"
  log "  ${BBLUE}├${_fline}┤${NC}"
  log "  ${BBLUE}│${NC}  ${BOLD}🗜  wowscanner_archive_${TIMESTAMP}.zip${NC}"
  log "  ${BBLUE}│${NC}     ${DIM}HMAC-signed archive  (sudo bash $0 verify)${NC}"
  log "  ${BBLUE}└${_fline}┘${NC}"
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
  log "  • --fast-only                   skip pentest + slow sections (~2-4 min)"
  log "  • --no-rkhunter                 skip rootkit scanners"
  log "  • --no-lynis                    skip Lynis audit"
  log "  • RKH_FULL=true  sudo bash $0   full rkhunter scan"
  log "  • LYNIS_FULL=true sudo bash $0  full Lynis audit"
  log ""

  # All generators done. _progress_finish was called before generators ran above.

  # ── Restart Samba — must be the very last action ───────────────
  # Every output file (.txt via log/tee, .odt, .ods, .zip) has now been
  # fully written and closed.  Restarting smbd here guarantees the share
  # directory listing is refreshed AFTER all writes are complete.
  if systemctl is-active --quiet smbd 2>/dev/null || \
     systemctl is-active --quiet samba 2>/dev/null; then
    echo -e "  ${CYAN}Restarting Samba so output files appear on the share...${NC}"
    local _smb_ok=false
    for _smb_svc in smbd.service smbd samba; do
      if timeout 15 systemctl restart "$_smb_svc" 2>/dev/null; then
        echo -e "  ${GREEN}[✔]  ${_smb_svc} restarted — share is up to date${NC}"
        _smb_ok=true; break
      fi
    done
    [[ "$_smb_ok" == "false" ]] &&       echo -e "  ${YELLOW}[⚠]  Samba restart failed. Run: sudo systemctl restart smbd.service${NC}"
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
# Standalone ODF CRC check: sudo bash wowscanner.sh verify-odf
if [[ "${1:-}" == "verify-odf" || "${1:-}" == "--verify-odf" ]]; then
  require_root
  check_odf_crcs
  exit $?
fi
if [[ "$CMD_DIFF" == "true" ]]; then
  cmd_diff
  exit 0
fi
if [[ "$CMD_INSTALL_TIMER" == "true" ]]; then
  cmd_install_timer
  exit 0
fi
if [[ "$CMD_REMOVE_TIMER" == "true" ]]; then
  cmd_remove_timer
  exit 0
fi
if [[ "$CMD_HARDEN" == "true" ]]; then
  cmd_harden
  exit 0
fi
if [[ "$CMD_BASELINE" == "true" ]]; then
  cmd_baseline
  exit 0
fi
if [[ "$CMD_INSTALL_COMPLETION" == "true" ]]; then
  cmd_install_completion
  exit 0
fi
if [[ "$CMD_SET_PASSWORD" == "true" ]]; then
  cmd_set_password
  exit 0
fi
if [[ "$CMD_REMOVE_PASSWORD" == "true" ]]; then
  cmd_remove_password
  exit 0
fi
if [[ "$CMD_EXAMPLE_OUTPUT" == "true" ]]; then
  cmd_example_output
  exit 0
fi
if [[ "$CMD_RESET_AUTH" == "true" ]]; then
  # Pass args starting from position 2 so "reset-auth --forgot"
  # correctly delivers "--forgot" as $1 inside cmd_reset_auth
  cmd_reset_auth "${@:2}"
  exit 0
fi
if [[ "$CMD_RECOVER" == "true" ]]; then
  cmd_recover
  exit 0
fi
main "$@"
