#!/usr/bin/env bash
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  bb-menu.sh
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  “real never lies.”  |  Support: buymeacoffee.com/kdairatchi
# =========================================================

set -Eeuo pipefail

# Source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/banner.sh"
source "${SCRIPT_DIR}/lib/log.sh"

# ---------- Paths from your setup ----------
JSFINDER='python3 ../tools/JSFinder/jsfinder.py'
JSRECON='./js_recon.sh'
JSSCAN='../tools/JSFScan.sh'
LAZYXSS='python3 ../tools/Lazyxss/main.py'
LOXS='python3 ../tools/loxs/loxs.py'
LUCKYSIN='./luckysin2.sh'
LUCKYSPIN='./luckyspin.sh'
MENU_WRAPPER='./bug_bounty_menu.sh'
NUCLEIH='./nuclei_debug_helper.sh'
PCUPDATER='./pcupdater'
PUNY='python3 ./punycode_gen.py'
RANDOM_BOT='python3 ./bounty_randomizer.py'
RECON='./recon.sh'
RUSTSCAN='../tools/RustScan/target/release/rustscan'
SECURECOMMS='./secure_comms.sh'
SNIPER='sudo ../tools/Sn1per/sniper'
SPIDERFOOT='python3 ../tools/spiderfoot/sf.py'
SQLI='./sqli_test.sh'
SWAGGER='./swagger.sh'
TRAFFICLOG='python3 ./traffic_analysis.py'
UFX='python3 ../tools/UFX/ufx.py'
ULTIBB='./ultibb.sh'
VT='./vt.sh'
WAYBACK='./wayback.sh'
WAYBACKFIND='python3 ../WayBackupFinder/wayBackupFinder.py'
WAYBACKMASTER='./waybackmaster'
XSSTRIKE='python3 ../tools/XSStrike/xsstrike.py'

# Optional defaults
DEFAULT_THREADS="${THREADS:-8}"
DEFAULT_RUST_PORTS="${RUST_PORTS:-1-65535}"
USER_AGENT="${UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari}"

# ---------- UI helpers ----------
bar()      { printf "┈%.0s" $(seq 1 60); echo; }
header() {
  clear
  kd_banner "Bug Bounty Toolkit" "1.0.0"
}

press() { read -rp "$(log_debug 'Press Enter…')" _;
}

exists() {
  # accepts a full command string or path; tries to verify executable/script presence
  local cmd="$1" bin first
  first="$(awk '{print $1}' <<<"$cmd")"
  if [[ "$first" == "python3" || "$first" == "sudo" ]]; then
    bin="$(awk '{print $2}' <<<"$cmd")"
  else
    bin="$first"
  fi
  # If it's an absolute path, check file; else try which
  if [[ "$bin" = /* ]]; then
    [[ -e "$bin" ]] && return 0 || return 1
  else
    command -v "$bin" >/dev/null 2>&1
  fi
}

run_or_warn() {
  local cmd="$1"
  if exists "$cmd"; then
    log_ok "→ Running: $cmd"
    eval "$cmd"
  else
    log_err "✖ Missing: $cmd"
    log_warn "Check the path or install the tool."
    return 127
  fi
}

# ---------- Prompts ----------
ask_target() { read -rp "Target (domain or URL): " TARGET; echo "${TARGET}"; }
ask_file()   { read -rp "File path: " FPATH; echo "${FPATH}"; }
ask_threads(){ read -rp "Threads [${DEFAULT_THREADS}]: " th; echo "${th:-$DEFAULT_THREADS}"; }

# ---------- Actions ----------
act_recon_basic()        { t=$(ask_target); run_or_warn "$RECON \"$t\""; }
act_jsfinder()           { t=$(ask_target); run_or_warn "$JSFINDER -u \"$t\" -d"; }
act_jsrecon()            { t=$(ask_target); run_or_warn "$JSRECON \"$t\""; }
act_jsscan()             { t=$(ask_target); run_or_warn "$JSSCAN \"$t\""; }
act_lazyxss()            { t=$(ask_target); run_or_warn "$LAZYXSS -u \"$t\""; }
act_xsstrike()           { t=$(ask_target); run_or_warn "$XSSTRIKE -u \"$t\" --crawl"; }
act_sqlitest()           { t=$(ask_target); run_or_warn "$SQLI \"$t\""; }
act_punycode()           { t=$(ask_target); run_or_warn "$PUNY \"$t\""; }
act_wayback()            { t=$(ask_target); run_or_warn "$WAYBACK \"$t\""; }
act_waybackfind()        { t=$(ask_target); run_or_warn "$WAYBACKFIND -u \"$t\""; }
act_waybackmaster()      { t=$(ask_target); run_or_warn "$WAYBACKMASTER \"$t\""; }
act_luckysin()           { run_or_warn "$LUCKYSIN"; }
act_luckyspin()          { run_or_warn "$LUCKYSPIN"; }
act_random_picker()      { run_or_warn "$RANDOM_BOT"; }
act_rustscan()           { t=$(ask_target); p=$(read -rp "Ports [${DEFAULT_RUST_PORTS}]: " _p; echo "${_p:-$DEFAULT_RUST_PORTS}"); run_or_warn "$RUSTSCAN -a \"$t\" -r \"$p\""; }
act_sn1per()             { t=$(ask_target); run_or_warn "$SNIPER -t \"$t\" -m stealth"; }
act_spiderfoot()         { t=$(ask_target); run_or_warn "$SPIDERFOOT -s \"$t\" -q"; }
act_nucleih()            { t=$(ask_target); run_or_warn "$NUCLEIH \"$t\""; }
act_loxs()               { t=$(ask_target); run_or_warn "$LOXS -u \"$t\""; }
act_ufx()                { t=$(ask_target); run_or_warn "$UFX -u \"$t\""; }
act_trafficlog()         { f=$(ask_file); run_or_warn "$TRAFFICLOG \"$f\""; }
act_securecomms()        { run_or_warn "$SECURECOMMS"; }
act_swagger()            { t=$(ask_target); run_or_warn "$SWAGGER \"$t\""; }
act_vt()                 { t=$(ask_target); run_or_warn "$VT \"$t\""; }
act_pcupdater()          { run_or_warn "$PCUPDATER"; }
act_ultibb()             { run_or_warn "$ULTIBB"; }
act_menu_wrapper()       { run_or_warn "$MENU_WRAPPER"; }

# ---------- Menu ----------
trap 'echo; log_err "Interrupted"; exit 130' INT

while true; do
  header
  log_info "Recon & Scope"
  echo "   1) Basic Recon (recon.sh)"
  echo "   2) RustScan"
  echo "   3) Sn1per"
  echo "   4) SpiderFoot"
  echo
  log_info "JavaScript & Client-Side"
  echo "   5) JSFinder"
  echo "   6) js_recon.sh"
  echo "   7) JSFScan.sh"
  echo "   8) LOXS"
  echo "   9) UFX"
  echo
  log_info "Vuln Testing"
  echo "  10) LazyXSS"
  echo "  11) XSStrike"
  echo "  12) SQLi tester"
  echo "  13) Nuclei helper"
  echo
  log_info "Archive/OSINT"
  echo "  14) Wayback (simple)"
  echo "  15) WayBackupFinder"
  echo "  16) WaybackMaster"
  echo
  log_info "Utilities"
  echo "  17) Punycode generator"
  echo "  18) Traffic log analyzer"
  echo "  19) Secure comms profile"
  echo "  20) Swagger helper"
  echo "  21) VirusTotal helper"
  echo
  log_info "Program Pickers / Meta"
  echo "  22) LuckySin (program spinner)"
  echo "  23) LuckySpin (ultimate)"
  echo "  24) Randomizer bot"
  echo "  25) ULTIBB (ultimate launcher)"
  echo "  26) Old menu wrapper"
  echo
  log_info "System / Maintenance"
  echo "  27) PC updater"
  echo
  echo "  0) Exit"
  echo
  read -rp "Select: " ch
  echo; bar

  case "${ch:-}" in
    1)  act_recon_basic ;;
    2)  act_rustscan ;;
    3)  act_sn1per ;;
    4)  act_spiderfoot ;;
    5)  act_jsfinder ;;
    6)  act_jsrecon ;;
    7)  act_jsscan ;;
    8)  act_loxs ;;
    9)  act_ufx ;;
    10) act_lazyxss ;;
    11) act_xsstrike ;;
    12) act_sqlitest ;;
    13) act_nucleih ;;
    14) act_wayback ;;
    15) act_waybackfind ;;
    16) act_waybackmaster ;;
    17) act_punycode ;;
    18) act_trafficlog ;;
    19) act_securecomms ;;
    20) act_swagger ;;
    21) act_vt ;;
    22) act_luckysin ;;
    23) act_luckyspin ;;
    24) act_random_picker ;;
    25) act_ultibb ;;
    26) act_menu_wrapper ;;
    27) act_pcupdater ;;
    0|q|Q) log_ok "Bye 👋"; exit 0 ;;
    *) log_err "Invalid choice" ;;
  esac

  echo; bar; press
done