#!/usr/bin/env bash

# ============================================================================
# RedChains.sh — Ultimate ProxyChains Manager
# Clean, parallel, and user-friendly proxy workflow
# Author: kdairatchi (enhanced by assistant)
# Version: 3.0
# ============================================================================

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# --------------------------- Colors & Styling ---------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ------------------------------ Paths ----------------------------------
DEFAULT_CONF4="/etc/proxychains4.conf"
DEFAULT_CONF3="/etc/proxychains.conf"
CONF_FILE=""

# Use a per-user temp directory to avoid permission issues if another user
# (e.g., root) previously created a global path in /tmp.
TEMP_DIR="${TMPDIR:-/tmp}/proxychains_manager_${USER:-uid$(id -u)}"
SRC_DIR="$TEMP_DIR/sources"
ALL_PROXIES="$TEMP_DIR/all_proxies.txt"
WORKING_PROXIES="$TEMP_DIR/working_proxies.txt"
CHECKED_PROXIES="$TEMP_DIR/checked_proxies.txt"
LOG_FILE="$TEMP_DIR/proxy_manager.log"

# ----------------------------- Settings --------------------------------
: "${MAX_JOBS:=5000}"          # Max concurrent network tasks
: "${CONNECT_TIMEOUT:=6}"    # Seconds per connection attempt
: "${TOTAL_TIMEOUT:=6}"      # Max seconds per curl
: "${TRY_ORDER:=socks5,socks4,http,https}"  # Try order for proxy types

# ------------------------------ Banner ---------------------------------
show_banner() {
  clear || true
  printf "%b\n" "$CYAN"
  printf " ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗\n"
  printf "██╔═══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝\n"
  printf "██║   ██║██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ██║     ███████║███████║██║██╔██╗ ██║███████╗\n"
  printf "██║   ██║██╔═══╝ ██║   ██║ ██╔██╗   ╚██╔╝  ██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║\n"
  printf "╚██████╔╝██║     ╚██████╔╝██╔╝ ██╗   ██║   ╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║\n"
  printf " ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝\n"
  printf "%b\n" "$NC"
  printf "%b════════════════════════════════════════════════════════════════════════════════%b\n" "$YELLOW" "$NC"
  printf "%b                 Ultimate Proxy Manager for ProxyChains%b\n" "$GREEN" "$NC"
  printf "%b════════════════════════════════════════════════════════════════════════════════%b\n\n" "$YELLOW" "$NC"
}

# ----------------------------- Logging ---------------------------------
log()   { printf "%b[+]%b %s\n" "$GREEN" "$NC" "$*" | tee -a "$LOG_FILE"; }
warn()  { printf "%b[!]%b %s\n" "$YELLOW" "$NC" "$*" | tee -a "$LOG_FILE"; }
err()   { printf "%b[-]%b %s\n" "$RED" "$NC" "$*" | tee -a "$LOG_FILE" >&2; }

die()   { err "$*"; exit 1; }

# --------------------------- Housekeeping ------------------------------
init_workspace() {
  mkdir -p "$TEMP_DIR" "$SRC_DIR"
  chmod 700 "$TEMP_DIR" 2>/dev/null || true
  : > "$ALL_PROXIES"
  : > "$WORKING_PROXIES"
  : > "$CHECKED_PROXIES"
  : > "$LOG_FILE"
}

ensure_workspace() { mkdir -p "$TEMP_DIR" "$SRC_DIR"; chmod 700 "$TEMP_DIR" 2>/dev/null || true; : > "$LOG_FILE"; }

cleanup() {
  # Ensure no stray jobs remain
  local pids
  pids=$(jobs -rp 2>/dev/null || true)
  if [[ -n "${pids:-}" ]]; then
    kill $pids 2>/dev/null || true
    wait $pids 2>/dev/null || true
  fi
}
trap cleanup EXIT

# --------------------------- Helper Utils ------------------------------
has_command() { command -v "$1" >/dev/null 2>&1; }

is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }

# Ensure required external commands are present
require_dependencies() {
  local missing=()
  local cmd
  for cmd in curl grep awk sort nl tee wc tr sed; do
    if ! has_command "$cmd"; then missing+=("$cmd"); fi
  done
  if (( ${#missing[@]} > 0 )); then
    die "Missing required commands: ${missing[*]}"
  fi
}

require_root_or_sudo() {
  if is_root; then return 0; fi
  if has_command sudo; then return 0; fi
  die "This operation requires root or sudo."
}

sudo_wrap() {
  if is_root; then "$@"; else sudo "$@"; fi
}

resolve_conf_file() {
  if [[ -z "$CONF_FILE" ]]; then
    if [[ -f "$DEFAULT_CONF4" ]]; then CONF_FILE="$DEFAULT_CONF4";
    elif [[ -f "$DEFAULT_CONF3" ]]; then CONF_FILE="$DEFAULT_CONF3";
    else die "No proxychains config found at $DEFAULT_CONF4 or $DEFAULT_CONF3"; fi
  fi
}

# ------------------------- Sources (Providers) -------------------------
PROXY_SOURCES=(
  "free-proxy-list.net|https://free-proxy-list.net/"
  "sslproxies.org|https://www.sslproxies.org/"
  "proxy-list.download HTTP|https://www.proxy-list.download/api/v1/get?type=http"
  "proxy-list.download HTTPS|https://www.proxy-list.download/api/v1/get?type=https"
  "proxy-list.download SOCKS4|https://www.proxy-list.download/api/v1/get?type=socks4"
  "proxy-list.download SOCKS5|https://www.proxy-list.download/api/v1/get?type=socks5"
  "proxyscrape HTTP|https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
  "proxyscrape SOCKS4|https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all"
  "proxyscrape SOCKS5|https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all"
  "TheSpeedX HTTP|https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
  "TheSpeedX SOCKS4|https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"
  "TheSpeedX SOCKS5|https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
  "ShiftyTR HTTP|https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"
  "ShiftyTR HTTPS|https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt"
  "ShiftyTR SOCKS4|https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt"
  "ShiftyTR SOCKS5|https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"
  "jetkai HTTP|https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"
  "jetkai HTTPS|https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt"
  "jetkai SOCKS4|https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt"
  "jetkai SOCKS5|https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"
)

# ------------------------- Fetching (Parallel) -------------------------
fetch_one_source() {
  local name="$1"; local url="$2"; local out_file="$SRC_DIR/${name// /_}.txt"
  curl -fsSL "$url" \
    | grep -E -o '[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}' \
    | awk 'length($0) > 0' \
    | sort -u >"$out_file" 2>>"$LOG_FILE" || true
}

limit_jobs() {
  # Limit concurrent background jobs to MAX_JOBS
  local current one
  while :; do
    current=$(jobs -rp 2>/dev/null | wc -l | tr -d ' ')
    if (( current < MAX_JOBS )); then break; fi
    if wait -n 2>/dev/null; then
      :
    else
      one=$(jobs -rp 2>/dev/null | head -n 1)
      if [[ -n "${one:-}" ]]; then
        wait "$one" 2>/dev/null || true
      else
        sleep 0.2
      fi
    fi
  done
}

fetch_proxies_parallel() {
  ensure_workspace
  mkdir -p "$SRC_DIR"
  : > "$ALL_PROXIES"

  log "Gathering proxies from multiple sources (parallel)..."

  local entry name url
  for entry in "${PROXY_SOURCES[@]}"; do
    name=${entry%%|*}
    url=${entry#*|}
    limit_jobs
    fetch_one_source "$name" "$url" &
  done
  wait || true

  # Merge and de-duplicate
  cat "$SRC_DIR"/*.txt 2>/dev/null | \
    grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$' | \
    sort -u > "$ALL_PROXIES" || :

  local count=0
  if [[ -s "$ALL_PROXIES" ]]; then count=$(wc -l < "$ALL_PROXIES"); fi
  log "Found $count unique proxies"
}

# ----------------------- Checking (Parallel) ---------------------------
try_types_in_order() {
  local ip_port="$1"
  IFS=',' read -r -a types <<<"$TRY_ORDER"
  local t
  for t in "${types[@]}"; do
    if curl --silent --fail \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$TOTAL_TIMEOUT" \
        --proxy "$t://$ip_port" \
        "http://ifconfig.me" >/dev/null 2>>"$LOG_FILE"; then
      printf "%s %s\n" "$t" "$ip_port"
      return 0
    fi
  done
  return 1
}

check_one_proxy() {
  local ip_port="$1"
  if result=$(try_types_in_order "$ip_port"); then
    printf "%s\n" "$result" >> "$WORKING_PROXIES"
    printf "%s\n" "$result" >> "$CHECKED_PROXIES"  # record as checked as well
    log "Working proxy: $result"
  else
    printf "%s\n" "fail $ip_port" >> "$CHECKED_PROXIES"
  fi
}

progress_monitor() {
  local total="$1"
  while :; do
    local done_cnt=0
    if [[ -f "$CHECKED_PROXIES" ]]; then done_cnt=$(wc -l < "$CHECKED_PROXIES"); fi
    printf "\r%b[*]%b Checking proxies: %d/%d" "$YELLOW" "$NC" "$done_cnt" "$total"
    if (( done_cnt >= total )); then
      printf "\n"
      break
    fi
    sleep 1
  done
}

check_all_proxies_parallel() {
  ensure_workspace
  if [[ ! -s "$ALL_PROXIES" ]]; then
    err "No proxies found. Fetch proxies first."
    return 1
  fi
  : > "$WORKING_PROXIES"
  : > "$CHECKED_PROXIES"

  local total
  total=$(wc -l < "$ALL_PROXIES")
  log "Checking $total proxies (parallel, up to $MAX_JOBS jobs)..."

  progress_monitor "$total" &
  local monitor_pid=$!

  while IFS= read -r ip_port; do
    limit_jobs
    check_one_proxy "$ip_port" &
  done < "$ALL_PROXIES"

  wait || true
  wait "$monitor_pid" 2>/dev/null || true

  local working=0
  if [[ -s "$WORKING_PROXIES" ]]; then working=$(wc -l < "$WORKING_PROXIES"); fi
  log "Proxy checking completed. Working: $working / $total"
}

# --------------------------- Config Update -----------------------------
backup_config() {
  resolve_conf_file
  require_root_or_sudo
  if [[ -f "$CONF_FILE" ]]; then
    sudo_wrap cp -f "$CONF_FILE" "$CONF_FILE.bak"
    warn "Configuration backed up to $CONF_FILE.bak"
  else
    die "ProxyChains config not found at $CONF_FILE"
  fi
}

update_config_safely() {
  resolve_conf_file
  require_root_or_sudo

  log "Updating $CONF_FILE with working proxies"

  local temp_conf="$TEMP_DIR/proxychains.temp"
  : > "$temp_conf"

  # Header: everything before [ProxyList]
  awk '/^\[ProxyList\]/{exit} {print}' "$CONF_FILE" > "$temp_conf" || true
  printf "\n[ProxyList]\n" >> "$temp_conf"

  if [[ -s "$WORKING_PROXIES" ]]; then
    # Convert "type ip:port" -> "type ip port" for ProxyChains config
    awk '{
      split($2, a, ":");
      if (length(a)==2) {
        printf "%s %s %s\n", $1, a[1], a[2]
      }
    }' "$WORKING_PROXIES" | sort -u >> "$temp_conf"
    log "Added $(wc -l < "$WORKING_PROXIES") working proxies"
  else
    warn "No working proxies to add"
    printf "# No working proxies available\n" >> "$temp_conf"
  fi

  sudo_wrap mv "$temp_conf" "$CONF_FILE"
  sudo_wrap chmod 0644 "$CONF_FILE"
  log "Config file updated"
}

# --------------------------- Display / Stats ---------------------------
show_stats() {
  local total=0 working=0 checked=0
  [[ -s "$ALL_PROXIES" ]] && total=$(wc -l < "$ALL_PROXIES")
  [[ -s "$WORKING_PROXIES" ]] && working=$(wc -l < "$WORKING_PROXIES")
  [[ -s "$CHECKED_PROXIES" ]] && checked=$(wc -l < "$CHECKED_PROXIES")

  printf "%b════════════════════════════════════════════════════════════════%b\n" "$YELLOW" "$NC"
  printf "%b Proxy Statistics:%b\n" "$GREEN" "$NC"
  printf "%b════════════════════════════════════════════════════════════════%b\n" "$YELLOW" "$NC"
  printf "%bTotal Proxies Found:%b %d\n" "$BLUE" "$NC" "$total"
  printf "%bWorking Proxies:%b %d\n" "$GREEN" "$NC" "$working"
  printf "%bFailed Proxies:%b %d\n" "$RED" "$NC" $(( checked>working ? checked-working : 0 ))
  printf "%b════════════════════════════════════════════════════════════════%b\n\n" "$YELLOW" "$NC"
}

view_file_with_numbers() { local f="$1"; if [[ -s "$f" ]]; then nl -ba "$f"; else warn "File empty: $f"; fi }

clean_workspace() { rm -rf "$TEMP_DIR" && log "Workspace cleaned"; }

# ------------------------------- Menu ----------------------------------
main_menu() {
  while :; do
    show_banner
    require_dependencies
    show_stats

    printf "%bMain Menu:%b\n" "$CYAN" "$NC"
    printf "1) Fetch Fresh Proxies (parallel)\n"
    printf "2) Check All Proxies (parallel)\n"
    printf "3) Update ProxyChains Config\n"
    printf "4) View Working Proxies\n"
    printf "5) View All Proxies\n"
    printf "6) View Log\n"
    printf "7) Clean Workspace\n"
    printf "8) Exit\n\n"

    read -r -p "Select an option [1-8]: " choice || true
    case "${choice:-}" in
      1)
        init_workspace
        fetch_proxies_parallel
        read -r -p "Press Enter to continue..." _ ;;
      2)
        ensure_workspace
        if [[ ! -s "$ALL_PROXIES" ]]; then err "No proxies found. Fetch first."; sleep 1; continue; fi
        : > "$WORKING_PROXIES"; : > "$CHECKED_PROXIES"
        check_all_proxies_parallel
        read -r -p "Press Enter to continue..." _ ;;
      3)
        if [[ ! -s "$WORKING_PROXIES" ]]; then err "No working proxies. Check first."; sleep 1; continue; fi
        backup_config
        update_config_safely
        read -r -p "Press Enter to continue..." _ ;;
      4)
        view_file_with_numbers "$WORKING_PROXIES"
        read -r -p "Press Enter to continue..." _ ;;
      5)
        view_file_with_numbers "$ALL_PROXIES"
        read -r -p "Press Enter to continue..." _ ;;
      6)
        if [[ -s "$LOG_FILE" ]]; then cat "$LOG_FILE"; else warn "Log is empty"; fi
        read -r -p "Press Enter to continue..." _ ;;
      7)
        clean_workspace; sleep 1 ;;
      8)
        warn "Exiting RedChains"
        exit 0 ;;
      *)
        warn "Invalid option"; sleep 1 ;;
    esac
  done
}

# ---------------------------- CLI Arguments ----------------------------
usage() {
  cat <<USAGE
RedChains — Ultimate ProxyChains Manager

Usage: ./RedChains.sh [options]

Options:
  --fetch                 Fetch fresh proxies in parallel
  --check                 Check all proxies in parallel
  --update                Update proxychains config with working proxies
  --stats                 Show statistics
  --view-working          Print working proxies
  --view-all              Print all proxies
  --view-log              Print log output
  --clean                 Remove workspace temp files
  --menu                  Launch interactive menu (default)

Tuning (env vars):
  MAX_JOBS                Max parallel jobs (default: $MAX_JOBS)
  CONNECT_TIMEOUT         Seconds per connection attempt (default: $CONNECT_TIMEOUT)
  TOTAL_TIMEOUT           Max seconds per curl (default: $TOTAL_TIMEOUT)
  TRY_ORDER               Try order of proxy types (default: $TRY_ORDER)
USAGE
}

run_cli() {
  require_dependencies
  ensure_workspace
  if [[ $# -eq 0 ]]; then main_menu; return; fi

  local did=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fetch) init_workspace; fetch_proxies_parallel; did=1 ;;
      --check) check_all_proxies_parallel; did=1 ;;
      --update) backup_config; update_config_safely; did=1 ;;
      --stats) show_stats; did=1 ;;
      --view-working) view_file_with_numbers "$WORKING_PROXIES"; did=1 ;;
      --view-all) view_file_with_numbers "$ALL_PROXIES"; did=1 ;;
      --view-log) if [[ -s "$LOG_FILE" ]]; then cat "$LOG_FILE"; else warn "Log is empty"; fi; did=1 ;;
      --clean) clean_workspace; did=1 ;;
      --menu) main_menu; return ;;
      -h|--help) usage; return ;;
      *) err "Unknown option: $1"; usage; return 1 ;;
    esac
    shift
  done

  if [[ "$did" -eq 0 ]]; then main_menu; fi
}

# ------------------------------- Start ---------------------------------
run_cli "$@"
