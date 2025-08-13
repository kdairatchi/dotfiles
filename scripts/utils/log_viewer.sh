#!/usr/bin/env bash

set -euo pipefail

# Simple interactive log viewer for Bug Bounty Toolkit
# Shows menu logs, recon logs, and supports filtering and tailing

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UTILS_DIR="$SCRIPT_DIR"
RECON_DIR="$REPO_ROOT/scripts/recon"

MENU_LOG="$UTILS_DIR/bug_bounty.log"
RECON_LOG_DIR="$RECON_DIR/logs"

log_info(){ printf "${GREEN}[info]${NC} %s\n" "$*"; }
log_warn(){ printf "${YELLOW}[warn]${NC} %s\n" "$*"; }
log_err(){ printf "${RED}[error]${NC} %s\n" "$*"; }

has_cmd(){ command -v "$1" >/dev/null 2>&1; }

ensure_deps(){
  local missing=()
  for c in less tail awk sed; do
    has_cmd "$c" || missing+=("$c")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    log_warn "Missing tools: ${missing[*]}. The viewer will have limited features."
  fi
}

choose_file(){
  local files=("$@")
  local count=${#files[@]}
  if [ "$count" -eq 0 ]; then
    log_warn "No log files found"
    return 1
  fi
  if [ "$count" -eq 1 ]; then
    printf "%s\n" "${files[0]}"
    return 0
  fi
  echo -e "${CYAN}Select a log file:${NC}"
  local i=1
  for f in "${files[@]}"; do
    printf "%2d) %s\n" "$i" "$(basename "$f")"
    i=$((i+1))
  done
  read -rp "Enter number: " n
  if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$count" ]; then
    printf "%s\n" "${files[$((n-1))]}"
    return 0
  fi
  log_warn "Invalid selection"
  return 1
}

view_with_filter(){
  local file="$1"
  [ -f "$file" ] || { log_err "File not found: $file"; return 1; }
  echo -e "${CYAN}Filter options:${NC}"
  echo "1) No filter (view full file)"
  echo "2) Filter by keyword"
  echo "3) Show only errors"
  echo "4) Tail -f"
  read -rp "Choice: " choice
  case "$choice" in
    1)
      if has_cmd less; then less -R "$file"; else cat "$file"; fi
      ;;
    2)
      read -rp "Enter keyword (regex supported if rg available): " kw
      if [ -z "${kw:-}" ]; then log_warn "Empty keyword"; return 0; fi
      if has_cmd rg; then rg -n --color=always "$kw" "$file" | (has_cmd less && less -R || cat); else
        grep -n --color=auto "$kw" "$file" | (has_cmd less && less -R || cat) || true
      fi
      ;;
    3)
      if has_cmd rg; then rg -n --color=always "(ERROR|\[ERROR\]|\[✗\])" "$file" | (has_cmd less && less -R || cat) || true
      else
        grep -nE "(ERROR|\[ERROR\]|\[✗\])" "$file" | (has_cmd less && less -R || cat) || true
      fi
      ;;
    4)
      tail -n 200 -f "$file"
      ;;
    *)
      log_warn "Unknown option"
      ;;
  esac
}

main_menu(){
  ensure_deps
  while :; do
    echo -e "\n${WHITE}=== Log Viewer ===${NC}"
    echo "1) View toolkit menu log ($MENU_LOG)"
    echo "2) View latest recon log"
    echo "3) Choose recon log file"
    echo "4) Search across logs"
    echo "0) Exit"
    read -rp "Select: " sel
    case "$sel" in
      1)
        if [ -f "$MENU_LOG" ]; then view_with_filter "$MENU_LOG"; else log_warn "No menu log found at $MENU_LOG"; fi
        ;;
      2)
        if [ -d "$RECON_LOG_DIR" ]; then
          # shellcheck disable=SC2012
          local latest
          latest=$(ls -1t "$RECON_LOG_DIR" 2>/dev/null | head -n1 || true)
          if [ -n "${latest:-}" ] && [ -f "$RECON_LOG_DIR/$latest" ]; then
            view_with_filter "$RECON_LOG_DIR/$latest"
          else
            log_warn "No recon logs found in $RECON_LOG_DIR"
          fi
        else
          log_warn "Recon log directory not found: $RECON_LOG_DIR"
        fi
        ;;
      3)
        if [ -d "$RECON_LOG_DIR" ]; then
          mapfile -t files < <(find "$RECON_LOG_DIR" -type f -maxdepth 1 -printf "%T@ %p\n" 2>/dev/null | sort -nr | awk '{ $1=""; sub(/^ /, ""); print }')
          sel_file=$(choose_file "${files[@]:-}") || continue
          view_with_filter "$sel_file"
        else
          log_warn "Recon log directory not found: $RECON_LOG_DIR"
        fi
        ;;
      4)
        read -rp "Enter search term (regex supported if rg): " term
        [ -z "${term:-}" ] && { log_warn "Empty term"; continue; }
        declare -a search_targets
        [ -f "$MENU_LOG" ] && search_targets+=("$MENU_LOG")
        if [ -d "$RECON_LOG_DIR" ]; then
          while IFS= read -r -d '' f; do search_targets+=("$f"); done < <(find "$RECON_LOG_DIR" -type f -print0 2>/dev/null)
        fi
        if [ ${#search_targets[@]} -eq 0 ]; then log_warn "No logs to search"; continue; fi
        echo -e "${CYAN}Search results:${NC}"
        if has_cmd rg; then
          rg -n --color=always "$term" "${search_targets[@]}" | (has_cmd less && less -R || cat) || true
        else
          grep -Rni --color=auto "$term" "${search_targets[@]}" | (has_cmd less && less -R || cat) || true
        fi
        ;;
      0)
        exit 0
        ;;
      *)
        log_warn "Invalid selection"
        ;;
    esac
  done
}

main_menu "$@"
