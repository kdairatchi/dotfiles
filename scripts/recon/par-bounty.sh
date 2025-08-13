#!/usr/bin/env bash
# par-bounty.sh — Parallel bug bounty launcher (GNU parallel powered)
# deps: parallel, curl, jq (some tools), plus your listed tools

set -Eeuo pipefail

# ---------- Config (edit if paths differ) ----------
JSFINDER='python3 /home/kali/tools/JSFinder/jsfinder.py'
XSSTRIKE='python3 /home/kali/tools/XSStrike/xsstrike.py'
RUSTSCAN='/home/kali/tools/RustScan/target/release/rustscan'
WAYBACKURLS='waybackurls'               # assumes in $PATH
NUCLEI='nuclei'                         # assumes in $PATH
HTTPX='httpx'                           # assumes in $PATH
GF='gf'                                 # assumes in $PATH

THREADS="${THREADS:-8}"
OUTDIR="${OUTDIR:-$PWD/par_out}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari}"

# ---------- UI helpers ----------
b() { printf "\e[1m%s\e[0m" "$*"; }
g() { printf "\e[32m%s\e[0m" "$*"; }
r() { printf "\e[31m%s\e[0m" "$*"; }
y() { printf "\e[33m%s\e[0m" "$*"; }
line(){ printf '─%.0s' $(seq 1 64); echo; }
pause(){ read -rp "$(printf '\e[2mPress Enter…\e[0m')" _; }
ensure_dir(){ mkdir -p "$OUTDIR"; }

need() { command -v "$1" >/dev/null 2>&1 || { r "Missing cmd: $1\n"; exit 1; }; }
need parallel

header() {
  clear; echo
  printf "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
  printf "┃  %s  ┃\n" "$(b 'Parallel Bug Bounty Launcher')"
  printf "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n"
  printf "%s Threads: %s   Out: %s\n" "$(b 'Config →')" "$(g "$THREADS")" "$(g "$OUTDIR")"
  line
}

ask_file()   { read -rp "Path to file list: " F; [[ -s "$F" ]] || { r "File not found or empty.\n"; return 1; }; echo "$F"; }
ask_pattern(){ read -rp "GF pattern (e.g., xss,sqli,ssrf): " P; [[ -n "$P" ]] || { r "Pattern required.\n"; return 1; }; echo "$P"; }
ask_ports()  { read -rp "Ports (default 1-65535): " P; echo "${P:-1-65535}"; }
ask_threads(){ read -rp "Threads [$THREADS]: " T; THREADS="${T:-$THREADS}"; }
ask_outdir() { read -rp "Output dir [$OUTDIR]: " D; OUTDIR="${D:-$OUTDIR}"; ensure_dir; }
ask_ua()     { read -rp "User-Agent [$UA]: " U; UA="${U:-$UA}"; }

# ---------- Core runners ----------
run_parallel() {
  local desc="$1" cmd="$2" filespec="$3"
  ensure_dir
  echo -e "$(b "Task:") $desc"
  echo -e "$(b "Cmd :") $cmd"
  echo
  if [[ "$filespec" == "stdin" ]]; then
    parallel -j"$THREADS" "$cmd"
  else
    parallel -j"$THREADS" "$cmd" :::: "$filespec"
  fi
}

# 1) HTTPX (status/title/tech) on URLs file
do_httpx() {
  need "$HTTPX"
  local file; file="$(ask_file)" || return
  run_parallel "httpx on ${file}" \
    "echo {} | $HTTPX -title -status-code -tech-detect -H 'User-Agent: $UA' | tee -a '$OUTDIR/httpx.out'" \
    "$file"
}

# 2) Nuclei on URLs file
do_nuclei() {
  need "$NUCLEI"
  local file; file="$(ask_file)" || return
  run_parallel "nuclei on ${file}" \
    "$NUCLEI -u {} -silent -H 'User-Agent: $UA' | tee -a '$OUTDIR/nuclei.findings.txt'" \
    "$file"
}

# 3) Waybackurls on domains file
do_wayback() {
  need "$WAYBACKURLS"
  local file; file="$(ask_file)" || return
  run_parallel "waybackurls on ${file}" \
    "echo {} && $WAYBACKURLS {} | tee '$OUTDIR/{}.wayback.txt' >/dev/null" \
    "$file"
}

# 4) GF pattern(s) on URLs file
do_gf() {
  need "$GF"
  local pat; pat="$(ask_pattern)" || return
  local file; file="$(ask_file)" || return
  run_parallel "gf:$pat on ${file}" \
    "$GF '$pat' < {} | tee '$OUTDIR/{}.${pat}.txt' >/dev/null" \
    "$file"
}

# 5) JSFinder on URLs file
do_jsfinder() {
  [[ -x "$(command -v python3)" ]] || { r "Missing python3\n"; return 1; }
  local file; file="$(ask_file)" || return
  run_parallel "JSFinder on ${file}" \
    "$JSFINDER -u {} -d | tee -a '$OUTDIR/jsfinder.out'" \
    "$file"
}

# 6) XSStrike on URLs file (crawl)
do_xsstrike() {
  [[ -x "$(command -v python3)" ]] || { r "Missing python3\n"; return 1; }
  local file; file="$(ask_file)" || return
  run_parallel "XSStrike on ${file}" \
    "$XSSTRIKE -u {} --crawl --skip-poc | tee -a '$OUTDIR/xsstrike.out'" \
    "$file"
}

# 7) RustScan on hosts file
do_rustscan() {
  [[ -x "$RUSTSCAN" ]] || { r "RustScan not found at $RUSTSCAN\n"; return 1; }
  local file; file="$(ask_file)" || return
  local ports; ports="$(ask_ports)"
  run_parallel "RustScan ${ports} on ${file}" \
    "$RUSTSCAN -a {} -r $ports | tee -a '$OUTDIR/rustscan.out'" \
    "$file"
}

# 8) Link checker (HTTP status) on URLs file — lightweight
do_linkcheck() {
  need curl
  local file; file="$(ask_file)" || return
  run_parallel "LinkCheck on ${file}" \
    "code=\$(curl -sIL -o /dev/null -w '%{http_code}' --max-time 10 -A '$UA' {} || echo 000); echo \"[\$code] {}\" | tee -a '$OUTDIR/linkcheck.out'" \
    "$file"
}

# 9) Pipeline: wayback → unique → httpx → nuclei (quick and dirty)
do_pipeline_fast() {
  need "$WAYBACKURLS"; need "$HTTPX"; need "$NUCLEI"
  local domain; read -rp "Root domain (e.g., example.com): " domain
  [[ -n "$domain" ]] || { r "Domain required.\n"; return 1; }
  ensure_dir
  echo -e "$(b 'Step 1: wayback…')"
  $WAYBACKURLS "$domain" | sort -u > "$OUTDIR/${domain}.wb.txt"
  echo -e "$(b 'Step 2: httpx…')"
  cat "$OUTDIR/${domain}.wb.txt" | parallel -j"$THREADS" "echo {} | $HTTPX -title -status-code -tech-detect -H 'User-Agent: $UA'" \
    > "$OUTDIR/${domain}.alive.txt"
  echo -e "$(b 'Step 3: nuclei…')"
  cut -d' ' -f1 "$OUTDIR/${domain}.alive.txt" | sed 's/^\[.*\]//' | sed 's/^https\?:\/\/\S\+/\0/' | grep -Eo 'https?://[^ ]+' \
    | sort -u | parallel -j"$THREADS" "$NUCLEI -u {} -silent -H 'User-Agent: $UA'" \
    | tee "$OUTDIR/${domain}.nuclei.txt"
  g "Pipeline complete → $OUTDIR/${domain}.{wb,alive,nuclei}.txt\n"
}

# ---------- Settings menu ----------
menu_settings() {
  header
  echo "1) Threads ($THREADS)"
  echo "2) Output dir ($OUTDIR)"
  echo "3) User-Agent"
  echo "4) Back"
  line
  read -rp "Select: " s
  case "$s" in
    1) ask_threads; ;;
    2) ask_outdir; ;;
    3) ask_ua; ;;
    *) ;;
  esac
}

# ---------- Main menu ----------
while true; do
  header
  echo "  $(b 'Targets from file (one per line)')"
  echo "  1) httpx (title/status/tech)"
  echo "  2) nuclei (per-URL)"
  echo "  3) waybackurls (per-domain)"
  echo "  4) gf (pattern match)"
  echo "  5) JSFinder (URLs)"
  echo "  6) XSStrike (URLs)"
  echo "  7) RustScan (hosts)"
  echo "  8) Link check (URLs)"
  echo
  echo "  $(b 'Pipelines')"
  echo "  9) wayback → httpx → nuclei (quick)"
  echo
  echo "  $(b 'Settings')"
  echo "  s) Threads / Output / UA"
  echo "  q) Quit"
  line
  read -rp "Select: " ch
  echo; line
  case "${ch:-}" in
    1) do_httpx ;;
    2) do_nuclei ;;
    3) do_wayback ;;
    4) do_gf ;;
    5) do_jsfinder ;;
    6) do_xsstrike ;;
    7) do_rustscan ;;
    8) do_linkcheck ;;
    9) do_pipeline_fast ;;
    s|S) menu_settings ;;
    q|Q) echo; g "Bye 👋"; exit 0 ;;
    *) r "Invalid choice\n" ;;
  esac
  echo; line; pause
done
