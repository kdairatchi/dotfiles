#!/usr/bin/env bash
# sqry-wrapper.sh — SQRY WRAPPER MENU TOOL (free-API OSINT + search helper)
# by @you — v1.6
# Deps (core): bash 4+, curl, jq, python3
# Optional: htmlq (or lynx), fzf, parallel, httpx, nuclei, nmap, waybackurls

set -Eeuo pipefail

VERSION="1.6"
ROOT="${ROOT:-$PWD}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTBASE="${OUTBASE:-$ROOT/results}"
OUTDIR="$OUTBASE/$STAMP"
mkdir -p "$OUTDIR"

# ---------- COLORS ----------
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'

# ---------- CONFIG ----------
UA=${UA:-"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari"}
THREADS=${THREADS:-8}
TIMEOUT=${TIMEOUT:-12}
LIMIT=${LIMIT:-100}

# Paths to tools (edit if needed)
WAYBACKURLS_BIN="${WAYBACKURLS_BIN:-$(command -v waybackurls || true)}"
HTTPX_BIN="${HTTPX_BIN:-$(command -v httpx || true)}"
NUCLEI_BIN="${NUCLEI_BIN:-$(command -v nuclei || true)}"
PARALLEL_BIN="${PARALLEL_BIN:-$(command -v parallel || true)}"
FZF_BIN="${FZF_BIN:-$(command -v fzf || true)}"
HTMLQ_BIN="${HTMLQ_BIN:-$(command -v htmlq || true)}"
LYNX_BIN="${LYNX_BIN:-$(command -v lynx || true)}"
NMAP_BIN="${NMAP_BIN:-$(command -v nmap || true)}"

# ---------- UTIL ----------
say() { printf "%s\n" "$*"; }
info() { printf "${CYAN}[i]${NC} %s\n" "$*"; }
ok() { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err() { printf "${RED}[-]${NC} %s\n" "$*"; }
pause() { read -rp "${DIM}Press Enter…${NC} " _; }

# Respect user alias/functions for jq by deferring resolution until exec time.
# If $JQ is set in environment or sourced from zshrc, use it; else fallback to command -v jq.
JQ_BIN="${JQ:-jq}"
JQ_OPTS="${JQ_OPTS:-}"

# Choose a file from OUTDIR (fallback to read if no fzf)
pick_file() {
  local prompt="${1:-Pick a file}"; local sel=""
  if [[ -n "$FZF_BIN" ]]; then
    sel="$(find "$OUTBASE" -maxdepth 2 -type f 2>/dev/null | sort | "$FZF_BIN" --prompt "$prompt> " || true)"
  else
    say "Files under $OUTBASE:"; find "$OUTBASE" -maxdepth 2 -type f | nl
    read -rp "$prompt (paste path): " sel
  fi
  [[ -n "$sel" ]] && printf "%s" "$sel" || return 1
}

# Extract public IPs from any text
only_public_ips() {
  # Grep all IPv4s then drop RFC1918 + special ranges
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
  awk '
    function private(a,b,c,d){ return (a==10) || (a==192 && b==168) || (a==172 && b>=16 && b<=31) }
    function special(a){ return (a==0 || a==127 || a>=224) }
    {
      split($0, o, ".")
      a=o[1]; b=o[2]; c=o[3]; d=o[4]
      if (a<256 && b<256 && c<256 && d<256 && !private(a,b,c,d) && !special(a)) print $0
    }' | sort -u
}

# Extract hostnames/URLs quickly
only_urls() { grep -Eoi '\bhttps?://[^ >"'\''\)]+' | sort -u; }
only_domains() {
  grep -Eoi '\b([a-z0-9-]+\.)+[a-z]{2,}\b' | sed 's/^www\.//' | sort -u
}

# ---------- CORE: The free-API sqry collectors ----------
# Safe URL-encode helper using Python (no heredoc to avoid syntax issues)
urlenc() { python3 -c 'import sys, urllib.parse as u; print(u.quote(sys.argv[1]))' "$1"; }
# Robust emit: accept large JSON via stdin or temp files to avoid argv limits
emit() {
  local src="$1"; local data_json="$2"
  # When data_json is already JSON text, avoid --argjson on huge strings; stream via stdin
  printf '%s' "$data_json" | "$JQ_BIN" ${JQ_OPTS:-} -nc --arg src "$src" 'input | {source:$src,data:.}'
}

c_theorg() {
  local org="$1"; local u="https://theorg.com/org/$(urlenc "$org")"
  if [[ -n "$HTMLQ_BIN" ]]; then
    local html; html="$(curl -sL -A "$UA" "$u")" || html=""
    local title desc hq emp
    title="$(printf "%s" "$html" | htmlq -t 'h1' | head -n1 | tr -d '\r' || true)"
    desc="$(printf "%s" "$html" | htmlq -t 'main' | head -n5 | tr -d '\r' || true)"
    hq="$(printf "%s" "$html" | htmlq -t 'a[href*="/explore/countries/"]' | head -n1 || true)"
    emp="$(printf "%s" "$html" | htmlq -t 'a[href*="/explore/employee-ranges/"]' | head -n1 || true)"
    emit theorg "$("$JQ_BIN" ${JQ_OPTS:-} -nc --arg url "$u" --arg title "$title" --arg desc "$desc" --arg hq "$hq" --arg emp "$emp" \
      '{url:$url,title:$title,summary:$desc,headquarters:$hq,employees:$emp}')"
  elif [[ -n "$LYNX_BIN" ]]; then
    local dump; dump="$(curl -sL -A "$UA" "$u" | lynx -dump -stdin || true)"
    local hq emp
    hq="$(grep -m1 -E '^ *Headquarters' <<<"$dump" | sed 's/.*Headquarters *//; s/^[:] *//' || true)"
    emp="$(grep -m1 -E '^ *Employees' <<<"$dump" | sed 's/.*Employees *//; s/^[:] *//' || true)"
    emit theorg "$("$JQ_BIN" ${JQ_OPTS:-} -nc --arg url "$u" --arg dump "$dump" --arg hq "$hq" --arg emp "$emp" \
      '{url:$url,raw:$dump,headquarters:$hq,employees:$emp}')"
  else
    emit theorg "$("$JQ_BIN" ${JQ_OPTS:-} -nc --arg url "$u" '{url:$url,notice:"Install htmlq or lynx for page scrape"}')"
  fi
}

c_wiki() {
  local org="$1"; local e=$(urlenc "$org")
  local j=$(curl -sL -A "$UA" "https://en.wikipedia.org/api/rest_v1/page/summary/$e" || echo '{}')
  emit wiki "$j"
}

c_wikidata() {
  local org="$1"; local e=$(urlenc "$org")
  local j=$(curl -sL -A "$UA" "https://www.wikidata.org/w/api.php?action=wbsearchentities&search=$e&language=en&format=json" || echo '{}')
  emit wikidata "$j"
}

c_github() {
  local org="$1"
  local p=$(curl -sL -A "$UA" "https://api.github.com/orgs/$org" || echo '{}')
  local r=$(curl -sL -A "$UA" "https://api.github.com/orgs/$org/repos?per_page=$LIMIT&type=public" || echo '[]')
  # Build the combined object via streaming to avoid long argv and preserve aliases
  local combined
  combined=$(printf '%s\n%s' "$p" "$r" | "$JQ_BIN" -s 'if length==2 then {profile:.[0], repos:.[1]} else {profile:{}, repos:[] } end' 2>/dev/null || echo '{"profile":{},"repos":[]}')
  emit github "$combined"
}

c_crtsh() {
  local domain="$1"; [[ -z "$domain" ]] && { emit crtsh '[]'; return 0; }
  local q="%25${domain}%25"
  local j=$(curl -sL -A "$UA" "https://crt.sh/?q=$q&output=json" || echo '[]')
  local out=$("$JQ_BIN" ${JQ_OPTS:-} -c '
    ( [ .[]?.name_value ] | flatten | map(gsub("\\*\\."; "")) | unique )' <<<"$j" 2>/dev/null || echo '[]')
  emit crtsh "$out"
}

c_wayback() {
  local domain="$1"; [[ -z "$domain" ]] && { emit wayback '[]'; return 0; }
  local j=$(curl -sL -A "$UA" "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=$LIMIT" || echo '[]')
  local out=$("$JQ_BIN" ${JQ_OPTS:-} -c '
    if type=="array" and length>0 then
      (.[0] as $h | [.[1:][] | reduce range(0;length) as $i ({}; .[$h[$i]] = .[$i])])
    else [] end
  ' <<<"$j" 2>/dev/null || echo '[]')
  emit wayback "$out"
}

c_hn() {
  local org="$1"; local e=$(urlenc "$org")
  local j=$(curl -sL -A "$UA" "https://hn.algolia.com/api/v1/search?query=$e&tags=story&hitsPerPage=$LIMIT" || echo '{}')
  emit hn "$j"
}

# ---------- SIMPLE SEARCH WRAPPER ----------
# These mimic your menu items: "apache", "port:443", "org:\"Google LLC\"" etc.
sqry_simple() {
  local q="$1"
  # Free endpoints we can hit generically:
  # - ipinfo asn/org searches are limited; we’ll rely on publicweb (HN), wayback, GitHub code search is rate-limited.
  # For demo, we run: wayback query if q looks like domain; else HN; plus a GET to DuckDuckGo Lite (HTML scrape).
  if [[ "$q" =~ ^port:([0-9]+)$ ]]; then
    # No free Shodan; do best-effort by checking wayback urls containing :port
    local port="${BASH_REMATCH[1]}"
    [[ -n "$WAYBACKURLS_BIN" ]] || { err "waybackurls not found"; return 1; }
    info "Searching wayback for :$port"
    "$WAYBACKURLS_BIN" ":" | grep -E ":[[:digit:]]{1,5}" | grep -E ":$port" | sort -u
    return 0
  fi
  if [[ "$q" =~ ^org: ]]; then
    # If "org:\"Google LLC\"" try Wikipedia summary as a cheap org probe
    local org="${q#org:}"
    org="${org%\"}"; org="${org#\"}"
    c_wiki "$org" | "$JQ_BIN" ${JQ_OPTS:-} -r '.data.extract' || true
    return 0
  fi
  if [[ "$q" == "apache" ]]; then
    # DuckDuckGo lite search for server:apache fingerprints (very rough)
    curl -sL "https://duckduckgo.com/lite/?q=server%3Aapache" \
      | sed -nE 's/.*href="([^"]+)".*/\1/p' \
      | sed -E 's#^/l/?u=##; s/&.*$##' \
      | sort -u
    return 0
  fi
  # default: HN search
  curl -sL "https://hn.algolia.com/api/v1/search?query=$(urlenc "$q")&tags=story&hitsPerPage=$LIMIT" | "$JQ_BIN" ${JQ_OPTS:-} -r '.hits[]?.url' | sed '/^null$/d' | sort -u
}

# ---------- HIGH-LEVEL OPS ----------
op_org_osint() {
  read -rp "Org (e.g., Xiaomi): " ORG
  read -rp "Domain (e.g., xiaomi.com) [optional]: " DOMAIN || true
  info "Running free OSINT collectors…"
  {
    c_theorg "$ORG"
    c_wiki "$ORG"
    c_wikidata "$ORG"
    c_github "$ORG"
    c_crtsh "${DOMAIN:-}"
    c_wayback "${DOMAIN:-}"
    c_hn "$ORG"
  } | tee "$OUTDIR/${ORG// /_}.ndjson" > /dev/null
  ok "Saved → $OUTDIR/${ORG// /_}.ndjson"
  say "Quick glance (sources):"; "$JQ_BIN" ${JQ_OPTS:-} -r '.source' "$OUTDIR/${ORG// /_}.ndjson" | sort | uniq -c
}

op_search_query() {
  read -rp 'Enter search query (e.g., apache | port:443 | org:"Google LLC"): ' Q
  info "Running sqry-like simple search for: $Q"
  sqry_simple "$Q" | tee "$OUTDIR/query_$(echo "$Q" | tr ' :"/' '__').txt"
  ok "Saved → $OUTDIR/query_$(echo "$Q" | tr ' :"/' '__').txt"
}

op_filter_public_ips() {
  local f; f="$(pick_file 'Pick file to filter')" || { warn "No file chosen"; return; }
  info "Extracting public IPs from: $f"
  <"$f" only_public_ips | tee "$OUTDIR/public_ips.txt" > /dev/null
  ok "Saved → $OUTDIR/public_ips.txt"
  wc -l "$OUTDIR/public_ips.txt" | awk '{print "[count]", $1, "IPs"}'
}

op_httpx_probe() {
  [[ -n "$HTTPX_BIN" ]] || { err "httpx not found"; return 1; }
  local f; f="$(pick_file 'URLs file for httpx')" || { warn "No file chosen"; return; }
  info "Probing with httpx (threads=$THREADS)…"
  if [[ -n "$PARALLEL_BIN" ]]; then
    "$PARALLEL_BIN" -j"$THREADS" "echo {} | $HTTPX_BIN -title -status-code -tech-detect -H 'User-Agent: $UA'" :::: "$f" \
      | tee "$OUTDIR/httpx.out" > /dev/null
  else
    <"$f" xargs -I{} sh -c "echo {} | $HTTPX_BIN -title -status-code -tech-detect -H 'User-Agent: $UA'" \
      | tee "$OUTDIR/httpx.out" > /dev/null
  fi
  ok "Saved → $OUTDIR/httpx.out"
}

op_nuclei_scan() {
  [[ -n "$NUCLEI_BIN" ]] || { err "nuclei not found"; return 1; }
  local f; f="$(pick_file 'URLs file for nuclei')" || { warn "No file chosen"; return; }
  info "Running nuclei (threads=$THREADS)…"
  if [[ -n "$PARALLEL_BIN" ]]; then
    "$PARALLEL_BIN" -j"$THREADS" "$NUCLEI_BIN -u {} -silent -H 'User-Agent: $UA'" :::: "$f" \
      | tee "$OUTDIR/nuclei.findings.txt" > /dev/null
  else
    <"$f" xargs -I{} sh -c "$NUCLEI_BIN -u {} -silent -H 'User-Agent: $UA'" \
      | tee "$OUTDIR/nuclei.findings.txt" > /dev/null
  fi
  ok "Saved → $OUTDIR/nuclei.findings.txt"
}

op_wayback_collect() {
  [[ -n "$WAYBACKURLS_BIN" ]] || { err "waybackurls not found"; return 1; }
  read -rp "Root domain (e.g., xiaomi.com): " DOM
  info "Collecting wayback URLs for $DOM…"
  "$WAYBACKURLS_BIN" "$DOM" | sort -u | tee "$OUTDIR/${DOM}.wayback.txt" > /dev/null
  ok "Saved → $OUTDIR/${DOM}.wayback.txt"
}

op_simple_port_scan() {
  [[ -n "$NMAP_BIN" ]] || { err "nmap not found"; return 1; }
  local f; f="$(pick_file 'IPs file for nmap')" || { warn "No file chosen"; return; }
  read -rp "Ports (e.g., 1-1000, 22,80,443 or top-1000) [default top-1000]: " P
  P="${P:-top-1000}"
  info "nmap on $(basename "$f") ports=$P"
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    if [[ "$P" =~ ^top-[0-9]+$ ]]; then
      local topn="${P#top-}"
      $NMAP_BIN -Pn -T4 --max-retries 1 --host-timeout 30s --top-ports "$topn" "$ip" 2>/dev/null | tee -a "$OUTDIR/nmap.out" >/dev/null
    else
      $NMAP_BIN -Pn -T4 --max-retries 1 --host-timeout 30s -p "$P" "$ip" 2>/dev/null | tee -a "$OUTDIR/nmap.out" >/dev/null
    fi
  done < <(cat "$f" | only_public_ips)
  ok "Saved → $OUTDIR/nmap.out"
}

op_save_and_count() {
  read -rp "Enter free-text search: " Q
  local of="$OUTDIR/query_$(echo "$Q" | tr ' :"/' '__').txt"
  info "Running query and saving to $of"
  sqry_simple "$Q" | tee "$of" | wc -l | awk '{print "[count]", $1, "lines"}'
}

op_tech_search_from_github() {
  local url="https://raw.githubusercontent.com/s0md3v/Striker/master/db/technologies.txt"
  info "Fetching tech list…"
  local tmp="$OUTDIR/techlist.txt"
  curl -sL "$url" -o "$tmp"
  local tech=""
  if [[ -n "$FZF_BIN" ]]; then
    tech="$(cat "$tmp" | "$FZF_BIN" --prompt 'Pick tech> ' || true)"
  else
    say "Tech list saved to $tmp"; read -rp "Enter a technology string: " tech
  fi
  [[ -z "$tech" ]] && { warn "No selection"; return; }
  info "Searching for technology: $tech"
  sqry_simple "$tech" | tee "$OUTDIR/tech_${tech// /_}.txt" > /dev/null
  ok "Saved → $OUTDIR/tech_${tech// /_}.txt"
}

op_pipeline_quick() {
  # domain → wayback → httpx → nuclei
  [[ -n "$WAYBACKURLS_BIN" && -n "$HTTPX_BIN" && -n "$NUCLEI_BIN" ]] || { err "need waybackurls + httpx + nuclei"; return 1; }
  read -rp "Root domain (e.g., example.com): " DOM
  info "Step 1: wayback"
  "$WAYBACKURLS_BIN" "$DOM" | sort -u > "$OUTDIR/${DOM}.wb.txt"
  info "Step 2: httpx (threads=$THREADS)"
  if [[ -n "$PARALLEL_BIN" ]]; then
    "$PARALLEL_BIN" -j"$THREADS" "echo {} | $HTTPX_BIN -title -status-code -tech-detect -H 'User-Agent: $UA'" :::: "$OUTDIR/${DOM}.wb.txt" \
      | tee "$OUTDIR/${DOM}.alive.txt" > /dev/null
  else
    <"$OUTDIR/${DOM}.wb.txt" xargs -I{} sh -c "echo {} | $HTTPX_BIN -title -status-code -tech-detect -H 'User-Agent: $UA'" \
      | tee "$OUTDIR/${DOM}.alive.txt" > /dev/null
  fi
  info "Step 3: nuclei"
  grep -Eo 'https?://[^ ]+' "$OUTDIR/${DOM}.alive.txt" | sort -u \
    | ( [[ -n "$PARALLEL_BIN" ]] && "$PARALLEL_BIN" -j"$THREADS" "$NUCLEI_BIN -u {} -silent -H 'User-Agent: $UA'" \
        || xargs -I{} sh -c "$NUCLEI_BIN -u {} -silent -H 'User-Agent: $UA'") \
    | tee "$OUTDIR/${DOM}.nuclei.txt" > /dev/null
  ok "Artifacts → $OUTDIR/${DOM}.{wb,alive,nuclei}.txt"
}

op_export_csv_from_httpx() {
  local f; f="$(pick_file 'Pick httpx.out file')" || { warn "No file chosen"; return; }
  info "Exporting CSV from $(basename "$f")"
  # Expect lines like: https://site 200 [Title] [tech: a,b]
  awk '
    BEGIN{FS=" " ; OFS=","; print "url,status,title"}
    {
      url=$1; status="";
      for(i=2;i<=NF;i++){ if($i ~ /^\[[0-9]{3}\]$/){status=substr($i,2,3)} }
      # crude title extraction between brackets
      title="";
      match($0, /\[[^]]+\]/, m); if(m[0]!=""){ gsub(/\[|\]/,"",m[0]); title=m[0]; }
      print url,status,title
    }' "$f" > "$OUTDIR/httpx.csv"
  ok "Saved → $OUTDIR/httpx.csv"
}

op_settings() {
  say
  say "Current: THREADS=$THREADS  UA=$(printf '%s' "$UA" | cut -c1-40)...  OUTBASE=$OUTBASE"
  say "1) Threads"
  say "2) User-Agent"
  say "3) Output base dir"
  say "4) Back"
  read -rp "Select: " s
  case "${s:-}" in
    1) read -rp "Threads: " t; THREADS="${t:-$THREADS}" ;;
    2) read -rp "User-Agent: " u; UA="${u:-$UA}" ;;
    3) read -rp "Output base dir: " d; [[ -n "$d" ]] && OUTBASE="$d" && OUTDIR="$OUTBASE/$STAMP" && mkdir -p "$OUTDIR" ;;
    *) ;;
  esac
}

banner() {
  clear
  cat <<'BANNER'
███████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗
██╔════╝ ██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
███████╗ █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
╚════██║ ██╔══╝  ██║   ██║██╔═══╝   ╚██╔╝  
███████║ ███████╗╚██████╔╝██║        ██║   
╚══════╝ ╚══════╝ ╚═════╝ ╚═╝        ╚═╝   
BANNER
  printf "            ${GREEN}SQRY Wrapper v%s${NC}   out: %s\n\n" "$VERSION" "$OUTDIR"
}

main_menu() {
  while true; do
    banner
    say "1) Org OSINT (TheOrg/Wiki/Wikidata/GitHub/crt.sh/Wayback/HN)"
    say "2) Search (apache | port:443 | org:\"Name\")"
    say "3) Filter public IPs from a file"
    say "4) HTTPX probe (URLs → status/title/tech)"
    say "5) Nuclei scan (URLs)"
    say "6) Wayback collect (domain)"
    say "7) Nmap quick scan (IPs file)"
    say "8) Save & count (free-text search)"
    say "9) Tech search from GitHub list"
    say "10) Pipeline: wayback → httpx → nuclei"
    say "11) Export CSV from httpx.out"
    say "S) Settings"
    say "Q) Quit"
    echo
    read -rp "Choose: " opt
    case "${opt,,}" in
      1) op_org_osint; pause ;;
      2) op_search_query; pause ;;
      3) op_filter_public_ips; pause ;;
      4) op_httpx_probe; pause ;;
      5) op_nuclei_scan; pause ;;
      6) op_wayback_collect; pause ;;
      7) op_simple_port_scan; pause ;;
      8) op_save_and_count; pause ;;
      9) op_tech_search_from_github; pause ;;
      10) op_pipeline_quick; pause ;;
      11) op_export_csv_from_httpx; pause ;;
      s) op_settings ;;
      q) ok "Bye"; exit 0 ;;
      *) warn "Invalid"; sleep 0.8 ;;
    esac
  done
}

# ---------- Start ----------
main_menu
