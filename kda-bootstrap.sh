#!/usr/bin/env bash
# kda-bootstrap.sh — Kdairatchi portable alias/dev env installer
# Usage:
#   ./kda-bootstrap.sh --install [--yes] [--shell auto|bash|zsh] [--tool-root /path]
#                      [--nuclei-templates /path/to/templates] [--hostname NAME]
#   ./kda-bootstrap.sh --doctor
#   ./kda-bootstrap.sh --uninstall
set -euo pipefail

APP="kda-bootstrap"
KDA_HOME="${KDA_HOME:-$HOME/.kda}"
ALIAS_DIR="$KDA_HOME/aliases"
HOST_DIR="$ALIAS_DIR/host"
CONF="$KDA_HOME/config.env"
LOADER="$ALIAS_DIR/loader.sh"
CORE="$ALIAS_DIR/core.sh"
SHELL_CHOSEN="auto"
YES="${YES:-0}"
NUCLEI_TEMPLATES_ARG=""
TOOL_ROOT_ARG=""
HOSTNAME_ARG=""

# --- helpers -----------------------------------------------------------------
log(){ printf "\033[36m[%s]\033[0m %s\n" "$APP" "$*"; }
ok(){  printf "\033[32m[ok]\033[0m %s\n" "$*"; }
warn(){ printf "\033[33m[warn]\033[0m %s\n" "$*"; }
err(){ printf "\033[31m[err]\033[0m %s\n" "$*"; }
ask(){ local p="$1" d="${2:-}"; read -r -p "$p${d:+ [$d]}: " r; echo "${r:-$d}"; }
yn(){ local p="$1"; if [ "$YES" = "1" ]; then echo y; else read -r -p "$p [y/N]: " r; echo "${r:-N}"; fi; }

_detect_shell_env() {
  if [ -n "${ZSH_VERSION:-}" ] || [[ "${SHELL:-}" == *zsh ]]; then echo zsh; else echo bash; fi
}

detect_shell() {
  case "${SHELL_CHOSEN}" in
    bash|zsh) echo "$SHELL_CHOSEN" ;;
    auto) _detect_shell_env ;;
    *) echo bash ;;
  esac
}

os_family() {
  case "$(uname -s)" in
    Linux) echo linux;;
    Darwin) echo mac;;
    *) echo other;;
  esac
}

ensure_dirs(){
  mkdir -p "$ALIAS_DIR" "$HOST_DIR"
  [ -f "$CONF" ] || cat >"$CONF" <<'EOF'
# ~/.kda/config.env — global knobs
export J=${J:-10}                    # parallel jobs default
export GOPATH="${GOPATH:-$HOME/go}"  # go bin path
export PATH="$HOME/.local/bin:$GOPATH/bin:$PATH"
# Override these if needed (bootstrap will try to auto-detect):
# export JSFINDER_PATH="$HOME/tools/JSFinder/jsfinder.py"
# export XSSTRIKE_PATH="$HOME/tools/XSStrike/xsstrike.py"
# export RUSTSCAN_BIN="$HOME/tools/RustScan/target/release/rustscan"
# export LAZYXSS_PATH="$HOME/tools/Lazyxss/main.py"
# export EYEWITNESS_PATH="$HOME/tools/EyeWitness/Python/EyeWitness.py"
# export CORSY_PATH="$HOME/tools/Corsy/corsy.py"
# export GITDORKER_PATH="$HOME/tools/GitDorker/GitDorker.py"
# export GSEC_PATH="$HOME/tools/Gsec/gsec.py"
# export LOXS_PATH="$HOME/tools/loxs/loxs.py"
# export SPIDERFOOT_PATH="$HOME/tools/spiderfoot/sf.py"
# export UFX_PATH="$HOME/tools/UFX/ufx.py"
# export GOBUSTER_BIN="$HOME/tools/gobuster/gobuster"
# export SN1PER_BIN="$HOME/tools/Sn1per/sniper"
# export JSSFSCAN_BIN="$HOME/tools/JSFScan.sh"
# export NUCLEI_CUSTOM_TEMPLATES="$HOME/nuclei-templates/customs"
EOF
}

ensure_loader(){
  cat >"$LOADER" <<'EOF'
# ~/.kda/aliases/loader.sh — sources config + aliases + host overrides
[ -f "$HOME/.kda/config.env" ] && . "$HOME/.kda/config.env"
# core aliases
[ -f "$HOME/.kda/aliases/core.sh" ] && . "$HOME/.kda/aliases/core.sh"
# host overrides
HOSTF="$HOME/.kda/aliases/host/$(hostname -s 2>/dev/null || hostname).sh"
[ -f "$HOSTF" ] && . "$HOSTF"
EOF
  chmod +x "$LOADER"
}

ensure_rc(){
  local sh="$(detect_shell)"
  local rcfile
  if [ "$sh" = "zsh" ]; then rcfile="$HOME/.zshrc"; else rcfile="$HOME/.bashrc"; fi
  touch "$rcfile"
  if ! grep -q "# >>> KDAIRATCHI ALIASES >>>" "$rcfile"; then
    cp "$rcfile" "$rcfile.bak.$(date +%s)" || true
    {
      echo ""
      echo "# >>> KDAIRATCHI ALIASES >>>"
      echo "[ -f \"$LOADER\" ] && . \"$LOADER\""
      echo "# <<< KDAIRATCHI ALIASES <<<"
    } >> "$rcfile"
    ok "Wired loader into $(basename "$rcfile")"
  else
    log "Loader already wired in $(basename "$rcfile")"
  fi
}

_append_conf_if_missing(){ local key="$1"; local line="$2"; grep -q "${key}=" "$CONF" 2>/dev/null || echo "$line" >> "$CONF"; }

_guess_first(){ shift || true; for p in "$@"; do [ -e "$p" ] && { echo "$p"; return 0; }; done; return 1; }

_try_find_file(){ local name="$1"; find "$HOME" -maxdepth 6 -type f -name "$name" 2>/dev/null | head -n1 || true; }

_try_find_exec(){ local name="$1"; command -v "$name" 2>/dev/null || true; }

# Enhance tool-path detection to cover all your custom tools
detect_tool_paths(){
  # allow explicit overrides
  [ -n "$TOOL_ROOT_ARG" ] && _append_conf_if_missing TOOL_ROOT "export TOOL_ROOT=\"$TOOL_ROOT_ARG\""
  [ -n "$NUCLEI_TEMPLATES_ARG" ] && _append_conf_if_missing NUCLEI_CUSTOM_TEMPLATES "export NUCLEI_CUSTOM_TEMPLATES=\"$NUCLEI_TEMPLATES_ARG\""

  # JSFinder
  if ! grep -q 'JSFINDER_PATH=' "$CONF"; then
    local guess="$(_guess_first X "$HOME/tools/JSFinder/jsfinder.py" "/opt/JSFinder/jsfinder.py")"
    [ -z "${guess:-}" ] && guess="$(_try_find_file jsfinder.py)"
    [ -n "${guess:-}" ] && echo "export JSFINDER_PATH=\"$guess\"" >> "$CONF" || warn "JSFinder not found. Set JSFINDER_PATH in $CONF if you install it."
  fi
  # XSStrike
  if ! grep -q 'XSSTRIKE_PATH=' "$CONF"; then
    local g2="$(_guess_first X "$HOME/tools/XSStrike/xsstrike.py" "/opt/XSStrike/xsstrike.py")"
    [ -z "${g2:-}" ] && g2="$(_try_find_file xsstrike.py)"
    [ -n "${g2:-}" ] && echo "export XSSTRIKE_PATH=\"$g2\"" >> "$CONF" || warn "XSStrike not found. Set XSSTRIKE_PATH in $CONF."
  fi
  # RustScan
  if ! grep -q 'RUSTSCAN_BIN=' "$CONF"; then
    local g3="$(_try_find_exec rustscan)"; [ -z "${g3:-}" ] && g3="$(_guess_first X "$HOME/tools/RustScan/target/release/rustscan" "/opt/RustScan/target/release/rustscan")"
    [ -n "${g3:-}" ] && echo "export RUSTSCAN_BIN=\"$g3\"" >> "$CONF" || warn "RustScan not found. Set RUSTSCAN_BIN in $CONF."
  fi
  # Gobuster
  if ! grep -q 'GOBUSTER_BIN=' "$CONF"; then
    local g4="$(_try_find_exec gobuster)"; [ -z "${g4:-}" ] && g4="$(_guess_first X "$HOME/tools/gobuster/gobuster")"
    [ -n "${g4:-}" ] && echo "export GOBUSTER_BIN=\"$g4\"" >> "$CONF" || true
  fi
  # Sn1per
  if ! grep -q 'SN1PER_BIN=' "$CONF"; then
    local g5="$(_guess_first X "$HOME/tools/Sn1per/sniper" "/opt/Sn1per/sniper")"
    [ -n "${g5:-}" ] && echo "export SN1PER_BIN=\"$g5\"" >> "$CONF" || true
  fi
  # EyeWitness
  if ! grep -q 'EYEWITNESS_PATH=' "$CONF"; then
    local g6="$(_guess_first X "$HOME/tools/EyeWitness/Python/EyeWitness.py" "/opt/EyeWitness/Python/EyeWitness.py")"
    [ -n "${g6:-}" ] && echo "export EYEWITNESS_PATH=\"$g6\"" >> "$CONF" || true
  fi
  # Corsy
  if ! grep -q 'CORSY_PATH=' "$CONF"; then
    local g7="$(_guess_first X "$HOME/tools/Corsy/corsy.py" "/opt/Corsy/corsy.py")"
    [ -n "${g7:-}" ] && echo "export CORSY_PATH=\"$g7\"" >> "$CONF" || true
  fi
  # GitDorker
  if ! grep -q 'GITDORKER_PATH=' "$CONF"; then
    local g8="$(_guess_first X "$HOME/tools/GitDorker/GitDorker.py" "/opt/GitDorker/GitDorker.py")"
    [ -n "${g8:-}" ] && echo "export GITDORKER_PATH=\"$g8\"" >> "$CONF" || true
  fi
  # Gsec
  if ! grep -q 'GSEC_PATH=' "$CONF"; then
    local g9="$(_guess_first X "$HOME/tools/Gsec/gsec.py" "/opt/Gsec/gsec.py")"
    [ -n "${g9:-}" ] && echo "export GSEC_PATH=\"$g9\"" >> "$CONF" || true
  fi
  # loxs
  if ! grep -q 'LOXS_PATH=' "$CONF"; then
    local g10="$(_guess_first X "$HOME/tools/loxs/loxs.py" "/opt/loxs/loxs.py")"
    [ -n "${g10:-}" ] && echo "export LOXS_PATH=\"$g10\"" >> "$CONF" || true
  fi
  # SpiderFoot
  if ! grep -q 'SPIDERFOOT_PATH=' "$CONF"; then
    local g11="$(_guess_first X "$HOME/tools/spiderfoot/sf.py" "/opt/spiderfoot/sf.py")"
    [ -n "${g11:-}" ] && echo "export SPIDERFOOT_PATH=\"$g11\"" >> "$CONF" || true
  fi
  # UFX
  if ! grep -q 'UFX_PATH=' "$CONF"; then
    local g12="$(_guess_first X "$HOME/tools/UFX/ufx.py" "/opt/UFX/ufx.py")"
    [ -n "${g12:-}" ] && echo "export UFX_PATH=\"$g12\"" >> "$CONF" || true
  fi
  # LazyXSS
  if ! grep -q 'LAZYXSS_PATH=' "$CONF"; then
    local g13="$(_guess_first X "$HOME/tools/Lazyxss/main.py" "/opt/Lazyxss/main.py")"
    [ -n "${g13:-}" ] && echo "export LAZYXSS_PATH=\"$g13\"" >> "$CONF" || true
  fi
  # JSFScan.sh
  if ! grep -q 'JSSFSCAN_BIN=' "$CONF"; then
    local g14="$(_guess_first X "$HOME/tools/JSFScan.sh" "/opt/JSFScan.sh")"
    [ -n "${g14:-}" ] && echo "export JSSFSCAN_BIN=\"$g14\"" >> "$CONF" || true
  fi
  # domsink scripts
  if ! grep -q 'DOMSINK_PATH=' "$CONF"; then
    local g15="$(_try_find_file domsink_scanner.py)"; [ -n "${g15:-}" ] && echo "export DOMSINK_PATH=\"$g15\"" >> "$CONF" || true
  fi
  if ! grep -q 'DOMSINKSCAN_PATH=' "$CONF"; then
    local g16="$(_try_find_file enhanced_domsink_scanner.py)"; [ -n "${g16:-}" ] && echo "export DOMSINKSCAN_PATH=\"$g16\"" >> "$CONF" || true
  fi
  # Nuclei templates default
  if ! grep -q 'NUCLEI_CUSTOM_TEMPLATES=' "$CONF"; then
    local nt="$HOME/nuclei-templates/customs"
    [ -d "$nt" ] && echo "export NUCLEI_CUSTOM_TEMPLATES=\"$nt\"" >> "$CONF" || warn "Custom Nuclei templates path not found. Update NUCLEI_CUSTOM_TEMPLATES in $CONF."
  fi
}

write_core_aliases(){
  cat >"$CORE" <<'EOF'
# ~/.kda/aliases/core.sh — core aliases/functions
# Load config if called standalone
[ -f "$HOME/.kda/config.env" ] && . "$HOME/.kda/config.env"

# ---------- helpers for guarded aliases ----------
alias_if_exists() { local name="$1"; shift; local target="$1"; [ -e "$target" ] && alias "$name"="$target"; }
py_alias_if_exists() { local name="$1"; shift; local script="$1"; [ -f "$script" ] && alias "$name"="python3 $script"; }

# ---------- UI / animation / QoL ----------
spin() { local t="$1"; shift; if command -v gum >/dev/null 2>&1; then gum spin --title "$t" -- "$@"; else echo "[*] $t"; "$@"; fi; }
P() { parallel --bar -j"${J:-10}" "$@"; }
banner() { if command -v figlet >/dev/null 2>&1; then figlet -w 120 "$*"; else printf "\n==== %s ====\n" "$*"; fi; }
timeit() { /usr/bin/time -f '[time] %E | RSS:%M KB' "$@"; }

# ---------- Web/text helpers ----------
htmltxt() { curl -s "$1" | lynx -dump -stdin; }
smartgrab() {
  local url="$1"
  if curl -sL --compressed "$url" | jq . >/dev/null 2>&1; then
    curl -sL --compressed "$url" | jq .
  else
    curl -sL --compressed -A 'Mozilla/5.0' "$url" | lynx -dump -stdin
  fi
}
linksabs() {
  local url="$1"
  if command -v htmlq >/dev/null 2>&1; then
    curl -sL --compressed -A 'Mozilla/5.0' "$url" \
    | htmlq -a href a \
    | python3 - "$url" <<'PY'
import sys, urllib.parse as U, html
base=sys.argv[1]; seen=set()
for line in sys.stdin:
    href=html.unescape(line.strip())
    if not href: continue
    abs=U.urljoin(base, href)
    if abs.startswith(("http://","https://")) and abs not in seen:
        seen.add(abs); print(abs)
PY
  else
    curl -sL --compressed -A 'Mozilla/5.0' "$url" \
    | grep -oE 'href=["'"'"'][^'"'"' >]+' \
    | sed -E 's/^href=["'"'"']//' \
    | python3 - "$url" <<'PY'
import sys, urllib.parse as U, html
base=sys.argv[1]; seen=set()
for line in sys.stdin:
    href=html.unescape(line.strip())
    if not href: continue
    abs=U.urljoin(base, href)
    if abs.startswith(("http://","https://")) and abs not in seen:
        seen.add(abs); print(abs)
PY
  fi
}

# ---------- Validation / scanners ----------
oty-validate-all(){ parallel -j"${J:-4}" 'echo "==> {}"; oty validate "{}"' ::: *.yaml; }

nuclei-par() {
  local urls_file="$1"
  [[ -z "$urls_file" ]] && { echo "Usage: nuclei-par urls.txt"; return 1; }
  local T="${NUCLEI_CUSTOM_TEMPLATES:-$HOME/nuclei-templates/customs}"
  P "nuclei -u {} -t '$T' -o \"{}.nuclei.txt\"" :::: "$urls_file"
}

httpx-par() {
  local urls_file="$1"
  [[ -z "$urls_file" ]] && { echo "Usage: httpx-par urls.txt"; return 1; }
  P 'echo {} | httpx -title -status-code -tech-detect' :::: "$urls_file"
}

wayback-par() {
  local domains_file="$1"
  [[ -z "$domains_file" ]] && { echo "Usage: wayback-par domains.txt"; return 1; }
  P "echo {} && waybackurls {} > '{}.wayback.txt'" :::: "$domains_file"
}

gf-par() {
  local pattern="$1" urls_file="$2"
  [[ -z "$pattern" || -z "$urls_file" ]] && { echo "Usage: gf-par pattern urls.txt"; return 1; }
  P "echo {} | gf '$pattern' > '"'"\$({ printf \"%s.%s.txt\" \"{}\" \"$pattern\"; })"'"'" :::: "$urls_file"
}

jsfinder-par() {
  local urls_file="$1"; local JSPATH="${JSFINDER_PATH:-}"
  [[ -z "$urls_file" ]] && { echo "Usage: jsfinder-par urls.txt"; return 1; }
  [[ -z "$JSPATH" ]] && { echo "Set JSFINDER_PATH in ~/.kda/config.env"; return 1; }
  P "python3 '$JSPATH' -u {} -d > '"'"\$({ printf \"%s.jsf.txt\" \"{}\"; })"'"'"" :::: "$urls_file"
}

xsstrike-par() {
  local urls_file="$1"; local XPATH="${XSSTRIKE_PATH:-}"
  [[ -z "$urls_file" ]] && { echo "Usage: xsstrike-par urls.txt"; return 1; }
  [[ -z "$XPATH" ]] && { echo "Set XSSTRIKE_PATH in ~/.kda/config.env"; return 1; }
  P "python3 '$XPATH' -u {} --crawl > '"'"\$({ printf \"%s.xss.txt\" \"{}\"; })"'"'"" :::: "$urls_file"
}

rustscan-par() {
  local targets_file="$1"; local RS="${RUSTSCAN_BIN:-$(command -v rustscan 2>/dev/null)}"
  [[ -z "$targets_file" ]] && { echo "Usage: rustscan-par targets.txt"; return 1; }
  [[ -z "${RS:-}" ]] && { echo "Set RUSTSCAN_BIN in ~/.kda/config.env or install rustscan"; return 1; }
  P "'$RS' -a {} -r 1-65535" :::: "$targets_file"
}

# ---------- Passive intel ----------
crtsh(){ local d="$1"; [ -z "$d" ] && { echo "Usage: crtsh domain.com"; return 1; }
  curl -sG 'https://crt.sh/' --data-urlencode "q=%25.$d" --data "output=json" \
  | jq -r '.[].name_value' | tr ' ' '\n' | sed 's/^\*\.///' | sort -u; }
certspotter(){ local d="$1"; [ -z "$d" ] && { echo "Usage: certspotter domain.com"; return 1; }
  curl -sG 'https://api.certspotter.com/v1/issuances' \
    --data-urlencode "domain=$d" --data "include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sed 's/^\*\.///' | sort -u; }
anubis(){ local d="$1"; [ -z "$d" ] && { echo "Usage: anubis domain.com"; return 1; }
  curl -s "https://jldc.me/anubis/subdomains/$d" | jq -r '.[]' | sort -u; }
subs-all(){ local d="$1"; [ -z "$d" ] && { echo "Usage: subs-all domain.com"; return 1; }
  { crtsh "$d"; certspotter "$d"; anubis "$d"; } | sort -u; }

# ---------- Site hygiene ----------
robotsgrab(){ local base="$1"; curl -sL --compressed "$base/robots.txt" | sed 's/\r$//'; }
sitemap-urls(){ local base="$1"; curl -sL --compressed "$base/sitemap.xml" | grep -oP '(?<=<loc>)[^<]+'; }
cors-check(){ curl -s -I -H 'Origin: https://evil.example' "$1" | grep -i 'access-control-allow-'; }
clickjack-check(){ curl -sI "$1" | egrep -i 'x-frame-options|content-security-policy'; }
csp-dump(){ curl -sI "$1" | grep -i 'content-security-policy'; }
jslinks(){ linksabs "$1" | grep -Ei '\\.js($|\\?)' | sort -u; }
openapi-probe(){
  local base="$1"; [ -z "$base" ] && { echo "Usage: openapi-probe https://site.tld"; return 1; }
  for p in /openapi.json /swagger.json /v2/swagger.json /api-docs /v3/api-docs; do
    if curl -skL "$base$p" | jq -e '.info.title' >/dev/null 2>&1; then echo "$base$p"; fi
  done
}

# ---------- API integrations (keys optional) ----------
urlscan-submit(){ : "${URLSCAN_API_KEY:?Set URLSCAN_API_KEY}"; local u="$1"
  curl -s 'https://urlscan.io/api/v1/scan/' -H "API-Key: $URLSCAN_API_KEY" \
  -H 'Content-Type: application/json' --data "{\"url\":\"$u\",\"visibility\":\"unlisted\"}" | jq -r '.result'; }
urlscan-search(){ local q="$*"; curl -sG 'https://urlscan.io/api/v1/search/' --data-urlencode "q=$q" | jq -r '.results[].task.url'; }

vt-url(){ : "${VT_API_KEY:?Set VT_API_KEY}"; local u="$1"
  local id; id=$(curl -s -X POST 'https://www.virustotal.com/api/v3/urls' -H "x-apikey: $VT_API_KEY" -F "url=$u" | jq -r '.data.id')
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/analyses/$id" | jq; }
vt-ip(){ : "${VT_API_KEY:?Set VT_API_KEY}"; local ip="$1"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/$ip" | jq; }

shodan-search(){ : "${SHODAN_API_KEY:?Set SHODAN_API_KEY}"; local q="$*"
  curl -sG 'https://api.shodan.io/shodan/host/search' --data-urlencode "query=$q" --data "key=$SHODAN_API_KEY" \
  | jq -r '.matches[] | "\(.ip_str):\(.port) \(.hostnames|join(",")) \(.product // \"\")"'; }
shodan-host(){ : "${SHODAN_API_KEY:?Set SHODAN_API_KEY}"; local ip="$1"
  curl -s "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY" | jq; }

gh-code(){ : "${GITHUB_TOKEN:?Set GITHUB_TOKEN}"; local q="$*"
  curl -sG 'https://api.github.com/search/code' -H "Authorization: Bearer $GITHUB_TOKEN" --data-urlencode "q=$q" \
  | jq -r '.items[] | [.repository.full_name, .path, .html_url] | @tsv'; }

st-subs(){ : "${ST_API_KEY:?Set ST_API_KEY}"; local d="$1"
  curl -s "https://api.securitytrails.com/v1/domain/$d/subdomains" -H "APIKEY: $ST_API_KEY" \
  | jq -r '.subdomains[]' | sed "s/$/.$d/" | sort -u; }

# ---------- Recon helpers / workflows ----------
gowit-par(){ local f="$1"; [ -z "$f" ] && { echo "Usage: gowit-par urls.txt"; return 1; }
  P "gowitness single --url {} --destination ./gowitness_shots" :::: "$f"; }

ffuf-common(){ local base="$1" wl="${2:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
  ffuf -u "$base/FUZZ" -w "$wl" -ac -t 50 -of md -o "ffuf_$(echo "$base"|sed 's#[^A-Za-z0-9]#_#g').md"; }

redir-probe(){ local f="$1" param="${2:-next}"; [ -z "$f" ] && { echo "Usage: redir-probe urls.txt [param]"; return 1; }
  P "curl -sk -I '{}'?$param=https://example.org | egrep -i 'location|http/'" :::: "$f"; }

bb-fast(){
  local domain="$1"; [ -z "$domain" ] && { echo "Usage: bb-fast domain.com"; return 1; }
  banner "Recon $domain"
  spin "Fetching subs (CT/Anubis/CertSpotter)" subs-all "$domain" | tee subs.txt >/dev/null
  spin "Resolving + probing live with httpx" bash -c 'sort -u subs.txt | httpx -silent -title -status-code -tech-detect' | tee httpx.out >/dev/null
  awk "/\[200]/{print \$1}" httpx.out | sort -u > live.txt
  spin "Nuclei customs on live" nuclei-par live.txt
  echo "[+] Done. Files: subs.txt, httpx.out, live.txt, *.nuclei.txt"
}

triage-api(){
  local target="$1"; [ -z "$target" ] && { echo "Usage: triage-api https://site.tld OR IP"; return 1; }
  banner "API Triage"
  if [[ "$target" =~ ^https?:// ]]; then
    spin "robots" robotsgrab "$target" | sed -n '1,40p'
    spin "sitemap" sitemap-urls "$target" | sed -n '1,40p'
    spin "CORS" cors-check "$target"
    spin "CSP" csp-dump "$target"
    spin "OpenAPI probe" openapi-probe "$target"
  else
    [ -n "${SHODAN_API_KEY:-}" ] && spin "Shodan host" shodan-host "$target" | jq '. | {ip_str,ports,hostnames,org,asn}'
    [ -n "${VT_API_KEY:-}" ] && spin "VT IP" vt-ip "$target" | jq '.data.attributes.last_analysis_stats'
  fi
}

# ---------- Your customized tool/script aliases (guarded) ----------
# Tool aliases via env overrides or guessed paths
[ -n "${GOBUSTER_BIN:-}" ] && alias gobuster="$GOBUSTER_BIN"
[ -n "${SN1PER_BIN:-}" ] && alias sniper="sudo $SN1PER_BIN"
[ -n "${RUSTSCAN_BIN:-}" ] && alias rustscan="$RUSTSCAN_BIN"
[ -n "${JSSFSCAN_BIN:-}" ] && alias jsscan="$JSSFSCAN_BIN"
[ -n "${JSFINDER_PATH:-}" ] && alias jsfinder="python3 $JSFINDER_PATH"
[ -n "${XSSTRIKE_PATH:-}" ] && alias xsstrike="python3 $XSSTRIKE_PATH"
[ -n "${EYEWITNESS_PATH:-}" ] && alias eyewitness="python3 $EYEWITNESS_PATH"
[ -n "${CORSY_PATH:-}" ] && alias corsy="python3 $CORSY_PATH"
[ -n "${GITDORKER_PATH:-}" ] && alias gitdorker="python3 $GITDORKER_PATH"
[ -n "${GSEC_PATH:-}" ] && alias gsec="python3 $GSEC_PATH"
[ -n "${LOXS_PATH:-}" ] && alias loxs="python3 $LOXS_PATH"
[ -n "${SPIDERFOOT_PATH:-}" ] && alias spiderfoot="python3 $SPIDERFOOT_PATH"
[ -n "${UFX_PATH:-}" ] && alias ufx="python3 $UFX_PATH"
[ -n "${LAZYXSS_PATH:-}" ] && alias lazyxss="python3 $LAZYXSS_PATH"
[ -n "${DOMSINK_PATH:-}" ] && alias domsink="python3 $DOMSINK_PATH"
[ -n "${DOMSINKSCAN_PATH:-}" ] && alias domsinkscan="python3 $DOMSINKSCAN_PATH"

# Personal scripts from ~/scripts (executables automatically aliased by filename without extension)
if [ -d "$HOME/scripts" ]; then
  for f in "$HOME/scripts"/*; do
    if [ -f "$f" ] && [ -x "$f" ]; then
      base="$(basename "$f")"; name="${base%.*}"
      if ! command -v "$name" >/dev/null 2>&1; then alias "$name"="$f"; fi
    fi
  done
fi

# Common QoL
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
EOF
  chmod +x "$CORE"
}

write_host_override(){
  local hn="${HOSTNAME_ARG:-$(hostname -s 2>/dev/null || hostname)}"
  local HF="$HOST_DIR/$hn.sh"
  if [ ! -f "$HF" ]; then
    cat >"$HF" <<EOF
# ~/.kda/aliases/host/$hn.sh — host-specific overrides
# Example: per-device templates location or tool paths
# export NUCLEI_CUSTOM_TEMPLATES="\$HOME/nuclei-templates/customs"
# export JSFINDER_PATH="\$HOME/tools/JSFinder/jsfinder.py"
# export XSSTRIKE_PATH="\$HOME/tools/XSStrike/xsstrike.py"
# export RUSTSCAN_BIN="\$HOME/tools/RustScan/target/release/rustscan"
EOF
    ok "Created host override: $HF"
  else
    log "Host override exists: $HF"
  fi
}

install_hint(){
  local osf=$(os_family)
  echo
  log "Recommended deps (run manually if you want auto-install):"
  if [ "$osf" = "linux" ]; then
    cat <<'LIN'
sudo apt-get update
sudo apt-get install -y jq curl parallel lynx python3 python3-pip figlet
# optional: gum, bat, htmlq, ffuf, gowitness
# Go tools:
#   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   go install github.com/tomnomnom/waybackurls@latest
#   go install github.com/tomnomnom/gf@latest
# Initialize GNU parallel:
parallel --citation
LIN
  elif [ "$osf" = "mac" ]; then
    cat <<'MAC'
brew install jq curl parallel lynx figlet coreutils
# optional: gum bat ffuf gowitness
# Go tools:
#   brew install go
#   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   go install github.com/tomnomnom/waybackurls@latest
#   go install github.com/tomnomnom/gf@latest
parallel --citation
MAC
  fi
}

doctor(){
  echo "== $APP doctor =="
  echo "Shell: $(detect_shell)"
  echo "OS: $(os_family)"
  echo "KDA_HOME: $KDA_HOME"
  for f in "$CONF" "$CORE" "$LOADER"; do [ -f "$f" ] && ok "Found $(basename "$f")" || warn "Missing $(basename "$f")"; done
  # quick checks
  for c in jq curl parallel lynx; do command -v "$c" >/dev/null && ok "$c ✓" || warn "$c not found"; done
  # config vars preview
  [ -f "$CONF" ] && grep -E '^(export (JSFINDER|XSSTRIKE|RUSTSCAN|NUCLEI_CUSTOM|J|GOBUSTER|SN1PER|EYEWITNESS|CORSY|GITDORKER|GSEC|LOXS|SPIDERFOOT|UFX|LAZYXSS|JSSFSCAN|DOMSINK|DOMSINKSCAN)=|^export GOPATH=)' "$CONF" || true
}

uninstall(){
  local sh="$(detect_shell)"; local rcfile="$HOME/.bashrc"; [ "$sh" = "zsh" ] && rcfile="$HOME/.zshrc"
  if [ -f "$rcfile" ]; then
    tmp="$(mktemp)"; awk '
      /# >>> KDAIRATCHI ALIASES >>>/ {skip=1}
      skip==1 && /# <<< KDAIRATCHI ALIASES <</ {skip=0; next}
      skip!=1 { print }
    ' "$rcfile" > "$tmp" && mv "$tmp" "$rcfile"
    ok "Removed loader block from $(basename "$rcfile")"
  fi
  if [ -d "$KDA_HOME" ]; then
    if [ "$(yn "Delete $KDA_HOME entirely?")" = "y" ]; then rm -rf "$KDA_HOME"; ok "Deleted $KDA_HOME"; fi
  fi
}

# --- arg parse ----------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --install) MODE=install;;
    --doctor) MODE=doctor;;
    --uninstall) MODE=uninstall;;
    --yes|-y) YES=1;;
    --shell) SHELL_CHOSEN="${2:-auto}"; shift;;
    --tool-root) TOOL_ROOT_ARG="${2:-}"; shift;;
    --nuclei-templates) NUCLEI_TEMPLATES_ARG="${2:-}"; shift;;
    --hostname) HOSTNAME_ARG="${2:-}"; shift;;
    *) err "Unknown arg $1"; exit 1;;
  esac
  shift
done

: "${MODE:=install}"

case "$MODE" in
  install)
    log "Installing to $KDA_HOME"
    ensure_dirs
    ensure_loader
    write_core_aliases
    write_host_override
    detect_tool_paths
    ensure_rc
    ok "Bootstrap complete."
    install_hint
    echo
    log "Reload your shell (or run: source ~/.kda/aliases/loader.sh) then try:"
    echo "  bb-fast example.com"
    echo "  httpx-par urls.txt"
    echo "  nuclei-par live.txt"
    ;;
  doctor) doctor ;;
  uninstall) uninstall ;;
  *) err "Unknown mode"; exit 1;;
esac
