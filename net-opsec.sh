#!/usr/bin/env bash
# net-opsec.sh — networking + Tor/DNS leak + MAC + OPSEC + proxychains/RedChains tests
# Author: kdairatchi edition
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# ---------- style ----------
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; B='\033[0;34m'; N='\033[0m'
ok(){ printf "${G}[+]${N} %s\n" "$*"; }
wr(){ printf "${Y}[!]${N} %s\n" "$*"; }
er(){ printf "${R}[-]${N} %s\n" "$*" >&2; }
hd(){ printf "${C}== %s ==${N}\n" "$*"; }

# ---------- deps (soft) ----------
have(){ command -v "$1" >/dev/null 2>&1; }

# ---------- config ----------
: "${TOR_SOCKS:=127.0.0.1:9050}"
: "${TIMEOUT:=6}"               # HTTP max-time
: "${CTIME:=2}"                 # HTTP connect-timeout
: "${DNS_TIMEOUT:=3}"           # dig/nslookup timeout
STATE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/netopsec"
mkdir -p "$STATE_DIR"

# ---------- helpers ----------
json_val(){ have jq && jq -r "$1" 2>/dev/null || sed -n "s/.*$1\"\s*:\s*\"\([^\"]*\)\".*/\1/p"; }
curlx(){ curl -fsSL --connect-timeout "$CTIME" --max-time "$TIMEOUT" -A 'curl/NetOpsec' "$@"; }
line(){ printf "%s\n" "────────────────────────────────────────────────────────"; }

# ---------- IP APIs ----------
IP_APIS=( "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com" "https://ifconfig.co/ip" )
# richer JSON
META_APIS=( "https://ipinfo.io/json" "https://ipwho.is" "https://ifconfig.co/json" "http://ip-api.com/json" )

get_public_ip(){
  local ip=""
  for u in "${IP_APIS[@]}"; do
    ip="$(curlx "$u" 2>/dev/null | tr -d '\r' | head -n1 || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$ ]]; then
      echo "$ip"; return 0
    fi
  done
  echo ""; return 1
}

get_tor_ip(){
  local ip=""
  ip="$(curlx --socks5-hostname "$TOR_SOCKS" https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] && echo "$ip" || echo ""
}

tor_is_torflag(){
  local j
  j="$(curlx --socks5-hostname "$TOR_SOCKS" https://check.torproject.org/api/ip 2>/dev/null || true)"
  if [[ -z "$j" ]]; then echo "unknown"; return 0; fi
  if echo "$j" | grep -qi '"IsTor"\s*:\s*true'; then echo "true"; else echo "false"; fi
}

show_meta_for_ip(){
  local label="$1" ip="$2"
  [[ -z "$ip" ]] && { wr "$label: no IP"; return 0; }
  echo
  hd "$label — $ip"
  for u in "${META_APIS[@]}"; do
    local body
    if [[ "$u" == *ipwho.is* ]]; then body="$(curlx "$u/$ip" || true)"; else body="$(curlx "$u" || true)"; fi
    if [[ -n "$body" ]] && (echo "$body" | grep -q '{'); then
      local country city asn org isp
      country="$(echo "$body" | json_val '.country' | head -n1)"
      city="$(echo "$body" | json_val '.city' | head -n1)"
      asn="$(echo "$body" | json_val '.asn' | head -n1)"; [[ -z "$asn" ]] && asn="$(echo "$body" | json_val '.asn.asn' | head -n1)"
      org="$(echo "$body" | json_val '.org' | head -n1)"; [[ -z "$org" ]] && org="$(echo "$body" | json_val '.connection.org' | head -n1)"
      isp="$(echo "$body" | json_val '.isp' | head -n1)"; [[ -z "$isp" ]] && isp="$(echo "$body" | json_val '.org' | head -n1)"
      printf " • %-18s %-15s  %-20s  %s\n" "$(echo "$u" | sed 's#https\?://##;s#/json##;s#/##g')" "${country:-?}" "${city:-?}" "${asn:-${isp:-?}}"
    fi
  done
}

# ---------- DNS leak tests ----------
digq(){ timeout "$DNS_TIMEOUT" dig +time=2 +tries=1 +short "$@" 2>/dev/null || true; }
nsq(){ timeout "$DNS_TIMEOUT" nslookup "$@" 2>/dev/null | awk '/Address: /{print $2}' || true; }

dns_resolvers(){
  if have resolvectl; then resolvectl dns 2>/dev/null | awk '{print $3}'
  elif have systemd-resolve; then systemd-resolve --status 2>/dev/null | awk '/DNS Servers/{print $3}'
  else grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'
  fi
}

dns_leak_check(){
  hd "DNS Leak Check"
  echo "System resolvers:"
  dns_resolvers | sed 's/^/ • /' || true

  local ip_http ip_odns ip_cf ip_google
  ip_http="$(get_public_ip || true)"
  ip_odns="$(digq @resolver1.opendns.com myip.opendns.com A | head -n1)"
  ip_cf="$(digq @1.1.1.1 whoami.cloudflare A | head -n1)"
  ip_google="$(digq TXT o-o.myaddr.l.google.com @ns1.google.com | tr -d '"' | awk '{print $NF}' | head -n1)"

  echo; echo "Who-am-I comparisons (HTTP vs DNS resolvers):"
  printf " • HTTP (direct):     %s\n" "${ip_http:-?}"
  printf " • OpenDNS resolver:  %s\n" "${ip_odns:-?}"
  printf " • Cloudflare 1.1.1.1 %s\n" "${ip_cf:-?}"
  printf " • Google NS whoami:  %s\n" "${ip_google:-?}"

  echo
  if [[ -n "$ip_http" && ( "$ip_http" != "$ip_odns" || "$ip_http" != "$ip_cf" || "$ip_http" != "$ip_google" ) ]]; then
    wr "Possible split-tunnel or proxy/Tor path: DNS resolvers see a different IP than HTTP."
  else
    ok "Resolvers and HTTP agree (no obvious DNS leak)."
  fi
}

# ---------- ProxyChains test ----------
proxychains_test(){
  hd "ProxyChains Test"
  if ! have proxychains && ! have proxychains4; then er "proxychains not installed"; return 1; fi
  local pc=$(have proxychains4 && echo proxychains4 || echo proxychains)
  local direct torpc
  direct="$(get_public_ip || true)"
  torpc="$(timeout "$TIMEOUT" $pc -q curl -fsSL --max-time "$TIMEOUT" https://api.ipify.org 2>/dev/null || true)"
  printf " • Direct IP:        %s\n" "${direct:-?}"
  printf " • proxychains IP:   %s\n" "${torpc:-?}"
  if [[ -n "$torpc" && "$torpc" != "$direct" ]]; then ok "proxychains appears to route traffic."; else wr "proxychains didn’t change the egress IP (check chain/proxy list)."; fi

  # quick config sanity
  local conf=""
  [[ -f /etc/proxychains4.conf ]] && conf=/etc/proxychains4.conf
  [[ -z "$conf" && -f /etc/proxychains.conf ]] && conf=/etc/proxychains.conf
  if [[ -n "$conf" ]]; then
    grep -Eq '^\s*proxy_dns' "$conf" && ok "proxy_dns enabled in $(basename "$conf")" || wr "proxy_dns not enabled in $(basename "$conf")"
    grep -Eq '^\s*(dynamic_chain)' "$conf" && ok "dynamic_chain enabled" || wr "dynamic_chain not enabled"
  fi
}

# ---------- RedChains test ----------
redchains_test(){
  local mode="${1:-quick}"
  hd "RedChains Smoke Test ($mode)"
  local rc_path="./RedChains.sh"
  [[ -x "$rc_path" ]] || rc_path="$(command -v RedChains.sh || true)"
  if [[ -z "$rc_path" ]]; then er "RedChains.sh not found in CWD or PATH"; return 1; fi
  ok "Found: $rc_path"
  if [[ "$mode" == "full" ]]; then
    MAX_JOBS=800 "$rc_path" --fetch
    MAX_JOBS=800 CONNECT_TIMEOUT=2 TOTAL_TIMEOUT=4 "$rc_path" --check
    "$rc_path" --stats
  else
    "$rc_path" --stats || true
  fi
}

# ---------- MAC randomize/restore ----------
rand_mac(){
  # local, unicast: set 0x02 at first byte
  printf '02:%02x:%02x:%02x:%02x:%02x\n' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}
mac_do(){
  local ifc="$1" mac="$2"
  if have ip; then
    sudo ip link set dev "$ifc" down
    sudo ip link set dev "$ifc" address "$mac"
    sudo ip link set dev "$ifc" up
  else
    sudo ifconfig "$ifc" down
    sudo ifconfig "$ifc" hw ether "$mac"
    sudo ifconfig "$ifc" up
  fi
}
mac_randomize(){
  local ifc="$1"; [[ -z "$ifc" ]] && { er "Usage: --mac-rand <iface>"; return 1; }
  local save="$STATE_DIR/mac_$ifc.orig"
  if ! [[ -f "$save" ]]; then
    if have ip; then ip -o link show "$ifc" | awk -F 'link/ether ' '{print $2}' | awk '{print $1}' > "$save" 2>/dev/null || true
    else ifconfig "$ifc" | awk '/ether/{print $2}' > "$save" 2>/dev/null || true
    fi
    [[ -s "$save" ]] && ok "Saved original MAC to $save" || wr "Couldn’t capture original MAC"
  fi
  local mac; mac="$(rand_mac)"
  mac_do "$ifc" "$mac"
  ok "Set $ifc MAC → $mac"
}
mac_restore(){
  local ifc="$1"; [[ -z "$ifc" ]] && { er "Usage: --mac-restore <iface>"; return 1; }
  local save="$STATE_DIR/mac_$ifc.orig"
  [[ -s "$save" ]] || { er "No saved MAC at $save"; return 1; }
  local mac; mac="$(cat "$save")"
  mac_do "$ifc" "$mac"
  ok "Restored $ifc MAC → $mac"
}

# ---------- OPSEC quick scan ----------
opsec_scan(){
  hd "OPSEC Quick Scan"
  printf " • User: %s  Host: %s  Kernel: %s\n" "$(id -un)" "$(hostname -s)" "$(uname -sr)"
  printf " • Interfaces (up):\n"
  if have ip; then ip -o -4 addr show up | awk '{printf "   - %-6s %s\n",$2,$4}'; echo; fi
  printf " • Default route: "; (ip route 2>/dev/null || route -n 2>/dev/null) | awk '/default|UG/{print $0}' | head -n1
  printf " • Env proxies: "; env | grep -iE '^(http|https|all|socks|ftp)_proxy=' || echo "none"
  printf " • Git identity: "; (git config --global user.name; git config --global user.email) 2>/dev/null | paste -sd' ' - || echo "unset"
  printf " • History files present: "
  ls -1a ~ | grep -E '(\.bash_history|\.zsh_history)' -q && echo "yes" || echo "no"
  printf " • Resolver sources:\n"; dns_resolvers | sed 's/^/   - /'
  echo
}

# ---------- Tor checks (full) ----------
tor_checks(){
  hd "Tor Egress & Sanity"
  local dir_ip tor_ip torflag
  dir_ip="$(get_public_ip || true)"
  tor_ip="$(get_tor_ip || true)"
  torflag="$(tor_is_torflag || true)"
  printf " • Direct IP:  %s\n" "${dir_ip:-?}"
  printf " • Tor IP:     %s\n" "${tor_ip:-?}"
  printf " • Tor flag:   %s (check.torproject.org)\n" "$torflag"
  [[ -n "$tor_ip" ]] && show_meta_for_ip "Tor egress" "$tor_ip"
  [[ -n "$dir_ip" ]] && show_meta_for_ip "Direct egress" "$dir_ip"
  echo
  if [[ -n "$tor_ip" && "$torflag" == "true" ]]; then ok "Tor appears healthy."; else wr "Tor test inconclusive or not Tor."; fi
}

# ---------- Public IP meta only ----------
ip_overview(){
  hd "Public IP Overview"
  local ip; ip="$(get_public_ip || true)"
  printf " • Direct IP: %s\n" "${ip:-?}"
  [[ -n "$ip" ]] && show_meta_for_ip "Direct egress" "$ip"
}

# ---------- Menu ----------
menu(){
  while :; do
    line
    echo "Net-OPSEC Menu:"
    echo " 1) Public IP overview"
    echo " 2) Tor checks"
    echo " 3) DNS leak checks"
    echo " 4) ProxyChains test"
    echo " 5) RedChains quick stats"
    echo " 6) RedChains full (fetch+check, capped)"
    echo " 7) OPSEC quick scan"
    echo " 8) MAC randomize (ask iface)"
    echo " 9) MAC restore (ask iface)"
    echo " 0) Exit"
    read -r -p "> " c || true
    case "${c:-}" in
      1) ip_overview ;;
      2) tor_checks ;;
      3) dns_leak_check ;;
      4) proxychains_test ;;
      5) redchains_test quick ;;
      6) redchains_test full ;;
      7) opsec_scan ;;
      8) read -r -p "Interface (e.g., wlan0/eth0): " i; mac_randomize "$i" ;;
      9) read -r -p "Interface: " i; mac_restore "$i" ;;
      0) exit 0 ;;
      *) wr "bad choice" ;;
    esac
  done
}

# ---------- CLI ----------
usage(){
cat <<EOF
Usage: $0 [flags]

 Core:
  --menu                 Interactive menu (default if no flags)
  --ip                   Public IP overview
  --tor                  Tor egress check (multi-API + Tor flag)
  --dns                  DNS leak checks
  --proxychains-test     Compare direct vs proxychains egress
  --redchains            Quick stats (looks for ./RedChains.sh or in PATH)
  --redchains-full       Fetch+check (caps jobs to keep sane)
  --opsec                OPSEC quick scan

 MAC:
  --mac-rand <iface>     Randomize MAC for interface (stores original)
  --mac-restore <iface>  Restore original MAC

 Options:
  --tor-socks host:port  Override Tor SOCKS (default: ${TOR_SOCKS})
  --timeout N            HTTP max-time (default: ${TIMEOUT})
  --help                 This help

Examples:
  $0 --tor --dns
  $0 --proxychains-test
  $0 --mac-rand wlan0
EOF
}

main(){
  local did=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --menu) menu; return 0 ;;
      --ip) ip_overview; did=1 ;;
      --tor) tor_checks; did=1 ;;
      --dns) dns_leak_check; did=1 ;;
      --proxychains-test) proxychains_test; did=1 ;;
      --redchains) redchains_test quick; did=1 ;;
      --redchains-full) redchains_test full; did=1 ;;
      --opsec) opsec_scan; did=1 ;;
      --mac-rand) shift; mac_randomize "${1:-}"; did=1 ;;
      --mac-restore) shift; mac_restore "${1:-}"; did=1 ;;
      --tor-socks) shift; TOR_SOCKS="${1:-$TOR_SOCKS}";;
      --timeout) shift; TIMEOUT="${1:-$TIMEOUT}";;
      -h|--help) usage; return 0 ;;
      *) er "Unknown flag: $1"; usage; return 1 ;;
    esac
    shift || true
  done
  [[ "$did" -eq 0 ]] && menu
}
main "$@"
