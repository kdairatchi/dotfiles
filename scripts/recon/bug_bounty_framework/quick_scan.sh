#!/bin/bash

set -euo pipefail  # Enhanced error handling

# -------------------------------------------------------------
# Common framework: verbosity, GNU parallel, monitoring, jobs
# -------------------------------------------------------------

usage() {
  cat <<'USAGE'
Usage: ./quick_scan.sh [options] <domain>

Options:
  -v, --verbose      Enable verbose execution (set -x)
  -m, --monitor      Show resource monitor (watch FDs, sockets)
  -h, --help         Show this help

Environment:
  J                  Concurrency for GNU parallel (default: calc_jobs)

Examples:
  ./quick_scan.sh example.com
  ./quick_scan.sh -v --monitor example.com
USAGE
}

VERBOSE=false
MONITOR=false

calc_jobs() {
  local cpus fd_limit target cap
  cpus=$(nproc 2>/dev/null || echo 4)
  fd_limit=$(ulimit -n 2>/dev/null || echo 1024)
  target=$(( cpus * 64 ))
  cap=$(( (fd_limit * 70) / 100 ))
  if (( cap < 32 )); then cap=32; fi
  if (( target > cap )); then target=$cap; fi
  if (( target > 9000 )); then target=9000; fi  # Updated to 9000 max parallel jobs
  echo "$target"
}

P() { parallel --bar -j"${J:-$(calc_jobs)}" "$@"; }  # Use calc_jobs as default

start_monitor() {
  command -v watch >/dev/null 2>&1 || return 0
  watch -n1 'echo "FDs: $(ls /proc/$$/fd | wc -l)"; ss -s; cat /proc/sys/net/ipv4/ip_local_port_range' &
  MONITOR_PID=$!
}

cleanup() { if [[ -n "${MONITOR_PID:-}" ]]; then kill "${MONITOR_PID}" 2>/dev/null || true; fi }
trap cleanup EXIT

# Parse options
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=true; shift ;;
    -m|--monitor) MONITOR=true; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
set -- "${ARGS[@]}" "$@"

# Quick Bug Bounty Scan Script
# Usage: ./quick_scan.sh example.com

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_DIR="$RESULTS_DIR/$(date +%Y%m%d_%H%M%S)_$TARGET"
mkdir -p "$OUTPUT_DIR"

# Enable verbose
if [[ "$VERBOSE" == true ]]; then set -x; fi

# Export dynamic parallelism
export J="${J:-$(calc_jobs)}"

# Start monitor if requested
if [[ "$MONITOR" == true ]]; then start_monitor; fi

echo "🎯 Starting quick scan for $TARGET"
echo "📁 Results will be saved to: $OUTPUT_DIR"


# Subdomain enumeration
echo "🔍 Finding subdomains..."
if command -v subfinder >/dev/null 2>&1; then
    subfinder -d "$TARGET" -silent | sort -u | tee "$OUTPUT_DIR/subdomains.txt"
else
    echo "subfinder not found!"; exit 1
fi

# Resolve and check live subdomains
echo "🌐 Checking live subdomains..."
if command -v dnsx >/dev/null 2>&1; then
    dnsx -l "$OUTPUT_DIR/subdomains.txt" -silent -resp-only | awk '{print $1}' | sort -u | tee "$OUTPUT_DIR/resolved.txt" >/dev/null
fi
if command -v httpx >/dev/null 2>&1; then
    INPUT_FOR_HTTPX="$OUTPUT_DIR/subdomains.txt"
    [ -s "$OUTPUT_DIR/resolved.txt" ] && INPUT_FOR_HTTPX="$OUTPUT_DIR/resolved.txt"
    httpx -l "$INPUT_FOR_HTTPX" -silent | sort -u | tee "$OUTPUT_DIR/live_subdomains.txt"
else
    echo "httpx not found!"; exit 1
fi

# Port scanning
echo "🚪 Scanning ports..."
if command -v naabu &> /dev/null; then
    naabu -host "$TARGET" -top-ports 1000 -silent | tee "$OUTPUT_DIR/ports.txt"
else
    echo "naabu not found!"; exit 1
fi

# URL discovery (gau / hakrawler / waybackurls / katana)
echo "🔗 Discovering URLs..."
> "$OUTPUT_DIR/urls.txt"
if command -v gau >/dev/null 2>&1; then
    gau --threads 50 --subs "$TARGET" | tee -a "$OUTPUT_DIR/urls.txt" >/dev/null
fi
if command -v waybackurls >/dev/null 2>&1; then
    cat "$OUTPUT_DIR/live_subdomains.txt" | waybackurls | tee -a "$OUTPUT_DIR/urls.txt" >/dev/null
fi
if command -v katana >/dev/null 2>&1; then
    katana -list "$OUTPUT_DIR/live_subdomains.txt" -silent -nc -kf all -ef woff,css,png,svg,jpg,woff2,jpeg,gif -xhr | tee -a "$OUTPUT_DIR/urls.txt" >/dev/null
fi
sort -u "$OUTPUT_DIR/urls.txt" -o "$OUTPUT_DIR/urls.txt"

# Vulnerability scanning
echo "🔍 Scanning for vulnerabilities..."
if command -v nuclei >/dev/null 2>&1; then
    nuclei -l "$OUTPUT_DIR/live_subdomains.txt" -severity critical,high,medium -o "$OUTPUT_DIR/vulnerabilities.txt" -silent || true
fi

# Quick directory fuzzing (parallelized)
echo "📂 Quick directory fuzzing..."
if command -v ffuf >/dev/null 2>&1; then
    WORDLIST="$SCRIPT_DIR/wordlists/common.txt"
    if [ ! -f "$WORDLIST" ]; then
        echo "Wordlist not found at $WORDLIST; skipping ffuf"
    else
        export WORDLIST OUTPUT_DIR
        head -5 "$OUTPUT_DIR/live_subdomains.txt" | P 'live={}; out="$OUTPUT_DIR/dirs_$(echo {= s:/:_: =} | tr ":" "_").json"; ffuf -u "${live%/}/FUZZ" -w "$WORDLIST" -ac -o "$out" -of json -s || true'
    fi
fi

# Juicy subdomains quick filter from oneliners
if command -v dnsx >/dev/null 2>&1; then
    echo "🍯 Identifying juicy subdomains..."
    awk '{print $1}' "$OUTPUT_DIR/live_subdomains.txt" | grep -E 'api|dev|stg|test|admin|demo|stage|pre|vpn' | sort -u > "$OUTPUT_DIR/juicy_subdomains.txt" || true
fi

echo "✅ Scan completed! Results saved to: $OUTPUT_DIR"
echo "📊 Summary:"
echo "   - Subdomains: $(wc -l < "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || echo "0")"
echo "   - Live subdomains: $(wc -l < "$OUTPUT_DIR/live_subdomains.txt" 2>/dev/null || echo "0")"
echo "   - URLs: $(wc -l < "$OUTPUT_DIR/urls.txt" 2>/dev/null || echo "0")"
echo "   - Vulnerabilities: $(wc -l < "$OUTPUT_DIR/vulnerabilities.txt" 2>/dev/null || echo "0")"
