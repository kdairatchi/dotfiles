#!/bin/bash

set -euo pipefail  # Enhanced error handling

# -------------------------------------------------------------
# Common framework: verbosity, GNU parallel, monitoring, jobs
# -------------------------------------------------------------

usage() {
  cat <<'USAGE'
Usage: ./advanced_scan.sh [options] <domain>

Options:
  -v, --verbose      Enable verbose execution (set -x)
  -m, --monitor      Show resource monitor (watch FDs, sockets)
  -h, --help         Show this help

Environment:
  J                  Concurrency for GNU parallel (default: calc_jobs)

Examples:
  ./advanced_scan.sh example.com
  ./advanced_scan.sh -v --monitor example.com
USAGE
}

VERBOSE=false
MONITOR=false

calc_jobs() {
  # Derive a safe default based on CPUs and file descriptor limit
  local cpus fd_limit target cap
  cpus=$(nproc 2>/dev/null || echo 4)
  fd_limit=$(ulimit -n 2>/dev/null || echo 1024)
  # Parallel HTTP tools consume many FDs. Leave headroom.
  # Aim for about 64x CPUs but cap by ~70% of FD limit and a hard ceiling.
  target=$(( cpus * 64 ))
  cap=$(( (fd_limit * 70) / 100 ))
  if (( cap < 32 )); then cap=32; fi
  if (( target > cap )); then target=$cap; fi
  # Hard cap to avoid overload; updated to 9000 for maximum performance
  if (( target > 9000 )); then target=9000; fi
  echo "$target"
}

# GNU parallel wrapper (mirrors user shell alias) - enhanced with calc_jobs default
P() { parallel --bar -j"${J:-$(calc_jobs)}" "$@"; }

start_monitor() {
  command -v watch >/dev/null 2>&1 || return 0
  watch -n1 'echo "FDs: $(ls /proc/$$/fd | wc -l)"; ss -s; cat /proc/sys/net/ipv4/ip_local_port_range' &
  MONITOR_PID=$!
}

cleanup() {
  if [[ -n "${MONITOR_PID:-}" ]]; then kill "${MONITOR_PID}" 2>/dev/null || true; fi
}
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

# Advanced Bug Bounty Scan Script
# Usage: ./advanced_scan.sh example.com

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

echo "🎯 Starting advanced scan for $TARGET"
echo "📁 Results will be saved to: $OUTPUT_DIR"

# Subdomain enumeration (multiple sources)
echo "🔍 Finding subdomains (multiple sources)..."
if command -v subfinder >/dev/null 2>&1; then
  subfinder -d "$TARGET" -all -silent | tee "$OUTPUT_DIR/subfinder.txt"
fi
if command -v assetfinder >/dev/null 2>&1; then
  assetfinder --subs-only "$TARGET" | tee "$OUTPUT_DIR/assetfinder.txt"
fi
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  # Oneliner sources
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee "$OUTPUT_DIR/crtsh.txt" >/dev/null || true
  curl -s "https://jldc.me/anubis/subdomains/$TARGET" | jq -r '.' | grep -o "\\w.*$TARGET" | sort -u | tee "$OUTPUT_DIR/anubis.txt" >/dev/null || true
  curl -s "https://dns.bufferover.run/dns?q=.$TARGET" | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u | tee "$OUTPUT_DIR/bufferover.txt" >/dev/null || true
  curl -s "https://api.subdomain.center/?domain=$TARGET" | jq -r '.[]' | sort -u | tee "$OUTPUT_DIR/subdomain_center.txt" >/dev/null || true
fi
cat "$OUTPUT_DIR"/*.txt 2>/dev/null | grep -F ".$TARGET" | sort -u | tee "$OUTPUT_DIR/all_subdomains.txt"

# Resolve and check live subdomains with details
echo "🌐 Checking live subdomains with details..."
if command -v dnsx >/dev/null 2>&1; then
  dnsx -l "$OUTPUT_DIR/all_subdomains.txt" -silent -r "${RESOLVERS_FILE:-}" | awk '{print $1}' | sort -u | tee "$OUTPUT_DIR/resolved.txt" >/dev/null
fi
if command -v httpx >/dev/null 2>&1; then
  INPUT_FOR_HTTPX="$OUTPUT_DIR/all_subdomains.txt"
  [ -s "$OUTPUT_DIR/resolved.txt" ] && INPUT_FOR_HTTPX="$OUTPUT_DIR/resolved.txt"
  httpx -l "$INPUT_FOR_HTTPX" -silent -tech-detect -status-code -content-length |
    tee "$OUTPUT_DIR/live_subdomains_detailed.txt"
  cut -d' ' -f1 "$OUTPUT_DIR/live_subdomains_detailed.txt" | sort -u | tee "$OUTPUT_DIR/live_subdomains.txt"
else
  echo "httpx not found!"; exit 1
fi

# Port scanning (comprehensive)
echo "🚪 Comprehensive port scanning..."
if command -v naabu >/dev/null 2>&1; then
  naabu -host "$TARGET" -top-ports 3000 -silent | tee "$OUTPUT_DIR/ports.txt"
fi

# URL discovery (multiple sources)
echo "🔗 Discovering URLs from multiple sources..."
> "$OUTPUT_DIR/all_urls.txt"
if command -v waybackurls >/dev/null 2>&1; then
  cat "$OUTPUT_DIR/live_subdomains.txt" | waybackurls | tee "$OUTPUT_DIR/wayback_urls.txt" >/dev/null
  cat "$OUTPUT_DIR/wayback_urls.txt" >> "$OUTPUT_DIR/all_urls.txt"
fi
if command -v gau >/dev/null 2>&1; then
  cat "$OUTPUT_DIR/live_subdomains.txt" | gau | tee "$OUTPUT_DIR/gau_urls.txt" >/dev/null
  cat "$OUTPUT_DIR/gau_urls.txt" >> "$OUTPUT_DIR/all_urls.txt"
fi
if command -v katana >/dev/null 2>&1; then
  katana -list "$OUTPUT_DIR/live_subdomains.txt" -silent -nc -kf all -ef woff,css,png,svg,jpg,woff2,jpeg,gif -xhr | tee "$OUTPUT_DIR/katana_urls.txt" >/dev/null
  cat "$OUTPUT_DIR/katana_urls.txt" >> "$OUTPUT_DIR/all_urls.txt"
fi
sort -u "$OUTPUT_DIR/all_urls.txt" -o "$OUTPUT_DIR/all_urls.txt"

# Filter live URLs
echo "🔍 Filtering live URLs..."
if command -v httpx >/dev/null 2>&1; then
  cat "$OUTPUT_DIR/all_urls.txt" | httpx -silent -mc 200,301,302,403 | tee "$OUTPUT_DIR/live_urls.txt"
fi

# Parameter discovery
echo "🔧 Discovering parameters..."
grep -E "\?" "$OUTPUT_DIR/live_urls.txt" | sort -u | tee "$OUTPUT_DIR/urls_with_params.txt" >/dev/null

# Vulnerability scanning (comprehensive)
echo "🔍 Comprehensive vulnerability scanning..."
if command -v nuclei >/dev/null 2>&1; then
  nuclei -l "$OUTPUT_DIR/live_subdomains.txt" -severity critical,high,medium -o "$OUTPUT_DIR/vulnerabilities.txt" -silent || true
fi

# XSS testing
echo "🔍 Testing for XSS vulnerabilities..."
if [ -s "$OUTPUT_DIR/urls_with_params.txt" ] && command -v dalfox >/dev/null 2>&1; then
  head -100 "$OUTPUT_DIR/urls_with_params.txt" | dalfox pipe -o "$OUTPUT_DIR/xss_results.txt" 2>/dev/null || true
fi

# Open Redirect quick check from oneliners
if [ -s "$OUTPUT_DIR/urls_with_params.txt" ] && command -v qsreplace >/dev/null 2>&1; then
  echo "🔁 Checking for open redirects (subset)..."
  head -200 "$OUTPUT_DIR/urls_with_params.txt" | qsreplace 'http://example.com' | httpx -silent -fr -title -match-string 'Example Domain' | tee "$OUTPUT_DIR/open_redirects.txt" >/dev/null || true
fi

# Directory fuzzing (parallelized)
echo "📂 Directory fuzzing..."
if command -v ffuf >/dev/null 2>&1; then
  WORDLIST="$SCRIPT_DIR/wordlists/common.txt"
  if [ -f "$WORDLIST" ]; then
    export WORDLIST
    export OUTPUT_DIR
    P 'subdomain={}; out="$OUTPUT_DIR/dirs_$(echo {= s:/:_: =} | tr ":" "_").json"; ffuf -u "${subdomain%/}/FUZZ" -w "$WORDLIST" -ac -o "$out" -of json -s || true' :::: "$OUTPUT_DIR/live_subdomains.txt"
  fi
fi

# Generate report
echo "📊 Generating report..."
cat > "$OUTPUT_DIR/report.html" << EOFHTML
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .vuln { background: #ffebee; border-left: 4px solid #f44336; }
        .info { background: #e3f2fd; border-left: 4px solid #2196f3; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Bug Bounty Report</h1>
        <p><strong>Target:</strong> $TARGET</p>
        <p><strong>Date:</strong> $(date)</p>
    </div>
    
    <div class="section info">
        <h2>📊 Summary</h2>
        <ul>
            <li>Total Subdomains: $(wc -l < "$OUTPUT_DIR/all_subdomains.txt")</li>
            <li>Live Subdomains: $(wc -l < "$OUTPUT_DIR/live_subdomains.txt")</li>
            <li>URLs Discovered: $(wc -l < "$OUTPUT_DIR/all_urls.txt")</li>
            <li>Live URLs: $(wc -l < "$OUTPUT_DIR/live_urls.txt")</li>
            <li>URLs with Parameters: $(wc -l < "$OUTPUT_DIR/urls_with_params.txt" 2>/dev/null || echo "0")</li>
        </ul>
    </div>
    
    <div class="section vuln">
        <h2>🔍 Vulnerability Findings</h2>
        <pre>$(cat "$OUTPUT_DIR/vulnerabilities.txt" 2>/dev/null || echo "No vulnerabilities found")</pre>
    </div>
    
    <div class="section info">
        <h2>🌐 Live Subdomains</h2>
        <pre>$(cat "$OUTPUT_DIR/live_subdomains.txt")</pre>
    </div>
    
    <div class="section info">
        <h2>🚪 Open Ports</h2>
        <pre>$(cat "$OUTPUT_DIR/ports.txt")</pre>
    </div>
</body>
</html>
EOFHTML

echo "✅ Advanced scan completed! Results saved to: $OUTPUT_DIR"
echo "📊 Summary:"
echo "   - Total Subdomains: $(wc -l < "$OUTPUT_DIR/all_subdomains.txt")"
echo "   - Live Subdomains: $(wc -l < "$OUTPUT_DIR/live_subdomains.txt")"
echo "   - URLs Discovered: $(wc -l < "$OUTPUT_DIR/all_urls.txt")"
echo "   - Live URLs: $(wc -l < "$OUTPUT_DIR/live_urls.txt")"
echo "   - Vulnerabilities: $(wc -l < "$OUTPUT_DIR/vulnerabilities.txt" 2>/dev/null || echo "0")"
echo "📄 HTML Report: $OUTPUT_DIR/report.html"
