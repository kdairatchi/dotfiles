#!/bin/bash

set -euo pipefail  # Enhanced error handling

# -------------------------------------------------------------
# Common framework: verbosity, monitoring, jobs (for future use)
# -------------------------------------------------------------

usage() {
  cat <<'USAGE'
Usage: ./docker_scan.sh [options] <domain>

Options:
  -v, --verbose      Enable verbose execution (set -x)
  -m, --monitor      Show resource monitor (watch FDs, sockets)
  -h, --help         Show this help

Examples:
  ./docker_scan.sh example.com
  ./docker_scan.sh -v --monitor example.com
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

# GNU parallel wrapper with optimized defaults
P() { parallel --bar -j"${J:-$(calc_jobs)}" "$@"; }

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

# Docker-based Bug Bounty Scan
# Usage: ./docker_scan.sh example.com

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_DIR="$RESULTS_DIR/$(date +%Y%m%d_%H%M%S)_$TARGET"
mkdir -p "$OUTPUT_DIR"

if [[ "$VERBOSE" == true ]]; then set -x; fi
if [[ "$MONITOR" == true ]]; then start_monitor; fi

echo "🐳 Starting Docker-based scan for $TARGET"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required but not installed."
  exit 1
fi

# Subfinder
echo "🔍 Running subfinder in Docker..."
docker run --rm -v "$OUTPUT_DIR:/output" projectdiscovery/subfinder:latest -d "$TARGET" -silent | sort -u | tee "$OUTPUT_DIR/subdomains.txt"

# DNS resolution (dnsx)
if docker image inspect projectdiscovery/dnsx:latest >/dev/null 2>&1; then :; else docker pull projectdiscovery/dnsx:latest >/dev/null 2>&1 || true; fi
echo "🧩 Resolving with dnsx..."
docker run --rm -v "$OUTPUT_DIR:/output" projectdiscovery/dnsx:latest -l /output/subdomains.txt -silent | awk '{print $1}' | sort -u | tee "$OUTPUT_DIR/resolved.txt" >/dev/null

# httpx
echo "🌐 Running httpx in Docker..."
docker run --rm -v "$OUTPUT_DIR:/output" projectdiscovery/httpx:latest -l /output/subdomains.txt -silent | sort -u | tee "$OUTPUT_DIR/live_subdomains.txt"
docker run --rm -v "$OUTPUT_DIR:/output" projectdiscovery/httpx:latest -l /output/subdomains.txt -silent -tech-detect -status-code -content-length | tee "$OUTPUT_DIR/live_subdomains_detailed.txt"

# Port scanning (naabu)
if docker image inspect projectdiscovery/naabu:latest >/dev/null 2>&1; then :; else docker pull projectdiscovery/naabu:latest >/dev/null 2>&1 || true; fi
echo "🚪 Running naabu in Docker..."
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$OUTPUT_DIR:/output" projectdiscovery/naabu:latest -host "$TARGET" -top-ports 1000 -silent | tee "$OUTPUT_DIR/ports.txt" || true

# URL discovery with katana
if docker image inspect projectdiscovery/katana:latest >/dev/null 2>&1; then :; else docker pull projectdiscovery/katana:latest >/dev/null 2>&1 || true; fi
echo "🔗 Running katana in Docker..."
docker run --rm -v "$OUTPUT_DIR:/output" projectdiscovery/katana:latest -list /output/live_subdomains.txt -silent -nc -kf all -ef woff,css,png,svg,jpg,woff2,jpeg,gif -xhr | sort -u | tee "$OUTPUT_DIR/katana_urls.txt"

# nuclei
echo "🔍 Running nuclei in Docker..."
docker run --rm projectdiscovery/nuclei:latest -update-templates >/dev/null 2>&1 || true
docker run --rm -v "$OUTPUT_DIR:/output" projectdiscovery/nuclei:latest -l /output/live_subdomains.txt -severity critical,high,medium -silent | tee "$OUTPUT_DIR/vulnerabilities.txt" || true

echo "✅ Docker scan completed! Results saved to: $OUTPUT_DIR"
