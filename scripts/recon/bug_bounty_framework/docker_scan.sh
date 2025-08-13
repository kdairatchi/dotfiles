#!/bin/bash

# Docker-based Bug Bounty Scan
# Usage: ./docker_scan.sh example.com

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="$HOME/bug_bounty_framework/results/$(date +%Y%m%d_%H%M%S)_$TARGET"
mkdir -p "$OUTPUT_DIR"

echo "🐳 Starting Docker-based scan for $TARGET"

# Run subfinder in Docker
echo "🔍 Running subfinder in Docker..."
docker run -it --rm -v "$OUTPUT_DIR:/output" projectdiscovery/subfinder:latest -d "$TARGET" -o /output/subdomains.txt

# Run httpx in Docker
echo "🌐 Running httpx in Docker..."
docker run -it --rm -v "$OUTPUT_DIR:/output" projectdiscovery/httpx:latest -l /output/subdomains.txt -o /output/live_subdomains.txt

# Run nuclei in Docker
echo "🔍 Running nuclei in Docker..."
docker run -it --rm -v "$OUTPUT_DIR:/output" projectdiscovery/nuclei:latest -l /output/live_subdomains.txt -o /output/vulnerabilities.txt

echo "✅ Docker scan completed! Results saved to: $OUTPUT_DIR"
