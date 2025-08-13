#!/bin/bash

# Quick Bug Bounty Scan Script
# Usage: ./quick_scan.sh example.com

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="$HOME/bug_bounty_framework/results/$(date +%Y%m%d_%H%M%S)_$TARGET"
mkdir -p "$OUTPUT_DIR"

echo "🎯 Starting quick scan for $TARGET"
echo "📁 Results will be saved to: $OUTPUT_DIR"


# Subdomain enumeration
echo "🔍 Finding subdomains..."
if command -v subfinder &> /dev/null; then
    subfinder -d "$TARGET" -silent | tee "$OUTPUT_DIR/subdomains.txt"
else
    echo "subfinder not found!"; exit 1
fi

# Check live subdomains
echo "🌐 Checking live subdomains..."
if command -v httpx &> /dev/null; then
    cat "$OUTPUT_DIR/subdomains.txt" | httpx -silent | tee "$OUTPUT_DIR/live_subdomains.txt"
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

# URL discovery
echo "🔗 Discovering URLs..."
if command -v waybackurls &> /dev/null; then
    cat "$OUTPUT_DIR/live_subdomains.txt" | waybackurls | tee "$OUTPUT_DIR/urls.txt"
else
    echo "waybackurls not found!"; exit 1
fi

# Vulnerability scanning
echo "🔍 Scanning for vulnerabilities..."
if command -v nuclei &> /dev/null; then
    nuclei -l "$OUTPUT_DIR/live_subdomains.txt" -t ~/nuclei-templates/ -o "$OUTPUT_DIR/vulnerabilities.txt" -silent
else
    echo "nuclei not found!"; exit 1
fi

# Quick directory fuzzing
echo "📂 Quick directory fuzzing..."
if command -v ffuf &> /dev/null; then
    ffuf -u "http://$TARGET/FUZZ" -w ~/bug_bounty_framework/wordlists/common.txt -o "$OUTPUT_DIR/directories.json" -of json -s
else
    echo "ffuf not found!"; exit 1
fi

echo "✅ Scan completed! Results saved to: $OUTPUT_DIR"
echo "📊 Summary:"
echo "   - Subdomains: $(wc -l < "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || echo "0")"
echo "   - Live subdomains: $(wc -l < "$OUTPUT_DIR/live_subdomains.txt" 2>/dev/null || echo "0")"
echo "   - URLs: $(wc -l < "$OUTPUT_DIR/urls.txt" 2>/dev/null || echo "0")"
echo "   - Vulnerabilities: $(wc -l < "$OUTPUT_DIR/vulnerabilities.txt" 2>/dev/null || echo "0")"
