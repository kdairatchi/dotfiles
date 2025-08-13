#!/bin/bash

# Advanced Bug Bounty Scan Script
# Usage: ./advanced_scan.sh example.com

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="$HOME/bug_bounty_framework/results/$(date +%Y%m%d_%H%M%S)_$TARGET"
mkdir -p "$OUTPUT_DIR"

echo "🎯 Starting advanced scan for $TARGET"
echo "📁 Results will be saved to: $OUTPUT_DIR"

# Subdomain enumeration (multiple sources)
echo "🔍 Finding subdomains (multiple sources)..."
subfinder -d "$TARGET" -silent | tee "$OUTPUT_DIR/subfinder.txt"
assetfinder --subs-only "$TARGET" | tee "$OUTPUT_DIR/assetfinder.txt"
cat "$OUTPUT_DIR/subfinder.txt" "$OUTPUT_DIR/assetfinder.txt" | sort -u | tee "$OUTPUT_DIR/all_subdomains.txt"

# Check live subdomains with details
echo "🌐 Checking live subdomains with details..."
cat "$OUTPUT_DIR/all_subdomains.txt" | httpx -silent -tech-detect -status-code -content-length | tee "$OUTPUT_DIR/live_subdomains_detailed.txt"
cat "$OUTPUT_DIR/live_subdomains_detailed.txt" | cut -d' ' -f1 | tee "$OUTPUT_DIR/live_subdomains.txt"

# Port scanning (comprehensive)
echo "🚪 Comprehensive port scanning..."
naabu -host "$TARGET" -top-ports 3000 -silent | tee "$OUTPUT_DIR/ports.txt"

# URL discovery (multiple sources)
echo "🔗 Discovering URLs from multiple sources..."
cat "$OUTPUT_DIR/live_subdomains.txt" | waybackurls | tee "$OUTPUT_DIR/wayback_urls.txt"
cat "$OUTPUT_DIR/live_subdomains.txt" | gau | tee "$OUTPUT_DIR/gau_urls.txt"
cat "$OUTPUT_DIR/wayback_urls.txt" "$OUTPUT_DIR/gau_urls.txt" | sort -u | tee "$OUTPUT_DIR/all_urls.txt"

# Filter live URLs
echo "🔍 Filtering live URLs..."
cat "$OUTPUT_DIR/all_urls.txt" | httpx -silent -mc 200,301,302,403 | tee "$OUTPUT_DIR/live_urls.txt"

# Parameter discovery
echo "🔧 Discovering parameters..."
cat "$OUTPUT_DIR/live_urls.txt" | grep -E "\?" | tee "$OUTPUT_DIR/urls_with_params.txt"

# Vulnerability scanning (comprehensive)
echo "🔍 Comprehensive vulnerability scanning..."
nuclei -l "$OUTPUT_DIR/live_subdomains.txt" -t ~/nuclei-templates/ -o "$OUTPUT_DIR/vulnerabilities.txt" -silent -severity critical,high,medium

# XSS testing
echo "🔍 Testing for XSS vulnerabilities..."
if [ -s "$OUTPUT_DIR/urls_with_params.txt" ]; then
    head -20 "$OUTPUT_DIR/urls_with_params.txt" | dalfox pipe -o "$OUTPUT_DIR/xss_results.txt" 2>/dev/null
fi

# Directory fuzzing
echo "📂 Directory fuzzing..."
head -10 "$OUTPUT_DIR/live_subdomains.txt" | while read subdomain; do
    echo "Fuzzing: $subdomain"
    ffuf -u "$subdomain/FUZZ" -w ~/bug_bounty_framework/wordlists/common.txt -o "$OUTPUT_DIR/dirs_$(echo $subdomain | tr '/:' '_').json" -of json -s
done

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
