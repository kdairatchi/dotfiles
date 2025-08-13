#!/bin/bash

# Enhanced Security Scanner Script
# Author: ~/.kdairatchi@anon
# Version: 2.0

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
RESET='\033[0m'
BOLD='\033[1m'

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/results_$(date +%Y%m%d_%H%M%S)"
THREADS=50
TIMEOUT=30
RETRIES=3

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${RESET} ${timestamp} - $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${RESET} ${timestamp} - $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${RESET} ${timestamp} - $message" ;;
        "SUCCESS") echo -e "${CYAN}[SUCCESS]${RESET} ${timestamp} - $message" ;;
    esac
}

# ASCII art banner
show_banner() {
    echo -e "${RED}${BOLD}"
    cat << "EOF"
 ______            _____________                              
___  /______________  /___  **/**_  _________________________
__  /_  __ \_  ___/  __/_  /_ *  / / /*_  /__  /_  * \*  ___/
*  / / /*/ /(__  )/ /_ *  *_/ / /_/ /__  /__  /_/  __/  /    
*/  \*___//____/ \__/ /_/    \__,_/ _____/____/\___//_/ 
      
                                Enhanced Security Scanner v2.0
                                       by ~/.kdairatchi@anon
EOF
    echo -e "${RESET}"
}

# Check if required tools are installed
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local required_tools=(
        "gau"
        "uro" 
        "httpx"
        "nuclei"
        "subfinder"
        "assetfinder"
        "amass"
        "waybackurls"
        "ffuf"
        "gobuster"
        "curl"
        "jq"
        "parallel"
    )
    
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        log "INFO" "Install missing tools with:"
        echo "  go install github.com/tomnomnom/gau/v2/cmd/gau@latest"
        echo "  go install github.com/s0md3v/uro@latest"
        echo "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        echo "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "  go install github.com/tomnomnom/assetfinder@latest"
        echo "  go install github.com/tomnomnom/waybackurls@latest"
        echo "  go install github.com/ffuf/ffuf@latest"
        echo "  apt install gobuster curl jq parallel"
        exit 1
    fi
    
    log "SUCCESS" "All dependencies are installed"
}

# Advanced subdomain enumeration
enumerate_subdomains() {
    local domain="$1"
    local output_file="$OUTPUT_DIR/subdomains_$domain.txt"
    
    log "INFO" "Starting subdomain enumeration for $domain"
    
    # Run multiple subdomain tools in parallel
    {
        subfinder -d "$domain" -silent &
        assetfinder --subs-only "$domain" &
        amass enum -passive -d "$domain" -silent &
        curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' &
        curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | cut -d',' -f1 &
    } | sort -u > "$output_file"
    
    wait
    
    # Remove wildcards and clean up
    sed -i '/^\*\./d' "$output_file"
    sed -i 's/^\.//g' "$output_file"
    sort -u "$output_file" -o "$output_file"
    
    local count=$(wc -l < "$output_file")
    log "SUCCESS" "Found $count subdomains for $domain"
    echo "$output_file"
}

# Enhanced URL discovery with multiple sources
discover_urls() {
    local target="$1"
    local output_file="$OUTPUT_DIR/urls_raw.txt"
    
    log "INFO" "Starting URL discovery for $target"
    
    # Use multiple URL discovery tools in parallel
    {
        echo "$target" | gau --threads "$THREADS" --timeout "$TIMEOUT" &
        echo "$target" | waybackurls &
        
        # Common paths discovery
        gobuster dir -u "https://$target" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t "$THREADS" -q --no-error -o "$OUTPUT_DIR/gobuster_$target.txt" 2>/dev/null &
        
        # Parameter discovery
        ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "https://$target/FUZZ" -mc 200,301,302,403 -t "$THREADS" -s &
        
        # Common file extensions
        for ext in php asp aspx jsp js json xml txt pdf doc; do
            echo "https://$target/sitemap.$ext"
            echo "https://$target/robots.txt"
            echo "https://$target/.well-known/security.txt"
        done
        
    } | sort -u > "$output_file"
    
    wait
    
    log "SUCCESS" "URL discovery completed"
    echo "$output_file"
}

# Advanced URL filtering and processing
process_urls() {
    local input_file="$1"
    local filtered_file="$OUTPUT_DIR/urls_filtered.txt"
    local live_urls_file="$OUTPUT_DIR/urls_live.txt"
    
    log "INFO" "Processing and filtering URLs"
    
    # Filter URLs with parameters and interesting patterns
    grep -E '\?[^=]+=.+$|\.js$|\.json$|\.xml$|\.txt$|\.pdf$|admin|login|api|v1|v2|upload|backup' "$input_file" | \
    uro --filters hasparams,duplicate,length,regex:".*\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$" | \
    sort -u > "$filtered_file"
    
    # Check for live URLs using httpx with parallel processing
    log "INFO" "Checking live URLs with httpx"
    httpx -l "$filtered_file" \
        -silent \
        -threads "$THREADS" \
        -timeout "$TIMEOUT" \
        -retries "$RETRIES" \
        -status-code \
        -content-length \
        -follow-redirects \
        -random-agent \
        -rate-limit 100 \
        -o "$live_urls_file"
    
    local count=$(wc -l < "$live_urls_file")
    log "SUCCESS" "Found $count live URLs"
    echo "$live_urls_file"
}

# Enhanced nuclei scanning with multiple templates
run_nuclei_scan() {
    local urls_file="$1"
    local nuclei_output="$OUTPUT_DIR/nuclei_results.txt"
    local nuclei_json="$OUTPUT_DIR/nuclei_results.json"
    
    log "INFO" "Starting Nuclei DAST scanning"
    
    # Update nuclei templates
    nuclei -update-templates -silent
    
    # Run nuclei with comprehensive templates
    nuclei \
        -list "$urls_file" \
        -dast \
        -t exposures/ \
        -t vulnerabilities/ \
        -t misconfiguration/ \
        -t default-logins/ \
        -t takeovers/ \
        -t technologies/ \
        -rate-limit 100 \
        -threads "$THREADS" \
        -retries "$RETRIES" \
        -timeout "$TIMEOUT" \
        -silent \
        -json \
        -o "$nuclei_json"
    
    # Convert JSON to readable format
    if [ -s "$nuclei_json" ]; then
        jq -r '.info.name + " | " + .host + " | " + .info.severity' "$nuclei_json" > "$nuclei_output"
        log "SUCCESS" "Nuclei scan completed - Results saved to $nuclei_output"
    else
        log "INFO" "No vulnerabilities found by Nuclei"
    fi
    
    echo "$nuclei_output"
}

# Additional security checks
run_additional_checks() {
    local targets_file="$1"
    local output_dir="$OUTPUT_DIR/additional_checks"
    
    mkdir -p "$output_dir"
    
    log "INFO" "Running additional security checks"
    
    # Check for common security headers
    log "INFO" "Checking security headers"
    while IFS= read -r url; do
        {
            echo "=== $url ==="
            curl -s -I "$url" | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy)"
        } >> "$output_dir/security_headers.txt"
    done < "$targets_file"
    
    # Check for sensitive files
    log "INFO" "Checking for sensitive files"
    local sensitive_files=(
        ".env"
        ".git/config"
        "wp-config.php"
        "config.php"
        "database.php"
        "phpinfo.php"
        ".htaccess"
        "web.config"
        "server.xml"
        "application.properties"
    )
    
    for file in "${sensitive_files[@]}"; do
        while IFS= read -r domain; do
            curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "https://$domain/$file"
        done < <(sed 's|https\?://||g' "$targets_file") >> "$output_dir/sensitive_files.txt"
    done
    
    log "SUCCESS" "Additional checks completed"
}

# Generate comprehensive report
generate_report() {
    local report_file="$OUTPUT_DIR/security_report.html"
    
    log "INFO" "Generating comprehensive security report"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }
        .critical { border-left-color: #ff4444; }
        .high { border-left-color: #ff8800; }
        .medium { border-left-color: #ffcc00; }
        .low { border-left-color: #44ff44; }
        .info { border-left-color: #007acc; }
        pre { background-color: #f8f8f8; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <p>Generated on: $(date)</p>
        <p>Scan Duration: $(date -d @$(($(date +%s) - START_TIME)) -u +%H:%M:%S)</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Subdomains</h3>
            <p>$(find "$OUTPUT_DIR" -name "subdomains_*.txt" -exec wc -l {} + | tail -1 | awk '{print $1}' || echo "0")</p>
        </div>
        <div class="stat-box">
            <h3>URLs Found</h3>
            <p>$(wc -l < "$OUTPUT_DIR/urls_live.txt" 2>/dev/null || echo "0")</p>
        </div>
        <div class="stat-box">
            <h3>Vulnerabilities</h3>
            <p>$(wc -l < "$OUTPUT_DIR/nuclei_results.txt" 2>/dev/null || echo "0")</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <p>This report contains the results of an automated security scan performed on the specified targets.</p>
    </div>
    
    <div class="section">
        <h2>Files Generated</h2>
        <ul>
EOF
    
    find "$OUTPUT_DIR" -type f -name "*.txt" -o -name "*.json" | while read -r file; do
        echo "            <li><a href=\"$(basename "$file")\">$(basename "$file")</a></li>" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF
        </ul>
    </div>
</body>
</html>
EOF
    
    log "SUCCESS" "Report generated: $report_file"
}

# Cleanup function
cleanup() {
    log "INFO" "Cleaning up temporary files"
    find /tmp -name "gau_*" -o -name "httpx_*" -o -name "nuclei_*" -delete 2>/dev/null || true
}

# Main execution function
main() {
    local start_time=$(date +%s)
    START_TIME=$start_time
    
    show_banner
    check_dependencies
    
    # Get user input
    echo -e "${CYAN}Enter target domain or path to subdomains file:${RESET}"
    read -r INPUT
    
    if [ -z "$INPUT" ]; then
        log "ERROR" "Input cannot be empty"
        exit 1
    fi
    
    # Process input
    if [ -f "$INPUT" ]; then
        log "INFO" "Using subdomains from file: $INPUT"
        TARGETS_FILE="$INPUT"
    else
        log "INFO" "Single domain provided: $INPUT"
        # Remove protocols if present
        DOMAIN=$(echo "$INPUT" | sed 's|https\?://||g')
        
        # Enumerate subdomains
        TARGETS_FILE=$(enumerate_subdomains "$DOMAIN")
        
        # Add main domain to targets
        echo "$DOMAIN" >> "$TARGETS_FILE"
        sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
    fi
    
    # Discover URLs
    log "INFO" "Starting URL discovery phase"
    URLS_FILE=$(discover_urls "$(head -1 "$TARGETS_FILE")")
    
    # Process additional targets in parallel
    if [ $(wc -l < "$TARGETS_FILE") -gt 1 ]; then
        tail -n +2 "$TARGETS_FILE" | parallel -j "$THREADS" "gau --threads 10 {} >> $URLS_FILE"
    fi
    
    # Process URLs
    LIVE_URLS_FILE=$(process_urls "$URLS_FILE")
    
    # Run security scans
    run_nuclei_scan "$LIVE_URLS_FILE"
    run_additional_checks "$LIVE_URLS_FILE"
    
    # Generate report
    generate_report
    
    # Show results
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo -e "\n${GREEN}${BOLD}=== SCAN COMPLETED ===${RESET}"
    log "SUCCESS" "Scan completed in $(date -d @$duration -u +%H:%M:%S)"
    log "INFO" "Results saved in: $OUTPUT_DIR"
    
    # Show summary
    if [ -f "$OUTPUT_DIR/nuclei_results.txt" ] && [ -s "$OUTPUT_DIR/nuclei_results.txt" ]; then
        echo -e "\n${RED}${BOLD}Vulnerabilities Found:${RESET}"
        cat "$OUTPUT_DIR/nuclei_results.txt"
    else
        echo -e "\n${GREEN}No vulnerabilities detected${RESET}"
    fi
    
    cleanup
}

# Signal handling
trap cleanup EXIT
trap 'log "ERROR" "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"
