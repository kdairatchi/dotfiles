#!/bin/bash
# Enhanced Wayback Machine URL Extractor
# Author: Security Research Team
# Version: 2.0

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               ENHANCED WAYBACK MACHINE TOOL                 ║"
    echo "║                  URL Discovery & Analysis                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Error handling
set -euo pipefail

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for required tools
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v sort >/dev/null 2>&1 || missing_deps+=("sort")
    command -v uniq >/dev/null 2>&1 || missing_deps+=("uniq")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing dependencies: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}[*] Please install missing tools and rerun${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] All dependencies satisfied${NC}"
}

# Create output directory with timestamp
create_output_dir() {
    local domain=$1
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local output_dir="wayback_${domain}_${timestamp}"
    
    mkdir -p "$output_dir"
    echo "$output_dir"
}

# Validate domain input
validate_domain() {
    local domain=$1
    
    # Basic domain validation
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${RED}[!] Invalid domain format: $domain${NC}"
        return 1
    fi
    
    return 0
}

# Enhanced URL fetching with better error handling
fetch_wayback_urls() {
    local domain=$1
    local output_dir=$2
    local url_type=$3
    
    echo -e "${YELLOW}[*] Fetching $url_type URLs for $domain...${NC}"
    
    local base_url="https://web.archive.org/cdx/search/cdx"
    local output_file="$output_dir/${url_type}_urls.txt"
    
    case $url_type in
        "all")
            curl -G "$base_url" \
                --connect-timeout 30 \
                --max-time 300 \
                --retry 3 \
                --retry-delay 5 \
                --data-urlencode "url=*.$domain/*" \
                --data-urlencode "collapse=urlkey" \
                --data-urlencode "output=text" \
                --data-urlencode "fl=original" \
                -o "$output_file" 2>/dev/null
            ;;
        "sensitive")
            curl -G "$base_url" \
                --connect-timeout 30 \
                --max-time 300 \
                --retry 3 \
                --retry-delay 5 \
                --data-urlencode "url=*.$domain/*" \
                --data-urlencode "collapse=urlkey" \
                --data-urlencode "output=text" \
                --data-urlencode "fl=original" \
                --data-urlencode "filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
                -o "$output_file" 2>/dev/null
            ;;
        "parameters")
            curl -G "$base_url" \
                --connect-timeout 30 \
                --max-time 300 \
                --retry 3 \
                --retry-delay 5 \
                --data-urlencode "url=*.$domain/*" \
                --data-urlencode "collapse=urlkey" \
                --data-urlencode "output=text" \
                --data-urlencode "fl=original" \
                --data-urlencode "filter=original:.*\?.*=" \
                -o "$output_file" 2>/dev/null
            ;;
        "javascript")
            curl -G "$base_url" \
                --connect-timeout 30 \
                --max-time 300 \
                --retry 3 \
                --retry-delay 5 \
                --data-urlencode "url=*.$domain/*" \
                --data-urlencode "collapse=urlkey" \
                --data-urlencode "output=text" \
                --data-urlencode "fl=original" \
                --data-urlencode "filter=original:.*\.js$" \
                -o "$output_file" 2>/dev/null
            ;;
    esac
    
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        local count=$(wc -l < "$output_file")
        echo -e "${GREEN}[+] Found $count $url_type URLs${NC}"
        
        # Remove duplicates and sort
        sort "$output_file" | uniq > "${output_file}.tmp"
        mv "${output_file}.tmp" "$output_file"
        
        return 0
    else
        echo -e "${RED}[!] Failed to fetch $url_type URLs${NC}"
        return 1
    fi
}

# Extract useful information from URLs
analyze_urls() {
    local output_dir=$1
    local domain=$2
    
    echo -e "${BLUE}[*] Analyzing discovered URLs...${NC}"
    
    # Combine all URL files
    cat "$output_dir"/*_urls.txt 2>/dev/null | sort | uniq > "$output_dir/combined_urls.txt"
    
    # Extract endpoints
    echo -e "${YELLOW}[*] Extracting unique endpoints...${NC}"
    grep -oE '/[^?#]*' "$output_dir/combined_urls.txt" 2>/dev/null | sort | uniq > "$output_dir/endpoints.txt" || true
    
    # Extract parameters
    echo -e "${YELLOW}[*] Extracting parameters...${NC}"
    grep -oE '\?[^#]*' "$output_dir/combined_urls.txt" 2>/dev/null | \
        sed 's/\?//' | sed 's/&/\n/g' | \
        grep -oE '^[^=]+' | sort | uniq > "$output_dir/parameters.txt" || true
    
    # Extract subdomains
    echo -e "${YELLOW}[*] Extracting subdomains...${NC}"
    grep -oE 'https?://[^/]+' "$output_dir/combined_urls.txt" 2>/dev/null | \
        sed 's|https\?://||' | grep "\.$domain" | sort | uniq > "$output_dir/subdomains.txt" || true
    
    # Find interesting paths
    echo -e "${YELLOW}[*] Finding interesting paths...${NC}"
    grep -iE '(admin|login|config|backup|test|dev|staging|api|secret|password|key|token)' "$output_dir/endpoints.txt" 2>/dev/null > "$output_dir/interesting_paths.txt" || true
}

# Generate comprehensive report
generate_report() {
    local output_dir=$1
    local domain=$2
    local report_file="$output_dir/wayback_report.html"
    
    echo -e "${BLUE}[*] Generating comprehensive HTML report...${NC}"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wayback Machine Analysis - $domain</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .url-list { max-height: 300px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 8px; }
        .url-item { padding: 5px 0; border-bottom: 1px solid #dee2e6; font-family: monospace; }
        .interesting { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        .critical { background-color: #f8d7da; border-left: 4px solid #dc3545; }
        .info { background-color: #d1ecf1; border-left: 4px solid #17a2b8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕰️ Wayback Machine Analysis</h1>
            <p><strong>Target:</strong> $domain</p>
            <p><strong>Generated:</strong> $(date)</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$([ -f "$output_dir/combined_urls.txt" ] && wc -l < "$output_dir/combined_urls.txt" || echo "0")</div>
                <div>Total URLs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$([ -f "$output_dir/subdomains.txt" ] && wc -l < "$output_dir/subdomains.txt" || echo "0")</div>
                <div>Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$([ -f "$output_dir/parameters.txt" ] && wc -l < "$output_dir/parameters.txt" || echo "0")</div>
                <div>Parameters</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$([ -f "$output_dir/interesting_paths.txt" ] && wc -l < "$output_dir/interesting_paths.txt" || echo "0")</div>
                <div>Interesting Paths</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <div class="info">
                <strong>Analysis Complete:</strong> Successfully retrieved and analyzed URLs from the Wayback Machine for $domain.
                $([ -f "$output_dir/interesting_paths.txt" ] && [ -s "$output_dir/interesting_paths.txt" ] && echo "<br><strong>⚠️ Attention:</strong> Found potentially interesting paths that may warrant manual review.")
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Discovered Subdomains</h2>
            <div class="url-list">
EOF

    if [ -f "$output_dir/subdomains.txt" ] && [ -s "$output_dir/subdomains.txt" ]; then
        head -20 "$output_dir/subdomains.txt" | while read -r subdomain; do
            echo "                <div class=\"url-item\">$subdomain</div>" >> "$report_file"
        done
        local subdomain_count=$(wc -l < "$output_dir/subdomains.txt")
        if [ "$subdomain_count" -gt 20 ]; then
            echo "                <div class=\"url-item\"><em>... and $((subdomain_count - 20)) more subdomains</em></div>" >> "$report_file"
        fi
    else
        echo "                <div class=\"url-item\">No subdomains found</div>" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
            </div>
        </div>
        
        <div class="section">
            <h2>⚡ Interesting Paths</h2>
            <div class="url-list">
EOF

    if [ -f "$output_dir/interesting_paths.txt" ] && [ -s "$output_dir/interesting_paths.txt" ]; then
        head -30 "$output_dir/interesting_paths.txt" | while read -r path; do
            echo "                <div class=\"url-item interesting\">$path</div>" >> "$report_file"
        done
    else
        echo "                <div class=\"url-item\">No interesting paths found</div>" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Discovered Parameters</h2>
            <div class="url-list">
EOF

    if [ -f "$output_dir/parameters.txt" ] && [ -s "$output_dir/parameters.txt" ]; then
        head -50 "$output_dir/parameters.txt" | while read -r param; do
            echo "                <div class=\"url-item\">$param</div>" >> "$report_file"
        done
        local param_count=$(wc -l < "$output_dir/parameters.txt")
        if [ "$param_count" -gt 50 ]; then
            echo "                <div class=\"url-item\"><em>... and $((param_count - 50)) more parameters</em></div>" >> "$report_file"
        fi
    else
        echo "                <div class=\"url-item\">No parameters found</div>" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
            </div>
        </div>
        
        <div class="section">
            <h2>📁 File Analysis</h2>
            <div class="info">
                <strong>File Types Discovered:</strong><br>
                $([ -f "$output_dir/sensitive_urls.txt" ] && grep -oE '\.[a-zA-Z0-9]+$' "$output_dir/sensitive_urls.txt" | sort | uniq -c | sort -nr | head -10 | awk '{print $2 " (" $1 " files)"}' | tr '\n' ', ' | sed 's/, $//' || echo "No sensitive files found")
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Recommendations</h2>
            <div class="interesting">
                <h4>Next Steps:</h4>
                <ul>
                    <li>Review interesting paths for potential vulnerabilities</li>
                    <li>Test discovered parameters for injection flaws</li>
                    <li>Enumerate subdomains for additional attack surface</li>
                    <li>Check sensitive file extensions for information disclosure</li>
                    <li>Verify current availability of discovered endpoints</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>📂 Generated Files</h2>
            <ul>
                <li><strong>combined_urls.txt</strong> - All discovered URLs</li>
                <li><strong>subdomains.txt</strong> - Discovered subdomains</li>
                <li><strong>parameters.txt</strong> - Extracted parameters</li>
                <li><strong>endpoints.txt</strong> - Unique endpoints</li>
                <li><strong>interesting_paths.txt</strong> - Potentially interesting paths</li>
                <li><strong>sensitive_urls.txt</strong> - URLs with sensitive file extensions</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}[+] HTML report generated: $report_file${NC}"
}

# Interactive mode
interactive_mode() {
    print_banner
    echo -e "${WHITE}Enhanced Wayback Machine URL Discovery Tool${NC}"
    echo -e "${YELLOW}Choose analysis type:${NC}"
    echo "1. Quick scan (all URLs)"
    echo "2. Comprehensive scan (all + analysis)"
    echo "3. Sensitive files only"
    echo "4. Parameter extraction only"
    echo "5. JavaScript files only"
    echo ""
    
    read -p "$(echo -e ${BLUE}"[+] Enter your choice (1-5): "${NC})" choice
    
    case $choice in
        1|2|3|4|5) ;;
        *) echo -e "${RED}[!] Invalid choice${NC}"; exit 1 ;;
    esac
    
    read -p "$(echo -e ${BLUE}"[+] Enter the domain (e.g., example.com): "${NC})" domain
    
    if ! validate_domain "$domain"; then
        exit 1
    fi
    
    process_domain "$domain" "$choice"
}

# Process domain based on choice
process_domain() {
    local domain=$1
    local choice=$2
    
    echo -e "${GREEN}[+] Starting Wayback Machine analysis for: $domain${NC}"
    
    local output_dir=$(create_output_dir "$domain")
    echo -e "${BLUE}[*] Output directory: $output_dir${NC}"
    
    case $choice in
        1) # Quick scan
            fetch_wayback_urls "$domain" "$output_dir" "all"
            ;;
        2) # Comprehensive scan
            fetch_wayback_urls "$domain" "$output_dir" "all"
            fetch_wayback_urls "$domain" "$output_dir" "sensitive"
            fetch_wayback_urls "$domain" "$output_dir" "parameters"
            fetch_wayback_urls "$domain" "$output_dir" "javascript"
            analyze_urls "$output_dir" "$domain"
            generate_report "$output_dir" "$domain"
            ;;
        3) # Sensitive files only
            fetch_wayback_urls "$domain" "$output_dir" "sensitive"
            ;;
        4) # Parameter extraction
            fetch_wayback_urls "$domain" "$output_dir" "parameters"
            analyze_urls "$output_dir" "$domain"
            ;;
        5) # JavaScript files
            fetch_wayback_urls "$domain" "$output_dir" "javascript"
            ;;
    esac
    
    echo -e "${GREEN}[+] Analysis complete! Results saved in: $output_dir${NC}"
    
    # Show summary
    if [ -d "$output_dir" ]; then
        echo -e "\n${CYAN}[*] Summary:${NC}"
        for file in "$output_dir"/*.txt; do
            if [ -f "$file" ] && [ -s "$file" ]; then
                local filename=$(basename "$file")
                local count=$(wc -l < "$file")
                echo -e "  ${YELLOW}$filename:${NC} $count entries"
            fi
        done
    fi
}

# Command line argument processing
main() {
    check_dependencies
    
    # Check for command line arguments
    if [ $# -eq 0 ]; then
        interactive_mode
    elif [ $# -eq 1 ]; then
        local domain=$1
        if validate_domain "$domain"; then
            process_domain "$domain" "2"  # Default to comprehensive scan
        else
            exit 1
        fi
    elif [ $# -eq 2 ]; then
        local domain=$1
        local choice=$2
        if validate_domain "$domain"; then
            process_domain "$domain" "$choice"
        else
            exit 1
        fi
    else
        echo -e "${RED}Usage: $0 [domain] [scan_type]${NC}"
        echo -e "${YELLOW}Scan types: 1=quick, 2=comprehensive, 3=sensitive, 4=parameters, 5=javascript${NC}"
        exit 1
    fi
}

# Trap for cleanup
trap 'echo -e "\n${RED}[!] Script interrupted${NC}"; exit 1' INT TERM

# Run main function
main "$@"
