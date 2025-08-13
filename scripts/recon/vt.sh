#!/bin/bash

# Ultimate URL Fetcher - Enhanced domain reconnaissance script with parallel processing
# Fetches URLs from multiple threat intelligence sources with parallel execution
# Author: Enhanced by Claude
# Version: 3.0

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
DOMAIN=""
OUTPUT_DIR=""
TOTAL_URLS=0
VT_API_KEY=""
ALIEN_VAULT_ENABLED=true
WAYBACK_ENABLED=true
URLSCAN_ENABLED=true
CRTSH_ENABLED=true
WAYMORE_ENABLED=true
COMMONCRAWL_ENABLED=true
THREADS=50
TIMEOUT=30
PARALLEL_JOBS=5
MAX_WAYMORE_URLS=10000

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

print_parallel() {
    echo -e "${CYAN}[PARALLEL]${NC} $1"
}

# Function to show banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╦ ╦╦ ╔╦╗╦╔╦╗╔═╗╔╦╗╔═╗  ╦ ╦╦═╗╦    ╔═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦═╗
    ║ ║║  ║ ║║║║╠═╣ ║ ║╣   ║ ║╠╦╝║    ╠╣ ║╣  ║ ║  ╠═╣║╣ ╠╦╝
    ╚═╝╩═╝╩ ╩╩ ╩╩ ╩ ╩ ╚═╝  ╚═╝╩╚═╩═╝  ╚  ╚═╝ ╩ ╚═╝╩ ╩╚═╝╩╚═
EOF
    echo -e "${NC}"
    echo -e "${CYAN}    Enhanced Domain URL Reconnaissance Tool v3.0${NC}"
    echo -e "${CYAN}    Parallel processing with Waymore integration${NC}"
    echo ""
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    local deps=("curl" "jq" "parallel")
    local optional_deps=("waymore" "httpx")
    local missing_deps=()
    local missing_optional=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    for dep in "${optional_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_optional+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install missing dependencies:"
        echo "  Ubuntu/Debian: sudo apt-get install ${missing_deps[*]}"
        echo "  CentOS/RHEL: sudo yum install ${missing_deps[*]}"
        echo "  macOS: brew install ${missing_deps[*]}"
        echo ""
        echo "For GNU parallel on Ubuntu/Debian: sudo apt-get install parallel"
        echo "For GNU parallel on macOS: brew install parallel"
        exit 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        print_warning "Missing optional dependencies: ${missing_optional[*]}"
        if [[ " ${missing_optional[*]} " =~ " waymore " ]]; then
            print_warning "Waymore not found. Install with: pip3 install waymore"
            WAYMORE_ENABLED=false
        fi
        if [[ " ${missing_optional[*]} " =~ " httpx " ]]; then
            print_warning "httpx not found. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        fi
    fi
    
    print_success "Required dependencies satisfied"
}

# Function to validate domain
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_error "Invalid domain format: $domain"
        return 1
    fi
    return 0
}

# Function to setup output directory
setup_output_dir() {
    OUTPUT_DIR="${DOMAIN}_recon_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR/raw" "$OUTPUT_DIR/processed"
    print_success "Created output directory: $OUTPUT_DIR"
}

# Function to get VirusTotal API key
get_vt_api_key() {
    if [[ -n "${VT_API_KEY:-}" ]]; then
        return 0
    fi
    
    # Check environment variable
    if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
        VT_API_KEY="$VIRUSTOTAL_API_KEY"
        return 0
    fi
    
    # Check config file
    if [[ -f ~/.config/recon/vt_api_key ]]; then
        VT_API_KEY=$(cat ~/.config/recon/vt_api_key)
        return 0
    fi
    
    print_warning "VirusTotal API key not found"
    read -p "Enter VirusTotal API key (or press Enter to skip): " VT_API_KEY
    
    if [[ -n "$VT_API_KEY" ]]; then
        # Optionally save the key
        read -p "Save API key for future use? (y/N): " save_key
        if [[ "$save_key" =~ ^[Yy]$ ]]; then
            mkdir -p ~/.config/recon
            echo "$VT_API_KEY" > ~/.config/recon/vt_api_key
            chmod 600 ~/.config/recon/vt_api_key
            print_success "API key saved to ~/.config/recon/vt_api_key"
        fi
    fi
}

# Function to create parallel job wrapper
create_job_function() {
    cat > "${OUTPUT_DIR}/.job_functions.sh" << 'EOF'
#!/bin/bash

# Job functions for parallel execution
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'

print_parallel() {
    echo -e "${CYAN}[PARALLEL-$1]${NC} $2"
}

print_success_parallel() {
    echo -e "${GREEN}[SUCCESS-$1]${NC} $2"
}

print_warning_parallel() {
    echo -e "${YELLOW}[WARNING-$1]${NC} $2"
}

# VirusTotal job
fetch_virustotal_job() {
    local domain="$1"
    local output_dir="$2"
    local api_key="$3"
    local timeout="$4"
    
    if [[ -z "$api_key" ]]; then
        print_warning_parallel "VT" "Skipping VirusTotal (no API key)"
        return 0
    fi
    
    print_parallel "VT" "Fetching VirusTotal URLs for: $domain"
    
    local output_file="${output_dir}/raw/virustotal_urls.txt"
    local temp_file=$(mktemp)
    
    local response
    response=$(curl -s --max-time "$timeout" \
        -H "x-apikey: $api_key" \
        "https://www.virustotal.com/api/v3/domains/${domain}/urls?limit=40" \
        2>/dev/null || true)
    
    if [[ -z "$response" ]]; then
        print_warning_parallel "VT" "No response from VirusTotal API"
        return 0
    fi
    
    if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"')
        print_warning_parallel "VT" "API error: $error_msg"
        return 0
    fi
    
    local urls
    urls=$(echo "$response" | jq -r '.data[]?.attributes?.url // empty' 2>/dev/null || true)
    
    if [[ -n "$urls" ]]; then
        echo "$urls" > "$output_file"
        local count
        count=$(wc -l < "$output_file")
        print_success_parallel "VT" "Found $count URLs"
    else
        print_warning_parallel "VT" "No URLs found"
    fi
    
    rm -f "$temp_file"
}

# AlienVault OTX job
fetch_alienvault_job() {
    local domain="$1"
    local output_dir="$2"
    local timeout="$3"
    
    print_parallel "OTX" "Fetching AlienVault OTX URLs for: $domain"
    
    local output_file="${output_dir}/raw/alienvault_urls.txt"
    local temp_file=$(mktemp)
    local page=1
    local limit=200
    local total_found=0
    
    > "$temp_file"
    
    while [[ $page -le 10 ]]; do  # Limit to 10 pages for performance
        local response
        response=$(curl -s --max-time "$timeout" \
            "https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=${limit}&page=${page}" \
            2>/dev/null || true)
        
        if [[ -z "$response" ]]; then
            break
        fi
        
        if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
            break
        fi
        
        local urls
        urls=$(echo "$response" | jq -r '.url_list[]?.url // empty' 2>/dev/null || true)
        
        if [[ -z "$urls" ]]; then
            break
        fi
        
        echo "$urls" >> "$temp_file"
        local page_count
        page_count=$(echo "$urls" | wc -l)
        total_found=$((total_found + page_count))
        
        if (( page_count < limit )); then
            break
        fi
        
        page=$((page + 1))
        sleep 0.5  # Rate limiting
    done
    
    if [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$output_file"
        print_success_parallel "OTX" "Found $total_found URLs"
    else
        print_warning_parallel "OTX" "No URLs found"
    fi
    
    rm -f "$temp_file"
}

# Wayback Machine job
fetch_wayback_job() {
    local domain="$1"
    local output_dir="$2"
    local timeout="$3"
    
    print_parallel "WB" "Fetching Wayback Machine URLs for: $domain"
    
    local output_file="${output_dir}/raw/wayback_urls.txt"
    
    local response
    response=$(curl -s --max-time "$timeout" \
        "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=txt&fl=original&collapse=urlkey" \
        2>/dev/null || true)
    
    if [[ -n "$response" ]]; then
        echo "$response" > "$output_file"
        local count
        count=$(wc -l < "$output_file")
        print_success_parallel "WB" "Found $count URLs"
    else
        print_warning_parallel "WB" "No URLs found"
    fi
}

# URLScan.io job
fetch_urlscan_job() {
    local domain="$1"
    local output_dir="$2"
    local timeout="$3"
    
    print_parallel "US" "Fetching URLScan.io URLs for: $domain"
    
    local output_file="${output_dir}/raw/urlscan_urls.txt"
    
    local response
    response=$(curl -s --max-time "$timeout" \
        "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000" \
        2>/dev/null || true)
    
    if [[ -n "$response" ]]; then
        local urls
        urls=$(echo "$response" | jq -r '.results[]?.page?.url // empty' 2>/dev/null || true)
        
        if [[ -n "$urls" ]]; then
            echo "$urls" > "$output_file"
            local count
            count=$(wc -l < "$output_file")
            print_success_parallel "US" "Found $count URLs"
        else
            print_warning_parallel "US" "No URLs found"
        fi
    else
        print_warning_parallel "US" "No response from API"
    fi
}

# crt.sh job
fetch_crtsh_job() {
    local domain="$1"
    local output_dir="$2"
    local timeout="$3"
    
    print_parallel "CRT" "Fetching subdomains from crt.sh for: $domain"
    
    local output_file="${output_dir}/raw/crtsh_subdomains.txt"
    
    local response
    response=$(curl -s --max-time "$timeout" \
        "https://crt.sh/?q=%.${domain}&output=json" \
        2>/dev/null || true)
    
    if [[ -n "$response" ]]; then
        local subdomains
        subdomains=$(echo "$response" | jq -r '.[].name_value' 2>/dev/null | \
                    grep -E "^[a-zA-Z0-9]" | sort -u || true)
        
        if [[ -n "$subdomains" ]]; then
            echo "$subdomains" > "$output_file"
            local count
            count=$(wc -l < "$output_file")
            print_success_parallel "CRT" "Found $count subdomains"
        else
            print_warning_parallel "CRT" "No subdomains found"
        fi
    else
        print_warning_parallel "CRT" "No response from crt.sh"
    fi
}

# Waymore job
fetch_waymore_job() {
    local domain="$1"
    local output_dir="$2"
    local max_urls="$3"
    
    print_parallel "WM" "Running Waymore for: $domain"
    
    local waymore_dir="${output_dir}/raw/waymore"
    mkdir -p "$waymore_dir"
    
    # Run waymore with comprehensive options
    if command -v waymore &>/dev/null; then
        waymore -i "$domain" \
                -mode U \
                -oU "${waymore_dir}/waymore_urls.txt" \
                -oR "${waymore_dir}/waymore_responses" \
                --limit-requests "$max_urls" \
                --no-subs \
                >/dev/null 2>&1 || true
        
        if [[ -f "${waymore_dir}/waymore_urls.txt" ]]; then
            local count
            count=$(wc -l < "${waymore_dir}/waymore_urls.txt" 2>/dev/null || echo "0")
            print_success_parallel "WM" "Found $count URLs"
        else
            print_warning_parallel "WM" "No URLs found"
        fi
    else
        print_warning_parallel "WM" "Waymore not available"
    fi
}

# CommonCrawl job
fetch_commoncrawl_job() {
    local domain="$1"
    local output_dir="$2"
    local timeout="$3"
    
    print_parallel "CC" "Fetching CommonCrawl URLs for: $domain"
    
    local output_file="${output_dir}/raw/commoncrawl_urls.txt"
    
    # Get latest CommonCrawl index
    local cc_index
    cc_index=$(curl -s --max-time 10 "https://index.commoncrawl.org/collinfo.json" | \
               jq -r '.[0].id' 2>/dev/null || echo "CC-MAIN-2024-10")
    
    local response
    response=$(curl -s --max-time "$timeout" \
        "https://index.commoncrawl.org/${cc_index}-index?url=*.${domain}/*&output=json" \
        2>/dev/null || true)
    
    if [[ -n "$response" ]]; then
        local urls
        urls=$(echo "$response" | jq -r '.url' 2>/dev/null | head -5000 || true)
        
        if [[ -n "$urls" ]]; then
            echo "$urls" > "$output_file"
            local count
            count=$(wc -l < "$output_file")
            print_success_parallel "CC" "Found $count URLs"
        else
            print_warning_parallel "CC" "No URLs found"
        fi
    else
        print_warning_parallel "CC" "No response from CommonCrawl"
    fi
}

export -f fetch_virustotal_job
export -f fetch_alienvault_job
export -f fetch_wayback_job
export -f fetch_urlscan_job
export -f fetch_crtsh_job
export -f fetch_waymore_job
export -f fetch_commoncrawl_job
export -f print_parallel
export -f print_success_parallel
export -f print_warning_parallel
EOF

    chmod +x "${OUTPUT_DIR}/.job_functions.sh"
    source "${OUTPUT_DIR}/.job_functions.sh"
}

# Function to run parallel jobs
run_parallel_jobs() {
    print_status "Starting parallel URL reconnaissance..."
    
    create_job_function
    
    local job_list=()
    
    # Build job list based on enabled sources
    if [[ -n "$VT_API_KEY" ]]; then
        job_list+=("fetch_virustotal_job $DOMAIN $OUTPUT_DIR $VT_API_KEY $TIMEOUT")
    fi
    
    if [[ "$ALIEN_VAULT_ENABLED" == true ]]; then
        job_list+=("fetch_alienvault_job $DOMAIN $OUTPUT_DIR $TIMEOUT")
    fi
    
    if [[ "$WAYBACK_ENABLED" == true ]]; then
        job_list+=("fetch_wayback_job $DOMAIN $OUTPUT_DIR $TIMEOUT")
    fi
    
    if [[ "$URLSCAN_ENABLED" == true ]]; then
        job_list+=("fetch_urlscan_job $DOMAIN $OUTPUT_DIR $TIMEOUT")
    fi
    
    if [[ "$CRTSH_ENABLED" == true ]]; then
        job_list+=("fetch_crtsh_job $DOMAIN $OUTPUT_DIR $TIMEOUT")
    fi
    
    if [[ "$WAYMORE_ENABLED" == true ]]; then
        job_list+=("fetch_waymore_job $DOMAIN $OUTPUT_DIR $MAX_WAYMORE_URLS")
    fi
    
    if [[ "$COMMONCRAWL_ENABLED" == true ]]; then
        job_list+=("fetch_commoncrawl_job $DOMAIN $OUTPUT_DIR $TIMEOUT")
    fi
    
    if [[ ${#job_list[@]} -eq 0 ]]; then
        print_warning "No data sources enabled"
        return 0
    fi
    
    print_status "Running ${#job_list[@]} parallel jobs with $PARALLEL_JOBS workers..."
    
    # Run jobs in parallel
    printf '%s\n' "${job_list[@]}" | \
        parallel --will-cite -j "$PARALLEL_JOBS" --bar \
        'source '"${OUTPUT_DIR}/.job_functions.sh"' && eval {}'
    
    print_success "Parallel job execution completed"
}

# Function to combine and deduplicate URLs
combine_urls() {
    print_status "Processing and combining URLs..."
    
    local combined_file="${OUTPUT_DIR}/processed/all_urls.txt"
    local unique_file="${OUTPUT_DIR}/processed/unique_urls.txt"
    local clean_file="${OUTPUT_DIR}/processed/clean_urls.txt"
    local live_file="${OUTPUT_DIR}/processed/live_urls.txt"
    
    # Combine all URL files including waymore
    {
        find "$OUTPUT_DIR/raw" -name "*_urls.txt" -exec cat {} \; 2>/dev/null || true
        [[ -f "$OUTPUT_DIR/raw/waymore/waymore_urls.txt" ]] && cat "$OUTPUT_DIR/raw/waymore/waymore_urls.txt" 2>/dev/null || true
    } > "$combined_file"
    
    if [[ -s "$combined_file" ]]; then
        # Remove duplicates and sort
        sort -u "$combined_file" > "$unique_file"
        local unique_count
        unique_count=$(wc -l < "$unique_file")
        local total_count
        total_count=$(wc -l < "$combined_file")
        
        print_success "Combined URLs: $total_count total, $unique_count unique"
        
        # Create a clean list (remove static files and apply filters)
        grep -E '^https?://' "$unique_file" | \
        grep -v -E '\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot|svg|pdf|zip|tar|gz|rar|exe|dmg|iso)(\?|#|$)' | \
        grep -E "\.${DOMAIN//./\\.}(/|$)" > "$clean_file" || touch "$clean_file"
        
        local clean_count
        clean_count=$(wc -l < "$clean_file")
        print_success "Clean URLs (filtered): $clean_count"
        
        # Check for live URLs if httpx is available
        if command -v httpx &>/dev/null && [[ -s "$clean_file" ]]; then
            print_status "Checking for live URLs with httpx..."
            httpx -l "$clean_file" -silent -timeout 10 -threads "$THREADS" > "$live_file" 2>/dev/null || touch "$live_file"
            local live_count
            live_count=$(wc -l < "$live_file")
            print_success "Live URLs found: $live_count"
        fi
    else
        print_warning "No URLs found to combine"
        touch "$unique_file" "$clean_file"
    fi
}

# Function to generate comprehensive statistics
generate_statistics() {
    print_status "Generating statistics..."
    
    local stats_file="${OUTPUT_DIR}/reconnaissance_report.txt"
    
    cat > "$stats_file" << EOF
===========================================
URL Reconnaissance Report
===========================================
Target Domain: $DOMAIN
Scan Date: $(date)
Output Directory: $OUTPUT_DIR

===========================================
Source Statistics
===========================================
EOF

    # Count URLs from each source
    local sources=("virustotal" "alienvault" "wayback" "urlscan" "crtsh" "commoncrawl")
    local total_raw=0
    
    for source in "${sources[@]}"; do
        local file="${OUTPUT_DIR}/raw/${source}_urls.txt"
        if [[ -f "$file" ]]; then
            local count
            count=$(wc -l < "$file")
            printf "%-15s: %d URLs\n" "$source" "$count" >> "$stats_file"
            total_raw=$((total_raw + count))
        else
            printf "%-15s: 0 URLs\n" "$source" >> "$stats_file"
        fi
    done
    
    # Waymore statistics
    local waymore_file="${OUTPUT_DIR}/raw/waymore/waymore_urls.txt"
    if [[ -f "$waymore_file" ]]; then
        local waymore_count
        waymore_count=$(wc -l < "$waymore_file")
        printf "%-15s: %d URLs\n" "waymore" "$waymore_count" >> "$stats_file"
        total_raw=$((total_raw + waymore_count))
    else
        printf "%-15s: 0 URLs\n" "waymore" >> "$stats_file"
    fi
    
    cat >> "$stats_file" << EOF

===========================================
Processing Statistics
===========================================
EOF
    
    # Processing statistics
    local processed_files=("all_urls.txt" "unique_urls.txt" "clean_urls.txt" "live_urls.txt")
    for file in "${processed_files[@]}"; do
        local filepath="${OUTPUT_DIR}/processed/${file}"
        if [[ -f "$filepath" ]]; then
            local count
            count=$(wc -l < "$filepath")
            printf "%-15s: %d URLs\n" "${file%.*}" "$count" >> "$stats_file"
        else
            printf "%-15s: 0 URLs\n" "${file%.*}" >> "$stats_file"
        fi
    done
    
    cat >> "$stats_file" << EOF

===========================================
File Breakdown
===========================================
Raw Data Files:
$(find "$OUTPUT_DIR/raw" -name "*.txt" -exec basename {} \; | sort | sed 's/^/  - /')

Processed Files:
$(find "$OUTPUT_DIR/processed" -name "*.txt" -exec basename {} \; | sort | sed 's/^/  - /')

===========================================
Recommended Next Steps
===========================================
1. HTTP Probing:
   httpx -l ${OUTPUT_DIR}/processed/clean_urls.txt -title -status-code -tech-detect -threads ${THREADS}

2. Parameter Discovery:
   paramspider -l ${OUTPUT_DIR}/processed/live_urls.txt

3. Directory Discovery:
   cat ${OUTPUT_DIR}/processed/live_urls.txt | feroxbuster --stdin

4. Screenshot Capture:
   gowitness file -f ${OUTPUT_DIR}/processed/live_urls.txt

5. Vulnerability Scanning:
   nuclei -l ${OUTPUT_DIR}/processed/live_urls.txt

6. Content Discovery:
   hakrawler -urls ${OUTPUT_DIR}/processed/live_urls.txt

===========================================
EOF

    print_success "Report generated: $stats_file"
}

# Function to show summary and next steps
show_summary() {
    echo ""
    print_header "🎯 RECONNAISSANCE SUMMARY"
    echo "Domain: $DOMAIN"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    
    print_header "📊 RESULTS OVERVIEW:"
    
    # Count results from each category
    local unique_count=0
    local clean_count=0
    local live_count=0
    
    [[ -f "${OUTPUT_DIR}/processed/unique_urls.txt" ]] && unique_count=$(wc -l < "${OUTPUT_DIR}/processed/unique_urls.txt")
    [[ -f "${OUTPUT_DIR}/processed/clean_urls.txt" ]] && clean_count=$(wc -l < "${OUTPUT_DIR}/processed/clean_urls.txt")
    [[ -f "${OUTPUT_DIR}/processed/live_urls.txt" ]] && live_count=$(wc -l < "${OUTPUT_DIR}/processed/live_urls.txt")
    
    printf "  %-20s %s\n" "Unique URLs:" "$unique_count"
    printf "  %-20s %s\n" "Clean URLs:" "$clean_count"
    printf "  %-20s %s\n" "Live URLs:" "$live_count"
    
    echo ""
    print_header "🔍 QUICK START COMMANDS:"
    echo ""
    echo "# Probe live URLs:"
    echo "httpx -l ${OUTPUT_DIR}/processed/clean_urls.txt -title -status-code -tech-detect"
    echo ""
    echo "# Find parameters:"
    echo "paramspider -l ${OUTPUT_DIR}/processed/live_urls.txt"
    echo ""
    echo "# Directory fuzzing:"
    echo "ffuf -u FUZZ -w /path/to/wordlist -ic -c"
    echo ""
    echo "# Vulnerability scanning:"
    echo "nuclei -l ${OUTPUT_DIR}/processed/live_urls.txt -t /path/to/templates"
    echo ""
    
    print_header "📋 Full report available at: ${OUTPUT_DIR}/reconnaissance_report.txt"
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN       Target domain (required)"
    echo "  -k, --api-key KEY         VirusTotal API key"
    echo "  -j, --jobs NUM            Number of parallel jobs (default: 5)"
    echo "  -t, --threads NUM         Number of threads for httpx (default: 50)"
    echo "  --timeout NUM             Request timeout in seconds (default: 30)"
    echo "  --max-waymore NUM         Max URLs for Waymore (default: 10000)"
    echo "  --no-alienvault           Disable AlienVault OTX"
    echo "  --no-wayback              Disable Wayback Machine"
    echo "  --no-urlscan              Disable URLScan.io"
    echo "  --no-crtsh                Disable crt.sh"
    echo "  --no-waymore              Disable Waymore"
    echo "  --no-commoncrawl          Disable CommonCrawl"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -k YOUR_VT_API_KEY -j 8"
    echo "  $0 -d example.com --no-wayback --no-waymore --threads 100"
    echo "  $0 -d example.com --max-waymore 50000 --timeout 60"
}

# Main function
main() {
    show_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -k|--api-key)
                VT_API_KEY="$2"
                shift 2
                ;;
            -j|--jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --max-waymore)
                MAX_WAYMORE_URLS="$2"
                shift 2
                ;;
            --no-alienvault)
                ALIEN_VAULT_ENABLED=false
                shift
                ;;
            --no-wayback)
                WAYBACK_ENABLED=false
                shift
                ;;
            --no-urlscan)
                URLSCAN_ENABLED=false
                shift
                ;;
            --no-crtsh)
                CRTSH_ENABLED=false
                shift
                ;;
            --no-waymore)
                WAYMORE_ENABLED=false
                shift
                ;;
            --no-commoncrawl)
                COMMONCRAWL_ENABLED=false
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Prompt for domain if not provided
    if [[ -z "$DOMAIN" ]]; then
        read -p "Enter the target domain (e.g., example.com): " DOMAIN
    fi
    
    # Validate domain
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Setup output directory
    setup_output_dir
    
    # Get API keys
    get_vt_api_key
    
    print_status "Starting parallel URL reconnaissance for: $DOMAIN"
    print_status "Parallel jobs: $PARALLEL_JOBS"
    print_status "HTTP threads: $THREADS"
    print_status "Request timeout: ${TIMEOUT}s"
    echo ""
    
    # Show enabled sources
    print_header "🔧 ENABLED SOURCES:"
    [[ -n "$VT_API_KEY" ]] && echo "  ✅ VirusTotal" || echo "  ❌ VirusTotal (no API key)"
    [[ "$ALIEN_VAULT_ENABLED" == true ]] && echo "  ✅ AlienVault OTX" || echo "  ❌ AlienVault OTX"
    [[ "$WAYBACK_ENABLED" == true ]] && echo "  ✅ Wayback Machine" || echo "  ❌ Wayback Machine"
    [[ "$URLSCAN_ENABLED" == true ]] && echo "  ✅ URLScan.io" || echo "  ❌ URLScan.io"
    [[ "$CRTSH_ENABLED" == true ]] && echo "  ✅ crt.sh" || echo "  ❌ crt.sh"
    [[ "$WAYMORE_ENABLED" == true ]] && echo "  ✅ Waymore" || echo "  ❌ Waymore"
    [[ "$COMMONCRAWL_ENABLED" == true ]] && echo "  ✅ CommonCrawl" || echo "  ❌ CommonCrawl"
    echo ""
    
    # Start timer
    local start_time
    start_time=$(date +%s)
    
    # Run parallel reconnaissance
    run_parallel_jobs
    
    # Process and combine results
    combine_urls
    
    # Generate comprehensive statistics
    generate_statistics
    
    # Calculate execution time
    local end_time
    end_time=$(date +%s)
    local execution_time=$((end_time - start_time))
    
    # Show summary
    show_summary
    
    print_success "Reconnaissance completed in ${execution_time} seconds"
    print_status "Check the full report: ${OUTPUT_DIR}/reconnaissance_report.txt"
}

# Trap to cleanup temp files on exit
trap 'rm -f /tmp/recon_temp_* "${OUTPUT_DIR}/.job_functions.sh" 2>/dev/null || true' EXIT

# Run main function
main "$@"
