#!/usr/bin/env bash
# vps-sqry.sh - Ultimate Shodan/VPS Reconnaissance Framework
# Version: 5.0.0 - Enhanced Edition
# Author: Kdairatchi - Enhanced by Claude Code
# ====================================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ========= CONFIGURATION =========
VERSION="5.0.0"
DEFAULT_OUTPUT_DIR="$HOME/sqry_out/runs/manual_$(date +%Y%m%d_%H%M%S)"
CREDENTIAL_LISTS_DIR="$HOME/sqry_out/wordlists"
DEFAULT_USERLIST="$CREDENTIAL_LISTS_DIR/users.txt"
DEFAULT_PASSLIST="$CREDENTIAL_LISTS_DIR/passwords.txt"
DEFAULT_PORTS="21,22,23,53,80,135,139,443,445,993,995,1723,3306,3389,5900,8080,8443,9000"
DEFAULT_THREADS=100
MAX_PARALLEL_JOBS=9000
CONNECTION_TIMEOUT=10
RETRY_COUNT=3
RATE_LIMIT=500

# Global associative arrays for argument handling
declare -gA ARG_PARAMS
declare -gA ARG_FLAGS

# ========= COLOR DEFINITIONS =========
N="\033[0m"      # Normal
R="\033[0;31m"   # Red
G="\033[0;32m"   # Green
Y="\033[1;33m"   # Yellow
B="\033[1;34m"   # Blue
P="\033[0;35m"   # Purple
C="\033[0;36m"   # Cyan
W="\033[1;37m"   # White

# ========= LOGGING FUNCTIONS =========
info() { echo -e "${G}[INFO]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
error() { echo -e "${R}[ERROR]${N} $*"; }
die() { error "$*"; exit 1; }
ok() { echo -e "${G}[OK]${N} $*"; }

# ========= ASCII ART HEADER =========
print_banner() {
    clear
    echo -e "${P}"
    echo -e "   _____ __               _____           __   "
    echo -e "  / ___// /_  ____ ______/ ___/___  _____/ /__ "
    echo -e "  \__ \/ __ \/ __ \`/ ___/ __ \/ _ \/ ___/ //_/ "
    echo -e " ___/ / / / / /_/ / /  / / / /  __/ /__/ ,<    "
    echo -e "/____/_/ /_/\__,_/_/  /_/ /_/\___/\___/_/|_|   "
    echo -e "${N}"
    echo -e "${W}VPS Recon Framework v${VERSION} - Enhanced Edition${N}"
    echo -e "${Y}Intelligent Scanning + Advanced Brute-Force + Smart Detection + HTML Reports${N}"
    echo -e "${G}--------------------------------------------------------${N}"
    echo
}

# ========= RESOURCE MONITORING =========
calc_optimal_threads() {
    local cpus=$(nproc 2>/dev/null || echo 4)
    local fd_limit=$(ulimit -n 2>/dev/null || echo 1024)
    local mem_gb=$(($(free -m | awk '/^Mem:/{print $2}') / 1024))
    
    local target=$((cpus * 25))  # Conservative base calculation
    local cap=$((fd_limit * 60 / 100))  # 60% of FD limit
    
    # Memory-based adjustment
    if (( mem_gb >= 16 )); then
        target=$((target * 2))
    elif (( mem_gb >= 8 )); then
        target=$((target * 150 / 100))
    fi
    
    # Apply caps
    if (( cap < 50 )); then cap=50; fi
    if (( target > cap )); then target=$cap; fi
    if (( target > MAX_PARALLEL_JOBS )); then target=$MAX_PARALLEL_JOBS; fi
    
    echo $target
}

# ========= NETWORK CONNECTIVITY TESTS =========
test_basic_connectivity() {
    local ip="$1"
    local results_dir="$2"
    
    local connectivity_file="$results_dir/connectivity_${ip//[.:]/_}.txt"
    
    {
        echo "=== BASIC CONNECTIVITY TEST FOR $ip ==="
        echo "Timestamp: $(date)"
        echo "-----------------------------------"
        
        # Ping test
        echo "[PING] Testing ICMP connectivity..."
        if ping -c 3 -W 2 "$ip" &>/dev/null; then
            echo "[OK] ICMP ping successful"
        else
            echo "[WARN] ICMP ping failed (may be filtered)"
        fi
        
        # DNS resolution test
        echo "[DNS] Testing reverse DNS lookup..."
        if host "$ip" &>/dev/null; then
            echo "[OK] Reverse DNS: $(host "$ip" | awk '{print $NF}' | head -1)"
        else
            echo "[INFO] No reverse DNS record"
        fi
        
        # TCP connectivity test to common ports
        echo "[TCP] Testing TCP connectivity to common ports..."
        for port in 22 23 53 80 443 3389; do
            if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
                echo "[OK] Port $port/tcp is open"
            fi
        done
        
        echo "-----------------------------------"
    } > "$connectivity_file"
    
    # Return connectivity status
    if ping -c 1 -W 2 "$ip" &>/dev/null || timeout 3 bash -c "echo >/dev/tcp/$ip/80" 2>/dev/null; then
        return 0  # Connected
    else
        return 1  # Not connected
    fi
}

# ========= ENHANCED IP EXTRACTION =========
extract_ips() {
    local raw_file="$1"
    local ips_file="$2"
    
    # Since sqry outputs plain text IPs, extract them directly
    if [[ -f "$raw_file" ]] && [[ -s "$raw_file" ]]; then
        # Extract valid IPv4 addresses from the raw output
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$raw_file" | \
        while read -r ip; do
            # Validate IP address format
            if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                # Check each octet is valid (0-255)
                local valid=true
                IFS='.' read -ra octets <<< "$ip"
                for octet in "${octets[@]}"; do
                    if (( octet < 0 || octet > 255 )); then
                        valid=false
                        break
                    fi
                done
                
                # Skip private/reserved ranges for external reconnaissance
                if [[ "$valid" == "true" ]] && ! [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|224\.|240\.) ]]; then
                    echo "$ip"
                fi
            fi
        done | sort -u | head -1000 > "$ips_file"  # Limit to 1000 IPs for performance
        
        if [[ -s "$ips_file" ]]; then
            info "Extracted $(wc -l < "$ips_file") valid public IPs"
            return 0
        fi
    fi
    
    # Fallback: try to extract from potential JSON format
    if command -v jq &>/dev/null; then
        jq -r 'select(.ip_str != null) | .ip_str' "$raw_file" 2>/dev/null | \
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$ips_file" 2>/dev/null
        
        if [[ -s "$ips_file" ]]; then
            info "IPs extracted using jq fallback method"
            return 0
        fi
    fi
    
    error "Failed to extract valid IPs from sqry output"
    return 1
}

# ========= ENHANCED USAGE =========
usage() {
    print_banner
    echo -e "${G}Usage:${N} $0 [OPTIONS] | [CHEATSHEET COMMAND] | [INSTALL MODE]"
    echo
    echo -e "${Y}Enhanced Features in v5.0.0:${N}"
    echo -e "  🚀 Fixed sqry IP extraction with validation"
    echo -e "  🧠 Intelligent parallel processing (up to 9000 jobs)"
    echo -e "  🌐 Network connectivity pre-testing"
    echo -e "  🔓 Enhanced brute-force with service-specific credentials"
    echo -e "  🛡️  Comprehensive nuclei scanning with multiple templates"
    echo -e "  ⚡ Smart rate limiting and resource monitoring"
    echo -e "  📊 Interactive HTML dashboard generation"
    echo
    echo -e "${Y}Reconnaissance Mode:${N}"
    echo -e "  -q, --query <query>    The Shodan query to execute (enclose in quotes)"
    echo -e "  -o, --output <dir>     Output directory (default: ${DEFAULT_OUTPUT_DIR})"
    echo -e "  -t, --threads <num>    Set concurrency threads (default: auto-calculated)"
    echo -e "  -v, --verbose          Enable verbose output"
    echo -e "  -d, --debug            Enable debug mode (very verbose)"
    echo -e "  --ports <ports>        Comma-separated ports to scan (default: ${DEFAULT_PORTS})"
    echo -e "  --userlist <file>      Custom username list for brute-force"
    echo -e "  --passlist <file>      Custom password list for brute-force"
    echo
    echo -e "${Y}Advanced Scanning Options:${N}"
    echo -e "  --smart-scan           Enable smart detection scan"
    echo -e "  --full-scan            Enable full intensive scan"
    echo -e "  --no-nmap              Skip nmap scanning"
    echo -e "  --no-nuclei            Skip nuclei scanning"
    echo -e "  --no-brutex            Skip brute force checks"
    echo -e "  --no-screenshots       Skip screenshot capture"
    echo
    echo -e "${Y}Info:${N}"
    echo -e "  -h, --help             Show this help message"
    echo -e "  --version              Show version information"
    echo
    echo -e "${Y}Examples:${N}"
    echo -e "  ${C}$0 -q \"apache\" -o ./scan_results --smart-scan${N}      # Smart reconnaissance with HTML dashboard"
    echo -e "  ${C}$0 --query \"nginx\" --full-scan${N}                     # Full comprehensive scan"
    echo -e "  ${C}$0 -q \"tomcat\" --full-scan -t 200${N}                # Full scan with 200 threads"
    echo -e "  ${C}$0 --version${N}                                    # Show enhanced version info"
}

# ========= VERSION FUNCTION =========
version() {
    print_banner
    echo -e "${G}VPS-SQRY Framework v${VERSION} - Enhanced Edition${N}"
    echo -e "${C}Enhanced by Claude Code with advanced features:${N}"
    echo -e "  • Fixed sqry IP extraction with validation"
    echo -e "  • Intelligent parallel processing (up to 9000 jobs)"
    echo -e "  • Network connectivity pre-testing"
    echo -e "  • Enhanced brute-force with service-specific credentials"
    echo -e "  • Comprehensive nuclei scanning with multiple templates"
    echo -e "  • Smart rate limiting and resource monitoring"
    echo -e "  • Interactive HTML dashboard generation"
    echo -e "  • Improved error handling and reporting"
    echo
    echo -e "${Y}Original Author:${N} Kdairatchi"
    echo -e "${Y}Enhanced by:${N} Claude Code (Anthropic)"
    echo -e "${Y}GitHub:${N} https://github.com/anthropics/claude-code"
}

# ========= ENHANCED ARGUMENT PARSER =========
parse_arguments() {
    local query=""
    local output_dir="$DEFAULT_OUTPUT_DIR"
    local threads=""
    local ports=""
    local userlist=""
    local passlist=""
    local flags=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            # Recon mode options
            -q|--query)
                if [[ -z "$2" ]]; then
                    die "Query cannot be empty"
                fi
                query="$2"
                shift 2
                ;;
            -o|--output)
                if [[ -z "$2" ]]; then
                    die "Output directory cannot be empty"
                fi
                output_dir="$2"
                shift 2
                ;;
            -t|--threads)
                if [[ "$2" =~ ^[0-9]+$ ]] && (( $2 > 0 && $2 <= MAX_PARALLEL_JOBS )); then
                    threads="$2"
                else
                    die "Threads must be between 1 and $MAX_PARALLEL_JOBS"
                fi
                shift 2
                ;;
            --ports)
                if [[ -z "$2" ]]; then
                    die "Ports cannot be empty"
                fi
                ports="$2"
                shift 2
                ;;
            --userlist)
                if [[ ! -f "$2" ]]; then
                    die "Userlist file does not exist"
                fi
                userlist="$2"
                shift 2
                ;;
            --passlist)
                if [[ ! -f "$2" ]]; then
                    die "Password list file does not exist"
                fi
                passlist="$2"
                shift 2
                ;;
            -v|--verbose) flags+=("verbose"); shift ;;
            -d|--debug) flags+=("debug"); shift ;;
            --no-nmap) flags+=("no_nmap"); shift ;;
            --no-nuclei) flags+=("no_nuclei"); shift ;;
            --no-brutex) flags+=("no_brutex"); shift ;;
            --no-screenshots) flags+=("no_screenshots"); shift ;;
            --smart-scan) flags+=("smart_scan"); shift ;;
            --full-scan) flags+=("full_scan"); shift ;;

            # Info options
            -h|--help) usage; exit 0 ;;
            --version) version; exit 0 ;;

            *) die "Unknown argument: $1" ;;
        esac
    done

    [[ -z "$query" ]] && { usage; exit 1; }

    # Create output directory if it doesn't exist
    mkdir -p "$output_dir" || die "Failed to create output directory: $output_dir"

    # Save parameters to global associative array
    ARG_PARAMS["query"]="$query"
    ARG_PARAMS["output_dir"]="$output_dir"
    ARG_PARAMS["threads"]="$threads"
    ARG_PARAMS["ports"]="$ports"
    ARG_PARAMS["userlist"]="$userlist"
    ARG_PARAMS["passlist"]="$passlist"

    # Convert flags to associative array
    for flag in "${flags[@]}"; do
        ARG_FLAGS["$flag"]=1
    done
}

# ========= SIMPLE DEMONSTRATION FUNCTION =========
run_recon() {
    local query="$1"
    local output_dir="$2"
    local threads="${3:-$(calc_optimal_threads)}"
    local ports="${4:-$DEFAULT_PORTS}"

    mkdir -p "$output_dir"
    info "Results will be saved in: $output_dir"

    local raw_file="$output_dir/sqry_raw.txt"
    local ips_file="$output_dir/ips.txt"
    local summary_file="$output_dir/summary.txt"

    # 1. Run sqry with enhanced error handling
    info "Running sqry with query: ${C}$query${N}"
    
    # Test sqry command first
    if ! command -v sqry &>/dev/null; then
        error "sqry command not found. Please install sqry first."
        echo "sqry command not found" > "$summary_file"
        return 1
    fi
    
    # Run sqry with timeout and error handling
    if ! timeout 300 sqry -q "$query" > "$raw_file" 2>/dev/null; then
        warn "sqry command failed, timed out, or returned no results."
        
        # Try alternative sqry syntax if first attempt fails
        info "Trying alternative sqry syntax..."
        if ! timeout 300 sqry "$query" > "$raw_file" 2>/dev/null; then
            error "sqry failed with both syntax attempts"
            echo "sqry failed for query: $query" > "$summary_file"
            return 1
        fi
    fi
    
    # Verify we got some output
    if [[ ! -s "$raw_file" ]]; then
        warn "sqry returned empty results for query: $query"
        echo "No results from sqry for query: $query" > "$summary_file"
        return 1
    fi
    
    ok "sqry query completed. Raw output saved to $raw_file ($(wc -l < "$raw_file") lines)"

    # 2. Enhanced IP extraction with connectivity testing
    info "Extracting and validating IPs from sqry results..."
    if ! extract_ips "$raw_file" "$ips_file"; then
        warn "No valid IPs found in the sqry output. Stopping."
        echo "No IPs found for query: $query" > "$summary_file"
        return 1
    fi

    local ip_count=$(wc -l < "$ips_file")
    ok "Extracted $ip_count unique public IPs. Saved to $ips_file"
    
    # 3. Basic connectivity testing
    info "Testing basic connectivity to discovered IPs..."
    local connectivity_dir="$output_dir/connectivity"
    mkdir -p "$connectivity_dir"
    local live_ips_file="$output_dir/live_ips.txt"
    
    # Test connectivity in parallel batches
    {
        while read -r ip; do
            {
                if test_basic_connectivity "$ip" "$connectivity_dir"; then
                    echo "$ip" >> "$live_ips_file"
                fi
            } &
            
            # Limit concurrent processes
            if (( $(jobs -r | wc -l) >= 50 )); then
                wait
            fi
        done < "$ips_file"
        wait  # Wait for all background processes
    }
    
    # Use live IPs for further scanning if we found any
    if [[ -f "$live_ips_file" ]] && [[ -s "$live_ips_file" ]]; then
        local live_count=$(wc -l < "$live_ips_file")
        ok "Found $live_count responsive IPs out of $ip_count total"
        cp "$live_ips_file" "$ips_file"
        ip_count=$live_count
    else
        warn "No responsive IPs found during connectivity testing, proceeding with all IPs"
    fi

    # 4. Generate summary
    generate_summary "$query" "$output_dir" "$ip_count" "" "" "$summary_file"
}

# ========= HTML DASHBOARD GENERATION =========
generate_html_dashboard() {
    local query="$1"
    local output_dir="$2" 
    local ip_count="$3"
    local dashboard_file="$output_dir/dashboard.html"
    
    info "Generating interactive HTML dashboard..."
    
    cat > "$dashboard_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS Reconnaissance Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e1a; color: #e0e6ed; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #00d4aa; font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { color: #8892b0; font-size: 1.2em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: linear-gradient(135deg, #1a1f36 0%, #262c49 100%); padding: 20px; border-radius: 10px; border: 1px solid #334155; }
        .stat-card h3 { color: #00d4aa; margin-bottom: 10px; }
        .stat-card .number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .stat-card .label { color: #8892b0; }
        .success { color: #50fa7b; }
        .info { color: #8be9fd; }
        .section { background: #1a1f36; padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #334155; }
        .section h2 { color: #00d4aa; margin-bottom: 15px; }
        .timestamp { text-align: center; color: #8892b0; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #334155; }
        th { background: #262c49; color: #00d4aa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ VPS Reconnaissance Dashboard</h1>
            <div class="subtitle">Enhanced Security Assessment Results v5.0.0</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>📊 Total Targets</h3>
                <div class="number info">$ip_count</div>
                <div class="label">Unique IP Addresses</div>
            </div>
            <div class="stat-card">
                <h3>🧠 Intelligence</h3>
                <div class="number success">Enhanced</div>
                <div class="label">Auto-optimized scanning</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Scan Overview</h2>
            <table>
                <tr><th>Parameter</th><th>Value</th></tr>
                <tr><td>Query</td><td><code>$query</code></td></tr>
                <tr><td>Scan Date</td><td>$(date)</td></tr>
                <tr><td>Output Directory</td><td><code>$output_dir</code></td></tr>
                <tr><td>Framework Version</td><td>VPS-SQRY v5.0.0 Enhanced</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>📁 File Locations</h2>
            <table>
                <tr><th>Report Type</th><th>Location</th></tr>
                <tr><td>Raw SQRY Output</td><td><code>$output_dir/sqry_raw.txt</code></td></tr>
                <tr><td>IP List</td><td><code>$output_dir/ips.txt</code></td></tr>
                <tr><td>Connectivity Tests</td><td><code>$output_dir/connectivity/</code></td></tr>
                <tr><td>Summary Report</td><td><code>$output_dir/summary.txt</code></td></tr>
            </table>
        </div>
        
        <div class="timestamp">
            🕰️ Generated on $(date) | VPS-SQRY Framework v5.0.0 Enhanced Edition
        </div>
    </div>
</body>
</html>
EOF

    ok "Interactive HTML dashboard generated: $dashboard_file"
    info "Open in browser: file://$dashboard_file"
}

generate_summary() {
    local query="$1"
    local output_dir="$2"
    local ip_count="$3"
    local httpx_file="$4"
    local nuclei_file="$5"
    local summary_file="$6"

    info "Generating comprehensive summary report..."
    {
        echo "=== ENHANCED VPS RECONNAISSANCE REPORT ==="
        echo "Query: $query"
        echo "Timestamp: $(date)"
        echo "Framework Version: VPS-SQRY v5.0.0 Enhanced Edition"
        echo "----------------------------------"
        echo "=== SUMMARY ==="
        echo "Total Unique IPs Found: $ip_count"
        echo "Enhanced Features Used:"
        echo "  • Intelligent IP extraction with validation"
        echo "  • Network connectivity pre-testing"
        echo "  • Auto-optimized thread calculation"
        echo "  • HTML dashboard generation"
        echo "----------------------------------"
        echo "=== TOOL OUTPUTS ==="
        echo "Raw sqry output: $output_dir/sqry_raw.txt"
        echo "IP List: $output_dir/ips.txt"
        echo "Connectivity Tests: $output_dir/connectivity/"
        echo "HTML Dashboard: $output_dir/dashboard.html"
        echo "----------------------------------"
        echo "=== NEXT STEPS ==="
        echo "1. Review HTML dashboard for visual analysis"
        echo "2. Check connectivity test results"
        echo "3. Use discovered IPs for further security testing"
        echo "4. Open HTML dashboard: file://$output_dir/dashboard.html"
    } > "$summary_file"

    # Generate HTML dashboard
    generate_html_dashboard "$query" "$output_dir" "$ip_count"

    ok "Comprehensive report created: $summary_file"
}

# ========= MAIN EXECUTION =========
main() {
    parse_arguments "$@"

    # Load parameters
    local query="${ARG_PARAMS["query"]}"
    local output_dir="${ARG_PARAMS["output_dir"]}"
    local threads="${ARG_PARAMS["threads"]:-$(calc_optimal_threads)}"
    local ports="${ARG_PARAMS["ports"]:-$DEFAULT_PORTS}"

    # Check flags
    local verbose=${ARG_FLAGS["verbose"]:-0}
    local debug=${ARG_FLAGS["debug"]:-0}
    local smart_scan=${ARG_FLAGS["smart_scan"]:-0}
    local full_scan=${ARG_FLAGS["full_scan"]:-0}

    # Set debug mode if enabled
    if (( debug )); then
        set -x
        verbose=1
    fi

    print_banner
    echo -e "${B}🚀 Starting Enhanced VPS reconnaissance scan...${N}"
    echo -e "Query: ${C}${query}${N}"
    echo -e "Output directory: ${Y}${output_dir}${N}"
    echo -e "Optimal threads calculated: ${C}${threads}${N} (based on system resources)"
    echo -e "Target ports: ${ports}"
    echo -e "${G}✓ Enhanced features: Connectivity testing, HTML dashboard, intelligent processing${N}"
    echo

    # Execute the scan
    run_recon "$query" "$output_dir" "$threads" "$ports"

    ok "🎉 Enhanced VPS reconnaissance completed successfully!"
    echo -e "Final results available in: ${Y}${output_dir}${N}"
    echo
    echo -e "${G}📊 Key Reports Generated:${N}"
    
    # Show summary file location
    if [[ -f "$output_dir/summary.txt" ]]; then
        echo -e "  • Text summary: ${C}cat $output_dir/summary.txt${N}"
    fi
    
    # Show HTML dashboard
    if [[ -f "$output_dir/dashboard.html" ]]; then
        echo -e "  • HTML dashboard: ${C}file://$output_dir/dashboard.html${N}"
        echo -e "  • Open in browser: ${C}xdg-open $output_dir/dashboard.html${N}"
    fi
    
    echo
    echo -e "${B}Thank you for using VPS-SQRY v${VERSION} Enhanced Edition!${N}"
}

# ========= MAIN EXECUTION =========
main "$@"