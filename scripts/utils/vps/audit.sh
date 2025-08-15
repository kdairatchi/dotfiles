#!/usr/bin/env bash
# Ultimate Security Reconnaissance & Exploitation Framework
# Author: Kdairatchi + Assistant
# Version: 3.0.0
# Features:
# - Comprehensive target discovery and enumeration
# - Advanced vulnerability assessment
# - Safe exploit verification
# - Automated remediation suggestions
# - Multi-format reporting

set -Eeuo pipefail
IFS=$'\n\t'

# ========= CONFIGURATION =========
BRUTEX_ENABLED=true     # Enable brute force testing
EXPLOIT_CHECKS=true     # Enable safe exploit verification
DEEP_SCAN=true          # Enable thorough scanning
REPORT_DIR="./reports"   # Output directory
NMAP_TIMING="-T4"       # Timing template (-T0 to -T5)
THREADS=10              # Parallel scanning threads
MAX_SCAN_TIME=86400     # Maximum scan time in seconds (24h)

# ========= STYLING =========
G='\033[0;32m'  # Green
Y='\033[1;33m'  # Yellow
R='\033[0;31m'  # Red
C='\033[0;36m'  # Cyan
B='\033[1;34m'  # Blue
N='\033[0m'     # No Color

# ========= LOGGING =========
info() { echo -e "${G}[INFO]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
error() { echo -e "${R}[ERROR]${N} $*"; }
die() { error "$*"; exit 1; }

# ========= BANNER =========
print_banner() {
    echo -e "${B}"
    cat <<'BANNER'
 ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
 ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
 ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗  
 ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
 ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
  ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
                                                                
            ADVANCED SECURITY ASSESSMENT FRAMEWORK
BANNER
    echo -e "${N}"
}

# ========= DEPENDENCY CHECKS =========
check_dependencies() {
    local required=(
        nmap curl jq nikto whatweb hydra sqlmap
        dnsenum whois masscan netcat git python3
        pip3 gobuster seclists testssl.sh ssh-audit
    )
    
    local missing=()
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing dependencies: ${missing[*]}"
        info "Attempting to install..."
        sudo apt-get update && sudo apt-get install -y "${missing[@]}" || {
            warn "Failed to install some packages. Manual installation required."
            for pkg in "${missing[@]}"; do
                case $pkg in
                    seclists) sudo apt-get install -y seclists ;;
                    testssl.sh) 
                        git clone https://github.com/drwetter/testssl.sh.git /opt/testssl
                        ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
                        ;;
                    ssh-audit)
                        pip3 install ssh-audit || {
                            git clone https://github.com/jtesta/ssh-audit.git /opt/ssh-audit
                            ln -s /opt/ssh-audit/ssh-audit.py /usr/local/bin/ssh-audit
                        }
                        ;;
                esac
            done
        }
    fi
    
    # Verify critical tools
    for cmd in nmap curl jq; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "Critical tool $cmd not found after installation attempts"
        fi
    done
}

# ========= TARGET VALIDATION =========
validate_target() {
    local target=$1
    
    # Check if target is IP or domain
    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if ! ping -c 1 -W 2 "$target" &>/dev/null; then
            warn "Target IP $target is not responding to ping"
            return 1
        fi
    else
        if ! host "$target" &>/dev/null; then
            error "Domain $target does not resolve"
            return 1
        fi
    fi
    
    # Check if target has at least one open port
    if ! nc -z -w 2 "$target" 80 443 22 &>/dev/null; then
        warn "No common ports (80,443,22) open on $target"
    fi
    
    return 0
}

# ========= TARGET DISCOVERY =========
discover_targets() {
    local target=$1
    local osint_dir="${REPORT_DIR}/osint"
    mkdir -p "$osint_dir"
    
    info "Starting comprehensive target discovery..."
    
    # 1. DNS Reconnaissance
    dns_enum() {
        info "Running DNS enumeration..."
        dnsenum --noreverse "$target" > "${osint_dir}/dns_enum.txt" 2>&1
        host "$target" > "${osint_dir}/dns_basic.txt" 2>&1
        dig ANY "$target" +noall +answer > "${osint_dir}/dns_dig.txt" 2>&1
        dnsrecon -d "$target" -t std,axfr > "${osint_dir}/dns_recon.txt" 2>&1
        subfinder -d "$target" -silent > "${osint_dir}/subdomains.txt" 2>&1
        curl -s "https://dns.bufferover.run/dns?q=$target" | jq . > "${osint_dir}/passive_dns.json" 2>&1 &
    }
    
    # 2. Network Mapping
    network_discovery() {
        info "Mapping network..."
        nmap -sn "$target"/24 -oG "${osint_dir}/network_discovery.txt" >/dev/null 2>&1
        masscan -p1-65535 "$target"/24 --rate=1000 -oG "${osint_dir}/masscan.txt" >/dev/null 2>&1
        whois "$target" > "${osint_dir}/whois.txt" 2>&1 &
        nslookup "$target" > "${osint_dir}/nslookup.txt" 2>&1 &
        netdiscover -i eth0 -r "$target"/24 -P > "${osint_dir}/netdiscover.txt" 2>&1 &
    }
    
    # 3. Certificate Transparency
    cert_checks() {
        info "Checking certificate logs..."
        curl -s "https://crt.sh/?q=%25.$target&output=json" | jq . > "${osint_dir}/cert_transparency.json" 2>&1
    }
    
    # 4. Web Archives
    web_archives() {
        info "Checking web archives..."
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.$target/*&output=json" | jq . > "${osint_dir}/wayback.json" 2>&1
        info "Harvesting search engine data (this may take a while)..."
        gobuster dns -d "$target" -w /usr/share/wordlists/dns/all.txt -q > "${osint_dir}/dns_brute.txt" 2>&1 &
    }
    
    # Run all discovery in parallel
    dns_enum &
    network_discovery &
    cert_checks &
    web_archives &
    wait
    
    # Process results
    local additional_targets=$(
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "${osint_dir}/"*.txt | 
        sort -u | 
        grep -vE '^(127\.|0\.|169\.254\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)'
    )
    
    local discovered_domains=$(
        grep -Eo '([a-zA-Z0-9.-]+\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}' "${osint_dir}/"*.txt |
        grep -i "$target" |
        sort -u
    )
    
    echo "$additional_targets $discovered_domains" | tr ' ' '\n' | sort -u
}

# ========= SCANNING FUNCTIONS =========
run_scan() {
    local target=$1
    local scan_type=${2:-full}
    
    case $scan_type in
        quick)
            quick_scan "$target"
            ;;
        full)
            full_scan "$target"
            ;;
        web)
            web_scan "$target"
            ;;
        vuln)
            vuln_scan "$target"
            ;;
        *)
            error "Invalid scan type: $scan_type"
            return 1
            ;;
    esac
}

quick_scan() {
    local target=$1
    info "Running quick scan on $target"
    
    nmap $NMAP_TIMING -Pn -T4 --top-ports 100 -sV --open -oN "${REPORT_DIR}/nmap_quick.txt" "$target" >/dev/null 2>&1
}

full_scan() {
    local target=$1
    info "Starting comprehensive scan of $target"
    
    # Phase 1: Discovery
    nmap $NMAP_TIMING -Pn -p- --min-rate 1000 -oN "${REPORT_DIR}/nmap_full_ports.txt" "$target" >/dev/null 2>&1
    
    # Get open ports
    local open_ports=$(grep -Eo '^[0-9]+/tcp' "${REPORT_DIR}/nmap_full_ports.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    [ -z "$open_ports" ] && { warn "No open ports found"; return 1; }
    
    # Phase 2: Service detection
    nmap $NMAP_TIMING -Pn -sV -sC -O -p "$open_ports" --script=banner -oN "${REPORT_DIR}/nmap_services.txt" "$target" >/dev/null 2>&1
    
    # Phase 3: Vulnerability scanning
    nmap $NMAP_TIMING -Pn --script vuln,vulners --script-args mincvss=5.0 -p "$open_ports" -oN "${REPORT_DIR}/nmap_vuln.txt" "$target" >/dev/null 2>&1
    
    # Service-specific checks
    check_web_services "$target" "$open_ports" &
    check_ssh "$target" &
    check_databases "$target" &
    check_smb "$target" &
    
    wait
}

web_scan() {
    local target=$1
    info "Running web application scan on $target"
    
    # HTTP service detection
    local web_ports=$(nmap $NMAP_TIMING -Pn -p80,443,8080,8443 --open "$target" | grep -Eo '^[0-9]+/tcp' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    [ -z "$web_ports" ] && { warn "No web ports open"; return 1; }
    
    # Web scanning tools
    nikto -h "$target" -p "$web_ports" -Tuning xb -output "${REPORT_DIR}/nikto.txt" >/dev/null 2>&1 &
    whatweb -v -a 3 "$target" > "${REPORT_DIR}/whatweb.txt" 2>&1 &
    testssl.sh "$target" > "${REPORT_DIR}/testssl.txt" 2>&1 &
    
    wait
}

vuln_scan() {
    local target=$1
    info "Running vulnerability scan on $target"
    
    # First identify open ports
    nmap $NMAP_TIMING -Pn --top-ports 100 --open -oN "${REPORT_DIR}/nmap_vuln_ports.txt" "$target" >/dev/null 2>&1
    local open_ports=$(grep -Eo '^[0-9]+/tcp' "${REPORT_DIR}/nmap_vuln_ports.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    [ -z "$open_ports" ] && { warn "No open ports found"; return 1; }
    
    # Run vulnerability scripts
    nmap $NMAP_TIMING -Pn --script vuln,vulners --script-args mincvss=5.0 -p "$open_ports" -oN "${REPORT_DIR}/nmap_vuln.txt" "$target" >/dev/null 2>&1
    
    # Check for exploits
    if $EXPLOIT_CHECKS; then
        searchsploit --nmap "${REPORT_DIR}/nmap_vuln_ports.txt" -v > "${REPORT_DIR}/exploits.txt" 2>&1
    fi
}

# ========= SERVICE-SPECIFIC CHECKS =========
check_web_services() {
    local target=$1
    local ports=$2
    
    info "Checking web services..."
    
    # Run standard web tools
    nikto -h "$target" -p "$ports" -Tuning xb -output "${REPORT_DIR}/web_nikto.txt" >/dev/null 2>&1 &
    whatweb -v -a 3 "$target" > "${REPORT_DIR}/web_whatweb.txt" 2>&1 &
    
    # Content discovery
    gobuster dir -u "http://$target" -w /usr/share/wordlists/dirb/common.txt -o "${REPORT_DIR}/gobuster.txt" >/dev/null 2>&1 &
    
    # SSL checks if HTTPS
    if [[ "$ports" == *"443"* ]]; then
        testssl.sh "$target" > "${REPORT_DIR}/testssl.txt" 2>&1 &
    fi
    
    # API testing
    if [[ "$ports" == *"8080"* ]] || [[ "$ports" == *"8443"* ]]; then
        run_api_tests "$target" &
    fi
    
    wait
}

check_ssh() {
    local target=$1
    
    if ! grep -q "22/tcp" "${REPORT_DIR}/nmap_services.txt"; then
        return 0
    fi
    
    info "Checking SSH service..."
    
    ssh-audit "$target" > "${REPORT_DIR}/ssh_audit.txt" 2>&1
    
    if $BRUTEX_ENABLED; then
        hydra -L /usr/share/wordlists/metasploit/common_users.txt \
              -P /usr/share/wordlists/metasploit/common_passwords.txt \
              -t 4 -o "${REPORT_DIR}/ssh_bruteforce.txt" ssh://"$target" >/dev/null 2>&1
    fi
}

check_databases() {
    local target=$1
    
    # MySQL
    if grep -q "3306/tcp" "${REPORT_DIR}/nmap_services.txt"; then
        nmap $NMAP_TIMING -p3306 --script mysql-audit,mysql-vuln-cve2012-2122 \
             -oN "${REPORT_DIR}/mysql_audit.txt" "$target" >/dev/null 2>&1
    fi
    
    # PostgreSQL
    if grep -q "5432/tcp" "${REPORT_DIR}/nmap_services.txt"; then
        nmap $NMAP_TIMING -p5432 --script pgsql-brute \
             -oN "${REPORT_DIR}/pgsql_audit.txt" "$target" >/dev/null 2>&1
    fi
}

check_smb() {
    local target=$1
    
    if grep -q "445/tcp" "${REPORT_DIR}/nmap_services.txt"; then
        nmap $NMAP_TIMING -p445 --script smb-vuln-* \
             -oN "${REPORT_DIR}/smb_audit.txt" "$target" >/dev/null 2>&1
    fi
}

# ========= REPORTING =========
generate_report() {
    local target=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="${REPORT_DIR}/security_report_${timestamp}.md"
    
    info "Generating security report..."
    
    {
        echo "# Security Assessment Report"
        echo "## Target: $target"
        echo "## Date: $(date)"
        echo ""
        echo "## Summary"
        echo "- Open ports: $(grep -c "open" "${REPORT_DIR}/nmap_services.txt")"
        echo "- Critical vulnerabilities: $(grep -ci "critical" "${REPORT_DIR}/nmap_vuln.txt")"
        echo "- Potential exploits: $(grep -c "Exploit: " "${REPORT_DIR}/exploits.txt" 2>/dev/null || echo 0)"
        echo ""
        echo "## Detailed Findings"
        
        # Network findings
        echo "### Network Services"
        grep "open" "${REPORT_DIR}/nmap_services.txt" | sed 's/^/- /'
        echo ""
        
        # Vulnerability findings
        if [ -f "${REPORT_DIR}/nmap_vuln.txt" ]; then
            echo "### Vulnerabilities"
            grep -i "vulnerable" "${REPORT_DIR}/nmap_vuln.txt" | sed 's/^/- /'
            echo ""
        fi
        
        # Web findings
        if [ -f "${REPORT_DIR}/web_nikto.txt" ]; then
            echo "### Web Application Issues"
            grep -i "vulnerability" "${REPORT_DIR}/web_nikto.txt" | head -n 10 | sed 's/^/- /'
            echo ""
        fi
        
        # Recommendations
        echo "## Recommendations"
        echo "1. Patch all identified vulnerabilities"
        echo "2. Disable unnecessary services"
        echo "3. Implement proper firewall rules"
        echo "4. Change default credentials"
        echo "5. Enable logging and monitoring"
    } > "$report_file"
    
    # Generate HTML version
    pandoc "$report_file" -o "${report_file%.md}.html" 2>/dev/null
    
    info "Report generated: $report_file"
}

# ========= MAIN FUNCTION =========
main() {
    print_banner
    check_dependencies
    
    local target=${1:-}
    local scan_type=${2:-full}
    
    if [ -z "$target" ]; then
        target=$(curl -s ifconfig.me)
        info "No target specified, using public IP: $target"
    fi
    
    if ! validate_target "$target"; then
        die "Target validation failed"
    fi
    
    mkdir -p "$REPORT_DIR"
    
    # Start timer
    local start_time=$(date +%s)
    
    # Run discovery and scanning
    discover_targets "$target" > "${REPORT_DIR}/discovered_targets.txt"
    run_scan "$target" "$scan_type"
    
    # Generate report
    generate_report "$target"
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    info "Scan completed in $duration seconds"
    
    # Display quick summary
    display_summary "$target"
}

display_summary() {
    local target=$1
    
    echo -e "\n${B}=== SCAN SUMMARY ===${N}"
    echo -e "Target: ${C}$target${N}"
    
    # Open ports
    local open_ports=$(grep -c "open" "${REPORT_DIR}/nmap_services.txt" 2>/dev/null || echo 0)
    echo -e "Open ports: ${Y}$open_ports${N}"
    
    # Critical vulnerabilities
    local crit_vulns=$(grep -ci "critical" "${REPORT_DIR}/nmap_vuln.txt" 2>/dev/null || echo 0)
    echo -e "Critical vulnerabilities: ${R}$crit_vulns${N}"
    
    # Web issues
    if [ -f "${REPORT_DIR}/web_nikto.txt" ]; then
        local web_issues=$(grep -ci "vulnerability" "${REPORT_DIR}/web_nikto.txt")
        echo -e "Web application issues: ${Y}$web_issues${N}"
    fi
    
    # Report location
    local latest_report=$(ls -t "${REPORT_DIR}/security_report_"*.md | head -1)
    echo -e "\nFull report: ${C}$latest_report${N}"
}

# ========= ENTRY POINT =========
main "$@"
