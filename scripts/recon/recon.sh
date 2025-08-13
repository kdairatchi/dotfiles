#!/bin/bash

# Ultimate Reconnaissance Menu
# A comprehensive tool for domain reconnaissance and information gathering

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Graceful interrupt handling
trap 'echo -e "${RED}[!] Interrupted. Exiting...${NC}"; exit 1' INT

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    ULTIMATE RECON MENU                      ║"
    echo "║                  Advanced Reconnaissance Tool               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Create output directory
create_output_dir() {
    if [ ! -d "recon_output" ]; then
        mkdir recon_output
        echo -e "${GREEN}[+] Created output directory: recon_output${NC}"
    fi
}

# Check dependencies
check_dependencies() {
    echo -e "${YELLOW}[*] Checking dependencies...${NC}"
    
    # List of required tools
    tools=("curl" "jq" "python3" "dig" "nslookup" "whois")
    missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[*] Please install missing tools and rerun${NC}"
        return 1
    fi
    
    # Optional tools
    optional_tools=("nmap" "timeout")
    missing_optional=()
    for tool in "${optional_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_optional+=($tool)
        fi
    done
    if [ ${#missing_optional[@]} -ne 0 ]; then
        echo -e "${YELLOW}[*] Optional tools missing (features degrade gracefully): ${missing_optional[*]}${NC}"
    fi

    # Python module for Google dorking
    if ! python3 - <<'PY' 2>/dev/null
try:
    from googlesearch import search  # type: ignore
except Exception:
    raise SystemExit(1)
PY
    then
        echo -e "${YELLOW}[*] Python module 'googlesearch' not found. Google dorking will attempt auto-install when used.${NC}"
    fi

    echo -e "${GREEN}[+] All dependencies satisfied${NC}"
    return 0
}

# Wayback Machine URLs
wayback_recon() {
    echo -e "${BLUE}[*] Starting Wayback Machine reconnaissance...${NC}"
    read -p "Enter the domain (e.g., example.com): " domain
    
    echo -e "${YELLOW}[*] Fetching all URLs from Wayback Machine...${NC}"
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      -o "recon_output/${domain}_all_urls.txt"
    
    echo -e "${YELLOW}[*] Fetching URLs with specific file extensions...${NC}"
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      --data-urlencode "filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
      -o "recon_output/${domain}_filtered_urls.txt"
    
    echo -e "${GREEN}[+] Wayback Machine results saved to recon_output/${NC}"
}

# AlienVault OTX reconnaissance
alienvault_recon() {
    echo -e "${BLUE}[*] Starting AlienVault OTX reconnaissance...${NC}"
    read -p "Enter the domain (e.g., example.com): " domain
    
    if ! command -v jq &>/dev/null; then
        echo -e "${RED}[!] jq is required but not installed${NC}"
        return 1
    fi
    
    page=1
    limit=500
    output_file="recon_output/${domain}_otx_urls.txt"
    
    echo -e "${YELLOW}[*] Fetching URLs from AlienVault OTX...${NC}"
    > "$output_file"
    
    while true; do
        echo -e "${CYAN}[*] Fetching page $page...${NC}"
        
        response=$(curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=${limit}&page=${page}")
        
        urls=$(echo "$response" | jq -r '.url_list[]?.url' 2>/dev/null)
        
        if [[ -z "$urls" ]]; then
            echo -e "${GREEN}[+] No more URLs found. Finishing.${NC}"
            break
        fi
        
        echo "$urls" >> "$output_file"
        
        count=$(echo "$response" | jq -r '.url_list | length' 2>/dev/null)
        echo -e "${GREEN}[+] Found $count URL(s) on page $page${NC}"
        
        if (( count < limit )); then
            echo -e "${GREEN}[+] Reached the last page${NC}"
            break
        fi
        
        page=$((page + 1))
        sleep 1
    done
    
    echo -e "${GREEN}[+] OTX results saved to $output_file${NC}"
}

# S3 bucket reconnaissance
s3_recon() {
    echo -e "${BLUE}[*] Starting S3 bucket reconnaissance...${NC}"
    read -p "Enter the domain/company name: " domain
    
    output_file="recon_output/${domain}_s3_buckets.txt"
    > "$output_file"
    
    echo -e "${YELLOW}[*] Searching for S3 buckets...${NC}"
    
    # Common S3 bucket naming patterns
    buckets=(
        "$domain"
        "$domain-backup"
        "$domain-backups"
        "$domain-dev"
        "$domain-staging"
        "$domain-prod"
        "$domain-production"
        "$domain-assets"
        "$domain-static"
        "$domain-logs"
        "$domain-data"
        "$domain-uploads"
        "$domain-files"
        "$domain-images"
        "$domain-videos"
        "$domain-downloads"
        "$domain-public"
        "$domain-private"
        "$domain-test"
        "$domain-tmp"
        "$domain-temp"
        "${domain}backup"
        "${domain}backups"
        "${domain}dev"
        "${domain}staging"
        "${domain}prod"
        "${domain}assets"
        "${domain}static"
        "${domain}logs"
        "${domain}data"
        "${domain}uploads"
        "backup-$domain"
        "backups-$domain"
        "dev-$domain"
        "staging-$domain"
        "prod-$domain"
        "assets-$domain"
        "static-$domain"
        "logs-$domain"
        "data-$domain"
        "uploads-$domain"
    )
    
    for bucket in "${buckets[@]}"; do
        echo -e "${CYAN}[*] Checking bucket: $bucket${NC}"
        
        # Check if bucket exists and is accessible
        response=$(curl -s -I "https://$bucket.s3.amazonaws.com/" 2>/dev/null)
        
        if echo "$response" | grep -Eqi "^HTTP/.* 200"; then
            echo -e "${GREEN}[+] Found accessible bucket: $bucket${NC}"
            echo "https://$bucket.s3.amazonaws.com/" >> "$output_file"
        elif echo "$response" | grep -Eqi "^HTTP/.* (403|301|302|307)"; then
            echo -e "${YELLOW}[!] Bucket exists but access denied: $bucket${NC}"
            echo "https://$bucket.s3.amazonaws.com/ (403 Forbidden)" >> "$output_file"
        fi
        
        sleep 0.5
    done
    
    echo -e "${GREEN}[+] S3 bucket results saved to $output_file${NC}"
}

# Certificate Transparency logs
ct_recon() {
    echo -e "${BLUE}[*] Starting Certificate Transparency reconnaissance...${NC}"
    read -p "Enter the domain (e.g., example.com): " domain
    
    output_file="recon_output/${domain}_ct_logs.txt"
    
    echo -e "${YELLOW}[*] Fetching subdomains from Certificate Transparency logs...${NC}"
    
    # Using crt.sh
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\*\.//g' | \
    sort -u > "$output_file"
    
    echo -e "${GREEN}[+] Certificate Transparency results saved to $output_file${NC}"
}

# DNS reconnaissance
dns_recon() {
    echo -e "${BLUE}[*] Starting DNS reconnaissance...${NC}"
    read -p "Enter the domain (e.g., example.com): " domain
    
    output_file="recon_output/${domain}_dns_info.txt"
    
    echo -e "${YELLOW}[*] Performing DNS lookups...${NC}"
    
    {
        echo "=== DNS RECONNAISSANCE FOR $domain ==="
        echo "Date: $(date)"
        echo ""
        
        echo "=== A RECORDS ==="
        dig +short A "$domain"
        echo ""
        
        echo "=== AAAA RECORDS ==="
        dig +short AAAA "$domain"
        echo ""
        
        echo "=== MX RECORDS ==="
        dig +short MX "$domain"
        echo ""
        
        echo "=== NS RECORDS ==="
        dig +short NS "$domain"
        echo ""
        
        echo "=== TXT RECORDS ==="
        dig +short TXT "$domain"
        echo ""
        
        echo "=== CNAME RECORDS ==="
        dig +short CNAME "$domain"
        echo ""
        
        echo "=== SOA RECORDS ==="
        dig +short SOA "$domain"
        echo ""
        
        echo "=== WHOIS INFORMATION ==="
        whois "$domain"
        
    } > "$output_file"
    
    echo -e "${GREEN}[+] DNS reconnaissance results saved to $output_file${NC}"
}

# Subdomain enumeration
subdomain_enum() {
    echo -e "${BLUE}[*] Starting subdomain enumeration...${NC}"
    read -p "Enter the domain (e.g., example.com): " domain
    
    output_file="recon_output/${domain}_subdomains.txt"
    
    echo -e "${YELLOW}[*] Enumerating subdomains...${NC}"
    
    # Common subdomains
    subdomains=(
        "www" "mail" "ftp" "admin" "webmail" "secure" "vpn" "remote" "blog"
        "dev" "staging" "test" "api" "app" "mobile" "portal" "support" "help"
        "docs" "cdn" "assets" "static" "img" "images" "upload" "downloads"
        "shop" "store" "payment" "pay" "checkout" "account" "login" "register"
        "dashboard" "panel" "cpanel" "phpmyadmin" "mysql" "db" "database"
        "backup" "old" "new" "beta" "alpha" "demo" "sandbox" "prod" "production"
        "ns1" "ns2" "dns" "mx" "smtp" "pop" "imap" "email" "webdisk"
        "forum" "forums" "community" "wiki" "kb" "faq" "news" "media"
        "video" "videos" "stream" "live" "tv" "radio" "podcast" "rss"
        "search" "find" "directory" "listing" "catalog" "index" "sitemap"
        "monitor" "stats" "analytics" "metrics" "reports" "logs" "status"
        "health" "ping" "uptime" "downtime" "maintenance" "service" "tools"
    )
    
    > "$output_file"
    
    for sub in "${subdomains[@]}"; do
        echo -e "${CYAN}[*] Checking: $sub.$domain${NC}"
        
        if nslookup "$sub.$domain" &>/dev/null; then
            echo -e "${GREEN}[+] Found: $sub.$domain${NC}"
            echo "$sub.$domain" >> "$output_file"
        fi
        
        sleep 0.2
    done
    
    echo -e "${GREEN}[+] Subdomain enumeration results saved to $output_file${NC}"
}

# Google Dorking
google_dorking() {
    echo -e "${BLUE}[*] Starting Google Dorking...${NC}"
    
    # Create Python script for Google dorking
    cat > "google_dorker.py" << 'EOF'
#!/usr/bin/env python3
import sys
import time
import argparse

try:
    from googlesearch import search
except ImportError:
    print("\033[91m[ERROR] Missing dependency: googlesearch-python\033[0m")
    print("\033[93m[INFO] Install it using: pip install googlesearch-python\033[0m")
    sys.exit(1)

class Colors:
    RED = "\033[91m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

def google_dork(query, num_results, output_file=None):
    print(f"{Colors.GREEN}[INFO] Searching for: {query}{Colors.RESET}")
    print(f"{Colors.BLUE}[INFO] Results limit: {num_results}{Colors.RESET}\n")
    
    results = []
    try:
        for i, result in enumerate(search(query, num_results=num_results, stop=num_results)):
            print(f"{Colors.YELLOW}[{i+1}] {Colors.RESET}{result}")
            results.append(result)
            time.sleep(0.5)  # Be respectful to Google
            
        if output_file:
            with open(output_file, 'w') as f:
                for result in results:
                    f.write(result + '\n')
            print(f"\n{Colors.GREEN}[+] Results saved to {output_file}{Colors.RESET}")
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Google Dorking Tool')
    parser.add_argument('query', help='Google dork query')
    parser.add_argument('-n', '--num', type=int, default=10, help='Number of results')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    google_dork(args.query, args.num, args.output)
EOF

    chmod +x google_dorker.py
    
    read -p "Enter the domain for dorking (e.g., example.com): " domain
    read -p "Enter number of results (default 10): " num_results
    
    num_results=${num_results:-10}
    output_file="recon_output/${domain}_google_dorks.txt"
    
    echo -e "${YELLOW}[*] Running common Google dorks...${NC}"
    
    # Ensure python dependency exists or attempt install
    if ! python3 - <<'PY' 2>/dev/null
try:
    from googlesearch import search  # type: ignore
except Exception:
    raise SystemExit(1)
PY
    then
        if command -v pip3 >/dev/null 2>&1; then
            echo -e "${YELLOW}[*] Installing python dependency: googlesearch-python${NC}"
            if ! pip3 install --user googlesearch-python >/dev/null 2>&1; then
                echo -e "${RED}[!] Failed to install googlesearch-python. Skipping Google dorking.${NC}"
                return 0
            fi
        else
            echo -e "${RED}[!] pip3 not available. Skipping Google dorking.${NC}"
            return 0
        fi
    fi

    # Common Google dorks
    dorks=(
        "site:$domain filetype:pdf"
        "site:$domain filetype:doc"
        "site:$domain filetype:xls"
        "site:$domain filetype:txt"
        "site:$domain filetype:xml"
        "site:$domain filetype:conf"
        "site:$domain filetype:cnf"
        "site:$domain filetype:reg"
        "site:$domain filetype:inf"
        "site:$domain filetype:rdp"
        "site:$domain filetype:cfg"
        "site:$domain filetype:yml"
        "site:$domain filetype:yaml"
        "site:$domain inurl:wp-config"
        "site:$domain inurl:admin"
        "site:$domain inurl:login"
        "site:$domain inurl:dashboard"
        "site:$domain inurl:phpmyadmin"
        "site:$domain inurl:test"
        "site:$domain inurl:dev"
        "site:$domain \"index of\""
        "site:$domain \"server status\""
        "site:$domain \"access denied\""
        "site:$domain \"forbidden\""
    )
    
    > "$output_file"
    
    for dork in "${dorks[@]}"; do
        echo -e "${CYAN}[*] Dorking: $dork${NC}"
        echo "=== $dork ===" >> "$output_file"
        if python3 google_dorker.py "$dork" -n "$num_results" -o temp_dork.txt >/dev/null 2>&1; then
            if [ -f temp_dork.txt ]; then
                cat temp_dork.txt >> "$output_file"
            fi
        else
            echo "[ERROR] Failed to fetch results for: $dork" >> "$output_file"
        fi
        echo "" >> "$output_file"
        rm -f temp_dork.txt
        sleep 2
    done
    
    rm -f google_dorker.py
    echo -e "${GREEN}[+] Google dorking results saved to $output_file${NC}"
}

# Shodan reconnaissance (requires API key)
shodan_recon() {
    echo -e "${BLUE}[*] Starting Shodan reconnaissance...${NC}"
    read -p "Enter your Shodan API key: " api_key
    read -p "Enter the domain/IP: " target
    
    if [ -z "$api_key" ]; then
        echo -e "${RED}[!] Shodan API key required${NC}"
        return 1
    fi
    
    output_file="recon_output/${target}_shodan.txt"
    
    echo -e "${YELLOW}[*] Querying Shodan...${NC}"
    
    curl -s "https://api.shodan.io/shodan/host/search?key=$api_key&query=$target" | \
    jq '.' > "$output_file"
    
    echo -e "${GREEN}[+] Shodan results saved to $output_file${NC}"
}

# Port scanning
port_scan() {
    echo -e "${BLUE}[*] Starting port scanning...${NC}"
    read -p "Enter the target IP/domain: " target
    read -p "Enter port range (e.g., 1-1000 or single port): " port_range
    
    output_file="recon_output/${target}_ports.txt"
    
    echo -e "${YELLOW}[*] Scanning ports $port_range on $target...${NC}"
    
    if command -v nmap &> /dev/null; then
        nmap -p "$port_range" "$target" > "$output_file"
    else
        echo -e "${RED}[!] nmap not found, using basic port check${NC}"
        
        IFS='-' read -ra RANGE <<< "$port_range"
        start=${RANGE[0]}
        end=${RANGE[1]:-${RANGE[0]}}
        
        > "$output_file"
        
        for ((port=start; port<=end; port++)); do
            if command -v timeout >/dev/null 2>&1; then
                checker="timeout 1 bash -c 'echo >/dev/tcp/$target/$port'"
            else
                checker="bash -c 'echo >/dev/tcp/$target/$port'"
            fi
            if eval "$checker" 2>/dev/null; then
                echo -e "${GREEN}[+] Port $port is open${NC}"
                echo "Port $port: Open" >> "$output_file"
            fi
        done
    fi
    
    echo -e "${GREEN}[+] Port scan results saved to $output_file${NC}"
}

# GitHub reconnaissance
github_recon() {
    echo -e "${BLUE}[*] Starting GitHub reconnaissance...${NC}"
    read -p "Enter the organization/username: " org
    
    output_file="recon_output/${org}_github.txt"
    
    echo -e "${YELLOW}[*] Fetching GitHub repositories...${NC}"
    
    curl -s -H "User-Agent: recon-script" "https://api.github.com/users/$org/repos?per_page=100" | \
    jq -r '.[] | .full_name + " - " + (.description // "")' > "$output_file"
    
    echo -e "${GREEN}[+] GitHub results saved to $output_file${NC}"
}

# Full reconnaissance
full_recon() {
    echo -e "${PURPLE}[*] Starting full reconnaissance suite...${NC}"
    read -p "Enter the target domain: " domain
    
    echo -e "${YELLOW}[*] Running all reconnaissance modules...${NC}"
    
    # Run all recon modules
    wayback_recon <<< "$domain"
    alienvault_recon <<< "$domain"
    s3_recon <<< "$domain"
    ct_recon <<< "$domain"
    dns_recon <<< "$domain"
    subdomain_enum <<< "$domain"
    google_dorking <<< "$domain"$'\n10'
    
    echo -e "${GREEN}[+] Full reconnaissance completed!${NC}"
    echo -e "${GREEN}[+] Check the recon_output directory for results${NC}"
}

# Main menu
main_menu() {
    while true; do
        clear
        print_banner
        echo -e "${WHITE}Select an option:${NC}"
        echo -e "${CYAN}[1]${NC} Wayback Machine URLs"
        echo -e "${CYAN}[2]${NC} AlienVault OTX Reconnaissance"
        echo -e "${CYAN}[3]${NC} S3 Bucket Reconnaissance"
        echo -e "${CYAN}[4]${NC} Certificate Transparency Logs"
        echo -e "${CYAN}[5]${NC} DNS Reconnaissance"
        echo -e "${CYAN}[6]${NC} Subdomain Enumeration"
        echo -e "${CYAN}[7]${NC} Google Dorking"
        echo -e "${CYAN}[8]${NC} Shodan Reconnaissance"
        echo -e "${CYAN}[9]${NC} Port Scanning"
        echo -e "${CYAN}[10]${NC} GitHub Reconnaissance"
        echo -e "${CYAN}[11]${NC} Full Reconnaissance Suite"
        echo -e "${CYAN}[0]${NC} Exit"
        echo ""
        read -p "Enter your choice: " choice
        
        case $choice in
            1) wayback_recon ;;
            2) alienvault_recon ;;
            3) s3_recon ;;
            4) ct_recon ;;
            5) dns_recon ;;
            6) subdomain_enum ;;
            7) google_dorking ;;
            8) shodan_recon ;;
            9) port_scan ;;
            10) github_recon ;;
            11) full_recon ;;
            0) echo -e "${GREEN}[+] Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}[!] Invalid choice${NC}"; sleep 2 ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Initialize
echo -e "${YELLOW}[*] Initializing Ultimate Recon Menu...${NC}"
create_output_dir

if check_dependencies; then
    main_menu
else
    echo -e "${RED}[!] Please install missing dependencies and rerun${NC}"
    exit 1
fi
