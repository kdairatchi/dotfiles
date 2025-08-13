#!/bin/bash

# Bug Bounty Oneliner Runner - Complete CLI Menu
# Author: Security Researcher
# Version: 2.0

# Colors for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗"
    echo "██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝"
    echo "██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ "
    echo "██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  "
    echo "██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   "
    echo "╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   "
    echo -e "${NC}"
    echo -e "${WHITE}                    Complete Bug Bounty Automation Suite${NC}"
    echo -e "${YELLOW}                         v2.0 - Advanced Edition${NC}"
    echo ""
}

# Check if target is set
check_target() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] No target set. Please set target first (Option 1)${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    return 0
}

# Set target domain
set_target() {
    echo -e "${CYAN}[+] Setting Target Domain${NC}"
    read -p "Enter target domain (e.g., example.com): " TARGET
    if [ ! -z "$TARGET" ]; then
        echo -e "${GREEN}[✓] Target set to: $TARGET${NC}"
        mkdir -p results/$TARGET
        cd results/$TARGET
    else
        echo -e "${RED}[!] Invalid target${NC}"
    fi
    read -p "Press Enter to continue..."
}

# Subdomain Enumeration Menu
subdomain_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== SUBDOMAIN ENUMERATION ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Basic Subdomain Discovery (subfinder)"
        echo "2. Asset Finder Discovery"
        echo "3. Combined Subdomain Discovery"
        echo "4. Live Subdomain Filtering"
        echo "5. Subdomain Takeover Check"
        echo "6. Full Subdomain Reconnaissance"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " sub_choice

        case $sub_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Running Subfinder...${NC}"
                    subfinder -d $TARGET -all -recursive > subdomains.txt
                    echo -e "${GREEN}[✓] Results saved to subdomains.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running AssetFinder...${NC}"
                    assetfinder $TARGET > assetfinder.txt
                    echo -e "${GREEN}[✓] Results saved to assetfinder.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Combined Discovery...${NC}"
                    subfinder -d $TARGET -all -recursive > subdomains.txt
                    assetfinder $TARGET > assetfinder.txt
                    sort -u subdomains.txt assetfinder.txt > total_subdomains.txt
                    echo -e "${GREEN}[✓] Combined results saved to total_subdomains.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Filtering Live Subdomains...${NC}"
                    if [ -f "total_subdomains.txt" ]; then
                        cat total_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
                        cat total_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -mc 200,403,400,500 -o live.txt
                        echo -e "${GREEN}[✓] Live subdomains saved to subdomains_alive.txt and live.txt${NC}"
                    else
                        echo -e "${RED}[!] No subdomains file found. Run discovery first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Checking Subdomain Takeover...${NC}"
                    if [ -f "total_subdomains.txt" ]; then
                        sudo subzy run --targets total_subdomains.txt --concurrency 100 --hide_fails --verify_ssl
                        echo -e "${GREEN}[✓] Subdomain takeover check completed${NC}"
                    else
                        echo -e "${RED}[!] No subdomains file found. Run discovery first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                if check_target; then
                    echo -e "${CYAN}[+] Running Full Subdomain Reconnaissance...${NC}"
                    subfinder -d $TARGET -all -recursive > subdomains.txt
                    assetfinder $TARGET > assetfinder.txt
                    sort -u subdomains.txt assetfinder.txt > total_subdomains.txt
                    cat total_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
                    sudo subzy run --targets total_subdomains.txt --concurrency 100 --hide_fails --verify_ssl
                    echo -e "${GREEN}[✓] Full subdomain reconnaissance completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Open Redirect Testing Submenu
open_redirect_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== OPEN REDIRECT TESTING ===${NC}"
        echo ""
        echo "1. Basic Open Redirect Detection"
        echo "2. OpenRedirex Scanner"
        echo "3. Nuclei Open Redirect Templates"
        echo "4. Custom Redirect Payloads"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " redirect_choice

        case $redirect_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic Open Redirect Detection...${NC}"
                    if [ -f "urls.txt" ]; then
                        cat urls.txt | gf redirect | tee -a redirect.txt | cut -f 3- -d';' | qsreplace "https://evil.com" | httpx -status-code
                    else
                        echo https://$TARGET | gau | urldedupe -qs | gf redirect > redirect.txt
                    fi
                    echo -e "${GREEN}[✓] Redirect candidates saved to redirect.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running OpenRedirex...${NC}"
                    if [ -f "redirect.txt" ]; then
                        cat redirect.txt | openredirex -p payloads.txt
                    else
                        echo -e "${RED}[!] No redirect candidates found. Run basic detection first.${NC}"
                    fi
                    echo -e "${GREEN}[✓] OpenRedirex scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei Open Redirect Templates...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        nuclei -l subdomains_alive.txt -tags redirect -o nuclei_redirect_results.txt
                    else
                        echo https://$TARGET | nuclei -tags redirect -o nuclei_redirect_results.txt
                    fi
                    echo -e "${GREEN}[✓] Nuclei redirect results saved to nuclei_redirect_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Testing Custom Redirect Payloads...${NC}"
                    echo -e "${YELLOW}[!] Common payloads:${NC}"
                    echo "?url=https://evil.com"
                    echo "?redirect=//evil.com"
                    echo "?next=javascript:alert(1)"
                    echo "?return_to=https://evil.com"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# SSRF Testing Submenu
ssrf_testing_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== SSRF TESTING ===${NC}"
        echo ""
        echo "1. Basic SSRF Detection"
        echo "2. Nuclei SSRF Templates"
        echo "3. Custom SSRF Payloads"
        echo "4. Collaborator-based SSRF"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " ssrf_choice

        case $ssrf_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic SSRF Detection...${NC}"
                    if [ -f "urls.txt" ]; then
                        cat urls.txt | gf ssrf | tee -a ssrf.txt | cut -f 3- -d';' | qsreplace "https://public-server" | httpx -status-code
                    else
                        echo https://$TARGET | gau | gf ssrf > ssrf.txt
                    fi
                    echo -e "${GREEN}[✓] SSRF candidates saved to ssrf.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei SSRF Templates...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        nuclei -l subdomains_alive.txt -tags ssrf -o nuclei_ssrf_results.txt
                    else
                        echo https://$TARGET | nuclei -tags ssrf -o nuclei_ssrf_results.txt
                    fi
                    echo -e "${GREEN}[✓] Nuclei SSRF results saved to nuclei_ssrf_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Testing Custom SSRF Payloads...${NC}"
                    echo -e "${YELLOW}[!] Common SSRF payloads:${NC}"
                    echo "http://127.0.0.1:80"
                    echo "http://localhost:22"
                    echo "http://169.254.169.254/latest/meta-data/"
                    echo "file:///etc/passwd"
                    echo "gopher://127.0.0.1:3306"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Collaborator-based SSRF Testing...${NC}"
                    read -p "Enter your collaborator URL: " collab_url
                    if [ -f "ssrf.txt" ]; then
                        cat ssrf.txt | qsreplace $collab_url | httpx -status-code
                    else
                        echo -e "${RED}[!] No SSRF candidates found. Run basic detection first.${NC}"
                    fi
                    echo -e "${GREEN}[✓] Collaborator-based SSRF testing completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Sensitive Data Discovery Menu
sensitive_data_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== SENSITIVE DATA DISCOVERY ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Sensitive File Detection"
        echo "2. Information Disclosure Dork"
        echo "3. Git Repository Detection"
        echo "4. API Key Finder"
        echo "5. AWS S3 Bucket Finder"
        echo "6. JavaScript Secret Scanner"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " sensitive_choice

        case $sensitive_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Detecting Sensitive Files...${NC}"
                    if [ -f "allurls.txt" ]; then
                        cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5" > sensitive_files.txt
                        echo -e "${GREEN}[✓] Sensitive files saved to sensitive_files.txt${NC}"
                    else
                        echo -e "${RED}[!] No URLs file found. Run URL collection first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Information Disclosure Dork...${NC}"
                    echo "site:*.$TARGET (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)"
                    echo -e "${YELLOW}[!] Use this dork in Google search manually${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Detecting Git Repositories...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        cat subdomains_alive.txt | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe > git_repos.txt
                        echo -e "${GREEN}[✓] Git repositories saved to git_repos.txt${NC}"
                    else
                        echo -e "${RED}[!] No live subdomains found. Run subdomain enumeration first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Searching for API Keys...${NC}"
                    if [ -f "allurls.txt" ]; then
                        cat allurls.txt | grep -E "\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)" > api_keys.txt
                        echo -e "${GREEN}[✓] API key scan results saved to api_keys.txt${NC}"
                    else
                        echo -e "${RED}[!] No URLs file found. Run URL collection first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Searching for AWS S3 Buckets...${NC}"
                    s3scanner scan -d $TARGET > s3_buckets.txt
                    echo -e "${GREEN}[✓] S3 bucket scan results saved to s3_buckets.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                if check_target; then
                    echo -e "${CYAN}[+] JavaScript Secret Scanner...${NC}"
                    if [ -f "js.txt" ]; then
                        cat js.txt | nuclei -t nuclei-templates/http/exposures/ > js_secrets.txt
                        echo -e "${GREEN}[✓] JavaScript secrets saved to js_secrets.txt${NC}"
                    else
                        echo -e "${RED}[!] No JavaScript files found. Run URL collection first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Network Scanning Menu
network_scanning_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== NETWORK SCANNING ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Naabu Port Scan"
        echo "2. Nmap Full Scan"
        echo "3. Masscan"
        echo "4. Service Detection"
        echo "5. Custom Port Scan"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " network_choice

        case $network_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Running Naabu Scan...${NC}"
                    if [ -f "total_subdomains.txt" ]; then
                        naabu -list total_subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt
                    else
                        naabu -host $TARGET -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt
                    fi
                    echo -e "${GREEN}[✓] Naabu results saved to naabu-full.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nmap Full Scan...${NC}"
                    nmap -p- --min-rate 1000 -T4 -A $TARGET -oA fullscan
                    echo -e "${GREEN}[✓] Nmap results saved to fullscan.*${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Masscan...${NC}"
                    masscan -p0-65535 $TARGET --rate 100000 -oG masscan-results.txt
                    echo -e "${GREEN}[✓] Masscan results saved to masscan-results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Service Detection...${NC}"
                    nmap -sV -sC $TARGET -oA service-detection
                    echo -e "${GREEN}[✓] Service detection results saved to service-detection.*${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Custom Port Scan...${NC}"
                    read -p "Enter ports to scan (e.g., 80,443,8080): " ports
                    nmap -p$ports -sV -sC $TARGET -oA custom-ports
                    echo -e "${GREEN}[✓] Custom port scan results saved to custom-ports.*${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# WordPress Scanning Menu
wordpress_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== WORDPRESS SCANNING ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Basic WordPress Detection"
        echo "2. Aggressive WordPress Scan"
        echo "3. Plugin Enumeration"
        echo "4. User Enumeration"
        echo "5. Theme Detection"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " wp_choice

        case $wp_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic WordPress Detection...${NC}"
                    curl -s https://$TARGET | grep -i wordpress
                    curl -s https://$TARGET/wp-admin/ | grep -i wordpress
                    echo -e "${GREEN}[✓] WordPress detection completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Aggressive WordPress Scan...${NC}"
                    read -p "Enter WPScan API token (or press Enter to skip): " api_token
                    if [ ! -z "$api_token" ]; then
                        wpscan --url https://$TARGET --disable-tls-checks --api-token $api_token -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
                    else
                        wpscan --url https://$TARGET --disable-tls-checks -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
                    fi
                    echo -e "${GREEN}[✓] WordPress scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] WordPress Plugin Enumeration...${NC}"
                    wpscan --url https://$TARGET --enumerate p --plugins-detection aggressive
                    echo -e "${GREEN}[✓] Plugin enumeration completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] WordPress User Enumeration...${NC}"
                    wpscan --url https://$TARGET --enumerate u
                    echo -e "${GREEN}[✓] User enumeration completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] WordPress Theme Detection...${NC}"
                    wpscan --url https://$TARGET --enumerate t
                    echo -e "${GREEN}[✓] Theme detection completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Parameter Discovery Menu
parameter_discovery_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== PARAMETER DISCOVERY ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Arjun Passive Discovery"
        echo "2. Arjun Wordlist Discovery"
        echo "3. FFUF Parameter Discovery"
        echo "4. ParamSpider"
        echo "5. Combined Parameter Discovery"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " param_choice

        case $param_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Arjun Passive Discovery...${NC}"
                    arjun -u https://$TARGET -oT arjun_passive.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"
                    echo -e "${GREEN}[✓] Arjun passive results saved to arjun_passive.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Arjun Wordlist Discovery...${NC}"
                    arjun -u https://$TARGET -oT arjun_wordlist.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"
                    echo -e "${GREEN}[✓] Arjun wordlist results saved to arjun_wordlist.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] FFUF Parameter Discovery...${NC}"
                    ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,301,302,403 -o ffuf_params.txt
                    echo -e "${GREEN}[✓] FFUF parameter results saved to ffuf_params.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Running ParamSpider...${NC}"
                    python3 ParamSpider.py -d $TARGET -o paramspider_results.txt
                    echo -e "${GREEN}[✓] ParamSpider results saved to paramspider_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Combined Parameter Discovery...${NC}"
                    arjun -u https://$TARGET -oT arjun_combined.txt --passive -m GET,POST
                    python3 ParamSpider.py -d $TARGET -o paramspider_combined.txt
                    cat arjun_combined.txt paramspider_combined.txt | sort -u > combined_parameters.txt
                    echo -e "${GREEN}[✓] Combined parameters saved to combined_parameters.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Full Automation Menu
full_automation_menu() {
    if check_target; then
        echo -e "${CYAN}[+] Starting Full Bug Bounty Automation...${NC}"
        echo -e "${YELLOW}[!] This will run all reconnaissance and vulnerability testing modules${NC}"
        read -p "Continue? (y/N): " confirm
        
        if [[ $confirm =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}[+] Phase 1: Subdomain Enumeration${NC}"
            subfinder -d $TARGET -all -recursive > subdomains.txt
            assetfinder $TARGET > assetfinder.txt
            sort -u subdomains.txt assetfinder.txt > total_subdomains.txt
            
            echo -e "${CYAN}[+] Phase 2: Live Host Discovery${NC}"
            cat total_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
            
            echo -e "${CYAN}[+] Phase 3: URL Collection${NC}"
            katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
            echo $TARGET | gau --mc 200 | urldedupe >> allurls.txt
            sort -u allurls.txt > combined_urls.txt
            
            echo -e "${CYAN}[+] Phase 4: Vulnerability Testing${NC}"
            # XSS
            cat combined_urls.txt | gf xss | uro | Gxss | kxss > xss_results.txt
            # SQLi
            cat combined_urls.txt | gf sqli > sqli_candidates.txt
            # LFI
            cat combined_urls.txt | gf lfi > lfi_candidates.txt
            # Open Redirect
            cat combined_urls.txt | gf redirect > redirect_candidates.txt
            # SSRF
            cat combined_urls.txt | gf ssrf > ssrf_candidates.txt
            
            echo -e "${CYAN}[+] Phase 5: Sensitive Data Discovery${NC}"
            cat allurls.txt | grep -E "\.js$" > js_files.txt
            cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config" > sensitive_files.txt
            
            echo -e "${CYAN}[+] Phase 6: Network Scanning${NC}"
            nmap -p- --min-rate 1000 -T4 $TARGET -oA full_nmap_scan
            
            echo -e "${GREEN}[✓] Full automation completed! Check the results files.${NC}"
        fi
    fi
    read -p "Press Enter to continue..."
}

# Results Analysis Menu
results_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== RESULTS ANALYSIS ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Show Discovered Subdomains"
        echo "2. Show Live Hosts"
        echo "3. Show Vulnerability Candidates"
        echo "4. Show Sensitive Files"
        echo "5. Generate HTML Report"
        echo "6. Show File Statistics"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " results_choice

        case $results_choice in
            1)
                if [ -f "total_subdomains.txt" ]; then
                    echo -e "${CYAN}[+] Discovered Subdomains:${NC}"
                    wc -l total_subdomains.txt
                    echo -e "${YELLOW}First 10 entries:${NC}"
                    head -10 total_subdomains.txt
                else
                    echo -e "${RED}[!] No subdomains file found${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if [ -f "subdomains_alive.txt" ]; then
                    echo -e "${CYAN}[+] Live Hosts:${NC}"
                    wc -l subdomains_alive.txt
                    echo -e "${YELLOW}First 10 entries:${NC}"
                    head -10 subdomains_alive.txt
                else
                    echo -e "${RED}[!] No live hosts file found${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${CYAN}[+] Vulnerability Candidates:${NC}"
                for file in xss_results.txt sqli_candidates.txt lfi_candidates.txt redirect_candidates.txt ssrf_candidates.txt; do
                    if [ -f "$file" ]; then
                        echo -e "${GREEN}$file: $(wc -l < $file) entries${NC}"
                    fi
                done
                read -p "Press Enter to continue..."
                ;;
            4)
                if [ -f "sensitive_files.txt" ]; then
                    echo -e "${CYAN}[+] Sensitive Files:${NC}"
                    wc -l sensitive_files.txt
                    echo -e "${YELLOW}First 10 entries:${NC}"
                    head -10 sensitive_files.txt
                else
                    echo -e "${RED}[!] No sensitive files found${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${CYAN}[+] Generating HTML Report...${NC}"
                generate_html_report
                echo -e "${GREEN}[✓] HTML report generated: report_$TARGET.html${NC}"
                read -p "Press Enter to continue..."
                ;;
            6)
                echo -e "${CYAN}[+] File Statistics:${NC}"
                for file in *.txt; do
                    if [ -f "$file" ]; then
                        echo -e "${GREEN}$file: $(wc -l < $file) lines${NC}"
                    fi
                done
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Generate HTML Report
generate_html_report() {
    cat > "report_$TARGET.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background-color: #ffebee; }
        .high { background-color: #fff3e0; }
        .medium { background-color: #f3e5f5; }
        .low { background-color: #e8f5e8; }
        pre { background-color: #f5f5f5; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Bug Bounty Report</h1>
        <h2>Target: $TARGET</h2>
        <p>Generated on: $(date)</p>
    </div>
    
    <div class="section">
        <h3>Summary</h3>
        <ul>
            <li>Subdomains Found: $([ -f "total_subdomains.txt" ] && wc -l < total_subdomains.txt || echo "0")</li>
            <li>Live Hosts: $([ -f "subdomains_alive.txt" ] && wc -l < subdomains_alive.txt || echo "0")</li>
            <li>URLs Collected: $([ -f "allurls.txt" ] && wc -l < allurls.txt || echo "0")</li>
            <li>JavaScript Files: $([ -f "js_files.txt" ] && wc -l < js_files.txt || echo "0")</li>
        </ul>
    </div>
    
    <div class="section critical">
        <h3>Critical Findings</h3>
        <p>XSS Candidates: $([ -f "xss_results.txt" ] && wc -l < xss_results.txt || echo "0")</p>
        <p>SQLi Candidates: $([ -f "sqli_candidates.txt" ] && wc -l < sqli_candidates.txt || echo "0")</p>
    </div>
    
    <div class="section high">
        <h3>High Findings</h3>
        <p>LFI Candidates: $([ -f "lfi_candidates.txt" ] && wc -l < lfi_candidates.txt || echo "0")</p>
        <p>SSRF Candidates: $([ -f "ssrf_candidates.txt" ] && wc -l < ssrf_candidates.txt || echo "0")</p>
    </div>
    
    <div class="section medium">
        <h3>Medium Findings</h3>
        <p>Open Redirect Candidates: $([ -f "redirect_candidates.txt" ] && wc -l < redirect_candidates.txt || echo "0")</p>
        <p>Sensitive Files: $([ -f "sensitive_files.txt" ] && wc -l < sensitive_files.txt || echo "0")</p>
    </div>
    
    <div class="section low">
        <h3>Information Gathering</h3>
        <p>Subdomains discovered and live hosts identified</p>
        <p>URL collection and parameter discovery completed</p>
    </div>
    
</body>
</html>
EOF
}

# Tools Installation Menu
tools_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== TOOLS INSTALLATION ===${NC}"
        echo ""
        echo "1. Install Basic Tools"
        echo "2. Install Go Tools"
        echo "3. Install Python Tools"
        echo "4. Install All Tools"
        echo "5. Check Tool Status"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " tools_choice

        case $tools_choice in
            1)
                echo -e "${CYAN}[+] Installing Basic Tools...${NC}"
                install_basic_tools
                ;;
            2)
                echo -e "${CYAN}[+] Installing Go Tools...${NC}"
                install_go_tools
                ;;
            3)
                echo -e "${CYAN}[+] Installing Python Tools...${NC}"
                install_python_tools
                ;;
            4)
                echo -e "${CYAN}[+] Installing All Tools...${NC}"
                install_basic_tools
                install_go_tools
                install_python_tools
                ;;
            5)
                echo -e "${CYAN}[+] Checking Tool Status...${NC}"
                check_tool_status
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Install Basic Tools
install_basic_tools() {
    echo -e "${CYAN}[+] Installing basic tools...${NC}"
    
    # Update package manager
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y curl wget git python3 python3-pip golang-go nmap masscan
    elif command -v yum &> /dev/null; then
        sudo yum update -y
        sudo yum install -y curl wget git python3 python3-pip golang nmap masscan
    elif command -v brew &> /dev/null; then
        brew update
        brew install curl wget git python3 go nmap masscan
    fi
    
    echo -e "${GREEN}[✓] Basic tools installation completed${NC}"
    read -p "Press Enter to continue..."
}

# Install Go Tools
install_go_tools() {
    echo -e "${CYAN}[+] Installing Go tools...${NC}"
    
    # Ensure Go is installed and GOPATH is set
    if ! command -v go &> /dev/null; then
        echo -e "${RED}[!] Go is not installed. Please install Go first.${NC}"
        return
    fi
    
    # Install Go tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/tomnomnom/gf@latest
    go install -v github.com/tomnomnom/qsreplace@latest
    go install -v github.com/projectdiscovery/urldedupe/cmd/urldedupe@latest
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/ffuf/ffuf@latest
    go install -v github.com/s0md3v/smap/cmd/smap@latest
    go install -v github.com/KathanP19/Gxss@latest
    go install -v github.com/Emoe/kxss@latest
    go install -v github.com/tomnomnom/anew@latest
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    
    echo -e "${GREEN}[✓] Go tools installation completed${NC}"
    read -p "Press Enter to continue..."
}

# Install Python Tools
install_python_tools() {
    echo -e "${CYAN}[+] Installing Python tools...${NC}"
    
    # Install pip tools
    pip3 install arjun
    pip3 install sqlmap
    pip3 install commix
    pip3 install corsy
    pip3 install dirsearch
    pip3 install paramspider
    pip3 install subzy
    pip3 install s3scanner
    
    # Clone GitHub repositories
    if [ ! -d "tools" ]; then
        mkdir tools
    fi
    
    cd tools
    
    # CORScanner
    if [ ! -d "CORScanner" ]; then
        git clone https://github.com/chenjj/CORScanner.git
        cd CORScanner
        pip3 install -r requirements.txt
        cd ..
    fi
    
    # OpenRedirex
    if [ ! -d "OpenRedirex" ]; then
        git clone https://github.com/devanshbatham/OpenRedirex.git
        cd OpenRedirex
        pip3 install -r requirements.txt
        cd ..
    fi
    
    # WPScan
    if ! command -v wpscan &> /dev/null; then
        gem install wpscan
    fi
    
    cd ..
    
    echo -e "${GREEN}[✓] Python tools installation completed${NC}"
    read -p "Press Enter to continue..."
}

# Check Tool Status
check_tool_status() {
    echo -e "${CYAN}[+] Checking tool installation status...${NC}"
    echo ""
    
    tools=(
        "subfinder" "assetfinder" "httpx" "katana" "gau" "nuclei" 
        "naabu" "gf" "qsreplace" "urldedupe" "dalfox" "ffuf" 
        "nmap" "masscan" "sqlmap" "wpscan" "arjun" "commix"
    )
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            echo -e "${GREEN}[✓] $tool - Installed${NC}"
        else
            echo -e "${RED}[✗] $tool - Not Found${NC}"
        fi
    done
    
    echo ""
    read -p "Press Enter to continue..."
}

# Custom Commands Menu
custom_commands_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== CUSTOM COMMANDS ===${NC}"
        echo ""
        echo "1. Run Custom Command"
        echo "2. Directory Fuzzing (Dirsearch)"
        echo "3. Technology Detection"
        echo "4. SSL Certificate Analysis"
        echo "5. Wayback Machine URLs"
        echo "6. GitHub Dorking"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " custom_choice

        case $custom_choice in
            1)
                echo -e "${CYAN}[+] Custom Command Runner${NC}"
                read -p "Enter your custom command: " custom_cmd
                eval $custom_cmd
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Directory Fuzzing...${NC}"
                    dirsearch -u https://$TARGET -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,lock,log,rar,sql,tar,txt,zip -o dirsearch_results.txt
                    echo -e "${GREEN}[✓] Directory fuzzing completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Technology Detection...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        cat subdomains_alive.txt | httpx -tech-detect -o tech_detection.txt
                    else
                        echo https://$TARGET | httpx -tech-detect -o tech_detection.txt
                    fi
                    echo -e "${GREEN}[✓] Technology detection completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] SSL Certificate Analysis...${NC}"
                    echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | openssl x509 -text -noout > ssl_cert_analysis.txt
                    echo -e "${GREEN}[✓] SSL certificate analysis saved to ssl_cert_analysis.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Collecting Wayback Machine URLs...${NC}"
                    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | sort -u > wayback_urls.txt
                    echo -e "${GREEN}[✓] Wayback URLs saved to wayback_urls.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                if check_target; then
                    echo -e "${CYAN}[+] GitHub Dorking Suggestions...${NC}"
                    echo "Use these dorks in GitHub search:"
                    echo "\"$TARGET\" password"
                    echo "\"$TARGET\" api_key"
                    echo "\"$TARGET\" secret"
                    echo "\"$TARGET\" token"
                    echo "\"$TARGET\" config"
                    echo "\"$TARGET\" database"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Main Menu
main_menu() {
    while true; do
        clear
        show_banner
        echo -e "${WHITE}Current Target: ${GREEN}${TARGET:-"Not Set"}${NC}"
        echo ""
        echo -e "${PURPLE}=== MAIN MENU ===${NC}"
        echo ""
        echo "1.  Set Target Domain"
        echo "2.  Subdomain Enumeration"
        echo "3.  URL Collection"
        echo "4.  Vulnerability Testing"
        echo "5.  Sensitive Data Discovery"
        echo "6.  Network Scanning"
        echo "7.  WordPress Scanning"
        echo "8.  Parameter Discovery"
        echo "9.  Full Automation"
        echo "10. Results Analysis"
        echo "11. Tools Installation"
        echo "12. Custom Commands"
        echo "0.  Exit"
        echo ""
        read -p "Select option: " choice

        case $choice in
            1)
                set_target
                ;;
            2)
                subdomain_menu
                ;;
            3)
                url_collection_menu
                ;;
            4)
                vuln_testing_menu
                ;;
            5)
                sensitive_data_menu
                ;;
            6)
                network_scanning_menu
                ;;
            7)
                wordpress_menu
                ;;
            8)
                parameter_discovery_menu
                ;;
            9)
                full_automation_menu
                ;;
            10)
                results_menu
                ;;
            11)
                tools_menu
                ;;
            12)
                custom_commands_menu
                ;;
            0)
                echo -e "${CYAN}[+] Exiting Bug Bounty CLI...${NC}"
                echo -e "${YELLOW}Happy Hunting! 🎯${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Initialize
echo -e "${CYAN}[+] Initializing Bug Bounty CLI...${NC}"
mkdir -p results
cd results

# Start main menu
main_menuac
    done
}

# URL Collection Menu
url_collection_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== URL COLLECTION ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. Passive URL Collection (Katana)"
        echo "2. Advanced URL Fetching"
        echo "3. GAU URL Collection"
        echo "4. Combined URL Discovery"
        echo "5. JavaScript File Collection"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " url_choice

        case $url_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Running Passive URL Collection...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
                        echo -e "${GREEN}[✓] URLs saved to allurls.txt${NC}"
                    else
                        echo -e "${RED}[!] No live subdomains file found. Run subdomain enumeration first.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Advanced URL Fetching...${NC}"
                    echo $TARGET | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe > output.txt
                    katana -u https://$TARGET -d 5 | grep '=' | urldedupe | anew output.txt
                    cat output.txt | sed 's/=.*/=/' > final.txt
                    echo -e "${GREEN}[✓] Advanced URLs saved to final.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running GAU Collection...${NC}"
                    echo $TARGET | gau --mc 200 | urldedupe > urls.txt
                    cat urls.txt | grep -E "\.php|\.asp|\.aspx|\.jspx|\.jsp" | grep '=' | sort > gau_output.txt
                    cat gau_output.txt | sed 's/=.*/=/' > gau_final.txt
                    echo -e "${GREEN}[✓] GAU URLs saved to gau_final.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Running Combined URL Discovery...${NC}"
                    # Katana
                    if [ -f "subdomains_alive.txt" ]; then
                        katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
                    fi
                    # GAU
                    echo $TARGET | gau --mc 200 | urldedupe >> allurls.txt
                    # Remove duplicates
                    sort -u allurls.txt > combined_urls.txt
                    echo -e "${GREEN}[✓] Combined URLs saved to combined_urls.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Collecting JavaScript Files...${NC}"
                    echo $TARGET | katana -d 5 | grep -E "\.js$" | nuclei -t /path/to/nuclei-templates/http/exposures/ -c 30 > js_scan.txt
                    if [ -f "allurls.txt" ]; then
                        cat allurls.txt | grep -E "\.js$" > js.txt
                        echo -e "${GREEN}[✓] JavaScript files saved to js.txt${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Vulnerability Testing Menu
vuln_testing_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== VULNERABILITY TESTING ===${NC}"
        echo -e "${WHITE}Current Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo "1. XSS Testing"
        echo "2. SQL Injection Testing"
        echo "3. LFI Testing"
        echo "4. Command Injection Testing"
        echo "5. CORS Testing"
        echo "6. Open Redirect Testing"
        echo "7. SSRF Testing"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select option: " vuln_choice

        case $vuln_choice in
            1)
                xss_testing_submenu
                ;;
            2)
                sqli_testing_submenu
                ;;
            3)
                lfi_testing_submenu
                ;;
            4)
                command_injection_submenu
                ;;
            5)
                cors_testing_submenu
                ;;
            6)
                open_redirect_submenu
                ;;
            7)
                ssrf_testing_submenu
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# XSS Testing Submenu
xss_testing_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== XSS TESTING ===${NC}"
        echo ""
        echo "1. Basic XSS Hunting Pipeline"
        echo "2. XSS with Dalfox"
        echo "3. Stored XSS Finder"
        echo "4. DOM XSS Detection"
        echo "5. Nuclei XSS Scan"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " xss_choice

        case $xss_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Running XSS Hunting Pipeline...${NC}"
                    echo https://$TARGET/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
                    echo -e "${GREEN}[✓] XSS results saved to xss_output.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Dalfox XSS Scan...${NC}"
                    read -p "Enter collaborator URL: " collab_url
                    if [ -f "xss_params.txt" ]; then
                        cat xss_params.txt | dalfox pipe --blind $collab_url --waf-bypass --silence
                    else
                        echo "https://$TARGET" | gau | gf xss | dalfox pipe --blind $collab_url --waf-bypass --silence
                    fi
                    echo -e "${GREEN}[✓] Dalfox scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Searching for Stored XSS...${NC}"
                    if [ -f "urls.txt" ]; then
                        cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high
                    else
                        echo https://$TARGET | gau | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high
                    fi
                    echo -e "${GREEN}[✓] Stored XSS scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] DOM XSS Detection...${NC}"
                    if [ -f "js_files.txt" ]; then
                        cat js_files.txt | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt
                    else
                        echo https://$TARGET | gau | grep -E "\.js$" | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt
                    fi
                    echo -e "${GREEN}[✓] DOM XSS results saved to dom_xss_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei XSS Scan...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        nuclei -l subdomains_alive.txt -tags xss -o nuclei_xss_results.txt
                    else
                        echo https://$TARGET | nuclei -tags xss -o nuclei_xss_results.txt
                    fi
                    echo -e "${GREEN}[✓] Nuclei XSS results saved to nuclei_xss_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# SQL Injection Testing Submenu
sqli_testing_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== SQL INJECTION TESTING ===${NC}"
        echo ""
        echo "1. Basic SQLi Detection"
        echo "2. SQLMap Automated Scan"
        echo "3. Nuclei SQLi Templates"
        echo "4. Custom SQLi Payloads"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " sqli_choice

        case $sqli_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic SQLi Detection...${NC}"
                    echo https://$TARGET | gau | urldedupe -qs | gf sqli > sqli_candidates.txt
                    echo -e "${GREEN}[✓] SQLi candidates saved to sqli_candidates.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running SQLMap...${NC}"
                    if [ -f "parameters.txt" ]; then
                        sqlmap -m parameters.txt --batch --level=5 --risk=3 --dbs
                    else
                        echo -e "${YELLOW}[!] No parameters.txt file found. Create one first.${NC}"
                    fi
                    echo -e "${GREEN}[✓] SQLMap scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei SQLi Templates...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        nuclei -l subdomains_alive.txt -tags sqli -o nuclei_sqli_results.txt
                    else
                        echo https://$TARGET | nuclei -tags sqli -o nuclei_sqli_results.txt
                    fi
                    echo -e "${GREEN}[✓] Nuclei SQLi results saved to nuclei_sqli_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Testing Custom SQLi Payloads...${NC}"
                    if [ -f "sqli_candidates.txt" ]; then
                        echo -e "${YELLOW}[!] Manual testing required for custom payloads${NC}"
                        echo "Use payloads like: ' OR 1=1--, admin'--, ' UNION SELECT NULL--"
                    else
                        echo -e "${RED}[!] Run basic detection first${NC}"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# LFI Testing Submenu
lfi_testing_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== LFI TESTING ===${NC}"
        echo ""
        echo "1. Basic LFI Detection"
        echo "2. FFUF LFI Fuzzing"
        echo "3. Nuclei LFI Templates"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " lfi_choice

        case $lfi_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic LFI Detection...${NC}"
                    echo "https://$TARGET/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u > lfi_candidates.txt
                    echo -e "${GREEN}[✓] LFI candidates saved to lfi_candidates.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] FFUF LFI Fuzzing...${NC}"
                    if [ -f "lfi_candidates.txt" ]; then
                        cat lfi_candidates.txt | xargs -I {} sh -c 'ffuf -u "{}?file=FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -v -mr "root:x:0:0:" -o lfi_results_$(echo {} | sed "s/[^a-zA-Z0-9]/_/g").txt'
                    else
                        echo -e "${RED}[!] No LFI candidates found. Run basic detection first.${NC}"
                    fi
                    echo -e "${GREEN}[✓] FFUF LFI fuzzing completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei LFI Templates...${NC}"
                    if [ -f "lfi_candidates.txt" ]; then
                        cat lfi_candidates.txt | nuclei -t nuclei-templates/vulnerabilities/lfi/ -dast
                    else
                        echo https://$TARGET | nuclei -t nuclei-templates/vulnerabilities/lfi/ -dast
                    fi
                    echo -e "${GREEN}[✓] Nuclei LFI scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Command Injection Testing Submenu
command_injection_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== COMMAND INJECTION TESTING ===${NC}"
        echo ""
        echo "1. Basic Command Injection Detection"
        echo "2. Commix Automated Scan"
        echo "3. Nuclei Command Injection Templates"
        echo "4. Header-based Injection Testing"
        echo "5. Time-based Blind Injection"
        echo "6. DNS Blind Injection"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " cmd_choice

        case $cmd_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic Command Injection Detection...${NC}"
                    if [ -f "urls.txt" ]; then
                        cat urls.txt | gf command-injection | tee cmd_injection_candidates.txt
                    else
                        echo https://$TARGET | gau | gf command-injection | tee cmd_injection_candidates.txt
                    fi
                    echo -e "${GREEN}[✓] Command injection candidates saved to cmd_injection_candidates.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running Commix Scan...${NC}"
                    if [ -f "cmd_injection_candidates.txt" ]; then
                        cat cmd_injection_candidates.txt | xargs -I{} commix --url={} --batch
                    else
                        echo -e "${RED}[!] No command injection candidates found. Run basic detection first.${NC}"
                    fi
                    echo -e "${GREEN}[✓] Commix scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei Command Injection Templates...${NC}"
                    nuclei -t nuclei-templates/vulnerabilities/generic/command-injection.yaml -u https://$TARGET
                    echo -e "${GREEN}[✓] Nuclei command injection scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Header-based Injection Testing...${NC}"
                    curl -H "User-Agent: \$(whoami)" https://$TARGET
                    curl -H "X-Forwarded-For: \$(id)" https://$TARGET
                    echo -e "${GREEN}[✓] Header-based injection testing completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Time-based Blind Injection Testing...${NC}"
                    echo -e "${YELLOW}[!] Manual testing with payloads:${NC}"
                    echo "; sleep 10"
                    echo "&& ping -c 5 localhost"
                    echo "; timeout 10"
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                if check_target; then
                    echo -e "${CYAN}[+] DNS Blind Injection Testing...${NC}"
                    read -p "Enter your DNS server (e.g., yourdomain.com): " dns_server
                    echo -e "${YELLOW}[!] Use payload: ; nslookup $dns_server && ping -c 1 $dns_server${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# CORS Testing Submenu
cors_testing_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== CORS TESTING ===${NC}"
        echo ""
        echo "1. Basic CORS Check"
        echo "2. CORScanner"
        echo "3. Nuclei CORS Scan"
        echo "4. Origin Reflection Test"
        echo "5. Corsy Scanner"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " cors_choice

        case $cors_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic CORS Check...${NC}"
                    curl -H "Origin: http://evil.com" -I https://$TARGET/
                    curl -H "Origin: http://$TARGET" -I https://$TARGET/wp-json/
                    echo -e "${GREEN}[✓] Basic CORS check completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running CORScanner...${NC}"
                    python3 CORScanner.py -u https://$TARGET -d -t 10
                    echo -e "${GREEN}[✓] CORScanner completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei CORS Scan...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        cat subdomains_alive.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt
                    else
                        echo https://$TARGET | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt
                    fi
                    echo -e "${GREEN}[✓] Nuclei CORS results saved to cors_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Origin Reflection Test...${NC}"
                    curl -H "Origin: https://evil.com" -I https://$TARGET/api/data | grep -i "access-control-allow-origin: https://evil.com"
                    echo -e "${GREEN}[✓] Origin reflection test completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if check_target; then
                    echo -e "${CYAN}[+] Running Corsy Scanner...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        python3 Corsy.py -i subdomains_alive.txt -t 100
                    else
                        echo https://$TARGET > temp_target.txt
                        python3 Corsy.py -i temp_target.txt -t 100
                        rm temp_target.txt
                    fi
                    echo -e "${GREEN}[✓] Corsy scan completed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}   
open_redirect_submenu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}=== OPEN REDIRECT TESTING ===${NC}"
        echo ""
        echo "1. Basic Open Redirect Detection"
        echo "2. OpenRedirex Scanner"
        echo "3. Nuclei Open Redirect Templates"
        echo "4. Custom Redirect Payloads"
        echo "0. Back to Vulnerability Menu"
        echo ""
        read -p "Select option: " redirect_choice

        case $redirect_choice in
            1)
                if check_target; then
                    echo -e "${CYAN}[+] Basic Open Redirect Detection...${NC}"
                    if ! command -v gf &> /dev/null || ! command -v qsreplace &> /dev/null; then
                        echo -e "${RED}[!] gf and qsreplace are required for this option. Please install them first.${NC}"
                    elif [ -f "urls.txt" ]; then
                        cat urls.txt | gf redirect | tee -a redirect.txt | cut -f 3- -d';' | qsreplace "https://evil.com" | httpx -status-code | tee open_redirect_results.txt
                    else
                        echo https://$TARGET | gau | urldedupe -qs | gf redirect > redirect.txt
                        cat redirect.txt | qsreplace "https://evil.com" | httpx -status-code | tee open_redirect_results.txt
                    fi
                    echo -e "${GREEN}[✓] Redirect candidates and results saved to redirect.txt and open_redirect_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                if check_target; then
                    echo -e "${CYAN}[+] Running OpenRedirex...${NC}"
                    if ! command -v openredirex &> /dev/null; then
                        echo -e "${RED}[!] OpenRedirex is not installed. Please install it first.${NC}"
                    elif [ -f "redirect.txt" ]; then
                        cat redirect.txt | openredirex -p payloads.txt | tee openredirex_results.txt
                    else
                        echo -e "${RED}[!] No redirect candidates found. Run basic detection first.${NC}"
                    fi
                    echo -e "${GREEN}[✓] OpenRedirex scan completed. Results in openredirex_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if check_target; then
                    echo -e "${CYAN}[+] Running Nuclei Open Redirect Templates...${NC}"
                    if [ -f "subdomains_alive.txt" ]; then
                        nuclei -l subdomains_alive.txt -tags redirect -o nuclei_redirect_results.txt
                    else
                        echo https://$TARGET | nuclei -tags redirect -o nuclei_redirect_results.txt
                    fi
                    echo -e "${GREEN}[✓] Nuclei redirect results saved to nuclei_redirect_results.txt${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if check_target; then
                    echo -e "${CYAN}[+] Testing Custom Redirect Payloads...${NC}"
                    echo -e "${YELLOW}[!] Try these payloads in parameters:${NC}"
                    echo "?url=https://evil.com"
                    echo "?redirect=//evil.com"
                    echo "?next=javascript:alert(1)"
                    echo "?return_to=https://evil.com"
                    echo "?dest=https://evil.com"
                    echo "?continue=https://evil.com"
                    echo "?data=https://evil.com"
                    echo "?reference=https://evil.com"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}