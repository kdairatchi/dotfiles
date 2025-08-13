#!/bin/bash

# Ultimate JS Recon & Secret Finder
# Combines subfinder/httpx/hakrawler/jsninja with gauplus/fff/gf/amass
# Author: Your Name
# Version: 3.0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
  ____  _____   ____  _____  ____  ____  _____ 
 / ___||____ | / ___|| ____||  _ \|  _ \| ____|
 \___ \  /_/ | \___ \|  _|  | |_) | |_) |  _|  
  ___) / ___|  ___) | |___ |  _ <|  _ <| |___ 
 |____/_/     |____/|_____||_| \_\_| \_\_____|
EOF
echo -e "${NC}"
echo -e "${YELLOW}Ultimate JavaScript Recon & Secret Finder${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"
echo ""

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}[!] Error: No domain specified.${NC}"
    echo -e "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="ultimate_recon_${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Check required tools
check_tools() {
    local tools=("subfinder" "httpx" "hakrawler" "jsninja" "gauplus" "fff" "gf" "amass" "curl")
    local missing=0
    
    echo -e "${BLUE}[*] Checking for required tools...${NC}"
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[-] $tool is not installed${NC}"
            missing=$((missing + 1))
        else
            echo -e "${GREEN}[+] $tool is installed${NC}"
        fi
    done
    
    if [ "$missing" -gt 0 ]; then
        echo -e "${RED}[!] Please install missing tools before running this script${NC}"
        echo -e "${YELLOW}Installation commands:${NC}"
        echo -e "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo -e "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo -e "go install github.com/hakluke/hakrawler@latest"
        echo -e "pip install jsninja"
        echo -e "go install github.com/bp0lr/gauplus@latest"
        echo -e "go install github.com/tomnomnom/fff@latest"
        echo -e "go install github.com/tomnomnom/gf@latest"
        echo -e "go install github.com/owasp-amass/amass/v3/...@master"
        exit 1
    fi
}

run_recon() {
    echo -e "\n${BLUE}[*] Starting comprehensive recon on ${DOMAIN}...${NC}"
    
    # PHASE 1: Subdomain-based recon
    echo -e "${YELLOW}[PHASE 1] Subdomain-based reconnaissance${NC}"
    
    # Step 1: Subdomain enumeration
    echo -e "${YELLOW}[1] Running subfinder to find subdomains...${NC}"
    subfinder -d "$DOMAIN" -silent | tee "${OUTPUT_DIR}/subdomains.txt"
    
    # Step 2: HTTP probing
    echo -e "\n${YELLOW}[2] Running httpx to find live web servers...${NC}"
    httpx -silent -l "${OUTPUT_DIR}/subdomains.txt" | tee "${OUTPUT_DIR}/live_servers.txt"
    
    # Step 3: JS file discovery with hakrawler
    echo -e "\n${YELLOW}[3] Finding JavaScript files with hakrawler...${NC}"
    while read -r url; do
        hakrawler "$url" | grep -E '\.js($|\?)' >> "${OUTPUT_DIR}/hakrawler_js_urls.txt"
    done < "${OUTPUT_DIR}/live_servers.txt"
    
    # PHASE 2: Gauplus-based recon
    echo -e "\n${YELLOW}[PHASE 2] Historical URL analysis${NC}"
    
    # Step 4: Find JS/JSON files with gauplus
    echo -e "${YELLOW}[4] Finding JS/JSON files with gauplus...${NC}"
    gauplus "$DOMAIN" -subs | cut -d"?" -f1 | grep -E "\.js+(?:on|)$" | tee "${OUTPUT_DIR}/gauplus_js_urls.txt"
    
    # Step 5: Combine and deduplicate JS URLs
    echo -e "\n${YELLOW}[5] Combining and deduplicating JS URLs...${NC}"
    cat "${OUTPUT_DIR}/hakrawler_js_urls.txt" "${OUTPUT_DIR}/gauplus_js_urls.txt" | sort -u > "${OUTPUT_DIR}/all_js_urls.txt"
    JS_COUNT=$(wc -l < "${OUTPUT_DIR}/all_js_urls.txt")
    echo -e "${GREEN}[+] Found ${JS_COUNT} unique JavaScript files${NC}"
    
    if [ "$JS_COUNT" -eq 0 ]; then
        echo -e "${RED}[!] No JavaScript files found. Exiting.${NC}"
        exit 1
    fi
    
    # Step 6: Fetch live JS files
    echo -e "\n${YELLOW}[6] Fetching live JS files with fff...${NC}"
    fff -s 200 -o "${OUTPUT_DIR}/js_files/" < "${OUTPUT_DIR}/all_js_urls.txt"
    
    # PHASE 3: Analysis
    echo -e "\n${YELLOW}[PHASE 3] Analysis${NC}"
    
    # Step 7: Secret scanning
    echo -e "${YELLOW}[7] Scanning for secrets with jsninja...${NC}"
    jsninja --secrets --urls -o "${OUTPUT_DIR}/jsninja_results.txt" < "${OUTPUT_DIR}/all_js_urls.txt"
    
    # Step 8: GF patterns scanning
    echo -e "\n${YELLOW}[8] Scanning with gf patterns...${NC}"
    for i in $(gf -list); do
        if [[ ${i} =~ "_secrets"* ]]; then
            echo -e "${BLUE}[*] Checking with ${i}...${NC}"
            gf "${i}" "${OUTPUT_DIR}/js_files/*" | tee -a "${OUTPUT_DIR}/gf_secrets.txt"
        fi
    done
    
    # Step 9: Amass enumeration and XSS detection
    echo -e "\n${YELLOW}[9] Running amass enumeration and XSS detection...${NC}"
    amass enum -passive -brute -d "$DOMAIN" | \
    gau | \
    egrep -v '(.css|.svg)' | \
    while read url; do 
        vars=$(curl -s "$url" | \
        grep -Eo "var [a-zA-Z0-9]+" | \
        sed -e "s,'var','$url'?,g" -e 's/ //g' | \
        grep -v '.js' | \
        sed 's/.*/&=xss/g')
        
        if [ -n "$vars" ]; then
            echo -e "${YELLOW}$url${NC}" | tee -a "${OUTPUT_DIR}/xss_vars.txt"
            echo -e "${GREEN}$vars${NC}" | tee -a "${OUTPUT_DIR}/xss_vars.txt"
        fi
    done
    
    # Final results
    SECRETS_COUNT=$(grep -c "Secret found" "${OUTPUT_DIR}/jsninja_results.txt" 2>/dev/null || echo "0")
    GF_SECRETS_COUNT=$(wc -l < "${OUTPUT_DIR}/gf_secrets.txt" 2>/dev/null || echo "0")
    XSS_VARS_COUNT=$(grep -c "http" "${OUTPUT_DIR}/xss_vars.txt" 2>/dev/null || echo "0")
    
    echo -e "\n${GREEN}[+] Recon completed!${NC}"
    echo -e "${BLUE}[*] Found ${JS_COUNT} JavaScript files${NC}"
    echo -e "${BLUE}[*] Found ${SECRETS_COUNT} potential secrets (jsninja)${NC}"
    echo -e "${BLUE}[*] Found ${GF_SECRETS_COUNT} potential secrets (gf)${NC}"
    echo -e "${BLUE}[*] Found ${XSS_VARS_COUNT} potential XSS variables${NC}"
    
    echo -e "\n${YELLOW}Results saved in: ${OUTPUT_DIR}/${NC}"
    echo -e "- Subdomains: ${OUTPUT_DIR}/subdomains.txt"
    echo -e "- Live servers: ${OUTPUT_DIR}/live_servers.txt"
    echo -e "- All JS URLs: ${OUTPUT_DIR}/all_js_urls.txt"
    echo -e "- Downloaded JS files: ${OUTPUT_DIR}/js_files/"
    echo -e "- JSninja results: ${OUTPUT_DIR}/jsninja_results.txt"
    echo -e "- GF secrets: ${OUTPUT_DIR}/gf_secrets.txt"
    echo -e "- XSS variables: ${OUTPUT_DIR}/xss_vars.txt"
}

# Main execution
check_tools
run_recon
