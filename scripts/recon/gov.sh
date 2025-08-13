#!/bin/bash

#####################################################################
# Government Domain OSINT Reconnaissance Script (Shell Wrapper)
# Enhanced with Comprehensive MITRE ATT&CK Framework Techniques
#
# DISCLAIMER: This script is for authorized security testing only.
# Only use on domains you own or have explicit permission to test.
# Unauthorized scanning of government systems is illegal.
#
# Author: Security Research Team
# Version: 3.0 - Enhanced with Full MITRE ATT&CK Reconnaissance
#####################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "=================================================================="
    echo "  Government Domain OSINT Reconnaissance Script"
    echo "  Enhanced with MITRE ATT&CK Framework Techniques"
    echo "  Version 3.0 - Comprehensive Reconnaissance Suite"
    echo "=================================================================="
    echo -e "${NC}"
}

# Help function
show_help() {
    echo -e "${CYAN}Usage: $0 [OPTIONS] <domain>${NC}"
    echo ""
    echo -e "${YELLOW}Required:${NC}"
    echo "  <domain>              Target .gov domain to scan"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -h, --help           Show this help message"
    echo "  -o, --output FILE    Output file name (default: gov_recon_results.json)"
    echo "  -c, --config FILE    Configuration file path"
    echo "  -f, --format FORMAT  Output format(s): json,csv,html,xml (default: json,csv)"
    echo "  --proxy PROXY        HTTP/HTTPS proxy (format: http://proxy:port)"
    echo "  --tor                Use Tor proxy (requires Tor running on 9050)"
    echo "  --threads NUM        Number of scanning threads (default: 20)"
    echo "  --timeout NUM        Request timeout in seconds (default: 10)"
    echo "  --max-domains NUM    Maximum domains to process (default: 50)"
    echo "  --browser            Enable browser automation for enhanced recon"
    echo "  --browser-type TYPE  Browser type: chromium,firefox,webkit (default: chromium)"
    echo "  --screenshot         Take screenshots of discovered pages"
    echo "  --headless           Run browser in headless mode (default: true)"
    echo "  --verbose            Enable verbose logging"
    echo ""
    echo -e "${YELLOW}MITRE ATT&CK Techniques Implemented:${NC}"
    echo "  T1595.001-003       Active Scanning (IP Blocks, Vuln Scanning, Wordlist)"
    echo "  T1590.001-006       Gather Victim Network Information"
    echo "  T1591.001-004       Gather Victim Organization Information"
    echo "  T1592.001-004       Gather Victim Host Information"
    echo "  T1589.001-003       Gather Victim Identity Information"
    echo "  T1596.001-005       Search Open Technical Databases"
    echo "  T1593.001-003       Search Open Websites/Domains"
    echo "  T1594               Search Victim-Owned Websites"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 example.gov"
    echo "  $0 -o my_scan.json --format json,html example.gov"
    echo "  $0 --browser --screenshot --verbose example.gov"
    echo "  $0 --proxy http://proxy:8080 --threads 10 example.gov"
    echo ""
    echo -e "${RED}WARNING: Use only on authorized targets!${NC}"
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}[+] Checking dependencies...${NC}"
    
    # Check if Python 3 is available
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python 3 is required but not installed.${NC}"
        exit 1
    fi
    
    # Check if the Python script exists
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
    PYTHON_SCRIPT="$SCRIPT_DIR/gov.py"
    
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo -e "${RED}[!] Python script gov.py not found in $SCRIPT_DIR${NC}"
        exit 1
    fi
    
    # Check Python dependencies
    echo -e "${BLUE}[+] Checking Python dependencies...${NC}"
    python3 -c "
import sys
required_modules = [
    'requests', 'dns.resolver', 'whois', 'socket', 'subprocess', 
    'json', 'csv', 'time', 'random', 'concurrent.futures', 're', 
    'ssl', 'datetime', 'warnings', 'logging', 'os', 'configparser', 
    'urllib3', 'asyncio', 'bs4', 'threading', 'dataclasses', 'typing', 'argparse'
]

missing_modules = []
for module in required_modules:
    try:
        if '.' in module:
            parts = module.split('.')
            __import__(parts[0])
            # Try to access the submodule
            exec(f'import {module}')
        else:
            __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print(f'Missing Python modules: {missing_modules}')
    print('Install with: pip3 install requests dnspython python-whois beautifulsoup4')
    sys.exit(1)
else:
    print('All required Python modules are available.')
" || exit 1
    
    echo -e "${GREEN}[+] All dependencies satisfied${NC}"
}

# Main execution
main() {
    print_banner
    
    # Check for help flag first
    if [[ "$1" == "-h" || "$1" == "--help" || $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    check_dependencies
    
    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
    PYTHON_SCRIPT="$SCRIPT_DIR/gov.py"
    
    # Default values
    OUTPUT_FILE="gov_recon_results.json"
    CONFIG_FILE=""
    FORMAT="json,csv"
    PROXY=""
    USE_TOR=false
    THREADS=""
    TIMEOUT=""
    MAX_DOMAINS=""
    USE_BROWSER=false
    BROWSER_TYPE="chromium"
    SCREENSHOT=false
    HEADLESS=true
    VERBOSE=false
    DOMAIN=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                shift 2
                ;;
            --proxy)
                PROXY="$2"
                shift 2
                ;;
            --tor)
                USE_TOR=true
                shift
                ;;
            --threads)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --max-domains)
                MAX_DOMAINS="$2"
                shift 2
                ;;
            --browser)
                USE_BROWSER=true
                shift
                ;;
            --browser-type)
                BROWSER_TYPE="$2"
                shift 2
                ;;
            --screenshot)
                SCREENSHOT=true
                shift
                ;;
            --headless)
                HEADLESS=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$DOMAIN" ]]; then
                    DOMAIN="$1"
                else
                    echo -e "${RED}[!] Multiple domains not supported. Use: $1${NC}"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$DOMAIN" ]]; then
        echo -e "${RED}[!] Domain is required${NC}"
        show_help
        exit 1
    fi
    
    # Validate domain format
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[!] Invalid domain format: $DOMAIN${NC}"
        exit 1
    fi
    
    # Build Python command
    PYTHON_CMD="python3 \"$PYTHON_SCRIPT\" \"$DOMAIN\""
    
    # Add optional arguments
    if [[ -n "$OUTPUT_FILE" ]]; then
        PYTHON_CMD="$PYTHON_CMD --output \"$OUTPUT_FILE\""
    fi
    
    if [[ -n "$CONFIG_FILE" ]]; then
        PYTHON_CMD="$PYTHON_CMD --config \"$CONFIG_FILE\""
    fi
    
    if [[ -n "$FORMAT" ]]; then
        IFS=',' read -ra FORMAT_ARRAY <<< "$FORMAT"
        for fmt in "${FORMAT_ARRAY[@]}"; do
            PYTHON_CMD="$PYTHON_CMD --format $fmt"
        done
    fi
    
    if [[ -n "$PROXY" ]]; then
        PYTHON_CMD="$PYTHON_CMD --proxy \"$PROXY\""
    fi
    
    if [[ "$USE_TOR" == true ]]; then
        PYTHON_CMD="$PYTHON_CMD --tor"
    fi
    
    if [[ -n "$THREADS" ]]; then
        PYTHON_CMD="$PYTHON_CMD --threads $THREADS"
    fi
    
    if [[ -n "$TIMEOUT" ]]; then
        PYTHON_CMD="$PYTHON_CMD --timeout $TIMEOUT"
    fi
    
    if [[ -n "$MAX_DOMAINS" ]]; then
        PYTHON_CMD="$PYTHON_CMD --max-domains $MAX_DOMAINS"
    fi
    
    if [[ "$USE_BROWSER" == true ]]; then
        PYTHON_CMD="$PYTHON_CMD --browser"
    fi
    
    if [[ -n "$BROWSER_TYPE" ]]; then
        PYTHON_CMD="$PYTHON_CMD --browser-type $BROWSER_TYPE"
    fi
    
    if [[ "$SCREENSHOT" == true ]]; then
        PYTHON_CMD="$PYTHON_CMD --screenshot"
    fi
    
    if [[ "$HEADLESS" == false ]]; then
        PYTHON_CMD="$PYTHON_CMD --no-headless"
    fi
    
    if [[ "$VERBOSE" == true ]]; then
        PYTHON_CMD="$PYTHON_CMD --verbose"
    fi
    
    # Display command info
    echo -e "${BLUE}[+] Target Domain: $DOMAIN${NC}"
    echo -e "${BLUE}[+] Output File: $OUTPUT_FILE${NC}"
    echo -e "${BLUE}[+] Output Formats: $FORMAT${NC}"
    
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${YELLOW}[DEBUG] Executing: $PYTHON_CMD${NC}"
    fi
    
    # Execute Python script
    echo -e "${GREEN}[+] Starting enhanced reconnaissance...${NC}"
    eval "$PYTHON_CMD"
    
    # Check execution result
    if [[ $? -eq 0 ]]; then
        echo ""
        echo -e "${GREEN}[+] Reconnaissance completed successfully!${NC}"
        echo -e "${BLUE}[+] Results saved to: $OUTPUT_FILE${NC}"
        
        # List generated files
        BASE_NAME="${OUTPUT_FILE%.*}"
        echo -e "${BLUE}[+] Generated files:${NC}"
        
        for file in "${BASE_NAME}"*; do
            if [[ -f "$file" ]]; then
                SIZE=$(ls -lh "$file" | awk '{print $5}')
                echo -e "    ${CYAN}- $file ($SIZE)${NC}"
            fi
        done
        
    else
        echo -e "${RED}[!] Reconnaissance failed with exit code $?${NC}"
        exit 1
    fi
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}[!] Reconnaissance interrupted by user${NC}"; exit 130' INT

# Execute main function
main "$@"