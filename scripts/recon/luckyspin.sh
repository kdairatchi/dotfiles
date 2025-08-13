#!/bin/bash
# by @kdairatchi | sacsecurity.tech
# Ultimate version with interactive mode and advanced features

API_URL="https://www.sacsecurity.tech/getLuckyProgram.php"
GITHUB_BOUNTY_DATA_URL="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/"
GOOGLE_DORKING_ENABLED=false
PLAYWRIGHT_ENABLED=false
HTMLQ_ENABLED=false
GITHUB_SOURCE_ENABLED=false
MULTI_SOURCE_MODE=false
DEFAULT_LOG="$HOME/.luckyspin_history.log"
CONFIG_FILE="$HOME/.luckyspin_config"
WORDLIST_DIR="$HOME/.luckyspin_wordlists"
CUSTOM_TEMPLATES_DIR="$HOME/.luckyspin_templates"
HISTORY_FILE="$HOME/.luckyspin_commands.history"

# Default settings
COUNT=1
OPEN=false
COPY=false
RECON=false
HTTPX=false
NUCLEI=false
MANUAL_MODE=false
INTERACTIVE=false
TARGET_DOMAIN=""
LOG_FILE="$DEFAULT_LOG"
WEBHOOK_URL=""
ENABLE_STATS=true
THREADS=10
RATE_LIMIT=150
SUBDOMAIN_BRUTEFORCE=false
SCREENSHOT=false
PASSIVE_MODE=false
FAST_MODE=false
THOROUGH_MODE=false
CUSTOM_WORDLIST=""
CUSTOM_RESOLVERS=""
CUSTOM_NUCLEI_TEMPLATES=""
SOURCE_SELECTION="api"
GITHUB_CACHE_DIR="$HOME/.luckyspin_github_cache"
GOOGLE_DORKING_QUERIES="$HOME/.luckyspin_google_dorks"
PLAYWRIGHT_SCRIPT="$HOME/.luckyspin_playwright.js"
SLACK_WEBHOOK=""
DISCORD_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
CUSTOM_HEADER=""
CUSTOM_USER_AGENT="LuckyBounty-Recon/7.0"
TIMEOUT=10
RETRIES=3
DNS_RESOLUTION=true
PORT_SCAN=false
PORTS="80,443,8080,8443"
VULN_SCAN_LEVEL="medium,high,critical"
TECHNOLOGY_DETECTION=false
CLOUD_ENUM=false
TAKEOVER_SCAN=false
SAVE_RESULTS=true
RESULTS_FORMAT="json,txt"
RESULTS_DIR="$HOME/LuckyBounty_Results"
MAX_HISTORY_SIZE=100
DEBUG_MODE=false
VERSION="1.0-BETA "

# Terminal colors and styles
RED="\e[1;91m"; GREEN="\e[1;92m"; BLUE="\e[1;94m"
YELLOW="\e[1;93m"; CYAN="\e[1;96m"; MAGENTA="\e[1;95m"
GRAY="\e[1;90m"; WHITE="\e[1;97m"; BOLD="\e[1m"; RESET="\e[0m"
BG_BLACK="\e[40m"; BG_BLUE="\e[44m"; BG_MAGENTA="\e[45m"
BG_GREEN="\e[42m"; BG_RED="\e[41m"; BG_CYAN="\e[46m"

# Fancy box drawing characters
BOX_TL="╭"; BOX_TR="╮"; BOX_BL="╰"; BOX_BR="╯"
BOX_H="─"; BOX_V="│"; BOX_VR="├"; BOX_VL="┤"
BOX_HU="┴"; BOX_HD="┬"; BOX_HV="┼"

# Emoji and symbols
EMOJI_TARGET="🎯"; EMOJI_ROCKET="🚀"; EMOJI_GLOBE="🌐"
EMOJI_CHECK="✓"; EMOJI_WARN="⚠️"; EMOJI_ERROR="✗"
EMOJI_SEARCH="🔍"; EMOJI_LINK="🔗"; EMOJI_COG="⚙"
EMOJI_FIRE="🔥"; EMOJI_SHIELD="🛡️"; EMOJI_STAR="⭐"
EMOJI_TOOL="🔧"; EMOJI_CROWN="👑"; EMOJI_LOCK="🔒"
EMOJI_INFO="ℹ️"; EMOJI_BELL="🔔"; EMOJI_CAMERA="📷"
EMOJI_DOCUMENT="📄"; EMOJI_CLOUD="☁️"

# Initialize directories
init_dirs() {
  mkdir -p "$WORDLIST_DIR" 2>/dev/null
  mkdir -p "$CUSTOM_TEMPLATES_DIR" 2>/dev/null
  mkdir -p "$RESULTS_DIR" 2>/dev/null
  mkdir -p "$GITHUB_CACHE_DIR" 2>/dev/null
  
  # Create history file if it doesn't exist
  touch "$HISTORY_FILE" 2>/dev/null
  
  # If no wordlists exist, create a basic one
  if [ ! -f "$WORDLIST_DIR/basic_subdomains.txt" ]; then
    echo -e "${YELLOW}[${EMOJI_INFO}] Creating basic wordlist...${RESET}"
    cat > "$WORDLIST_DIR/basic_subdomains.txt" << EOF
www
api
mail
admin
blog
dev
test
stage
app
m
mobile
shop
store
cdn
media
portal
sso
auth
login
internal
staging
beta
alpha
v1
v2
support
help
secure
pay
payment
checkout
docs
documentation
status
static
assets
images
files
download
uploads
corp
corporate
EOF
  fi
  
  # Initialize Google dorking queries if they don't exist
  if [ ! -f "$GOOGLE_DORKING_QUERIES" ]; then
    echo -e "${YELLOW}[${EMOJI_INFO}] Creating Google dorking queries...${RESET}"
    cat > "$GOOGLE_DORKING_QUERIES" << 'EOF'
site:hackerone.com inurl:"/reports/" "bug bounty"
site:bugcrowd.com inurl:"/programs/" "bug bounty"
site:github.com "bug bounty" "responsible disclosure"
site:*.com "security researcher" "vulnerability disclosure"
intitle:"Bug Bounty" site:*.com
"responsible disclosure" "security" site:*.com
"vulnerability disclosure policy" site:*.com
"security bug bounty" site:*.com
"hall of fame" security site:*.com
"security researcher" "bounty" site:*.com
EOF
  fi
  
  # Initialize Playwright script if it doesn't exist
  if [ ! -f "$PLAYWRIGHT_SCRIPT" ]; then
    echo -e "${YELLOW}[${EMOJI_INFO}] Creating Playwright script...${RESET}"
    cat > "$PLAYWRIGHT_SCRIPT" << 'EOF'
const { chromium } = require('playwright');

async function extractBountyPrograms() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  const sources = [
    'https://hackerone.com/directory/programs',
    'https://bugcrowd.com/programs',
    'https://www.intigriti.com/programs'
  ];
  
  const programs = [];
  
  for (const source of sources) {
    try {
      await page.goto(source);
      await page.waitForLoadState('networkidle');
      
      // Extract program data based on the source
      const sourcePrograms = await page.evaluate(() => {
        const results = [];
        // Add source-specific extraction logic here
        return results;
      });
      
      programs.push(...sourcePrograms);
    } catch (error) {
      console.error(`Error fetching ${source}:`, error);
    }
  }
  
  await browser.close();
  return programs;
}

if (require.main === module) {
  extractBountyPrograms().then(programs => {
    console.log(JSON.stringify(programs, null, 2));
  });
}
EOF
  fi
}

# Load configuration if exists
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    echo -e "${GRAY}[${EMOJI_COG}] Loaded configuration from $CONFIG_FILE${RESET}"
  fi
}

# Save current settings to config
save_config() {
  cat > "$CONFIG_FILE" << EOF
# Lucky Bounty Picker Ultimate Configuration
# Generated on $(date)
WEBHOOK_URL="$WEBHOOK_URL"
LOG_FILE="$LOG_FILE"
ENABLE_STATS=$ENABLE_STATS
THREADS=$THREADS
RATE_LIMIT=$RATE_LIMIT
DISCORD_WEBHOOK="$DISCORD_WEBHOOK"
SLACK_WEBHOOK="$SLACK_WEBHOOK"
TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
CUSTOM_HEADER="$CUSTOM_HEADER"
CUSTOM_USER_AGENT="$CUSTOM_USER_AGENT"
SUBDOMAIN_BRUTEFORCE=$SUBDOMAIN_BRUTEFORCE
SCREENSHOT=$SCREENSHOT
PASSIVE_MODE=$PASSIVE_MODE
FAST_MODE=$FAST_MODE
THOROUGH_MODE=$THOROUGH_MODE
CUSTOM_WORDLIST="$CUSTOM_WORDLIST"
CUSTOM_RESOLVERS="$CUSTOM_RESOLVERS"
CUSTOM_NUCLEI_TEMPLATES="$CUSTOM_NUCLEI_TEMPLATES"
VULN_SCAN_LEVEL="$VULN_SCAN_LEVEL"
TECHNOLOGY_DETECTION=$TECHNOLOGY_DETECTION
CLOUD_ENUM=$CLOUD_ENUM
TAKEOVER_SCAN=$TAKEOVER_SCAN
SAVE_RESULTS=$SAVE_RESULTS
RESULTS_FORMAT="$RESULTS_FORMAT"
RESULTS_DIR="$RESULTS_DIR"
EOF
  echo -e "${GREEN}[${EMOJI_CHECK}] Configuration saved to $CONFIG_FILE${RESET}"
}

# Add command to history
add_to_history() {
  local cmd="$*"
  echo "$cmd" >> "$HISTORY_FILE"
  # Keep history file within size limit
  tail -n $MAX_HISTORY_SIZE "$HISTORY_FILE" > "${HISTORY_FILE}.tmp"
  mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE"
}

# Enhanced spinner with progress text and color options
spinner() {
  local pid=$1 
  local message="${2:-Spinning for a lucky target}"
  local color="${3:-$YELLOW}"
  local delay=0.08 
  local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  
  printf "${color}${BOLD}${message} "
  
  while kill -0 $pid 2>/dev/null; do
    for ((i=0; i<${#spinstr}; i++)); do
      printf "\b${spinstr:$i:1}"
      sleep $delay
    done
  done
  
  printf "\b ${EMOJI_CHECK}${RESET}\n"
}

# Center text in terminal with optional background
center_text() {
  local text="$1"
  local width=${2:-$(tput cols)}
  local bg_color="${3:-}"
  local fg_color="${4:-$WHITE}"
  local padding=$(( (width - ${#text}) / 2 ))
  
  printf "%${padding}s" ""
  if [[ -n "$bg_color" ]]; then
    printf "${bg_color}${fg_color}%s${RESET}" " $text "
  else
    printf "${fg_color}%s${RESET}" "$text"
  fi
  printf "%${padding}s" ""
  echo
}

# Draw a fancy box with title and optional color scheme
draw_box() {
  local title="$1"
  local content=("${@:2}")
  local width=70
  local box_color="${CYAN}"
  local title_bg="${BG_BLUE}"
  local title_fg="${WHITE}"
  
  # Check for box style parameter (last parameter)
  if [[ "${content[-1]}" == "style:"* ]]; then
    local style=${content[-1]#style:}
    unset 'content[-1]'
    
    case "$style" in
      "info") box_color="${BLUE}"; title_bg="${BG_BLUE}"; title_fg="${WHITE}" ;;
      "success") box_color="${GREEN}"; title_bg="${BG_GREEN}"; title_fg="${WHITE}" ;;
      "error") box_color="${RED}"; title_bg="${BG_RED}"; title_fg="${WHITE}" ;;
      "warning") box_color="${YELLOW}"; title_bg="${BG_BLACK}"; title_fg="${YELLOW}" ;;
      "highlight") box_color="${MAGENTA}"; title_bg="${BG_MAGENTA}"; title_fg="${WHITE}" ;;
      *) ;;
    esac
  fi
  
  local title_start=$(( (width - ${#title} - 4) / 2 ))
  
  echo -e "${box_color}${BOX_TL}${BOX_H}${BOX_H}${BOX_H}${BOX_H}"
  printf "%${title_start}s" "" 
  echo -e "${title_bg}${title_fg} ${title} ${RESET}${box_color}"
  printf "%s" "${BOX_H}"
  for ((i=0; i<width-title_start-${#title}-6; i++)); do
    printf "%s" "${BOX_H}"
  done
  echo -e "${BOX_TR}"
  
  for line in "${content[@]}"; do
    # Check if line contains tab characters for column alignment
    if [[ "$line" == *$'\t'* ]]; then
      local columns=()
      IFS=$'\t' read -ra columns <<< "$line"
      local col_text="${RESET}${columns[0]}"
      local col_width=$(( (width - 4) / 2 ))
      
      echo -ne "${box_color}${BOX_V} ${RESET}${col_text}"
      printf "%$((col_width - ${#col_text}))s" ""
      
      if [[ ${#columns[@]} -gt 1 ]]; then
        echo -ne "${columns[1]}"
        printf "%$((width - col_width - ${#columns[1]} - 3))s" ""
      else
        printf "%$((width - col_width - 3))s" ""
      fi
      echo -e "${box_color}${BOX_V}${RESET}"
    else
      echo -e "${box_color}${BOX_V} ${RESET}${line}$(printf "%$((width - ${#line} - 3))s" "")${box_color}${BOX_V}"
    fi
  done
  
  echo -e "${BOX_BL}"
  for ((i=0; i<width; i++)); do
    printf "%s" "${BOX_H}"
  done
  echo -e "${BOX_BR}${RESET}"
}

# Progress bar display
progress_bar() {
  local current=$1
  local total=$2
  local message="${3:-Progress}"
  local width=40
  local percentage=$((current * 100 / total))
  local completed=$((width * current / total))
  local remaining=$((width - completed))
  
  printf "\r${YELLOW}${message}: ["
  printf "%${completed}s" | tr ' ' '█'
  printf "%${remaining}s" | tr ' ' '░'
  printf "] ${percentage}%%${RESET}"
  
  [[ $current -eq $total ]] && echo
}

# Display an interactive menu with options
show_menu() {
  local title="$1"
  local options=("${@:2}")
  local choice
  
  echo -e "${CYAN}${BOLD}${title}${RESET}"
  echo -e "${CYAN}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${BOX_H}${RESET}"
  
  for i in "${!options[@]}"; do
    echo -e "${CYAN}[${WHITE}$((i+1))${CYAN}]${RESET} ${options[$i]}"
  done
  
  echo -e "${CYAN}[${WHITE}q${CYAN}]${RESET} Quit/Back"
  echo
  
  read -p "$(echo -e ${YELLOW}Enter choice:${RESET} ) " choice
  
  if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
    return 0
  elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le "${#options[@]}" ]]; then
    return "$choice"
  else
    echo -e "${RED}[${EMOJI_ERROR}] Invalid choice.${RESET}"
    return 255
  fi
}

# Parse command line arguments
parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --count|-c) COUNT="$2"; shift ;;
      --open|-o) OPEN=true ;;
      --copy) COPY=true ;;
      --recon) RECON=true ;;
      --httpx) HTTPX=true ;;
      --nuclei) NUCLEI=true ;;
      --manual) MANUAL_MODE=true ;;
      --interactive|-i) INTERACTIVE=true ;;
      --target|-t) TARGET_DOMAIN="$2"; shift ;;
      --webhook|-w) WEBHOOK_URL="$2"; shift ;;
      --log|-l) LOG_FILE="$2"; shift ;;
      --threads) THREADS="$2"; shift ;;
      --rate) RATE_LIMIT="$2"; shift ;;
      --no-stats) ENABLE_STATS=false ;;
      --save-config) SAVE_CONFIG=true ;;
      --subdomain-bruteforce|-b) SUBDOMAIN_BRUTEFORCE=true ;;
      --screenshot|-s) SCREENSHOT=true ;;
      --passive) PASSIVE_MODE=true ;;
      --fast) FAST_MODE=true ;;
      --thorough) THOROUGH_MODE=true ;;
      --wordlist) CUSTOM_WORDLIST="$2"; shift ;;
      --resolvers) CUSTOM_RESOLVERS="$2"; shift ;;
      --templates) CUSTOM_NUCLEI_TEMPLATES="$2"; shift ;;
      --discord) DISCORD_WEBHOOK="$2"; shift ;;
      --slack) SLACK_WEBHOOK="$2"; shift ;;
      --telegram-token) TELEGRAM_BOT_TOKEN="$2"; shift ;;
      --telegram-chat) TELEGRAM_CHAT_ID="$2"; shift ;;
      --header) CUSTOM_HEADER="$2"; shift ;;
      --user-agent) CUSTOM_USER_AGENT="$2"; shift ;;
      --timeout) TIMEOUT="$2"; shift ;;
      --retries) RETRIES="$2"; shift ;;
      --no-dns) DNS_RESOLUTION=false ;;
      --ports) PORT_SCAN=true; PORTS="$2"; shift ;;
      --scan-level) VULN_SCAN_LEVEL="$2"; shift ;;
      --tech-detect) TECHNOLOGY_DETECTION=true ;;
      --cloud-enum) CLOUD_ENUM=true ;;
      --takeover) TAKEOVER_SCAN=true ;;
      --no-save) SAVE_RESULTS=false ;;
      --format) RESULTS_FORMAT="$2"; shift ;;
      --output-dir) RESULTS_DIR="$2"; shift ;;
      --debug) DEBUG_MODE=true ;;
      --source) SOURCE_SELECTION="$2"; shift ;;
      --github-source) GITHUB_SOURCE_ENABLED=true; SOURCE_SELECTION="github" ;;
      --google-dorking) GOOGLE_DORKING_ENABLED=true; SOURCE_SELECTION="google" ;;
      --playwright) PLAYWRIGHT_ENABLED=true; SOURCE_SELECTION="playwright" ;;
      --htmlq) HTMLQ_ENABLED=true ;;
      --multi-source) MULTI_SOURCE_MODE=true ;;
      --version|-v) echo -e "${GREEN}${BOLD}Lucky Bounty Picker v${VERSION}${RESET}"; exit 0 ;;
      --help|-h) show_help; exit 0 ;;
      *) echo -e "${RED}[${EMOJI_ERROR}] Unknown option: $1${RESET}"; show_help; exit 1 ;;
    esac
    shift
  done
  
  # Add command to history for interactive recall
  add_to_history "$@"
  
  # Handle conflicting modes
  if [[ "$FAST_MODE" == true && "$THOROUGH_MODE" == true ]]; then
    echo -e "${YELLOW}[${EMOJI_WARN}] Fast and thorough modes cannot be used together. Using thorough mode.${RESET}"
    FAST_MODE=false
  fi
  
  # Enable multi-source mode if requested
  if [[ "$MULTI_SOURCE_MODE" == true ]]; then
    SOURCE_SELECTION="multi"
    GITHUB_SOURCE_ENABLED=true
    GOOGLE_DORKING_ENABLED=true
    PLAYWRIGHT_ENABLED=true
  fi
  
  # Set preset configurations based on modes
  if [[ "$FAST_MODE" == true ]]; then
    THREADS=50
    RATE_LIMIT=300
    TIMEOUT=5
    RETRIES=1
  elif [[ "$THOROUGH_MODE" == true ]]; then
    THREADS=5
    RATE_LIMIT=50
    TIMEOUT=30
    RETRIES=3
    TAKEOVER_SCAN=true
    SCREENSHOT=true
    SUBDOMAIN_BRUTEFORCE=true
    TECHNOLOGY_DETECTION=true
  fi
}

# Display help information
show_help() {
  clear
  center_text "${WHITE}${BG_MAGENTA} Lucky Bounty Picker Ultimate v${VERSION} ${RESET}" 
  echo
  
  local content=(
    "${BOLD}USAGE:${RESET} ./luckyspin.sh [options]"
    ""
    "${BOLD}${CYAN}=== BASIC OPTIONS ===${RESET}"
    "  ${GREEN}--count, -c <n>${RESET}     Number of spins (default: 1)"
    "  ${GREEN}--interactive, -i${RESET}   Start in interactive mode with menu"
    "  ${GREEN}--manual${RESET}            Ask for manual domain input"
    "  ${GREEN}--target, -t <domain>${RESET} Use specific domain"
    "  ${GREEN}--open, -o${RESET}          Auto-open URL in browser"
    "  ${GREEN}--copy${RESET}              Copy spun URL to clipboard"
    ""
    "${BOLD}${CYAN}=== RECON OPTIONS ===${RESET}"
    "  ${GREEN}--recon${RESET}             Run subfinder on extracted domain(s)"
    "  ${GREEN}--httpx${RESET}             Probe with httpx"
    "  ${GREEN}--nuclei${RESET}            Scan with nuclei"
    "  ${GREEN}--subdomain-bruteforce, -b${RESET} Enable subdomain bruteforce"
    "  ${GREEN}--screenshot, -s${RESET}    Take screenshots of discovered hosts"
    "  ${GREEN}--passive${RESET}           Passive mode (no active probing)"
    "  ${GREEN}--fast${RESET}              Optimize for speed (less thorough)"
    "  ${GREEN}--thorough${RESET}          Thorough scanning (slower but more complete)"
    "  ${GREEN}--ports <list>${RESET}      Enable port scanning (comma-separated list)"
    "  ${GREEN}--tech-detect${RESET}       Enable technology detection"
    "  ${GREEN}--cloud-enum${RESET}        Enable cloud resource enumeration"
    "  ${GREEN}--takeover${RESET}          Scan for subdomain takeover vulnerabilities"
    ""
    "${BOLD}${CYAN}=== CUSTOMIZATION ===${RESET}"
    "  ${GREEN}--wordlist <file>${RESET}   Custom wordlist for bruteforce"
    "  ${GREEN}--resolvers <file>${RESET}  Custom DNS resolvers"
    "  ${GREEN}--templates <dir>${RESET}   Custom nuclei templates"
    "  ${GREEN}--scan-level <level>${RESET} Vulnerability scan level (default: medium,high,critical)"
    "  ${GREEN}--header <header>${RESET}   Custom HTTP header for requests"
    "  ${GREEN}--user-agent <ua>${RESET}   Custom User-Agent"
    "  ${GREEN}--timeout <sec>${RESET}     Connection timeout (default: 10)"
    "  ${GREEN}--retries <n>${RESET}       Number of retries (default: 3)"
    "  ${GREEN}--no-dns${RESET}           Disable DNS resolution"
    "  ${GREEN}--format <formats>${RESET}   Results format (default: json,txt)"
    "  ${GREEN}--output-dir <dir>${RESET}   Results directory"
    "  ${GREEN}--no-save${RESET}           Disable saving results"
    ""
    "${BOLD}${CYAN}=== NOTIFICATIONS ===${RESET}"
    "  ${GREEN}--webhook, -w <url>${RESET} Send results to webhook"
    "  ${GREEN}--discord <url>${RESET}     Discord webhook URL"
    "  ${GREEN}--slack <url>${RESET}       Slack webhook URL"
    "  ${GREEN}--telegram-token <token>${RESET} Telegram bot token"
    "  ${GREEN}--telegram-chat <id>${RESET} Telegram chat ID"
    ""
    "${BOLD}${CYAN}=== SOURCE OPTIONS ===${RESET}"
    "  ${GREEN}--source <type>${RESET}     Choose source: api, github, google, playwright, multi"
    "  ${GREEN}--github-source${RESET}     Use GitHub bounty-targets-data"
    "  ${GREEN}--google-dorking${RESET}    Use Google dorking for programs"
    "  ${GREEN}--playwright${RESET}        Use Playwright for dynamic extraction"
    "  ${GREEN}--htmlq${RESET}             Use htmlq for static site parsing"
    "  ${GREEN}--multi-source${RESET}      Use multiple sources randomly"
    ""
    "${BOLD}${CYAN}=== OTHER OPTIONS ===${RESET}"
    "  ${GREEN}--log, -l <file>${RESET}    Output log location"
    "  ${GREEN}--threads <n>${RESET}       Set number of threads (default: 10)"
    "  ${GREEN}--rate <n>${RESET}          Set rate limit (default: 150)"
    "  ${GREEN}--no-stats${RESET}          Disable statistics display"
    "  ${GREEN}--save-config${RESET}       Save current settings to config file"
    "  ${GREEN}--debug${RESET}             Enable debug output"
    "  ${GREEN}--version, -v${RESET}       Show version"
    ""
    "${BOLD}EXAMPLES:${RESET}"
    "  ${GRAY}# Start interactive mode${RESET}"
    "  ./luckyspin.sh -i"
    ""
    "  ${GRAY}# Spin 3 times with full recon${RESET}"
    "  ./luckyspin.sh -c 3 --recon --httpx --nuclei"
    ""
    "  ${GRAY}# Thorough scan with all tools${RESET}"
    "  ./luckyspin.sh -t example.com --thorough"
    ""
    "  ${GRAY}# Fast passive reconnaissance${RESET}"
    "  ./luckyspin.sh -t example.com --recon --passive --fast"
    ""
    "  ${GRAY}# Use GitHub bounty-targets-data${RESET}"
    "  ./luckyspin.sh --github-source --recon"
    ""
    "  ${GRAY}# Use Google dorking with htmlq${RESET}"
    "  ./luckyspin.sh --google-dorking --htmlq"
    ""
    "  ${GRAY}# Use multi-source mode${RESET}"
    "  ./luckyspin.sh --multi-source --recon --httpx"
  )
  
  draw_box "Help & Documentation" "${content[@]}" "style:highlight"
}

# Check for required tools and dependencies
check_dependencies() {
  local missing=0
  local tools_info=()

  # Create array of required and optional tools
  declare -A req_tools=( 
    ["jq"]="JSON processor" 
  )
  
  declare -A opt_tools=(
    ["subfinder"]="Subdomain discovery tool"
    ["httpx"]="HTTP probing tool"
    ["nuclei"]="Vulnerability scanner"
    ["amass"]="Network mapping tool"
    ["assetfinder"]="Find domains and subdomains"
    ["ffuf"]="Fast web fuzzer"
    ["aquatone"]="Visual inspection tool"
    ["waybackurls"]="Fetch URLs from Wayback Machine"
    ["subjack"]="Subdomain Takeover tool"
    ["dnsx"]="DNS toolkit"
    ["nmap"]="Port scanner"
    ["notify"]="Notification utility"
    ["htmlq"]="HTML parsing tool"
    ["googler"]="Google search tool"
    ["node"]="Node.js runtime for Playwright"
    ["playwright"]="Browser automation framework"
  )

  # Check required tools
  for tool in "${!req_tools[@]}"; do
    if ! command -v $tool &>/dev/null; then
      echo -e "${RED}[${EMOJI_ERROR}] Required tool ${WHITE}$tool${RED} (${req_tools[$tool]}) is missing.${RESET}"
      missing=1
    else
      tools_info+=("${EMOJI_CHECK} ${WHITE}$tool${RESET}: ${GRAY}${req_tools[$tool]}${RESET}")
    fi
  done

  # Check selected optional tools based on options
  if $RECON && ! command -v subfinder &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] subfinder missing - required for reconnaissance.${RESET}"
    missing=1
  fi
  
  if $HTTPX && ! command -v httpx &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] httpx missing - required for HTTP probing.${RESET}"
    missing=1
  fi
  
  if $NUCLEI && ! command -v nuclei &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] nuclei missing - required for vulnerability scanning.${RESET}"
    missing=1
  fi
  
  if $SUBDOMAIN_BRUTEFORCE && ! command -v ffuf &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] ffuf missing - required for subdomain bruteforce.${RESET}"
    SUBDOMAIN_BRUTEFORCE=false
  fi
  
  if $SCREENSHOT && ! command -v aquatone &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] aquatone missing - required for screenshots.${RESET}"
    SCREENSHOT=false
  fi
  
  if $CLOUD_ENUM && ! command -v cloudenum &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] cloudenum missing - required for cloud enumeration.${RESET}"
    CLOUD_ENUM=false
  fi
  
  if $TAKEOVER_SCAN && ! command -v subjack &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] subjack missing - required for takeover scanning.${RESET}"
    TAKEOVER_SCAN=false
  fi
  
  if $PORT_SCAN && ! command -v nmap &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] nmap missing - required for port scanning.${RESET}"
    PORT_SCAN=false
  fi
  
  # Check Google dorking dependencies
  if $GOOGLE_DORKING_ENABLED && ! command -v googler &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] googler missing - required for Google dorking.${RESET}"
    GOOGLE_DORKING_ENABLED=false
  fi
  
  # Check Playwright dependencies
  if $PLAYWRIGHT_ENABLED && ! command -v node &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] node missing - required for Playwright.${RESET}"
    PLAYWRIGHT_ENABLED=false
  fi
  
  # Check htmlq
  if $HTMLQ_ENABLED && ! command -v htmlq &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] htmlq missing - required for enhanced HTML parsing.${RESET}"
    HTMLQ_ENABLED=false
  fi

  # Check clipboard commands
  if $COPY; then
    if command -v pbcopy &>/dev/null; then
      CLIP_CMD="pbcopy"
    elif command -v xclip &>/dev/null; then
      CLIP_CMD="xclip -selection clipboard"
    elif command -v xsel &>/dev/null; then
      CLIP_CMD="xsel --clipboard --input"
    elif command -v wl-copy &>/dev/null; then
      CLIP_CMD="wl-copy"
    else
      echo -e "${YELLOW}[${EMOJI_WARN}] No clipboard tool found. Disabling copy feature.${RESET}"
      COPY=false
    fi
  fi

  # Check browser opener commands
  if $OPEN; then
    if command -v xdg-open &>/dev/null; then
      OPEN_CMD="xdg-open"
    elif command -v open &>/dev/null; then
      OPEN_CMD="open"
    elif command -v start &>/dev/null; then
      OPEN_CMD="start"
    else
      echo -e "${YELLOW}[${EMOJI_WARN}] No browser opener found. Disabling auto-open.${RESET}"
      OPEN=false
    fi
  fi

  # Check for custom wordlist
  if [[ -n "$CUSTOM_WORDLIST" && ! -f "$CUSTOM_WORDLIST" ]]; then
    echo -e "${YELLOW}[${EMOJI_WARN}] Custom wordlist not found: $CUSTOM_WORDLIST${RESET}"
    CUSTOM_WORDLIST=""
  fi

  # Check for custom resolvers
  if [[ -n "$CUSTOM_RESOLVERS" && ! -f "$CUSTOM_RESOLVERS" ]]; then
    echo -e "${YELLOW}[${EMOJI_WARN}] Custom resolvers file not found: $CUSTOM_RESOLVERS${RESET}"
    CUSTOM_RESOLVERS=""
  fi

  # Exit if required tools are missing
  if [[ $missing -eq 1 ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] Missing required tools. Please install them and try again.${RESET}"
    exit 1
  fi

  # Get tool versions for display if debug mode is on
  if [[ "$DEBUG_MODE" == true ]]; then
    # Get versions
    JQ_VER=$(jq --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
    
    if $RECON; then
      SUBFINDER_VER=$(subfinder -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
      tools_info+=("${EMOJI_CHECK} ${WHITE}subfinder${RESET}: ${GRAY}v${SUBFINDER_VER}${RESET}")
    fi
    
    if $HTTPX; then
      HTTPX_VER=$(httpx -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
      tools_info+=("${EMOJI_CHECK} ${WHITE}httpx${RESET}: ${GRAY}v${HTTPX_VER}${RESET}")
    fi
    
    if $NUCLEI; then
      NUCLEI_VER=$(nuclei -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
      tools_info+=("${EMOJI_CHECK} ${WHITE}nuclei${RESET}: ${GRAY}v${NUCLEI_VER}${RESET}")
    fi
    
    # Display tools info box
    draw_box "Available Tools" "${tools_info[@]}" "style:info"
  fi
}

# Fetch GitHub bounty-targets-data
fetch_github_bounty_data() {
  echo -e "${CYAN}[${EMOJI_SEARCH}] Fetching GitHub bounty-targets-data...${RESET}"
  
  local cache_file="$GITHUB_CACHE_DIR/bounty_targets_$(date +%Y%m%d).json"
  
  # Check if cache exists and is fresh (less than 24 hours old)
  if [[ -f "$cache_file" && $(find "$cache_file" -mtime -1 2>/dev/null) ]]; then
    echo -e "${GREEN}[${EMOJI_CHECK}] Using cached data from $cache_file${RESET}"
    echo "$cache_file"
    return 0
  fi
  
  # Fetch fresh data
  local data_sources=("hackerone_data.json" "bugcrowd_data.json" "intigriti_data.json" "yeswehack_data.json")
  local combined_data="[]"
  
  for source in "${data_sources[@]}"; do
    echo -e "${YELLOW}[${EMOJI_SEARCH}] Fetching $source...${RESET}"
    local url="${GITHUB_BOUNTY_DATA_URL}${source}"
    local temp_file=$(mktemp)
    
    if curl -s -L --max-time 30 "$url" -o "$temp_file"; then
      if jq -e . "$temp_file" >/dev/null 2>&1; then
        combined_data=$(jq -s '.[0] + .[1]' <(echo "$combined_data") "$temp_file")
      else
        echo -e "${YELLOW}[${EMOJI_WARN}] Invalid JSON in $source, skipping...${RESET}"
      fi
    else
      echo -e "${YELLOW}[${EMOJI_WARN}] Failed to fetch $source, skipping...${RESET}"
    fi
    
    rm -f "$temp_file"
  done
  
  # Save to cache
  echo "$combined_data" > "$cache_file"
  echo -e "${GREEN}[${EMOJI_CHECK}] Cached GitHub data to $cache_file${RESET}"
  
  echo "$cache_file"
}

# Get random program from GitHub data
get_random_program_github() {
  local cache_file=$(fetch_github_bounty_data)
  
  if [[ ! -f "$cache_file" ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] Failed to fetch GitHub bounty data.${RESET}"
    return 1
  fi
  
  local program_count=$(jq length "$cache_file")
  
  if [[ $program_count -eq 0 ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] No programs found in GitHub data.${RESET}"
    return 1
  fi
  
  local random_index=$((RANDOM % program_count))
  local program=$(jq -r ".[$random_index]" "$cache_file")
  
  local program_name=$(echo "$program" | jq -r '.name // .handle // "Unknown"')
  local program_url=$(echo "$program" | jq -r '.url // .program_url // ""')
  local domains=$(echo "$program" | jq -r '.targets.in_scope[]?.asset_identifier // empty' | tr '\n' ',' | sed 's/,$//')
  local bounty_status=$(echo "$program" | jq -r '.offers_bounties // "Unknown"')
  
  # If URL is empty, try to construct from handle
  if [[ -z "$program_url" || "$program_url" == "null" ]]; then
    local handle=$(echo "$program" | jq -r '.handle // ""')
    if [[ -n "$handle" && "$handle" != "null" ]]; then
      program_url="https://hackerone.com/${handle}"
    fi
  fi
  
  echo -e "${GREEN}[${EMOJI_CHECK}] Got ${WHITE}$program_name${GREEN} from GitHub data! Bounty: ${WHITE}$bounty_status${RESET}"
  echo -e "${GREEN}[${EMOJI_CHECK}] Domains: ${WHITE}$domains${RESET}"
  
  # Export domains for later use
  API_DOMAINS="$domains"
  
  echo "$program_url"
}

# Google dorking for bug bounty programs
google_dork_search() {
  echo -e "${CYAN}[${EMOJI_SEARCH}] Performing Google dorking for bug bounty programs...${RESET}"
  
  if ! command -v googler &>/dev/null; then
    echo -e "${RED}[${EMOJI_ERROR}] googler not found. Please install it for Google dorking.${RESET}"
    return 1
  fi
  
  local queries_file="$GOOGLE_DORKING_QUERIES"
  local results_file="$GITHUB_CACHE_DIR/google_dork_results_$(date +%Y%m%d).txt"
  
  # Check cache
  if [[ -f "$results_file" && $(find "$results_file" -mtime -1 2>/dev/null) ]]; then
    echo -e "${GREEN}[${EMOJI_CHECK}] Using cached Google dorking results${RESET}"
  else
    echo -e "${YELLOW}[${EMOJI_SEARCH}] Running fresh Google dorking queries...${RESET}"
    > "$results_file"
    
    while IFS= read -r query; do
      [[ "$query" =~ ^#.*$ || -z "$query" ]] && continue
      
      echo -e "${GRAY}[${EMOJI_SEARCH}] Searching: $query${RESET}"
      googler --json -n 10 "$query" 2>/dev/null | jq -r '.[] | .url' >> "$results_file" 2>/dev/null || true
      
      # Rate limiting to avoid getting blocked
      sleep 2
    done < "$queries_file"
    
    # Remove duplicates
    sort -u "$results_file" -o "$results_file"
  fi
  
  local url_count=$(wc -l < "$results_file")
  
  if [[ $url_count -eq 0 ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] No URLs found from Google dorking.${RESET}"
    return 1
  fi
  
  # Pick a random URL
  local random_line=$((RANDOM % url_count + 1))
  local program_url=$(sed -n "${random_line}p" "$results_file")
  
  echo -e "${GREEN}[${EMOJI_CHECK}] Found ${WHITE}$url_count${GREEN} URLs from Google dorking${RESET}"
  echo -e "${GREEN}[${EMOJI_LINK}] Selected URL: ${WHITE}$program_url${RESET}"
  
  echo "$program_url"
}

# Playwright-based program extraction
playwright_extract_programs() {
  echo -e "${CYAN}[${EMOJI_SEARCH}] Using Playwright for dynamic program extraction...${RESET}"
  
  if ! command -v node &>/dev/null; then
    echo -e "${RED}[${EMOJI_ERROR}] Node.js not found. Please install Node.js for Playwright.${RESET}"
    return 1
  fi
  
  local playwright_script="$PLAYWRIGHT_SCRIPT"
  local results_file="$GITHUB_CACHE_DIR/playwright_results_$(date +%Y%m%d).json"
  
  # Check cache
  if [[ -f "$results_file" && $(find "$results_file" -mtime -1 2>/dev/null) ]]; then
    echo -e "${GREEN}[${EMOJI_CHECK}] Using cached Playwright results${RESET}"
  else
    echo -e "${YELLOW}[${EMOJI_SEARCH}] Running Playwright extraction...${RESET}"
    
    # Install playwright if not available
    if ! npm list playwright &>/dev/null; then
      echo -e "${YELLOW}[${EMOJI_INFO}] Installing Playwright...${RESET}"
      npm install playwright 2>/dev/null || {
        echo -e "${RED}[${EMOJI_ERROR}] Failed to install Playwright${RESET}"
        return 1
      }
    fi
    
    # Run Playwright script
    node "$playwright_script" > "$results_file" 2>/dev/null || {
      echo -e "${RED}[${EMOJI_ERROR}] Playwright extraction failed${RESET}"
      return 1
    }
  fi
  
  local program_count=$(jq length "$results_file" 2>/dev/null || echo 0)
  
  if [[ $program_count -eq 0 ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] No programs found from Playwright extraction.${RESET}"
    return 1
  fi
  
  # Pick a random program
  local random_index=$((RANDOM % program_count))
  local program=$(jq -r ".[$random_index]" "$results_file")
  local program_url=$(echo "$program" | jq -r '.url // ""')
  
  echo -e "${GREEN}[${EMOJI_CHECK}] Found ${WHITE}$program_count${GREEN} programs from Playwright${RESET}"
  echo -e "${GREEN}[${EMOJI_LINK}] Selected program: ${WHITE}$program_url${RESET}"
  
  echo "$program_url"
}

# Multi-source program fetching
get_random_program_multi_source() {
  local sources=("api")
  
  $GITHUB_SOURCE_ENABLED && sources+=("github")
  $GOOGLE_DORKING_ENABLED && sources+=("google")
  $PLAYWRIGHT_ENABLED && sources+=("playwright")
  
  # If no additional sources enabled, add them by default
  if [[ ${#sources[@]} -eq 1 ]]; then
    sources+=("github" "google")
  fi
  
  local random_source=${sources[$((RANDOM % ${#sources[@]}))]}
  
  echo -e "${CYAN}[${EMOJI_INFO}] Using source: ${WHITE}$random_source${RESET}"
  
  case "$random_source" in
    "api")
      get_random_program
      ;;
    "github")
      get_random_program_github
      ;;
    "google")
      google_dork_search
      ;;
    "playwright")
      playwright_extract_programs
      ;;
    *)
      echo -e "${RED}[${EMOJI_ERROR}] Unknown source: $random_source${RESET}"
      return 1
      ;;
  esac
}

# Enhanced domain extraction with htmlq support
extract_domains_with_htmlq() {
  local url="$1"
  local output_file="$2"
  
  echo -e "${YELLOW}[${EMOJI_SEARCH}] Extracting domains using htmlq...${RESET}"
  
  if ! command -v htmlq &>/dev/null; then
    echo -e "${YELLOW}[${EMOJI_WARN}] htmlq not found, falling back to regular extraction${RESET}"
    extract_scope_from_url "$url" "$output_file"
    return $?
  fi
  
  local tmpfile=$(mktemp)
  
  curl -s -L --max-time 30 -A "$CUSTOM_USER_AGENT" "$url" > "$tmpfile" &
  local curl_pid=$!
  spinner $curl_pid "Fetching program page for htmlq extraction" "$CYAN"
  
  # Use htmlq to extract domains from common selectors
  local selectors=(
    "code"
    "pre"
    "span.scope"
    ".scope"
    "td"
    "li"
    "p"
  )
  
  > "$output_file"
  
  for selector in "${selectors[@]}"; do
    htmlq --text "$selector" < "$tmpfile" 2>/dev/null | \
    grep -o -E '([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z0-9]{2,}' | \
    grep -v -E '(javascript|css|img|image|cdn|video|media)\.com' >> "$output_file" 2>/dev/null || true
  done
  
  # Also do regular extraction as fallback
  grep -o -E '([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z0-9]{2,}' "$tmpfile" | \
  grep -v -E '(javascript|css|img|image|cdn|video|media)\.com' >> "$output_file" 2>/dev/null || true
  
  # Clean up and deduplicate
  sort -u "$output_file" -o "$output_file"
  
  local count=$(wc -l < "$output_file")
  if [[ $count -eq 0 ]]; then
    echo -e "${YELLOW}[${EMOJI_WARN}] No domains found with htmlq extraction.${RESET}"
    rm -f "$tmpfile"
    return 1
  else
    echo -e "${GREEN}[${EMOJI_CHECK}] Extracted ${WHITE}$count${GREEN} domains using htmlq.${RESET}"
    rm -f "$tmpfile"
    return 0
  fi
}

# Extract domains from scope
# Extract domains from scope or use the ones from API
extract_scope_from_url() {
  local url="$1"
  local tmpfile=$(mktemp)
  local output_file="${2:-${tmpfile}.domains}"
  
  # Check if domains were provided directly from the API response
  if [[ -n "$API_DOMAINS" ]]; then
    echo -e "${GREEN}[${EMOJI_CHECK}] Using domains from API response.${RESET}"
    echo "$API_DOMAINS" | tr ',' '\n' > "$output_file"
    return 0
  fi
  
  # Use htmlq extraction if enabled
  if $HTMLQ_ENABLED; then
    extract_domains_with_htmlq "$url" "$output_file"
    return $?
  fi
  
  echo -e "${YELLOW}[${EMOJI_SEARCH}] Extracting scope from program page...${RESET}"
  
  curl -s -L --max-time 30 -A "$CUSTOM_USER_AGENT" "$url" > "$tmpfile" &
  local curl_pid=$!
  spinner $curl_pid "Fetching program page" "$CYAN"
  
  # Extract domains using various patterns
  # Process the extracted domains
  grep -o -E '([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z0-9]{2,}' "$tmpfile" | grep -v -E '(javascript|css|img|image|cdn|video|media)\.com' | sort -u > "$output_file"
  
  # Check if any domains were extracted
  local count=$(wc -l < "$output_file")
  if [[ $count -eq 0 ]]; then
    echo -e "${YELLOW}[${EMOJI_WARN}] No domains found in program page.${RESET}"
    return 1
  else
    echo -e "${GREEN}[${EMOJI_CHECK}] Extracted ${WHITE}$count${GREEN} domains from program page.${RESET}"
    return 0
  fi
}

# Get a random program URL from the API
get_random_program() {
  # Route to appropriate source based on settings
  case "$SOURCE_SELECTION" in
    "github")
      get_random_program_github
      ;;
    "google")
      google_dork_search
      ;;
    "playwright")
      playwright_extract_programs
      ;;
    "multi")
      get_random_program_multi_source
      ;;
    "api"|*)
      get_random_program_api
      ;;
  esac
}

# Original API-based program fetching
get_random_program_api() {
  local response
  
  echo -e "${CYAN}[${EMOJI_GLOBE}] Spinning for a lucky program from API...${RESET}"
  
  # Make API request
  response=$(curl -s -H "User-Agent: $CUSTOM_USER_AGENT" "$API_URL")
  
  # Check if the response is valid JSON
  if ! echo "$response" | jq -e . >/dev/null 2>&1; then
    echo -e "${RED}[${EMOJI_ERROR}] Invalid response from API. Try again later.${RESET}"
    return 1
  fi
  
  # Extract program details based on the actual JSON structure
  local program_url=$(echo "$response" | jq -r '.url')
  local program_name=$(echo "$response" | jq -r '.name')
  local domains=$(echo "$response" | jq -r '.domains | join(", ")')
  local has_bounty=$(echo "$response" | jq -r '.bounty')
  
  # Check if URL is valid
  if [[ "$program_url" == "null" || -z "$program_url" ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] Failed to get a program URL. Try again later.${RESET}"
    return 1
  fi
  
  # Export domains for later use
  API_DOMAINS="$domains"
  
  echo -e "${GREEN}[${EMOJI_CHECK}] Got ${WHITE}$program_name${GREEN}! Bounty: ${WHITE}$has_bounty${RESET}"
  echo -e "${GREEN}[${EMOJI_CHECK}] Domains: ${WHITE}$domains${RESET}"
  echo "$program_url"
}

# Perform reconnaissance on a domain
do_recon() {
  local domain="$1"
  local output_dir="$RESULTS_DIR/$(echo "$domain" | tr '.' '_')"
  local subdomains_file="$output_dir/subdomains.txt"
  local httpx_file="$output_dir/httpx.json"
  local nuclei_file="$output_dir/nuclei.json"
  local screenshot_dir="$output_dir/screenshots"
  local takeover_file="$output_dir/takeovers.txt"
  local ports_file="$output_dir/ports.txt"
  local tech_file="$output_dir/technologies.json"
  local start_time=$(date +%s)
  
  # Create output directory
  mkdir -p "$output_dir"
  
# Print banner
draw_box "Reconnaissance for $domain" \
    "${CYAN}Starting comprehensive reconnaissance...${RESET}" \
    "${GRAY}Output directory: $output_dir${RESET}" \
    "" \
    "style:info"
  
  # Subdomain enumeration
  if $RECON; then
    echo -e "${CYAN}[${EMOJI_SEARCH}] Starting subdomain enumeration...${RESET}"
    
    local subfinder_cmd="subfinder -d $domain -o $subdomains_file -t $THREADS -nW"
    
    # Add custom resolvers if specified
    [[ -n "$CUSTOM_RESOLVERS" ]] && subfinder_cmd+=" -r $CUSTOM_RESOLVERS"
    
    # Set timeout
    subfinder_cmd+=" -timeout $TIMEOUT"
    
    # Run subfinder
    eval "$subfinder_cmd" &
    local subfinder_pid=$!
    spinner $subfinder_pid "Running subfinder" "$CYAN"
    
    # Add additional subdomain enumeration tools
    if [[ "$THOROUGH_MODE" == true ]]; then
      # Run additional tools
      if command -v assetfinder &>/dev/null; then
        assetfinder --subs-only "$domain" | tee -a "$subdomains_file" >/dev/null &
        local assetfinder_pid=$!
        spinner $assetfinder_pid "Running assetfinder" "$CYAN"
      fi
      
      if command -v amass &>/dev/null; then
        amass enum -passive -d "$domain" | tee -a "$subdomains_file" >/dev/null &
        local amass_pid=$!
        spinner $amass_pid "Running amass (passive mode)" "$CYAN"
      fi
      
      # Check waybackurls
      if command -v waybackurls &>/dev/null; then
        echo -e "${CYAN}[${EMOJI_SEARCH}] Checking Wayback Machine for subdomains...${RESET}"
        waybackurls "$domain" | grep -o -E "([a-zA-Z0-9][-a-zA-Z0-9]*\.)+$domain" | sort -u | tee -a "$subdomains_file" >/dev/null &
        local wayback_pid=$!
        spinner $wayback_pid "Checking Wayback Machine" "$CYAN"
      fi
    fi
    
    # Deduplicate subdomains
    sort -u "$subdomains_file" -o "$subdomains_file"
    local subdomain_count=$(wc -l < "$subdomains_file")
    echo -e "${GREEN}[${EMOJI_CHECK}] Found ${WHITE}$subdomain_count${GREEN} subdomains.${RESET}"
  fi
  
  # Subdomain bruteforce
  if $SUBDOMAIN_BRUTEFORCE; then
    echo -e "${CYAN}[${EMOJI_SEARCH}] Starting subdomain bruteforce...${RESET}"
    
    # Select wordlist
    local wordlist
    if [[ -n "$CUSTOM_WORDLIST" ]]; then
      wordlist="$CUSTOM_WORDLIST"
    else
      wordlist="$WORDLIST_DIR/basic_subdomains.txt"
    fi
    
    # Run ffuf for subdomain bruteforce
    ffuf -u "FUZZ.$domain" -w "$wordlist" -v -o "$output_dir/ffuf.json" \
      -rate $RATE_LIMIT -t $THREADS -se -sf -mc 200,301,302,403 -H "User-Agent: $CUSTOM_USER_AGENT" \
      -of json &
    local ffuf_pid=$!
    spinner $ffuf_pid "Bruteforcing subdomains with ffuf" "$CYAN"
    
    # Extract subdomains from ffuf results
    if [[ -f "$output_dir/ffuf.json" ]]; then
      cat "$output_dir/ffuf.json" | jq -r '.results[].url' | cut -d '/' -f3 | tee -a "$subdomains_file" >/dev/null
      sort -u "$subdomains_file" -o "$subdomains_file"
      local new_count=$(wc -l < "$subdomains_file")
      echo -e "${GREEN}[${EMOJI_CHECK}] Total subdomains after bruteforce: ${WHITE}$new_count${GREEN}.${RESET}"
    fi
  fi
  
  # HTTP probing with httpx
  if $HTTPX; then
    echo -e "${CYAN}[${EMOJI_LINK}] Probing for live hosts with httpx...${RESET}"
    
    local httpx_cmd="cat \"$subdomains_file\" | httpx -json -o \"$httpx_file\" -threads $THREADS -rate-limit $RATE_LIMIT -timeout $TIMEOUT -retries $RETRIES"
    
    # Add custom header if specified
    [[ -n "$CUSTOM_HEADER" ]] && httpx_cmd+=" -H \"$CUSTOM_HEADER\""
    
    # Add user agent
    httpx_cmd+=" -H \"User-Agent: $CUSTOM_USER_AGENT\""
    
    # Enable technology detection if needed
    $TECHNOLOGY_DETECTION && httpx_cmd+=" -tech-detect"
    
    # Enable additional features based on mode
    [[ "$THOROUGH_MODE" == true ]] && httpx_cmd+=" -status-code -title -content-type -content-length -ip -cname -asn -follow-redirects -probe"
    
    # Run httpx
    eval "$httpx_cmd" &
    local httpx_pid=$!
    spinner $httpx_pid "Running httpx" "$BLUE"
    
    # Extract live hosts from httpx results
    if [[ -f "$httpx_file" ]]; then
      local live_hosts=$(jq -r '. | length' "$httpx_file")
      echo -e "${GREEN}[${EMOJI_CHECK}] Found ${WHITE}$live_hosts${GREEN} live hosts.${RESET}"
      
      # Create a file with just the URLs for later use
      jq -r '.url' "$httpx_file" > "$output_dir/live_urls.txt"
    fi
  fi
  
  # Port scanning
  if $PORT_SCAN; then
    echo -e "${CYAN}[${EMOJI_SEARCH}] Scanning ports...${RESET}"
    
    # Run nmap scan on live hosts
    if [[ -f "$output_dir/live_urls.txt" ]]; then
      # Extract IP addresses from httpx results
      jq -r '.ip' "$httpx_file" | sort -u > "$output_dir/ips.txt"
      
      # Run nmap scan
      nmap -iL "$output_dir/ips.txt" -p "$PORTS" -oX "$output_dir/nmap.xml" --open -T4 &
      local nmap_pid=$!
      spinner $nmap_pid "Scanning ports with nmap" "$CYAN"
      
      # Parse nmap results
      if [[ -f "$output_dir/nmap.xml" ]]; then
        echo -e "${GREEN}[${EMOJI_CHECK}] Port scan complete. Results in $output_dir/nmap.xml${RESET}"
      fi
    else
      echo -e "${YELLOW}[${EMOJI_WARN}] No live hosts found for port scanning.${RESET}"
    fi
  fi
  
  # Subdomain takeover scanning
  if $TAKEOVER_SCAN; then
    echo -e "${CYAN}[${EMOJI_SHIELD}] Scanning for subdomain takeover vulnerabilities...${RESET}"
    
    # Run subjack for takeover detection
    subjack -w "$subdomains_file" -t $THREADS -timeout $TIMEOUT -o "$takeover_file" -ssl &
    local subjack_pid=$!
    spinner $subjack_pid "Scanning for takeover vulnerabilities" "$RED"
    
    # Check if any takeovers were found
    if [[ -f "$takeover_file" && -s "$takeover_file" ]]; then
      echo -e "${RED}[${EMOJI_WARN}] Possible subdomain takeover vulnerabilities found!${RESET}"
      cat "$takeover_file"
    else
      echo -e "${GREEN}[${EMOJI_CHECK}] No subdomain takeover vulnerabilities found.${RESET}"
    fi
  fi
  
  # Screenshot capture
  if $SCREENSHOT; then
    echo -e "${CYAN}[${EMOJI_CAMERA}] Taking screenshots of discovered hosts...${RESET}"
    
    mkdir -p "$screenshot_dir"
    
    # Check if we have live urls
    if [[ -f "$output_dir/live_urls.txt" ]]; then
      cat "$output_dir/live_urls.txt" | aquatone -out "$screenshot_dir" -threads $THREADS -silent &
      local aquatone_pid=$!
      spinner $aquatone_pid "Capturing screenshots" "$MAGENTA"
      
      echo -e "${GREEN}[${EMOJI_CHECK}] Screenshots saved to $screenshot_dir${RESET}"
    else
      echo -e "${YELLOW}[${EMOJI_WARN}] No live hosts found for screenshots.${RESET}"
    fi
  fi
  
  # Vulnerability scanning with nuclei
  if $NUCLEI; then
    echo -e "${CYAN}[${EMOJI_FIRE}] Scanning for vulnerabilities with nuclei...${RESET}"
    
    local nuclei_cmd="nuclei -l \"$output_dir/live_urls.txt\" -o \"$nuclei_file\" -c $THREADS -rate-limit $RATE_LIMIT"
    
    # Add custom templates if specified
    [[ -n "$CUSTOM_NUCLEI_TEMPLATES" ]] && nuclei_cmd+=" -t \"$CUSTOM_NUCLEI_TEMPLATES\""
    
    # Add severity filter
    nuclei_cmd+=" -severity $VULN_SCAN_LEVEL"
    
    # Add user agent
    nuclei_cmd+=" -H \"User-Agent: $CUSTOM_USER_AGENT\""
    
    # Add timeout
    nuclei_cmd+=" -timeout $TIMEOUT"
    
    # Run nuclei
    eval "$nuclei_cmd" &
    local nuclei_pid=$!
    spinner $nuclei_pid "Scanning for vulnerabilities" "$RED"
    
    # Check if any vulnerabilities were found
    if [[ -f "$nuclei_file" && -s "$nuclei_file" ]]; then
      local vuln_count=$(wc -l < "$nuclei_file")
      echo -e "${YELLOW}[${EMOJI_WARN}] Found ${WHITE}$vuln_count${YELLOW} potential vulnerabilities.${RESET}"
    else
      echo -e "${GREEN}[${EMOJI_CHECK}] No vulnerabilities found.${RESET}"
    fi
  fi
  
  # Calculate elapsed time
  local end_time=$(date +%s)
  local elapsed=$((end_time - start_time))
  local minutes=$((elapsed / 60))
  local seconds=$((elapsed % 60))
  
  # Generate summary report
  echo -e "${CYAN}[${EMOJI_DOCUMENT}] Generating summary report...${RESET}"
  
  local report_file="$output_dir/summary.md"
  
  cat > "$report_file" << EOF
# Reconnaissance Report for $domain
Generated on $(date)

## Summary
- Total subdomains discovered: $(wc -l < "$subdomains_file" 2>/dev/null || echo "0")
- Live hosts: $(wc -l < "$output_dir/live_urls.txt" 2>/dev/null || echo "0") 
- Elapsed time: ${minutes}m ${seconds}s

## Tools Used
$(echo -e "- Subfinder: Subdomain enumeration" | tee "$report_file")
$([ "$SUBDOMAIN_BRUTEFORCE" == true ] && echo -e "- FFUF: Subdomain bruteforce" | tee -a "$report_file")
$([ "$HTTPX" == true ] && echo -e "- HTTPX: HTTP probing" | tee -a "$report_file")
$([ "$SCREENSHOT" == true ] && echo -e "- Aquatone: Visual reconnaissance" | tee -a "$report_file")
$([ "$TAKEOVER_SCAN" == true ] && echo -e "- Subjack: Subdomain takeover scanning" | tee -a "$report_file")
$([ "$PORT_SCAN" == true ] && echo -e "- Nmap: Port scanning" | tee -a "$report_file")
$([ "$NUCLEI" == true ] && echo -e "- Nuclei: Vulnerability scanning" | tee -a "$report_file")

## Interesting Findings
$([ -f "$nuclei_file" ] && [ -s "$nuclei_file" ] && echo -e "### Vulnerabilities\n" && cat "$nuclei_file" | jq -r '"\n- " + .info.severity + ": " + .info.name + " (" + .host + ")"' | tee -a "$report_file")
$([ -f "$takeover_file" ] && [ -s "$takeover_file" ] && echo -e "\n### Possible Subdomain Takeovers\n" && cat "$takeover_file" | tee -a "$report_file")

## Next Steps
- Review the detailed scan results
- Investigate potential vulnerabilities
- Perform targeted testing on interesting endpoints
EOF
  
  echo -e "${GREEN}[${EMOJI_CHECK}] Recon complete! Summary saved to $report_file${RESET}"
  
  # Send notifications if configured
  send_notifications "$domain" "$report_file"
  
  return 0
}

# Send notifications to configured channels
send_notifications() {
  local domain="$1"
  local report_file="$2"
  
  # Check if any notification channels are configured
  if [[ -n "$WEBHOOK_URL" || -n "$DISCORD_WEBHOOK" || -n "$SLACK_WEBHOOK" || 
        (-n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID") ]]; then
    echo -e "${CYAN}[${EMOJI_BELL}] Sending notifications...${RESET}"
    
    # Create a summary message
    local summary=$(cat "$report_file" | head -20)
    
    # Send to generic webhook
    if [[ -n "$WEBHOOK_URL" ]]; then
      curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"message\": \"Recon complete for $domain\", \"summary\": \"$summary\"}" \
        "$WEBHOOK_URL" &>/dev/null &
    fi
    
    # Send to Discord
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
      curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"content\": \"Recon complete for $domain\", \"embeds\": [{\"title\": \"Reconnaissance Summary\", \"description\": \"$summary\"}]}" \
        "$DISCORD_WEBHOOK" &>/dev/null &
    fi
    
    # Send to Slack
    if [[ -n "$SLACK_WEBHOOK" ]]; then
      curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"text\": \"Recon complete for $domain\", \"blocks\": [{\"type\": \"section\", \"text\": {\"type\": \"mrkdwn\", \"text\": \"$summary\"}}]}" \
        "$SLACK_WEBHOOK" &>/dev/null &
    fi
    
    # Send to Telegram
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
      curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID&text=Recon complete for $domain. Summary: $summary" &>/dev/null &
    fi
  fi
}

# Display interactive menu for main operations
show_interactive_menu() {
  clear
  
  # Display welcome banner
  center_text "${WHITE}${BG_MAGENTA} Lucky Bounty Picker Ultimate v${VERSION} ${RESET}"
  echo
  
  # Display main menu
  local options=(
    "Spin for a lucky program"
    "Target specific domain"
    "Reconnaissance tools"
    "Configuration"
    "View history"
    "Help & Documentation"
  )
  
  show_menu "Main Menu" "${options[@]}"
  local choice=$?
  
  case $choice in
    1) # Spin for a lucky program
      show_spin_menu
      ;;
    2) # Target specific domain
      read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      show_target_menu
      ;;
    3) # Recon tools
      show_recon_menu
      ;;
    4) # Configuration
      show_config_menu
      ;;
    5) # View history
      show_history
      ;;
    6) # Help
      show_help
      read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
      show_interactive_menu
      ;;
    0|255) # Quit
      echo -e "${CYAN}[${EMOJI_INFO}] Thanks for using Lucky Bounty Picker!${RESET}"
      exit 0
      ;;
  esac
}

# Show menu for spin options
show_spin_menu() {
  local options=(
    "Quick spin (default settings)"
    "Spin with recon"
    "Spin with thorough recon"
    "Spin and open in browser"
    "Multiple spins"
  )
  
  show_menu "Spin Options" "${options[@]}"
  local choice=$?
  
  case $choice in
    1) # Quick spin
      program_url=$(get_random_program)
      [[ -n "$program_url" ]] && {
        echo -e "${GREEN}[${EMOJI_LINK}] Program URL: ${WHITE}$program_url${RESET}"
        $COPY && echo "$program_url" | $CLIP_CMD && echo -e "${GRAY}[${EMOJI_INFO}] URL copied to clipboard.${RESET}"
        echo "$program_url" >> "$LOG_FILE"
      }
      ;;
    2) # Spin with recon
      program_url=$(get_random_program)
      [[ -n "$program_url" ]] && {
        echo -e "${GREEN}[${EMOJI_LINK}] Program URL: ${WHITE}$program_url${RESET}"
        echo "$program_url" >> "$LOG_FILE"
        
        # Extract domain
        local tmpfile=$(mktemp)
        extract_scope_from_url "$program_url" "$tmpfile"
        local domain=$(head -1 "$tmpfile")
        
        if [[ -n "$domain" ]]; then
          RECON=true
          HTTPX=true
          do_recon "$domain"
        else
          echo -e "${YELLOW}[${EMOJI_WARN}] Could not extract domain from program.${RESET}"
        fi
      }
      ;;
    3) # Spin with thorough recon
 program_url=$(get_random_program)
[[ -n "$program_url" ]] && {
  echo -e "${GREEN}[${EMOJI_LINK}] Program URL: ${WHITE}$program_url${RESET}"
  echo "$program_url" >> "$LOG_FILE"
  
  # Extract domain from API response if available, otherwise from program page
  API_DOMAINS=$(echo "$response" | jq -r '.domains | join(",")')
  local tmpfile=$(mktemp)
  extract_scope_from_url "$program_url" "$tmpfile"
  local domain=$(head -1 "$tmpfile")
  
  if [[ -n "$domain" ]]; then
          RECON=true
          HTTPX=true
          NUCLEI=true
          SUBDOMAIN_BRUTEFORCE=true
          SCREENSHOT=true
          THOROUGH_MODE=true
          do_recon "$domain"
        else
          echo -e "${YELLOW}[${EMOJI_WARN}] Could not extract domain from program.${RESET}"
        fi
      }
      ;;
    4) # Spin and open
      program_url=$(get_random_program)
      [[ -n "$program_url" ]] && {
        echo -e "${GREEN}[${EMOJI_LINK}] Program URL: ${WHITE}$program_url${RESET}"
        echo "$program_url" >> "$LOG_FILE"
        $OPEN && $OPEN_CMD "$program_url" && echo -e "${GRAY}[${EMOJI_INFO}] Opened in browser.${RESET}"
      }
      ;;
    5) # Multiple spins
      read -p "$(echo -e "${YELLOW}Number of spins:${RESET} ") " COUNT
      for ((i=1; i<=$COUNT; i++)); do
        echo -e "${CYAN}[${EMOJI_INFO}] Spin $i of $COUNT${RESET}"
        program_url=$(get_random_program)
        [[ -n "$program_url" ]] && {
          echo -e "${GREEN}[${EMOJI_LINK}] Program URL: ${WHITE}$program_url${RESET}"
          echo "$program_url" >> "$LOG_FILE"
        }
      done
      ;;
    0|255) # Back
      show_interactive_menu
      ;;
  esac
  
  read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
  show_interactive_menu
}

# Show menu for target options
show_target_menu() {
  if [[ -z "$TARGET_DOMAIN" ]]; then
    echo -e "${RED}[${EMOJI_ERROR}] No target domain specified.${RESET}"
    read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
    show_interactive_menu
    return
  fi
  
  local options=(
    "Basic reconnaissance"
    "Thorough reconnaissance"
    "Custom scan"
    "Passive reconnaissance"
    "Fast scan"
  )
  
  show_menu "Target Options for $TARGET_DOMAIN" "${options[@]}"
  local choice=$?
  
  case $choice in
    1) # Basic recon
      RECON=true
      HTTPX=true
      do_recon "$TARGET_DOMAIN"
      ;;
    2) # Thorough recon
      RECON=true
      HTTPX=true
      NUCLEI=true
      SUBDOMAIN_BRUTEFORCE=true
      SCREENSHOT=true
      THOROUGH_MODE=true
      do_recon "$TARGET_DOMAIN"
      ;;
    3) # Custom scan
      show_custom_scan_menu
      ;;
    4) # Passive recon
      RECON=true
      PASSIVE_MODE=true
      do_recon "$TARGET_DOMAIN"
      ;;
    5) # Fast scan
      RECON=true
      HTTPX=true
      FAST_MODE=true
      do_recon "$TARGET_DOMAIN"
      ;;
    0|255) # Back
      show_interactive_menu
      ;;
  esac
  
  read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
  show_interactive_menu
}

# Show menu for custom scan options
show_custom_scan_menu() {
  echo -e "${CYAN}[${EMOJI_COG}] Configure custom scan for ${WHITE}$TARGET_DOMAIN${RESET}${CYAN}:${RESET}"
  echo
  
  # Toggle options
  local toggle_options=(
    "Subdomain enumeration ($RECON)"
    "HTTP probing ($HTTPX)"
    "Vulnerability scanning ($NUCLEI)"
    "Subdomain bruteforce ($SUBDOMAIN_BRUTEFORCE)"
    "Screenshot capture ($SCREENSHOT)"
    "Port scanning ($PORT_SCAN)"
    "Technology detection ($TECHNOLOGY_DETECTION)"
    "Takeover scanning ($TAKEOVER_SCAN)"
  )
  
  show_menu "Scan Options" "${toggle_options[@]}"
  local choice=$?
  
  case $choice in
    1) # Toggle subdomain enum
      RECON=$([ "$RECON" == true ] && echo false || echo true)
      ;;
    2) # Toggle HTTP probing
      HTTPX=$([ "$HTTPX" == true ] && echo false || echo true)
      ;;
    3) # Toggle vuln scanning
      NUCLEI=$([ "$NUCLEI" == true ] && echo false || echo true)
      ;;
    4) # Toggle subdomain bruteforce
      SUBDOMAIN_BRUTEFORCE=$([ "$SUBDOMAIN_BRUTEFORCE" == true ] && echo false || echo true)
      ;;
    5) # Toggle screenshots
      SCREENSHOT=$([ "$SCREENSHOT" == true ] && echo false || echo true)
      ;;
    6) # Toggle port scanning
      PORT_SCAN=$([ "$PORT_SCAN" == true ] && echo false || echo true)
      if [ "$PORT_SCAN" == true ]; then
       read -p "$(echo -e "${YELLOW}Enter ports (comma-separated):${RESET} ") " PORTS
      fi
      ;;
    7) # Toggle tech detection
      TECHNOLOGY_DETECTION=$([ "$TECHNOLOGY_DETECTION" == true ] && echo false || echo true)
      ;;
    8) # Toggle takeover scanning
      TAKEOVER_SCAN=$([ "$TAKEOVER_SCAN" == true ] && echo false || echo true)
      ;;
    0|255) # Back/Done
      # Check if at least one option is enabled
      if [[ "$RECON" == true || "$HTTPX" == true || "$NUCLEI" == true ]]; then
        do_recon "$TARGET_DOMAIN"
      else
        echo -e "${YELLOW}[${EMOJI_WARN}] No scan options selected. Returning to menu.${RESET}"
        show_target_menu
      fi
      return
      ;;
  esac
  
  # Show menu again after toggling
  show_custom_scan_menu
}

# Show recon tools menu
show_recon_menu() {
  local options=(
    "Subdomain enumeration"
    "HTTP probing"
    "Vulnerability scanning"
    "Screenshot capture"
    "Subdomain takeover scanning"
    "Port scanning"
    "Cloud enumeration"
  )
  
  show_menu "Reconnaissance Tools" "${options[@]}"
  local choice=$?
  
  case $choice in
    1) # Subdomain enumeration
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      fi
      RECON=true
      do_recon "$TARGET_DOMAIN"
      ;;
    2) # HTTP probing
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET}") " TARGET_DOMAIN
      fi
      RECON=true
      HTTPX=true
      do_recon "$TARGET_DOMAIN"
      ;;
    3) # Vulnerability scanning
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      fi
      RECON=true
      HTTPX=true
      NUCLEI=true
      do_recon "$TARGET_DOMAIN"
      ;;
    4) # Screenshot capture
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      fi
      RECON=true
      HTTPX=true
      SCREENSHOT=true
      do_recon "$TARGET_DOMAIN"
      ;;
    5) # Takeover scanning
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      fi
      RECON=true
      TAKEOVER_SCAN=true
      do_recon "$TARGET_DOMAIN"
      ;;
    6) # Port scanning
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      fi
      RECON=true
      HTTPX=true
      PORT_SCAN=true
      do_recon "$TARGET_DOMAIN"
      ;;
    7) # Cloud enumeration
      if [[ -z "$TARGET_DOMAIN" ]]; then
        read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
      fi
      RECON=true
      CLOUD_ENUM=true
      do_recon "$TARGET_DOMAIN"
      ;;
    0|255) # Back
      show_interactive_menu
      ;;
  esac
  
read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
  show_interactive_menu
}

# Show configuration menu
show_config_menu() {
  local options=(
    "Set threads ($THREADS)"
    "Set rate limit ($RATE_LIMIT)"
    "Set timeout ($TIMEOUT)"
    "Set output directory ($RESULTS_DIR)"
    "Configure notifications"
    "Set custom wordlist"
    "Set custom resolvers"
    "Save configuration"
    "Reset to defaults"
  )
  
  show_menu "Configuration" "${options[@]}"
  local choice=$?
  
  case $choice in
    1) # Set threads
      read -p "$(echo -e "${YELLOW}Enter number of threads:${RESET} ") " new_threads
      if [[ "$new_threads" =~ ^[0-9]+$ ]]; then
        THREADS="$new_threads"
        echo -e "${GREEN}[${EMOJI_CHECK}] Threads set to $THREADS.${RESET}"
      else
        echo -e "${RED}[${EMOJI_ERROR}] Invalid number.${RESET}"
      fi
      ;;
    2) # Set rate limit
      read -p "$(echo -e "${YELLOW}Enter rate limit:${RESET} ") " new_rate
      if [[ "$new_rate" =~ ^[0-9]+$ ]]; then
        RATE_LIMIT="$new_rate"
        echo -e "${GREEN}[${EMOJI_CHECK}] Rate limit set to $RATE_LIMIT.${RESET}"
      else
        echo -e "${RED}[${EMOJI_ERROR}] Invalid number.${RESET}"
      fi
      ;;
    3) # Set timeout
      read -p "$(echo -e "${YELLOW}Enter timeout (seconds):${RESET} ") " new_timeout
      if [[ "$new_timeout" =~ ^[0-9]+$ ]]; then
        TIMEOUT="$new_timeout"
        echo -e "${GREEN}[${EMOJI_CHECK}] Timeout set to $TIMEOUT seconds.${RESET}"
      else
        echo -e "${RED}[${EMOJI_ERROR}] Invalid number.${RESET}"
      fi
      ;;
    4) # Set output directory
      read -p "$(echo -e "${YELLOW}Enter output directory:${RESET} ") " new_dir
      if [[ -d "$new_dir" || -d "$(dirname "$new_dir")" ]]; then
        mkdir -p "$new_dir"
        RESULTS_DIR="$new_dir"
        echo -e "${GREEN}[${EMOJI_CHECK}] Output directory set to $RESULTS_DIR.${RESET}"
      else
        echo -e "${RED}[${EMOJI_ERROR}] Invalid directory.${RESET}"
      fi
      ;;
    5) # Configure notifications
      show_notification_menu
      ;;
    6) # Set custom wordlist
      read -p "$(echo -e "${YELLOW}Enter path to wordlist:${RESET} ") " new_wordlist
      if [[ -f "$new_wordlist" ]]; then
        CUSTOM_WORDLIST="$new_wordlist"
        echo -e "${GREEN}[${EMOJI_CHECK}] Custom wordlist set to $CUSTOM_WORDLIST.${RESET}"
      else
        echo -e "${RED}[${EMOJI_ERROR}] File not found.${RESET}"
      fi
      ;;
    7) # Set custom resolvers
      read -p "$(echo -e "${YELLOW}Enter path to resolvers file:${RESET} ") " new_resolvers
      if [[ -f "$new_resolvers" ]]; then
        CUSTOM_RESOLVERS="$new_resolvers"
        echo -e "${GREEN}[${EMOJI_CHECK}] Custom resolvers set to $CUSTOM_RESOLVERS.${RESET}"
      else
        echo -e "${RED}[${EMOJI_ERROR}] File not found.${RESET}"
      fi
      ;;
    8) # Save configuration
      save_config
      ;;
    9) # Reset to defaults
      THREADS=10
      RATE_LIMIT=150
      TIMEOUT=10
      RETRIES=3
      CUSTOM_WORDLIST=""
      CUSTOM_RESOLVERS=""
      CUSTOM_NUCLEI_TEMPLATES=""
      WEBHOOK_URL=""
      DISCORD_WEBHOOK=""
      SLACK_WEBHOOK=""
      TELEGRAM_BOT_TOKEN=""
      TELEGRAM_CHAT_ID=""
      echo -e "${GREEN}[${EMOJI_CHECK}] Settings reset to defaults.${RESET}"
      ;;
    0|255) # Back
      show_interactive_menu
      ;;
  esac
  
  read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
  show_config_menu
}

# Show notification configuration menu
show_notification_menu() {
  local options=(
    "Set Discord webhook"
    "Set Slack webhook"
    "Set Telegram bot token and chat ID"
    "Set custom webhook URL"
    "Enable/disable notifications"
  )
  
  show_menu "Notification Configuration" "${options[@]}"
  local choice=$?
  
  case $choice in
    1) # Set Discord webhook
      read -p "$(echo -e "${YELLOW}Enter Discord webhook URL:${RESET} ") " DISCORD_WEBHOOK
      echo -e "${GREEN}[${EMOJI_CHECK}] Discord webhook set.${RESET}"
      ;;
    2) # Set Slack webhook
      read -p "$(echo -e "${YELLOW}Enter Slack webhook URL:${RESET} ") " SLACK_WEBHOOK
      echo -e "${GREEN}[${EMOJI_CHECK}] Slack webhook set.${RESET}"
      ;;
    3) # Set Telegram
      read -p "$(echo -e "${YELLOW}Enter Telegram bot token:${RESET} ") " TELEGRAM_BOT_TOKEN
      read -p "$(echo -e "${YELLOW}Enter Telegram chat ID:${RESET} ") " TELEGRAM_CHAT_ID
      echo -e "${GREEN}[${EMOJI_CHECK}] Telegram settings set.${RESET}"
      ;;
    4) # Set custom webhook
      read -p "$(echo -e "${YELLOW}Enter custom webhook URL:${RESET} ") " WEBHOOK_URL
      echo -e "${GREEN}[${EMOJI_CHECK}] Custom webhook set.${RESET}"
      ;;
    5) # Toggle notifications
      echo -e "${YELLOW}Notifications are currently activated via:${RESET}"
      [[ -n "$WEBHOOK_URL" ]] && echo -e "${CYAN}- Custom webhook${RESET}"
      [[ -n "$DISCORD_WEBHOOK" ]] && echo -e "${CYAN}- Discord${RESET}"
      [[ -n "$SLACK_WEBHOOK" ]] && echo -e "${CYAN}- Slack${RESET}"
      [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]] && echo -e "${CYAN}- Telegram${RESET}"
      
      read -p "$(echo -e "${YELLOW}Disable all notifications? (y/n):${RESET} ") " confirm
      if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        WEBHOOK_URL=""
        DISCORD_WEBHOOK=""
        SLACK_WEBHOOK=""
        TELEGRAM_BOT_TOKEN=""
        TELEGRAM_CHAT_ID=""
        echo -e "${GREEN}[${EMOJI_CHECK}] All notifications disabled.${RESET}"
      fi
      ;;
    0|255) # Back
      show_config_menu
      ;;
  esac
  
  read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
  show_notification_menu
}

# Show command history
show_history() {
  if [[ ! -f "$HISTORY_FILE" || ! -s "$HISTORY_FILE" ]]; then
    echo -e "${YELLOW}[${EMOJI_INFO}] No command history found.${RESET}"
    read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
    show_interactive_menu
    return
  fi
  
  local history_lines=()
  local line_num=1
  
  while IFS= read -r line; do
    history_lines+=("$line_num: $line")
    ((line_num++))
  done < "$HISTORY_FILE"
  
  # Reverse array to show newest first
  local reversed_lines=()
  for ((i=${#history_lines[@]}-1; i>=0; i--)); do
    reversed_lines+=("${history_lines[$i]}")
  done
  
  draw_box "Command History" "${reversed_lines[@]}" "style:info"
  
  read -p "$(echo -e "${YELLOW}Run a command? (number/n):${RESET} ") " choice
  
  if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le "${#history_lines[@]}" ]]; then
    local cmd=$(sed -n "${choice}p" "$HISTORY_FILE")
    echo -e "${CYAN}[${EMOJI_INFO}] Running: ${WHITE}$cmd${RESET}"
    eval "$cmd"
  fi
  
  read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
  show_interactive_menu
}

# Display statistics from log file
show_statistics() {
  if [[ ! -f "$LOG_FILE" || ! -s "$LOG_FILE" ]]; then
    return
  fi
  
  echo -e "${CYAN}[${EMOJI_INFO}] Analyzing statistics...${RESET}"
  
  local total=$(wc -l < "$LOG_FILE")
  local unique=$(sort "$LOG_FILE" | uniq | wc -l)
  
  local content=(
    "Total programs spun: ${WHITE}$total${RESET}"
    "Unique programs: ${WHITE}$unique${RESET}"
    "Log file: ${GRAY}$LOG_FILE${RESET}"
  )
  
  draw_box "Statistics" "${content[@]}" "style:info"
}

# Main function
main() {
  # Initialize directories
  init_dirs
  
  # Load configuration
  load_config
  
  # Parse command line arguments
  parse_args "$@"
  
  # Check dependencies
  check_dependencies
  
  # Show statistics if enabled
  $ENABLE_STATS && show_statistics
  
  # Interactive mode
  if $INTERACTIVE; then
    show_interactive_menu
    exit 0
  fi
  
  # Manual mode
  if $MANUAL_MODE; then
    read -p "$(echo -e "${YELLOW}Enter domain:${RESET} ") " TARGET_DOMAIN
  fi
  
  # Target domain specified
  if [[ -n "$TARGET_DOMAIN" ]]; then
    echo -e "${CYAN}[${EMOJI_TARGET}] Target: ${WHITE}$TARGET_DOMAIN${RESET}"
    
    # Run recon if enabled
    if $RECON || $HTTPX || $NUCLEI; then
      do_recon "$TARGET_DOMAIN"
    else
      echo -e "${YELLOW}[${EMOJI_WARN}] No recon options enabled. Use --recon, --httpx, or --nuclei.${RESET}"
    fi
    
    exit 0
  fi
  
  # No target domain specified, spin for random programs
# No target domain specified, spin for random programs
for ((i=1; i<=$COUNT; i++)); do
  [[ $COUNT -gt 1 ]] && echo -e "${CYAN}[${EMOJI_INFO}] Spin $i of $COUNT${RESET}"
  
  # Get random program
  program_url=$(get_random_program)
  response=$(curl -s -H "User-Agent: $CUSTOM_USER_AGENT" "$API_URL")
  
  if [[ -n "$program_url" ]]; then
    echo -e "${GREEN}[${EMOJI_LINK}] Program URL: ${WHITE}$program_url${RESET}"
    
    # Log URL
    echo "$program_url" >> "$LOG_FILE"
    
    # Copy to clipboard if enabled
    $COPY && echo "$program_url" | $CLIP_CMD && echo -e "${GRAY}[${EMOJI_INFO}] URL copied to clipboard.${RESET}"
    
    # Open in browser if enabled
    $OPEN && $OPEN_CMD "$program_url" && echo -e "${GRAY}[${EMOJI_INFO}] Opened in browser.${RESET}"
    
    # Run recon if enabled
    if $RECON || $HTTPX || $NUCLEI; then
      # Extract domain from API response if available
      API_DOMAINS=$(echo "$response" | jq -r '.domains | join(",")')
      local tmpfile=$(mktemp)
      extract_scope_from_url "$program_url" "$tmpfile"
      local domain=$(head -1 "$tmpfile")
      
      if [[ -n "$domain" ]]; then
        do_recon "$domain"
      else
        echo -e "${YELLOW}[${EMOJI_WARN}] Could not extract domain from program.${RESET}"
      fi
    fi
  fi
done
  
  # Save config if requested
  $SAVE_CONFIG && save_config
  
  exit 0
}

# Execute main function
main "$@"
