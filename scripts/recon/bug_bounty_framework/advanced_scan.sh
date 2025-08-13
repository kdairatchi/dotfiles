#!/bin/bash

# Advanced Reconnaissance & Reporting Framework
# Author: Gemini
# Version: 1.0
# Description: Performs advanced reconnaissance with a focus on dotfiles and generates detailed reports.

# --- Configuration ---
# Colors for UI/UX enhancement
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# --- Globals ---
TARGET_DOMAIN=""
OUTPUT_DIR=""
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# --- Banners & UI ---
# Display a stylish banner for the script
show_banner() {
    echo -e "${CYAN}"
    echo "     ___    __    ____  _  _  ____  __  __  ____  ____   __   "
    echo "    / __)  /__\  (  _ \(\ \/ )(  _ \(  )(  )(  _ \(  _ \ / _\  "
    echo "   ( (__  /(__)\  )   / )  /  ) _ < )(__)(  )   / )   //    \ "
    echo "    \___)(__)(__)(_)\_) (__/ (____/(__)(__)(_)\_)(_)\_)\_/\_/ "
    echo "                                                            "
    echo -e "${PURPLE}                Advanced Recon & Reporting Framework ${NC}"
    echo -e "${YELLOW}                     Version 1.0 - By Gemini ${NC}"
    echo
}

# --- Helper Functions ---
# Log messages with a timestamp
log() {
    echo -e "${GREEN}[$(date +"%T")]${NC} $1"
}

# Log errors
log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# --- Core Logic ---
# Set the target domain for the scan
set_target() {
    read -p "Enter the target domain (e.g., example.com): " -r TARGET_DOMAIN
    if [[ -z "$TARGET_DOMAIN" ]]; then
        log_error "Target domain cannot be empty."
        exit 1
    fi
    OUTPUT_DIR="results/${TARGET_DOMAIN}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR/reports"
    log "Target set to ${PURPLE}${TARGET_DOMAIN}${NC}"
    log "Output will be saved in ${PURPLE}${OUTPUT_DIR}${NC}"
}

# Reconnaissance phase for dotfiles
recon_dotfiles() {
    log "Starting dotfile reconnaissance..."
    local dotfile_wordlist="
.git/config
.svn/entries
.DS_Store
.bash_history
.bashrc
.ssh/id_rsa
.ssh/known_hosts
.aws/credentials
.env
.env.local
.env.production
.npmrc
.yarnrc
"
    local dotfiles_found_file="$OUTPUT_DIR/dotfiles_found.txt"
    touch "$dotfiles_found_file"

    if ! command_exists "httpx"; then
        log_error "httpx is not installed. Please install it to continue."
        return
    fi

    for dotfile in $dotfile_wordlist; do
        echo "https://www.${TARGET_DOMAIN}/${dotfile}"
        echo "https://${TARGET_DOMAIN}/${dotfile}"
    done | httpx -silent -status-code -content-length -o "$dotfiles_found_file"

    log "Dotfile reconnaissance complete. Found potential files are in ${PURPLE}$dotfiles_found_file${NC}"
}

# Generate a detailed HTML report
generate_report() {
    log "Generating HTML report..."
    local report_file="$OUTPUT_DIR/reports/advanced_recon_report.html"
    
    # Report Header
    cat > "$report_file" <<-"EOFHTML"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Reconnaissance Report for ${TARGET_DOMAIN}</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2 { color: #4a4a4a; }
        pre { background: #eee; padding: 10px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Advanced Reconnaissance Report</h1>
        <p><strong>Target:</strong> ${TARGET_DOMAIN}</p>
        <p><strong>Date:</strong> $(date)</p>
        
        <h2>Dotfiles Found</h2>
        <pre>
EOFHTML

    # Report Body
    if [[ -s "$OUTPUT_DIR/dotfiles_found.txt" ]]; then
        cat "$OUTPUT_DIR/dotfiles_found.txt" >> "$report_file"
    else
        echo "No dotfiles found." >> "$report_file"
    fi

    # Report Footer
    cat >> "$report_file" <<-"EOFHTML"
        </pre>
    </div>
</body>
</html>
EOFHTML
    log "HTML report generated at ${PURPLE}${report_file}${NC}"
}

# --- Main Function ---
main() {
    show_banner
    set_target
    recon_dotfiles
    generate_report
    log "Advanced scan complete for ${TARGET_DOMAIN}."
}

# Script entry point
main