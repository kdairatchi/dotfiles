#!/bin/bash

# Advanced Bug Bounty Tools Installation Script
# Installs additional specialized tools for bug bounty hunting

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Install additional Go tools
install_advanced_go_tools() {
    log "Installing advanced Go tools..."
    
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
    go install -v github.com/tomnomnom/gf@latest
    go install -v github.com/tomnomnom/anew@latest
    go install -v github.com/tomnomnom/unfurl@latest
    go install -v github.com/tomnomnom/qsreplace@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/hakluke/hakrawler@latest
    go install -v github.com/003random/getJS@latest
    go install -v github.com/dwisiswant0/urldedupe@latest
}

# Install specialized Python tools
install_specialized_tools() {
    log "Installing specialized Python tools..."
    
    cd $HOME/tools
    
    # XSStrike
    if [ ! -d "XSStrike" ]; then
        git clone https://github.com/s0md3v/XSStrike.git
        cd XSStrike && pip3 install -r requirements.txt && cd ..
    fi
    
    # Corsy
    if [ ! -d "Corsy" ]; then
        git clone https://github.com/s0md3v/Corsy.git
        cd Corsy && pip3 install -r requirements.txt && cd ..
    fi
    
    # GitDorker
    if [ ! -d "GitDorker" ]; then
        git clone https://github.com/obheda12/GitDorker.git
        cd GitDorker && pip3 install -r requirements.txt && cd ..
    fi
    
    # SQLMap
    if [ ! -d "sqlmap" ]; then
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
    fi
    
    # Arjun
    if [ ! -d "Arjun" ]; then
        git clone https://github.com/s0md3v/Arjun.git
        cd Arjun && pip3 install -r requirements.txt && cd ..
    fi
}

# Install wordlists
install_wordlists() {
    log "Installing wordlists..."
    
    cd $HOME/wordlists
    
    # SecLists
    if [ ! -d "SecLists" ]; then
        git clone https://github.com/danielmiessler/SecLists.git
    fi
    
    # Download common wordlists
    wget -q -O common.txt https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/common.txt 2>/dev/null || true
    wget -q -O subdomains-top1million-5000.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt 2>/dev/null || true
}

# Setup GF patterns
setup_gf_patterns() {
    log "Setting up GF patterns..."
    
    mkdir -p ~/.gf
    cd ~/.gf
    
    git clone https://github.com/1ndianl33t/Gf-Patterns.git temp_patterns 2>/dev/null || true
    if [ -d "temp_patterns" ]; then
        cp temp_patterns/*.json . 2>/dev/null || true
        rm -rf temp_patterns
    fi
}

# Install additional utilities
install_utilities() {
    log "Installing additional utilities..."
    
    # Install htmlq for HTML parsing
    if ! command -v htmlq &> /dev/null; then
        cargo install htmlq 2>/dev/null || warn "Failed to install htmlq - requires Rust"
    fi
    
    # Install ripgrep
    if ! command -v rg &> /dev/null; then
        sudo apt install -y ripgrep 2>/dev/null || warn "Failed to install ripgrep"
    fi
}

# Main function
main() {
    log "Installing advanced bug bounty tools..."
    
    mkdir -p $HOME/tools
    mkdir -p $HOME/wordlists
    
    install_advanced_go_tools
    install_specialized_tools
    install_wordlists
    setup_gf_patterns
    install_utilities
    
    log "Advanced tools installation completed!"
    warn "Some tools may require additional configuration"
    warn "Check individual tool documentation for setup instructions"
}

main "$@"