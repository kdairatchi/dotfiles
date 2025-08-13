#!/bin/bash

# Dotfiles Setup Script
# Installs and configures the bug bounty environment

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

# Check if running on Kali/Debian-based system
check_system() {
    if ! command -v apt &> /dev/null; then
        error "This script is designed for Debian-based systems (Kali Linux recommended)"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    log "Installing system dependencies..."
    sudo apt update
    sudo apt install -y \
        curl \
        wget \
        git \
        python3 \
        python3-pip \
        golang-go \
        nodejs \
        npm \
        parallel \
        jq \
        lynx \
        zsh \
        fonts-powerline
}

# Install Oh My Zsh and Powerlevel10k
install_zsh_setup() {
    log "Installing Oh My Zsh and Powerlevel10k..."
    
    # Install Oh My Zsh
    if [ ! -d "$HOME/.oh-my-zsh" ]; then
        sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    fi
    
    # Install Powerlevel10k theme
    if [ ! -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k" ]; then
        git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
    fi
    
    # Install zsh plugins
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions 2>/dev/null || true
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting 2>/dev/null || true
    git clone https://github.com/zsh-users/zsh-completions ${ZSH_CUSTOM:=~/.oh-my-zsh/custom}/plugins/zsh-completions 2>/dev/null || true
}

# Install Go tools
install_go_tools() {
    log "Installing Go-based security tools..."
    
    # Set up Go environment
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    
    mkdir -p $GOPATH/bin
    
    # Install tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/ffuf/ffuf@latest
    go install -v github.com/hahwul/dalfox/v2@latest
}

# Install Python tools
install_python_tools() {
    log "Installing Python-based security tools..."
    
    pip3 install --user requests beautifulsoup4 colorama urllib3 lxml pyyaml
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    mkdir -p $HOME/tools
    mkdir -p $HOME/scripts
    mkdir -p $HOME/wordlists
    mkdir -p $HOME/results
}

# Link configuration files
link_configs() {
    log "Linking configuration files..."
    
    # Backup existing configs
    [ -f "$HOME/.bashrc" ] && cp "$HOME/.bashrc" "$HOME/.bashrc.backup.$(date +%Y%m%d)"
    [ -f "$HOME/.zshrc" ] && cp "$HOME/.zshrc" "$HOME/.zshrc.backup.$(date +%Y%m%d)"
    [ -f "$HOME/.gitconfig" ] && cp "$HOME/.gitconfig" "$HOME/.gitconfig.backup.$(date +%Y%m%d)"
    [ -f "$HOME/.p10k.zsh" ] && cp "$HOME/.p10k.zsh" "$HOME/.p10k.zsh.backup.$(date +%Y%m%d)"
    
    # Link new configs
    ln -sf "$(pwd)/config/shell/bashrc" "$HOME/.bashrc"
    ln -sf "$(pwd)/config/shell/zshrc" "$HOME/.zshrc"
    ln -sf "$(pwd)/config/shell/p10k.zsh" "$HOME/.p10k.zsh"
    ln -sf "$(pwd)/config/git/gitconfig" "$HOME/.gitconfig"
    ln -sf "$(pwd)/config/shell/common.sh" "$HOME/.shell_common"
    
    warn "Remember to update your git config with your actual email and name!"
}

# Install Nuclei templates
install_nuclei_templates() {
    log "Installing Nuclei templates..."
    nuclei -update-templates
}

# Copy scripts and tools
copy_tools() {
    log "Copying scripts and tools..."
    
    # Copy scripts to home directory
    cp -r scripts/* $HOME/scripts/ 2>/dev/null || true
    cp -r tools/* $HOME/tools/ 2>/dev/null || true
    
    # Make scripts executable
    find $HOME/scripts -name "*.sh" -exec chmod +x {} \;
    find $HOME/scripts -name "*.py" -exec chmod +x {} \;
}

# Main installation function
main() {
    log "Starting dotfiles installation..."
    
    check_system
    install_system_deps
    install_zsh_setup
    create_directories
    install_go_tools
    install_python_tools
    link_configs
    copy_tools
    
    log "Installation completed!"
    log "Please run 'source ~/.zshrc' or restart your terminal"
    log "Run 'p10k configure' to configure your prompt"
    warn "Don't forget to:"
    warn "1. Update your .gitconfig with your actual email and name"
    warn "2. Set up your API keys in environment variables"
    warn "3. Review and customize your aliases in ~/.zshrc"
}

main "$@"