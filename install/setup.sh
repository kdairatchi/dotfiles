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
        fonts-powerline \
        ripgrep \
        net-tools \
        dnsutils \
        whois \
        nmap \
        openssl \
        unzip
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
    # Detect Go paths robustly
    if command -v go >/dev/null 2>&1; then
        export GOPATH="${GOPATH:-$HOME/go}"
        export PATH="$GOPATH/bin:$PATH"
    else
        warn "Go is not installed via PATH. Installing golang-go package should provide 'go'."
    fi
    
    mkdir -p $GOPATH/bin
    
    # Install tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || warn "subfinder install failed"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || warn "httpx install failed"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || warn "nuclei install failed"
    go install -v github.com/tomnomnom/waybackurls@latest || warn "waybackurls install failed"
    go install -v github.com/tomnomnom/assetfinder@latest || warn "assetfinder install failed"
    go install -v github.com/ffuf/ffuf@latest || warn "ffuf install failed"
    go install -v github.com/hahwul/dalfox/v2@latest || warn "dalfox install failed"
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
    
    # Ensure destinations
    mkdir -p "$HOME/scripts" "$HOME/tools" "$HOME/wordlists" "$HOME/tools/payloads"

    # Copy repo scripts into ~/scripts
    if [ -d "scripts" ]; then
      cp -r scripts/* "$HOME/scripts/" 2>/dev/null || true
    fi

    # Flatten tools: copy contents of tools/tools into ~/tools
    if [ -d "tools/tools" ]; then
      cp -r tools/tools/* "$HOME/tools/" 2>/dev/null || true
    fi

    # Wordlists go to ~/wordlists
    if [ -d "tools/wordlists" ]; then
      cp -r tools/wordlists/* "$HOME/wordlists/" 2>/dev/null || true
    fi

    # Payloads into ~/tools/payloads
    if [ -d "tools/payloads" ]; then
      cp -r tools/payloads/* "$HOME/tools/payloads/" 2>/dev/null || true
    fi

    # Make scripts executable
    find "$HOME/scripts" -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    find "$HOME/scripts" -type f -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
    find "$HOME/tools" -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
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
    
    # Install advanced tools and patterns if helper script exists
    if [ -f "$(pwd)/install/tools.sh" ]; then
      log "Installing advanced tools..."
      bash "$(pwd)/install/tools.sh" || warn "Advanced tools installation script exited with warnings"
    fi
    
    # Initialize alias/bootstrap layer if present
    if [ -f "$(pwd)/kda-bootstrap.sh" ]; then
      log "Configuring portable aliases and per-host overrides..."
      bash "$(pwd)/kda-bootstrap.sh" --install --yes || warn "Bootstrap configuration reported warnings"
    fi
    
    log "Installation completed!"
    log "Please run 'source ~/.zshrc' or restart your terminal"
    log "Run 'p10k configure' to configure your prompt"
    warn "Don't forget to:"
    warn "1. Update your .gitconfig with your actual email and name"
    warn "2. Set up your API keys in environment variables"
    warn "3. Review and customize your aliases in ~/.zshrc"
}

main "$@"