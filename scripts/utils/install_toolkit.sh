#!/usr/bin/env bash
set -euo pipefail

# Automated installer for Bug Bounty Toolkit dependencies
# Installs: apt packages, Go tools, Python tools, wordlists, and configures environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/bug_bounty_install.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

require_sudo() {
  if [[ "$EUID" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    else
      log "sudo not found and script not running as root. Please run as root."; exit 1
    fi
  else
    SUDO=""
  fi
}

install_apt_packages() {
  require_sudo
  log "Updating apt cache and installing core packages"
  $SUDO apt-get update -y
  $SUDO apt-get install -y \
    git curl wget jq build-essential python3 python3-pip python3-venv \
    nmap dnsutils whois openssl netcat-traditional \
    dirb gobuster nikto cron ca-certificates
}

install_go() {
  if ! command -v go >/dev/null 2>&1; then
    log "Go not found. Skipping Go tool installation. Install Golang to proceed."
    return
  fi
  export GOPATH="${GOPATH:-$HOME/go}"
  export GOBIN="$GOPATH/bin"
  export PATH="$GOBIN:$PATH"
  log "Installing/Updating Go tools"
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true
  go install -v github.com/tomnomnom/waybackurls@latest || true
  go install -v github.com/tomnomnom/assetfinder@latest || true
  go install -v github.com/ffuf/ffuf@latest || true
  go install -v github.com/lc/gau/v2/cmd/gau@latest || true
  go install -v github.com/hakluke/hakrawler@latest || true
  go install -v github.com/tomnomnom/gf@latest || true
  go install -v github.com/tomnomnom/fff@latest || true
  go install -v github.com/bp0lr/gauplus@latest || true
  go install -v github.com/owasp-amass/amass/v3/...@master || true
}

install_python_tools() {
  log "Installing/Updating Python tools"
  python3 -m pip install --upgrade pip setuptools wheel || true
  python3 -m pip install --upgrade sqlmap arjun jsninja || true
}

setup_wordlists() {
  require_sudo
  local wl_dir="/usr/share/wordlists"
  $SUDO mkdir -p "$wl_dir"
  if [ ! -d "$wl_dir/SecLists" ]; then
    log "Cloning SecLists into $wl_dir/SecLists"
    $SUDO git clone https://github.com/danielmiessler/SecLists.git "$wl_dir/SecLists" || true
  else
    log "Updating SecLists"
    $SUDO git -C "$wl_dir/SecLists" pull || true
  fi
}

post_setup() {
  # Ensure installer is executable and helper scripts are executable
  chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true
  # Create nuclei templates dir if missing
  if [ ! -d "$HOME/nuclei-templates" ]; then
    mkdir -p "$HOME/nuclei-templates"
  fi
  # Update nuclei templates if nuclei exists
  if command -v nuclei >/dev/null 2>&1; then
    nuclei -update-templates || true
  fi
}

main() {
  log "Starting Bug Bounty Toolkit installation"
  install_apt_packages
  install_go
  install_python_tools
  setup_wordlists
  post_setup
  log "Installation complete"
}

main "$@"
