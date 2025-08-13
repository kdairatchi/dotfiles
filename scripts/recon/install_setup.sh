#!/usr/bin/env bash
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  install_setup.sh
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  "real never lies."  |  Support: buymeacoffee.com/kdairatchi
# =========================================================

set -Eeuo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${PURPLE}[DEBUG]${NC} $1"; }

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    KDAIRATCHI SECURITY TOOLKIT               ║"
    echo "║                        Installation & Setup                  ║"
    echo "║                                                              ║"
    echo "║  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles ║"
    echo "║  \"real never lies.\"  |  Support: buymeacoffee.com/kdairatchi ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if file exists
file_exists() {
    [[ -f "$1" ]]
}

# Check if directory exists
dir_exists() {
    [[ -d "$1" ]]
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "debian"
        elif command_exists yum; then
            echo "rhel"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Install package based on OS
install_package() {
    local package="$1"
    local os=$(detect_os)
    
    case $os in
        "debian")
            sudo apt-get update && sudo apt-get install -y "$package"
            ;;
        "rhel")
            sudo yum install -y "$package"
            ;;
        "arch")
            sudo pacman -S --noconfirm "$package"
            ;;
        "macos")
            if command_exists brew; then
                brew install "$package"
            else
                log_error "Homebrew not found. Please install Homebrew first."
                return 1
            fi
            ;;
        *)
            log_warning "Automatic package installation not supported for this OS. Please install $package manually."
            return 1
            ;;
    esac
}

# Check and install Python
check_python() {
    log_info "Checking Python installation..."
    
    if command_exists python3; then
        local version=$(python3 --version 2>&1 | cut -d' ' -f2)
        log_success "Python3 found: $version"
        return 0
    elif command_exists python; then
        local version=$(python --version 2>&1 | cut -d' ' -f2)
        log_success "Python found: $version"
        return 0
    else
        log_warning "Python not found. Installing Python3..."
        install_package "python3"
        if command_exists python3; then
            log_success "Python3 installed successfully"
            return 0
        else
            log_error "Failed to install Python3"
            return 1
        fi
    fi
}

# Check and install pip
check_pip() {
    log_info "Checking pip installation..."
    
    if command_exists pip3; then
        log_success "pip3 found"
        return 0
    elif command_exists pip; then
        log_success "pip found"
        return 0
    else
        log_warning "pip not found. Installing pip..."
        install_package "python3-pip"
        if command_exists pip3; then
            log_success "pip3 installed successfully"
            return 0
        else
            log_error "Failed to install pip"
            return 1
        fi
    fi
}

# Check and install git
check_git() {
    log_info "Checking Git installation..."
    
    if command_exists git; then
        local version=$(git --version | cut -d' ' -f3)
        log_success "Git found: $version"
        return 0
    else
        log_warning "Git not found. Installing Git..."
        install_package "git"
        if command_exists git; then
            log_success "Git installed successfully"
            return 0
        else
            log_error "Failed to install Git"
            return 1
        fi
    fi
}

# Check and install Go
check_go() {
    log_info "Checking Go installation..."
    
    if command_exists go; then
        local version=$(go version | cut -d' ' -f3)
        log_success "Go found: $version"
        return 0
    else
        log_warning "Go not found. Installing Go..."
        install_package "golang-go"
        if command_exists go; then
            log_success "Go installed successfully"
            return 0
        else
            log_error "Failed to install Go"
            return 1
        fi
    fi
}

# Check and install Rust
check_rust() {
    log_info "Checking Rust installation..."
    
    if command_exists rustc; then
        local version=$(rustc --version | cut -d' ' -f2)
        log_success "Rust found: $version"
        return 0
    else
        log_warning "Rust not found. Installing Rust..."
        if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
            source "$HOME/.cargo/env"
            log_success "Rust installed successfully"
            return 0
        else
            log_error "Failed to install Rust"
            return 1
        fi
    fi
}

# Check and install Node.js
check_nodejs() {
    log_info "Checking Node.js installation..."
    
    if command_exists node; then
        local version=$(node --version)
        log_success "Node.js found: $version"
        return 0
    else
        log_warning "Node.js not found. Installing Node.js..."
        install_package "nodejs"
        if command_exists node; then
            log_success "Node.js installed successfully"
            return 0
        else
            log_error "Failed to install Node.js"
            return 1
        fi
    fi
}

# Setup virtual environment
setup_venv() {
    log_info "Setting up Python virtual environment..."
    
    local venv_path="${SCRIPT_DIR}/venv"
    
    if dir_exists "$venv_path"; then
        log_warning "Virtual environment already exists at $venv_path"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing existing virtual environment..."
            rm -rf "$venv_path"
        else
            log_info "Using existing virtual environment"
            return 0
        fi
    fi
    
    if python3 -m venv "$venv_path"; then
        log_success "Virtual environment created successfully"
        
        # Activate virtual environment
        source "$venv_path/bin/activate"
        
        # Upgrade pip
        pip install --upgrade pip
        
        return 0
    else
        log_error "Failed to create virtual environment"
        return 1
    fi
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    local venv_path="${SCRIPT_DIR}/venv"
    local requirements_file="${SCRIPT_DIR}/requirements.txt"
    
    # Create requirements.txt if it doesn't exist
    if ! file_exists "$requirements_file"; then
        log_info "Creating requirements.txt..."
        cat > "$requirements_file" << EOF
# Core dependencies
requests>=2.28.0
aiohttp>=3.8.0
aiofiles>=0.8.0
asyncio-throttle>=1.0.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
dnspython>=2.2.0
colorama>=0.4.5
rich>=12.0.0
click>=8.1.0
pyyaml>=6.0
jinja2>=3.1.0

# Security tools
cryptography>=3.4.0
paramiko>=2.10.0
scapy>=2.4.5

# Web scraping and analysis
selenium>=4.1.0
playwright>=1.20.0
httpx>=0.23.0
urllib3>=1.26.0

# Data processing
pandas>=1.4.0
numpy>=1.21.0
matplotlib>=3.5.0

# Testing
pytest>=7.0.0
pytest-asyncio>=0.20.0
pytest-cov>=3.0.0

# Development
black>=22.0.0
flake8>=4.0.0
mypy>=0.950
EOF
    fi
    
    # Activate virtual environment
    source "$venv_path/bin/activate"
    
    # Install dependencies
    if pip install -r "$requirements_file"; then
        log_success "Python dependencies installed successfully"
        return 0
    else
        log_error "Failed to install Python dependencies"
        return 1
    fi
}

# Check and install security tools
check_security_tools() {
    log_info "Checking security tools..."
    
    local tools=(
        "nmap"
        "masscan"
        "subfinder"
        "amass"
        "httpx"
        "nuclei"
        "gobuster"
        "dirsearch"
        "sqlmap"
        "nikto"
        "whatweb"
        "wafw00f"
        "theHarvester"
        "recon-ng"
        "maltego"
    )
    
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            log_success "✓ $tool found"
        else
            log_warning "✗ $tool not found"
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo
        log_info "Missing tools: ${missing_tools[*]}"
        read -p "Do you want to install missing tools? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_missing_tools "${missing_tools[@]}"
        fi
    fi
}

# Install missing security tools
install_missing_tools() {
    local tools=("$@")
    local os=$(detect_os)
    
    for tool in "${tools[@]}"; do
        log_info "Installing $tool..."
        
        case $tool in
            "nmap")
                install_package "nmap"
                ;;
            "masscan")
                if [[ "$os" == "debian" ]]; then
                    sudo apt-get install -y masscan
                else
                    log_warning "Please install masscan manually from https://github.com/robertdavidgraham/masscan"
                fi
                ;;
            "subfinder")
                if command_exists go; then
                    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                else
                    log_warning "Go not found. Please install Go first to install subfinder"
                fi
                ;;
            "amass")
                if command_exists go; then
                    go install -v github.com/owasp-amass/amass/v4/...@master
                else
                    log_warning "Go not found. Please install Go first to install amass"
                fi
                ;;
            "httpx")
                if command_exists go; then
                    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
                else
                    log_warning "Go not found. Please install Go first to install httpx"
                fi
                ;;
            "nuclei")
                if command_exists go; then
                    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
                else
                    log_warning "Go not found. Please install Go first to install nuclei"
                fi
                ;;
            "gobuster")
                if command_exists go; then
                    go install github.com/OJ/gobuster/v3@latest
                else
                    log_warning "Go not found. Please install Go first to install gobuster"
                fi
                ;;
            "dirsearch")
                if command_exists pip3; then
                    pip3 install dirsearch
                else
                    log_warning "pip3 not found. Please install pip3 first to install dirsearch"
                fi
                ;;
            "sqlmap")
                if command_exists pip3; then
                    pip3 install sqlmap
                else
                    log_warning "pip3 not found. Please install pip3 first to install sqlmap"
                fi
                ;;
            "nikto")
                install_package "nikto"
                ;;
            "whatweb")
                install_package "whatweb"
                ;;
            "wafw00f")
                if command_exists pip3; then
                    pip3 install wafw00f
                else
                    log_warning "pip3 not found. Please install pip3 first to install wafw00f"
                fi
                ;;
            "theHarvester")
                if command_exists pip3; then
                    pip3 install theHarvester
                else
                    log_warning "pip3 not found. Please install pip3 first to install theHarvester"
                fi
                ;;
            *)
                log_warning "Automatic installation not available for $tool. Please install manually."
                ;;
        esac
    done
}

# Setup configuration files
setup_config() {
    log_info "Setting up configuration files..."
    
    local config_dir="${SCRIPT_DIR}/config"
    
    # Create config directory if it doesn't exist
    mkdir -p "$config_dir"
    
    # Create API keys configuration
    local api_config="${config_dir}/api_keys.conf"
    if ! file_exists "$api_config"; then
        log_info "Creating API keys configuration..."
        cat > "$api_config" << EOF
# API Keys Configuration
# Add your API keys here for various services

# VirusTotal API Key
VT_API_KEY=""

# Shodan API Key
SHODAN_API_KEY=""

# Censys API Key
CENSYS_API_KEY=""
CENSYS_SECRET=""

# SecurityTrails API Key
SECURITYTRAILS_API_KEY=""

# HackerTarget API Key
HACKERTARGET_API_KEY=""

# AlienVault OTX API Key
OTX_API_KEY=""

# URLScan.io API Key
URLSCAN_API_KEY=""

# Wayback Machine (no API key needed)
# WAYBACK_API_KEY=""

# Common Crawl (no API key needed)
# COMMONCRAWL_API_KEY=""
EOF
        log_success "API keys configuration created at $api_config"
    fi
    
    # Create tools configuration
    local tools_config="${config_dir}/tools.conf"
    if ! file_exists "$tools_config"; then
        log_info "Creating tools configuration..."
        cat > "$tools_config" << EOF
# Tools Configuration
# Paths to various security tools

# Subdomain enumeration
SUBFINDER_PATH="subfinder"
AMASS_PATH="amass"
ASSETFINDER_PATH="assetfinder"

# Port scanning
NMAP_PATH="nmap"
MASSCAN_PATH="masscan"
RUSTSCAN_PATH="rustscan"

# Web scanning
HTTPX_PATH="httpx"
NUCLEI_PATH="nuclei"
GOBUSTER_PATH="gobuster"
DIRSEARCH_PATH="dirsearch"

# Vulnerability scanning
SQLMAP_PATH="sqlmap"
NIKTO_PATH="nikto"
WHATWEB_PATH="whatweb"
WAFW00F_PATH="wafw00f"

# OSINT tools
THEHARVESTER_PATH="theHarvester"
RECON_NG_PATH="recon-ng"

# Custom paths (if tools are installed in custom locations)
# SUBFINDER_PATH="/usr/local/bin/subfinder"
# AMASS_PATH="/opt/amass/amass"
EOF
        log_success "Tools configuration created at $tools_config"
    fi
}

# Setup wordlists
setup_wordlists() {
    log_info "Setting up wordlists..."
    
    local wordlists_dir="${SCRIPT_DIR}/wordlists"
    
    # Create wordlists directory if it doesn't exist
    mkdir -p "$wordlists_dir"
    
    # Check if SecLists is already present
    if dir_exists "${wordlists_dir}/SecLists"; then
        log_success "SecLists wordlists already present"
    else
        log_info "Cloning SecLists wordlists..."
        if git clone https://github.com/danielmiessler/SecLists.git "${wordlists_dir}/SecLists"; then
            log_success "SecLists wordlists downloaded successfully"
        else
            log_warning "Failed to download SecLists wordlists"
        fi
    fi
    
    # Create custom wordlists directory
    mkdir -p "${wordlists_dir}/custom"
    
    # Create a basic custom wordlist
    local custom_wordlist="${wordlists_dir}/custom/common_paths.txt"
    if ! file_exists "$custom_wordlist"; then
        log_info "Creating basic custom wordlist..."
        cat > "$custom_wordlist" << EOF
# Common web paths for directory enumeration
admin
api
assets
backup
config
data
db
dev
docs
files
images
img
js
lib
login
logout
media
panel
php
private
public
scripts
src
static
test
tmp
upload
uploads
user
users
wp-admin
wp-content
wp-includes
EOF
        log_success "Basic custom wordlist created"
    fi
}

# Setup logging
setup_logging() {
    log_info "Setting up logging..."
    
    local logs_dir="${SCRIPT_DIR}/logs"
    
    # Create logs directory if it doesn't exist
    mkdir -p "$logs_dir"
    
    # Create log rotation configuration
    local logrotate_config="${SCRIPT_DIR}/config/logrotate.conf"
    if ! file_exists "$logrotate_config"; then
        log_info "Creating log rotation configuration..."
        cat > "$logrotate_config" << EOF
# Log rotation configuration for security toolkit
${logs_dir}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        /usr/bin/killall -HUP rsyslogd >/dev/null 2>&1 || true
    endscript
}
EOF
        log_success "Log rotation configuration created"
    fi
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    local venv_path="${SCRIPT_DIR}/venv"
    
    # Activate virtual environment
    source "$venv_path/bin/activate"
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Run Python tests
    if command_exists pytest; then
        log_info "Running Python tests..."
        if pytest tests/ -v; then
            log_success "Python tests passed"
        else
            log_warning "Some Python tests failed"
        fi
    else
        log_warning "pytest not found. Skipping Python tests"
    fi
    
    # Run shell script tests if available
    if file_exists "tests/test_alienvault.sh"; then
        log_info "Running shell script tests..."
        if bash tests/test_alienvault.sh; then
            log_success "Shell script tests passed"
        else
            log_warning "Some shell script tests failed"
        fi
    fi
}

# Create activation script
create_activation_script() {
    log_info "Creating activation script..."
    
    local activation_script="${SCRIPT_DIR}/activate.sh"
    
    cat > "$activation_script" << 'EOF'
#!/usr/bin/env bash
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  activate.sh
#  Activation script for the security toolkit
# =========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate virtual environment
if [[ -d "${SCRIPT_DIR}/venv" ]]; then
    source "${SCRIPT_DIR}/venv/bin/activate"
    echo "Virtual environment activated"
else
    echo "Virtual environment not found. Run install_setup.sh first."
    exit 1
fi

# Set environment variables
export SECURITY_TOOLKIT_DIR="${SCRIPT_DIR}"
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

# Load configurations
if [[ -f "${SCRIPT_DIR}/config/api_keys.conf" ]]; then
    source "${SCRIPT_DIR}/config/api_keys.conf"
fi

if [[ -f "${SCRIPT_DIR}/config/tools.conf" ]]; then
    source "${SCRIPT_DIR}/config/tools.conf"
fi

echo "Security toolkit environment loaded"
echo "Available commands:"
echo "  - python bug_hunting_arsenal.py"
echo "  - bash bb-menu.sh"
echo "  - bash recon.sh"
echo "  - python alienvault.sh"
EOF
    
    chmod +x "$activation_script"
    log_success "Activation script created at $activation_script"
}

# Main installation function
main() {
    show_banner
    
    log_info "Starting installation and setup..."
    
    # Check system requirements
    log_info "Checking system requirements..."
    
    if ! check_python; then
        log_error "Python installation failed. Exiting."
        exit 1
    fi
    
    if ! check_pip; then
        log_error "pip installation failed. Exiting."
        exit 1
    fi
    
    if ! check_git; then
        log_error "Git installation failed. Exiting."
        exit 1
    fi
    
    # Setup virtual environment
    if ! setup_venv; then
        log_error "Virtual environment setup failed. Exiting."
        exit 1
    fi
    
    # Install Python dependencies
    if ! install_python_deps; then
        log_error "Python dependencies installation failed. Exiting."
        exit 1
    fi
    
    # Check and install additional tools
    check_go
    check_rust
    check_nodejs
    
    # Check security tools
    check_security_tools
    
    # Setup configuration
    setup_config
    
    # Setup wordlists
    setup_wordlists
    
    # Setup logging
    setup_logging
    
    # Create activation script
    create_activation_script
    
    # Run tests
    run_tests
    
    echo
    log_success "Installation and setup completed successfully!"
    echo
    log_info "Next steps:"
    echo "1. Activate the environment: source venv/bin/activate"
    echo "2. Configure API keys in config/api_keys.conf"
    echo "3. Run the toolkit: python bug_hunting_arsenal.py"
    echo "4. Or use the menu: bash bb-menu.sh"
    echo
    log_info "For activation script: source activate.sh"
    echo
}

# Run main function
main "$@"

