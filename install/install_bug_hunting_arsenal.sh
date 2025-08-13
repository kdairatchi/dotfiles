#!/bin/bash

# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  Bug Hunting Arsenal Installer
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  "real never lies."  |  Support: buymeacoffee.com/kdairatchi
# =========================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RECON_DIR="$PROJECT_ROOT/scripts/recon"
VENV_DIR="$RECON_DIR/venv"
REQUIREMENTS_FILE="$RECON_DIR/requirements.txt"
PYTHON_VERSION="3.8"

# Logging functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root"
        exit 1
    fi
}

# Check system requirements
check_system() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log "Detected Linux system"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log "Detected macOS system"
    else
        warn "Unsupported OS: $OSTYPE"
    fi
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION_ACTUAL=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
        log "Python version: $PYTHON_VERSION_ACTUAL"
        
        if [[ $(echo "$PYTHON_VERSION_ACTUAL >= $PYTHON_VERSION" | bc -l) -eq 1 ]]; then
            log "Python version is compatible"
        else
            error "Python $PYTHON_VERSION or higher is required"
            exit 1
        fi
    else
        error "Python3 is not installed"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        error "pip3 is not installed"
        exit 1
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        error "git is not installed"
        exit 1
    fi
}

# Create requirements.txt if it doesn't exist
create_requirements() {
    if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
        log "Creating requirements.txt..."
        cat > "$REQUIREMENTS_FILE" << 'EOF'
# Core dependencies
aiofiles>=23.0.0
aiohttp>=3.8.0
crawl4ai>=0.1.0
dnspython>=2.3.0
python-whois>=0.8.0
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
urllib3>=1.26.0
lxml>=4.9.0
pyyaml>=6.0
asyncio-throttle>=1.0.0

# Security and testing
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0

# Development tools
black>=23.0.0
flake8>=6.0.0
mypy>=1.0.0
EOF
        log "Created requirements.txt"
    else
        log "requirements.txt already exists"
    fi
}

# Setup virtual environment
setup_venv() {
    log "Setting up Python virtual environment..."
    
    if [[ -d "$VENV_DIR" ]]; then
        warn "Virtual environment already exists at $VENV_DIR"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        else
            log "Using existing virtual environment"
            return 0
        fi
    fi
    
    # Create virtual environment
    log "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    log "Upgrading pip..."
    pip install --upgrade pip
    
    # Install requirements
    log "Installing Python dependencies..."
    pip install -r "$REQUIREMENTS_FILE"
    
    log "Virtual environment setup complete"
}

# Check and install system tools
check_system_tools() {
    log "Checking system tools..."
    
    local missing_tools=()
    local tools_to_check=(
        "curl" "wget" "git" "jq" "parallel"
    )
    
    for tool in "${tools_to_check[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        else
            log "✓ $tool is installed"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warn "Missing system tools: ${missing_tools[*]}"
        read -p "Do you want to install missing system tools? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_system_tools "${missing_tools[@]}"
        fi
    fi
}

# Install system tools
install_system_tools() {
    local tools=("$@")
    log "Installing system tools: ${tools[*]}"
    
    if command -v apt &> /dev/null; then
        # Debian/Ubuntu/Kali
        sudo apt update
        sudo apt install -y "${tools[@]}"
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        sudo yum install -y "${tools[@]}"
    elif command -v brew &> /dev/null; then
        # macOS
        brew install "${tools[@]}"
    else
        error "No supported package manager found"
        return 1
    fi
}

# Check and install Go tools
check_go_tools() {
    log "Checking Go-based security tools..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        warn "Go is not installed"
        read -p "Do you want to install Go? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_go
        else
            return 0
        fi
    fi
    
    # Set up Go environment
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"
    
    local go_tools=(
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "waybackurls:github.com/tomnomnom/waybackurls@latest"
        "assetfinder:github.com/tomnomnom/assetfinder@latest"
        "ffuf:github.com/ffuf/ffuf@latest"
        "dalfox:github.com/hahwul/dalfox/v2@latest"
        "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
        "gau:github.com/lc/gau/v2/cmd/gau@latest"
        "waymore:github.com/xnl-h4ck3r/waymore@latest"
    )
    
    local missing_go_tools=()
    
    for tool_info in "${go_tools[@]}"; do
        IFS=':' read -r tool_name tool_path <<< "$tool_info"
        if ! command -v "$tool_name" &> /dev/null; then
            missing_go_tools+=("$tool_info")
        else
            log "✓ $tool_name is installed"
        fi
    done
    
    if [[ ${#missing_go_tools[@]} -gt 0 ]]; then
        warn "Missing Go tools: ${missing_go_tools[*]}"
        read -p "Do you want to install missing Go tools? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_go_tools "${missing_go_tools[@]}"
        fi
    fi
}

# Install Go
install_go() {
    log "Installing Go..."
    
    local go_version="1.21.0"
    local arch=$(uname -m)
    
    if [[ "$arch" == "x86_64" ]]; then
        arch="amd64"
    elif [[ "$arch" == "aarch64" ]]; then
        arch="arm64"
    fi
    
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local download_url="https://go.dev/dl/go${go_version}.${os}-${arch}.tar.gz"
    
    log "Downloading Go from: $download_url"
    
    # Download and install Go
    cd /tmp
    wget "$download_url"
    sudo tar -C /usr/local -xzf "go${go_version}.${os}-${arch}.tar.gz"
    rm "go${go_version}.${os}-${arch}.tar.gz"
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
    
    export PATH=$PATH:/usr/local/go/bin
    
    log "Go installation complete"
}

# Install Go tools
install_go_tools() {
    local tools=("$@")
    log "Installing Go tools..."
    
    # Set up Go environment
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"
    
    mkdir -p "$GOPATH/bin"
    
    for tool_info in "${tools[@]}"; do
        IFS=':' read -r tool_name tool_path <<< "$tool_info"
        log "Installing $tool_name..."
        go install -v "$tool_path"
    done
    
    log "Go tools installation complete"
}

# Check and install additional tools
check_additional_tools() {
    log "Checking additional security tools..."
    
    local additional_tools=(
        "nmap"
        "whatweb"
        "whois"
    )
    
    local missing_tools=()
    
    for tool in "${additional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        else
            log "✓ $tool is installed"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warn "Missing additional tools: ${missing_tools[*]}"
        read -p "Do you want to install missing additional tools? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_additional_tools "${missing_tools[@]}"
        fi
    fi
}

# Install additional tools
install_additional_tools() {
    local tools=("$@")
    log "Installing additional tools: ${tools[*]}"
    
    if command -v apt &> /dev/null; then
        # Debian/Ubuntu/Kali
        sudo apt update
        sudo apt install -y "${tools[@]}"
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        sudo yum install -y "${tools[@]}"
    elif command -v brew &> /dev/null; then
        # macOS
        brew install "${tools[@]}"
    else
        error "No supported package manager found"
        return 1
    fi
}

# Setup project structure
setup_project_structure() {
    log "Setting up project structure..."
    
    # Create necessary directories
    local dirs=(
        "$RECON_DIR/logs"
        "$RECON_DIR/results"
        "$RECON_DIR/tests"
        "$RECON_DIR/config"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log "Created directory: $dir"
        fi
    done
    
    # Make scripts executable
    find "$RECON_DIR" -name "*.sh" -type f -exec chmod +x {} \;
    find "$RECON_DIR" -name "*.py" -type f -exec chmod +x {} \;
}

# Run tests
run_tests() {
    log "Running tests..."
    
    cd "$RECON_DIR"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Run Python tests
    if python -m pytest tests/ -v; then
        log "✓ All tests passed"
    else
        warn "Some tests failed"
    fi
}

# Create activation script
create_activation_script() {
    log "Creating activation script..."
    
    cat > "$RECON_DIR/activate.sh" << EOF
#!/bin/bash
# Activate the bug hunting arsenal environment

export RECON_DIR="$RECON_DIR"
export PATH="\$RECON_DIR/venv/bin:\$PATH"

# Activate virtual environment
source "\$RECON_DIR/venv/bin/activate"

# Add Go tools to PATH
export GOPATH="\$HOME/go"
export PATH="\$GOPATH/bin:\$PATH"

echo "Bug Hunting Arsenal environment activated!"
echo "Python virtual environment: \$RECON_DIR/venv"
echo "Go tools: \$GOPATH/bin"
echo ""
echo "Available commands:"
echo "  python bug_hunting_arsenal.py --help"
echo "  python tests/test_bug_hunting_arsenal.py"
EOF
    
    chmod +x "$RECON_DIR/activate.sh"
    log "Created activation script: $RECON_DIR/activate.sh"
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "========================================================="
    echo "  KDAIRATCHI SECURITY TOOLKIT  —  Bug Hunting Arsenal"
    echo "  Automated Installation and Setup"
    echo "========================================================="
    echo -e "${NC}"
    
    # Check if not running as root
    check_root
    
    # Check system requirements
    check_system
    
    # Create requirements.txt
    create_requirements
    
    # Setup virtual environment
    setup_venv
    
    # Check and install system tools
    check_system_tools
    
    # Check and install Go tools
    check_go_tools
    
    # Check and install additional tools
    check_additional_tools
    
    # Setup project structure
    setup_project_structure
    
    # Create activation script
    create_activation_script
    
    # Run tests
    run_tests
    
    echo -e "${GREEN}"
    echo "========================================================="
    echo "  Installation Complete!"
    echo "========================================================="
    echo -e "${NC}"
    echo ""
    echo "To activate the environment, run:"
    echo "  source $RECON_DIR/activate.sh"
    echo ""
    echo "To run the bug hunting arsenal:"
    echo "  cd $RECON_DIR"
    echo "  python bug_hunting_arsenal.py --help"
    echo ""
    echo "To run tests:"
    echo "  cd $RECON_DIR"
    echo "  python -m pytest tests/ -v"
    echo ""
}

# Run main function
main "$@"

