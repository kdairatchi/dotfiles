#!/bin/bash

# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  Setup Checker
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  "real never lies."  |  Support: buymeacoffee.com/kdairatchi
# =========================================================

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

# Logging functions
log() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check system requirements
check_system() {
    echo -e "${BLUE}=== System Requirements ===${NC}"
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log "Python: $PYTHON_VERSION"
    else
        error "Python3 not found"
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        log "pip3: Available"
    else
        error "pip3 not found"
    fi
    
    # Check git
    if command -v git &> /dev/null; then
        log "git: Available"
    else
        error "git not found"
    fi
    
    # Check Go
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | cut -d' ' -f3)
        log "Go: $GO_VERSION"
    else
        warn "Go not found"
    fi
}

# Check virtual environment
check_venv() {
    echo -e "${BLUE}=== Virtual Environment ===${NC}"
    
    if [[ -d "$VENV_DIR" ]]; then
        log "Virtual environment exists: $VENV_DIR"
        
        # Check if activated
        if [[ "$VIRTUAL_ENV" == "$VENV_DIR" ]]; then
            log "Virtual environment is active"
        else
            warn "Virtual environment exists but not active"
        fi
        
        # Check requirements
        if [[ -f "$RECON_DIR/requirements.txt" ]]; then
            log "requirements.txt exists"
        else
            warn "requirements.txt not found"
        fi
    else
        error "Virtual environment not found"
    fi
}

# Check system tools
check_system_tools() {
    echo -e "${BLUE}=== System Tools ===${NC}"
    
    local tools=("curl" "wget" "git" "jq" "parallel")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log "$tool: Available"
        else
            warn "$tool: Not found"
        fi
    done
}

# Check Go tools
check_go_tools() {
    echo -e "${BLUE}=== Go Security Tools ===${NC}"
    
    # Set up Go environment
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"
    
    local go_tools=(
        "subfinder"
        "httpx"
        "nuclei"
        "waybackurls"
        "assetfinder"
        "ffuf"
        "dalfox"
        "katana"
        "gau"
        "waymore"
    )
    
    for tool in "${go_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log "$tool: Available"
        else
            warn "$tool: Not found"
        fi
    done
}

# Check additional tools
check_additional_tools() {
    echo -e "${BLUE}=== Additional Security Tools ===${NC}"
    
    local tools=("nmap" "whatweb" "whois")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log "$tool: Available"
        else
            warn "$tool: Not found"
        fi
    done
}

# Check Python dependencies
check_python_deps() {
    echo -e "${BLUE}=== Python Dependencies ===${NC}"
    
    if [[ -d "$VENV_DIR" ]]; then
        # Activate virtual environment
        source "$VENV_DIR/bin/activate" 2>/dev/null || return
        
        local deps=(
            "aiofiles"
            "aiohttp"
            "dnspython"
            "python-whois"
            "requests"
            "beautifulsoup4"
            "pytest"
        )
        
        for dep in "${deps[@]}"; do
            if python -c "import $dep" 2>/dev/null; then
                log "$dep: Installed"
            else
                warn "$dep: Not installed"
            fi
        done
    else
        warn "Virtual environment not found, cannot check Python dependencies"
    fi
}

# Check project structure
check_project_structure() {
    echo -e "${BLUE}=== Project Structure ===${NC}"
    
    local dirs=(
        "$RECON_DIR"
        "$RECON_DIR/logs"
        "$RECON_DIR/results"
        "$RECON_DIR/tests"
        "$RECON_DIR/config"
        "$RECON_DIR/lib"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log "Directory exists: $(basename "$dir")"
        else
            warn "Directory missing: $(basename "$dir")"
        fi
    done
    
    # Check key files
    local files=(
        "$RECON_DIR/bug_hunting_arsenal.py"
        "$RECON_DIR/requirements.txt"
        "$RECON_DIR/activate.sh"
    )
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            log "File exists: $(basename "$file")"
        else
            warn "File missing: $(basename "$file")"
        fi
    done
}

# Run tests
run_tests() {
    echo -e "${BLUE}=== Running Tests ===${NC}"
    
    if [[ -d "$RECON_DIR" ]]; then
        cd "$RECON_DIR"
        
        if [[ -d "$VENV_DIR" ]]; then
            source "$VENV_DIR/bin/activate" 2>/dev/null
            
            if python -m pytest tests/ -q 2>/dev/null; then
                log "All tests passed"
            else
                warn "Some tests failed"
            fi
        else
            warn "Virtual environment not found, cannot run tests"
        fi
    else
        warn "Recon directory not found"
    fi
}

# Generate summary
generate_summary() {
    echo -e "${BLUE}=== Summary ===${NC}"
    
    local total_checks=0
    local passed_checks=0
    
    # Count system tools
    local system_tools=("python3" "pip3" "git" "curl" "wget" "jq" "parallel")
    for tool in "${system_tools[@]}"; do
        ((total_checks++))
        if command -v "$tool" &> /dev/null; then
            ((passed_checks++))
        fi
    done
    
    # Count Go tools
    local go_tools=("go" "subfinder" "httpx" "nuclei" "waybackurls" "assetfinder" "ffuf" "dalfox" "katana" "gau" "waymore")
    for tool in "${go_tools[@]}"; do
        ((total_checks++))
        if command -v "$tool" &> /dev/null; then
            ((passed_checks++))
        fi
    done
    
    # Count additional tools
    local additional_tools=("nmap" "whatweb" "whois")
    for tool in "${additional_tools[@]}"; do
        ((total_checks++))
        if command -v "$tool" &> /dev/null; then
            ((passed_checks++))
        fi
    done
    
    # Check virtual environment
    ((total_checks++))
    if [[ -d "$VENV_DIR" ]]; then
        ((passed_checks++))
    fi
    
    # Check requirements.txt
    ((total_checks++))
    if [[ -f "$RECON_DIR/requirements.txt" ]]; then
        ((passed_checks++))
    fi
    
    # Calculate percentage
    local percentage=$((passed_checks * 100 / total_checks))
    
    echo "Overall setup status: $passed_checks/$total_checks ($percentage%)"
    
    if [[ $percentage -eq 100 ]]; then
        log "Setup is complete!"
    elif [[ $percentage -ge 80 ]]; then
        warn "Setup is mostly complete"
    else
        error "Setup is incomplete"
    fi
}

# Main function
main() {
    echo -e "${BLUE}"
    echo "========================================================="
    echo "  KDAIRATCHI SECURITY TOOLKIT  —  Setup Checker"
    echo "========================================================="
    echo -e "${NC}"
    
    check_system
    echo
    check_venv
    echo
    check_system_tools
    echo
    check_go_tools
    echo
    check_additional_tools
    echo
    check_python_deps
    echo
    check_project_structure
    echo
    run_tests
    echo
    generate_summary
    echo
    
    echo -e "${BLUE}=== Next Steps ===${NC}"
    echo "If setup is incomplete, run:"
    echo "  ./install/install_bug_hunting_arsenal.sh"
    echo ""
    echo "To activate the environment:"
    echo "  source $RECON_DIR/activate.sh"
    echo ""
    echo "To run the bug hunting arsenal:"
    echo "  cd $RECON_DIR"
    echo "  python bug_hunting_arsenal.py --help"
}

# Run main function
main "$@"

