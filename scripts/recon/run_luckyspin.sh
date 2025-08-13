#!/bin/bash

# =========================================================
#  LUCKYSPIN Launcher Script
#  Enhanced Bug Bounty OSINT Automation Tool
# =========================================================

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Function to print status
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python is available
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "Python is not installed"
        exit 1
    fi
}

# Check if virtual environment exists
check_venv() {
    if [[ -d "$VENV_DIR" ]]; then
        print_status "Virtual environment found"
        return 0
    else
        print_warning "Virtual environment not found"
        return 1
    fi
}

# Activate virtual environment
activate_venv() {
    if [[ -d "$VENV_DIR" ]]; then
        source "$VENV_DIR/bin/activate"
        print_success "Virtual environment activated"
    else
        print_warning "No virtual environment found, using system Python"
    fi
}

# Install dependencies
install_deps() {
    print_status "Installing dependencies..."
    
    if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
        pip install -r "$SCRIPT_DIR/requirements.txt"
        print_success "Dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Main function
main() {
    echo -e "${BLUE}"
    echo "========================================================="
    echo "  🎰 LUCKYSPIN - Enhanced Bug Bounty OSINT Tool"
    echo "========================================================="
    echo -e "${NC}"
    
    # Check Python
    check_python
    print_status "Using Python: $PYTHON_CMD"
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Check virtual environment
    if check_venv; then
        activate_venv
    else
        print_warning "Consider creating a virtual environment first"
        read -p "Continue with system Python? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Run './install/install_bug_hunting_arsenal.sh' to setup environment"
            exit 0
        fi
    fi
    
    # Check if luckyspin.sh exists
    if [[ ! -f "$SCRIPT_DIR/luckyspin.sh" ]]; then
        print_error "luckyspin.sh not found"
        exit 1
    fi
    
    # Make executable
    chmod +x "$SCRIPT_DIR/luckyspin.sh"
    
    # Run LuckySpin
    print_status "Starting LuckySpin..."
    echo
    
    # Pass all arguments to the Python script
    "$PYTHON_CMD" "$SCRIPT_DIR/luckyspin.sh" "$@"
}

# Run main function
main "$@"
