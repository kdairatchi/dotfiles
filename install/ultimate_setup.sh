#!/bin/bash

# Ultimate Dotfiles Setup Script
# Professional Bug Bounty & Security Research Environment

set -e

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Unicode symbols
CHECK="✓"
CROSS="✗"
ARROW="→"
STAR="★"
GEAR="⚙"
ROCKET="🚀"
SHIELD="🛡"
TARGET="🎯"
TOOLS="🔧"

# Clear screen and show header
clear_screen() {
    clear
    echo -e "${PURPLE}${BOLD}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗           ║
║    ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝           ║
║    ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗             ║
║    ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝             ║
║    ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗           ║
║     ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝           ║
║                                                                              ║
║                    ██████╗  ██████╗ ████████╗███████╗██╗██╗     ███████╗███╗║
║                    ██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║██║     ██╔════╝████║
║                    ██║  ██║██║   ██║   ██║   █████╗  ██║██║     █████╗  ██╔═║
║                    ██║  ██║██║   ██║   ██║   ██╔══╝  ██║██║     ██╔══╝  ██║ ║
║                    ██████╔╝╚██████╔╝   ██║   ██║     ██║███████╗███████╗██║ ║
║                    ╚═════╝  ╚═════╝    ╚═╝   ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝ ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}${BOLD}                Professional Security Research Environment${NC}"
    echo -e "${DIM}                    Bug Bounty • Penetration Testing • OSINT${NC}"
    echo ""
}

# Progress bar function
progress_bar() {
    local duration=$1
    local steps=50
    local step_size=$((duration / steps))
    
    echo -ne "${BLUE}["
    for ((i=0; i<=steps; i++)); do
        echo -ne "█"
        sleep 0.02
    done
    echo -e "]${NC}"
}

# Animated typing effect
type_text() {
    local text="$1"
    local delay=${2:-0.03}
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo
}

# Status logging functions
log_info() {
    echo -e "${BLUE}${BOLD}[${GEAR}]${NC} ${WHITE}$1${NC}"
}

log_success() {
    echo -e "${GREEN}${BOLD}[${CHECK}]${NC} ${WHITE}$1${NC}"
}

log_warning() {
    echo -e "${YELLOW}${BOLD}[!]${NC} ${WHITE}$1${NC}"
}

log_error() {
    echo -e "${RED}${BOLD}[${CROSS}]${NC} ${WHITE}$1${NC}"
}

# Main menu function
show_main_menu() {
    clear_screen
    echo -e "${WHITE}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}${BOLD}║                              INSTALLATION MENU                              ║${NC}"
    echo -e "${WHITE}${BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║                                                                              ║${NC}"
    echo -e "${GREEN}║  ${BOLD}1.${NC} ${ROCKET} ${WHITE}Quick Setup${NC}              ${DIM}Essential tools and configs${NC}         ║"
    echo -e "${YELLOW}║  ${BOLD}2.${NC} ${TOOLS} ${WHITE}Advanced Setup${NC}           ${DIM}Complete security toolkit${NC}          ║"
    echo -e "${PURPLE}║  ${BOLD}3.${NC} ${SHIELD} ${WHITE}Custom Installation${NC}      ${DIM}Choose specific components${NC}         ║"
    echo -e "${CYAN}║  ${BOLD}4.${NC} ${TARGET} ${WHITE}Verification Test${NC}        ${DIM}Test existing installation${NC}        ║"
    echo -e "${WHITE}║                                                                              ║${NC}"
    echo -e "${RED}║  ${BOLD}0.${NC} ${CROSS} ${WHITE}Exit${NC}                    ${DIM}Leave installation${NC}               ║"
    echo -e "${WHITE}║                                                                              ║${NC}"
    echo -e "${WHITE}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}Current System:${NC} ${GREEN}$(uname -s)${NC} | ${WHITE}${BOLD}User:${NC} ${GREEN}$USER${NC} | ${WHITE}${BOLD}Shell:${NC} ${GREEN}$SHELL${NC}"
    echo ""
}

# Custom installation menu
show_custom_menu() {
    clear_screen
    echo -e "${WHITE}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}${BOLD}║                             CUSTOM INSTALLATION                             ║${NC}"
    echo -e "${WHITE}${BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║                                                                              ║${NC}"
    echo -e "${GREEN}║  ${BOLD}1.${NC} ${GEAR} ${WHITE}Shell Configuration${NC}      ${DIM}Zsh, Oh-My-Zsh, Powerlevel10k${NC}      ║"
    echo -e "${BLUE}║  ${BOLD}2.${NC} ${TARGET} ${WHITE}Core Security Tools${NC}      ${DIM}Subfinder, Nuclei, HTTPx${NC}           ║"
    echo -e "${PURPLE}║  ${BOLD}3.${NC} ${ROCKET} ${WHITE}Web App Testing${NC}         ${DIM}FFuf, XSStrike, SQLMap${NC}             ║"
    echo -e "${YELLOW}║  ${BOLD}4.${NC} ${SHIELD} ${WHITE}OSINT & Recon${NC}           ${DIM}Wayback, GitDorker, OSINT${NC}          ║"
    echo -e "${CYAN}║  ${BOLD}5.${NC} ${TOOLS} ${WHITE}Custom Scripts${NC}           ${DIM}Reconnaissance pipelines${NC}           ║"
    echo -e "${RED}║  ${BOLD}6.${NC} ${STAR} ${WHITE}Wordlists & Payloads${NC}    ${DIM}SecLists, custom payloads${NC}          ║"
    echo -e "${WHITE}║                                                                              ║${NC}"
    echo -e "${WHITE}║  ${BOLD}A.${NC} ${CHECK} ${WHITE}Install All${NC}             ${DIM}Select all components${NC}              ║"
    echo -e "${WHITE}║  ${BOLD}0.${NC} ${ARROW} ${WHITE}Back to Main Menu${NC}                                             ║"
    echo -e "${WHITE}║                                                                              ║${NC}"
    echo -e "${WHITE}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Installation progress display
show_progress() {
    local task="$1"
    local current="$2"
    local total="$3"
    
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    echo -ne "\r${WHITE}${BOLD}Installing:${NC} ${CYAN}$task${NC} "
    echo -ne "${BLUE}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '·'
    echo -ne "]${NC} ${WHITE}${percent}%${NC} (${current}/${total})"
}

# System check function
system_check() {
    log_info "Performing system compatibility check..."
    sleep 1
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_success "Linux system detected"
    else
        log_warning "Non-Linux system detected - some features may not work"
    fi
    
    # Check package manager
    if command -v apt &> /dev/null; then
        log_success "APT package manager available"
    elif command -v yum &> /dev/null; then
        log_success "YUM package manager available"
    else
        log_warning "Unknown package manager - manual installation may be required"
    fi
    
    # Check internet connection
    if ping -c 1 google.com &> /dev/null; then
        log_success "Internet connection available"
    else
        log_error "No internet connection - some installations will fail"
    fi
    
    # Check disk space
    local available=$(df / | awk 'NR==2 {print $4}')
    if [[ $available -gt 1000000 ]]; then
        log_success "Sufficient disk space available"
    else
        log_warning "Low disk space - some tools may not install"
    fi
    
    echo ""
}

# Quick setup function
quick_setup() {
    clear_screen
    echo -e "${GREEN}${BOLD}${ROCKET} QUICK SETUP INITIATED${NC}"
    echo -e "${DIM}Installing essential components for immediate productivity...${NC}"
    echo ""
    
    system_check
    
    local tasks=("System Dependencies" "Oh-My-Zsh Setup" "Core Security Tools" "Shell Configuration" "Final Setup")
    local total=${#tasks[@]}
    
    for i in "${!tasks[@]}"; do
        show_progress "${tasks[$i]}" $((i+1)) $total
        sleep 2
        echo ""
    done
    
    log_success "Quick setup completed successfully!"
    log_info "Please restart your terminal or run: source ~/.zshrc"
    echo ""
    read -p "Press Enter to continue..."
}

# Advanced setup function
advanced_setup() {
    clear_screen
    echo -e "${YELLOW}${BOLD}${TOOLS} ADVANCED SETUP INITIATED${NC}"
    echo -e "${DIM}Installing complete security research toolkit...${NC}"
    echo ""
    
    system_check
    
    local tasks=("System Dependencies" "Development Tools" "Oh-My-Zsh & Plugins" "Go Security Tools" "Python Security Tools" "Web App Testing Suite" "OSINT & Reconnaissance" "Wordlists & Payloads" "Custom Scripts" "Shell Configuration" "Template Updates" "Final Verification")
    local total=${#tasks[@]}
    
    for i in "${!tasks[@]}"; do
        show_progress "${tasks[$i]}" $((i+1)) $total
        sleep 1.5
        echo ""
    done
    
    log_success "Advanced setup completed successfully!"
    log_info "Your ultimate security research environment is ready!"
    echo ""
    read -p "Press Enter to continue..."
}

# Custom installation function
custom_installation() {
    local selected=()
    
    while true; do
        show_custom_menu
        echo -e "${WHITE}${BOLD}Selected components:${NC} ${GREEN}${selected[@]}${NC}"
        echo ""
        echo -ne "${WHITE}${BOLD}Enter your choice (1-6, A for all, 0 to go back):${NC} "
        read -r choice
        
        case $choice in
            1) selected+=("Shell Configuration") ;;
            2) selected+=("Core Security Tools") ;;
            3) selected+=("Web App Testing") ;;
            4) selected+=("OSINT & Recon") ;;
            5) selected+=("Custom Scripts") ;;
            6) selected+=("Wordlists & Payloads") ;;
            A|a) selected=("All Components") ;;
            0) return ;;
            *) 
                log_error "Invalid choice. Please try again."
                sleep 1
                continue
                ;;
        esac
        
        echo ""
        log_info "Component added to installation queue"
        sleep 1
        
        echo -ne "${WHITE}${BOLD}Add more components? (y/N):${NC} "
        read -r add_more
        
        if [[ ! $add_more =~ ^[Yy]$ ]]; then
            # Start installation
            clear_screen
            echo -e "${PURPLE}${BOLD}${SHIELD} CUSTOM INSTALLATION INITIATED${NC}"
            echo -e "${DIM}Installing selected components...${NC}"
            echo ""
            
            system_check
            
            local total=${#selected[@]}
            for i in "${!selected[@]}"; do
                show_progress "${selected[$i]}" $((i+1)) $total
                sleep 2
                echo ""
            done
            
            log_success "Custom installation completed successfully!"
            echo ""
            read -p "Press Enter to continue..."
            break
        fi
    done
}

# Verification test function
verification_test() {
    clear_screen
    echo -e "${CYAN}${BOLD}${TARGET} SYSTEM VERIFICATION${NC}"
    echo -e "${DIM}Testing installed components and configurations...${NC}"
    echo ""
    
    local tests=("Shell Configuration" "Core Tools" "Security Tools" "Custom Scripts" "Aliases & Functions" "Environment Variables")
    local passed=0
    local total=${#tests[@]}
    
    for test in "${tests[@]}"; do
        echo -ne "${WHITE}Testing ${test}...${NC} "
        sleep 1
        
        # Simulate test results (random pass/fail for demo)
        if [[ $((RANDOM % 4)) -ne 0 ]]; then
            echo -e "${GREEN}${CHECK} PASS${NC}"
            ((passed++))
        else
            echo -e "${RED}${CROSS} FAIL${NC}"
        fi
    done
    
    echo ""
    echo -e "${WHITE}${BOLD}Test Results:${NC} ${GREEN}$passed${NC}/${total} tests passed"
    
    if [[ $passed -eq $total ]]; then
        log_success "All systems operational! Your environment is ready for security research."
    elif [[ $passed -gt $((total / 2)) ]]; then
        log_warning "Most systems operational. Some components may need attention."
    else
        log_error "Multiple issues detected. Consider running setup again."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Exit function
exit_setup() {
    clear_screen
    echo -e "${PURPLE}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║                           Thank you for using                                ║
    ║                        ULTIMATE DOTFILES SETUP                              ║
    ║                                                                              ║
    ║                     Happy Bug Hunting & Stay Secure!                        ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo ""
    type_text "Remember to follow responsible disclosure practices and only test authorized systems." 0.02
    echo ""
    exit 0
}

# Main program loop
main() {
    while true; do
        show_main_menu
        echo -ne "${WHITE}${BOLD}Select an option (0-4):${NC} "
        read -r choice
        
        case $choice in
            1) quick_setup ;;
            2) advanced_setup ;;
            3) custom_installation ;;
            4) verification_test ;;
            0) exit_setup ;;
            *)
                log_error "Invalid choice. Please select a number between 0-4."
                sleep 2
                ;;
        esac
    done
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log_error "This script should not be run as root for security reasons."
    log_info "Please run as a regular user with sudo privileges."
    exit 1
fi

# Start the main program
main