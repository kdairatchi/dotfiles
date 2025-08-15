#!/usr/bin/env bash
# VPS Ultimate Toolkit - A comprehensive menu-driven script for VPS management
# Version: 1.0.0
# Author: Gemini

set -Eeuo pipefail
IFS=$'\n\t'

# ========= STYLING & LOGGING =========
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; B='\033[1;34m'; N='\033[0m'
info() { echo -e "${G}[INFO]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
error() { echo -e "${R}[ERROR]${N} $*"; }
die() { error "$*"; exit 1; }
ok() { echo -e "${G}[OK]${N} $*"; }

# ========= BANNER =========
print_banner() {
    echo -e "${B}"
    cat <<'BANNER'
 __      __   _  _  _  _   ___    ___   _  _  ____  _  _  ___ 
(  )    /__\ ( \/ )( \/ ) / __)  / __) ( \/ )( ___)( \( )/ __)
/ (_-. /(__)\ \  /  )  / ( (__  ( (__   \  /  )__)  )  (( (_-.
\____/(__)(__)(__)  (__/   \___)  \___)   \/  (____)(_)\_)\___/
                                                             
      VPS ULTIMATE TOOLKIT - By Gemini
BANNER
    echo -e "${N}"
}

# ========= PRESS ENTER TO CONTINUE =========
press_enter() {
    read -rp "Press [Enter] to continue..."
}

# ========= MENU FUNCTIONS =========

# --- VPS Hardening & Auditing ---
run_harden_audit() {
    info "Running VPS Hardening & Auditing..."
    bash vps-harden-audit.sh
    ok "VPS Hardening & Auditing complete."
    press_enter
}

# --- Reconnaissance ---
run_recon() {
    info "Running Reconnaissance..."
    bash vps-sqry-enhanced.sh
    ok "Reconnaissance complete."
    press_enter
}

# --- Tool Installation ---
run_install_tools() {
    info "Running Tool Installation..."
    bash install-bruteforce-tools.sh
    ok "Tool Installation complete."
    press_enter
}

# --- Automation ---
run_automation() {
    info "Running Automation..."
    bash automate-vps-recon.sh
    ok "Automation complete."
    press_enter
}

# --- Red Team Operations ---
run_red_team() {
    info "Running Red Team Operations..."
    bash enhanced_audit.sh
    ok "Red Team Operations complete."
    press_enter
}

# --- Main Menu ---
main_menu() {
    while true; do
        clear
        print_banner
        echo -e "${C}Please choose an option:${N}"
        echo "1. VPS Hardening & Auditing"
        echo "2. Reconnaissance"
        echo "3. Install Brute-Force Tools"
        echo "4. Automated Reconnaissance"
        echo "5. Red Team Operations"
        echo "0. Exit"
        read -rp "Enter your choice: " choice

        case $choice in
            1) run_harden_audit ;;
            2) run_recon ;;
            3) run_install_tools ;;
            4) run_automation ;;
            5) run_red_team ;;
            0) break ;;
            *) warn "Invalid option, please try again." && sleep 2 ;;
        esac
d    done
}

# ========= MAIN EXECUTION =========
main() {
    main_menu
}

main "$@"
