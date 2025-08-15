#!/usr/bin/env bash
# install-bruteforce-tools.sh - Enhanced Brute-Force Tools Installation
# Installs ncrack, hydra, and medusa for comprehensive password attacks

set -Eeuo pipefail
IFS=$'\n\t'

# Color definitions
R="\033[0;31m"   # Red
G="\033[0;32m"   # Green
Y="\033[1;33m"   # Yellow
B="\033[1;34m"   # Blue
N="\033[0m"      # Normal

# Logging functions
info() { echo -e "${G}[INFO]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
error() { echo -e "${R}[ERROR]${N} $*"; }
ok() { echo -e "${G}[OK]${N} $*"; }

print_banner() {
    echo -e "${B}"
    echo "============================================="
    echo "   Enhanced Brute-Force Tools Installer    "
    echo "============================================="
    echo -e "${N}"
}

# Check if running as root for system-wide installation
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        info "Running as root - will install system-wide"
        INSTALL_PREFIX="/usr/local"
        USE_SUDO=""
    else
        info "Running as user - will install to \$HOME/local"
        INSTALL_PREFIX="$HOME/local"
        USE_SUDO=""
        mkdir -p "$INSTALL_PREFIX"/{bin,lib,include,share}
    fi
}

# Install system dependencies
install_dependencies() {
    info "Installing system dependencies..."
    
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        $USE_SUDO apt-get update
        $USE_SUDO apt-get install -y build-essential libssl-dev libssh-dev \
            libidn11-dev libpcre3-dev libgtk2.0-dev libmysqlclient-dev \
            libpq-dev libsvn-dev firebird-dev libmemcached-dev libgpg-error-dev \
            libgcrypt-dev libgcrypt20-dev wget curl git
    elif command -v yum &>/dev/null; then
        # CentOS/RHEL
        $USE_SUDO yum groupinstall -y "Development Tools"
        $USE_SUDO yum install -y openssl-devel libssh-devel libidn-devel \
            pcre-devel gtk2-devel mysql-devel postgresql-devel subversion-devel \
            firebird-devel libmemcached-devel gpgme-devel libgcrypt-devel \
            wget curl git
    elif command -v pacman &>/dev/null; then
        # Arch Linux
        $USE_SUDO pacman -S --needed base-devel openssl libssh libidn pcre2 \
            gtk2 mariadb-libs postgresql-libs subversion firebird2 libmemcached \
            gpgme libgcrypt wget curl git
    else
        warn "Unknown package manager. Please install build dependencies manually."
    fi
}

# Install Hydra (if not already installed)
install_hydra() {
    if command -v hydra &>/dev/null; then
        ok "Hydra already installed: $(hydra -h 2>&1 | head -1 || echo 'version unknown')"
        return 0
    fi
    
    info "Installing THC-Hydra v9.0..."
    
    local build_dir="/tmp/hydra-build-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Download and extract
    wget https://github.com/vanhauser-thc/thc-hydra/archive/v9.0.tar.gz
    tar xf v9.0.tar.gz
    cd thc-hydra-9.0
    
    # Configure and build
    ./configure --prefix="$INSTALL_PREFIX"
    make -j$(nproc)
    
    # Install
    if [[ $EUID -eq 0 ]]; then
        make install
    else
        make install
        # Add to PATH for user installation
        echo 'export PATH="$HOME/local/bin:$PATH"' >> ~/.bashrc
    fi
    
    # Cleanup
    cd /
    rm -rf "$build_dir"
    
    ok "Hydra installed successfully"
}

# Install Ncrack
install_ncrack() {
    if command -v ncrack &>/dev/null; then
        ok "Ncrack already installed: $(ncrack --version 2>&1 | head -1 || echo 'version unknown')"
        return 0
    fi
    
    info "Installing Ncrack v0.7..."
    
    local build_dir="/tmp/ncrack-build-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Download and extract
    wget https://nmap.org/ncrack/dist/ncrack-0.7.tar.gz
    tar xf ncrack-0.7.tar.gz
    cd ncrack-0.7
    
    # Configure and build
    ./configure --prefix="$INSTALL_PREFIX"
    make -j$(nproc)
    
    # Install
    if [[ $EUID -eq 0 ]]; then
        make install
    else
        make install
    fi
    
    # Cleanup
    cd /
    rm -rf "$build_dir"
    
    ok "Ncrack installed successfully"
}

# Install Medusa
install_medusa() {
    if command -v medusa &>/dev/null; then
        ok "Medusa already installed: $(medusa -V 2>&1 | head -1 || echo 'version unknown')"
        return 0
    fi
    
    info "Installing Medusa v2.2..."
    
    local build_dir="/tmp/medusa-build-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Download and extract
    wget http://www.foofus.net/jmk/tools/medusa-2.2.tar.gz
    tar xf medusa-2.2.tar.gz
    cd medusa-2.2
    
    # Configure and build
    ./configure --prefix="$INSTALL_PREFIX" --enable-module-ssh=yes \
        --enable-module-http=yes --enable-module-ftp=yes
    make -j$(nproc)
    
    # Install
    if [[ $EUID -eq 0 ]]; then
        make install
    else
        make install
    fi
    
    # Cleanup
    cd /
    rm -rf "$build_dir"
    
    ok "Medusa installed successfully"
}

# Install enhanced password wordlists
install_wordlists() {
    info "Setting up enhanced wordlists..."
    
    local wordlist_dir="$HOME/sqry_out/wordlists"
    mkdir -p "$wordlist_dir"
    
    # Download 500 worst passwords
    if [[ ! -f "$wordlist_dir/500-worst-passwords.txt" ]]; then
        info "Downloading 500 worst passwords list..."
        wget -O "$wordlist_dir/500-worst-passwords.txt.bz2" \
            https://downloads.skullsecurity.org/passwords/500-worst-passwords.txt.bz2
        
        if [[ -f "$wordlist_dir/500-worst-passwords.txt.bz2" ]]; then
            bzip2 -d "$wordlist_dir/500-worst-passwords.txt.bz2"
            ok "Enhanced password list downloaded"
        else
            warn "Failed to download enhanced password list"
        fi
    fi
    
    # Create comprehensive username list
    if [[ ! -f "$wordlist_dir/comprehensive-users.txt" ]]; then
        info "Creating comprehensive username list..."
        cat > "$wordlist_dir/comprehensive-users.txt" <<EOL
root
admin
administrator
user
test
guest
ubuntu
centos
debian
redhat
oracle
postgres
mysql
ftp
www
www-data
nginx
apache
service
daemon
syslog
mail
proxy
nobody
operator
games
backup
bin
sys
sync
shutdown
halt
lp
uucp
nuucp
listen
gdm
xfs
apache2
postfix
bind
named
dovecot
exim
sendmail
qmail
cyrus
sasl
vpopmail
vmail
clamav
amavis
dcc
razor
pyzor
spamassassin
EOL
        ok "Comprehensive username list created"
    fi
    
    # Create service-specific password lists
    create_service_passwords
}

# Create service-specific password lists
create_service_passwords() {
    local wordlist_dir="$HOME/sqry_out/wordlists"
    
    # SSH/Linux specific passwords
    if [[ ! -f "$wordlist_dir/ssh-passwords.txt" ]]; then
        info "Creating SSH-specific password list..."
        cat > "$wordlist_dir/ssh-passwords.txt" <<EOL
root
toor
ubuntu
centos
debian
redhat
admin
password
123456
12345678
qwerty
linux
server
welcome
changeme
default
EOL
    fi
    
    # Router/Network device passwords
    if [[ ! -f "$wordlist_dir/router-passwords.txt" ]]; then
        info "Creating router-specific password list..."
        cat > "$wordlist_dir/router-passwords.txt" <<EOL
admin
password
default
cisco
linksys
netgear
dlink
router
1234
12345
123456
admin123
password123
secret
public
private
enable
EOL
    fi
    
    ok "Service-specific wordlists created"
}

# Verify installations
verify_installations() {
    info "Verifying tool installations..."
    
    local tools=("hydra" "ncrack" "medusa")
    local all_good=1
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            ok "$tool: $(command -v "$tool")"
        else
            error "$tool: NOT FOUND"
            all_good=0
        fi
    done
    
    if (( all_good )); then
        ok "All brute-force tools installed successfully!"
        info "Tools are ready for use with vps-sqry.sh"
    else
        error "Some tools failed to install. Check the output above."
        return 1
    fi
}

# Create tool usage examples
create_examples() {
    info "Creating usage examples..."
    
    local examples_file="$HOME/brute-force-examples.txt"
    cat > "$examples_file" <<EOL
# Enhanced Brute-Force Tools - Usage Examples
# ============================================

# VPS-SQRY Framework Integration
./vps-sqry.sh --query "apache" --smart-scan --threads 8
./vps-sqry.sh --query "nginx" --full-scan --userlist custom-users.txt
./vps-sqry.sh --brute-cheatsheet

# Direct Hydra Usage
hydra -L users.txt -P passwords.txt -e nsr -t 4 ssh://target
hydra -l admin -P passwords.txt -w 30 http-get://target/admin/

# Direct Ncrack Usage
ncrack -p ssh:22,ftp:21,rdp:3389 -U users.txt -P passwords.txt target
ncrack -T5 --connection-limit 5 -p ssh -U users.txt -P passwords.txt target

# Direct Medusa Usage
medusa -u root -P passwords.txt -h target -M ssh -t 2 -r 1
medusa -U users.txt -P passwords.txt -H targets.txt -M ftp -v 6

# Performance Comparison Test
time hydra -l root -P passwords.txt ssh://target
time ncrack -p ssh -u root -P passwords.txt target  
time medusa -u root -P passwords.txt -h target -M ssh
EOL
    
    ok "Usage examples saved to: $examples_file"
}

# Main installation function
main() {
    print_banner
    
    info "Starting enhanced brute-force tools installation..."
    
    check_privileges
    install_dependencies
    
    # Install the three main tools
    install_hydra
    install_ncrack
    install_medusa
    
    # Setup wordlists
    install_wordlists
    
    # Verify everything worked
    verify_installations
    
    # Create usage examples
    create_examples
    
    echo
    ok "Enhanced brute-force toolkit installation complete!"
    info "Integration with vps-sqry.sh is automatic"
    info "Run './vps-sqry.sh --brute-cheatsheet' for usage examples"
    
    # Update PATH for current session if user install
    if [[ $EUID -ne 0 && -d "$HOME/local/bin" ]]; then
        export PATH="$HOME/local/bin:$PATH"
        info "Added $HOME/local/bin to PATH for current session"
        info "Restart your shell or run 'source ~/.bashrc' to make permanent"
    fi
}

# Run main function
main "$@"