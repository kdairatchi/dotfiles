#!/bin/bash

# Ultimate Bug Bounty VPS Setup Script
# Version: 2025.3
# Author: Security Engineer
# Description: Complete setup for a hardened VPS with all essential bug bounty tools
# Includes: kdairatchi/dotfiles integration, full system hardening, and 100+ security tools

set -euo pipefail
exec > >(tee -a "/var/log/vps_setup.log") 2>&1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
RESTORE='\033[0m'

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/vps_setup.log"
CONFIG_FILE="/root/vps_config.conf"
TOOLS_DIR="/opt/tools"
WORDLISTS_DIR="/opt/wordlists"
SSH_PORT=2222
INSTALL_DOCKER="yes"
INSTALL_METASPLOIT="yes"
ENABLE_2FA="yes"
DOTFILES_REPO="https://github.com/kdairatchi/dotfiles.git"
KITERUNNERVER="2.0.2"

# Get user input for username
get_user_input() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    VPS SETUP CONFIGURATION                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get username
    while true; do
        read -p "Enter username for the bug bounty user (default: bbuser): " USER_NAME
        USER_NAME=${USER_NAME:-bbuser}
        
        if [[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            break
        else
            echo -e "${RED}[!] Invalid username. Use only lowercase letters, numbers, hyphens, and underscores.${NC}"
        fi
    done
    
    echo -e "${GREEN}[+] Username set to: $USER_NAME${NC}"
    echo ""
}

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Error handling
trap 'echo -e "${RED}[!] Error on line $LINENO${NC}"; exit 1' ERR

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check internet connectivity
check_internet() {
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${RED}[!] No internet connection detected${NC}"
        exit 1
    fi
}

# Function to show progress
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r["
    printf "%${completed}s" | tr ' ' '#'
    printf "%${remaining}s" | tr ' ' '-'
    printf "] %d%%" $percentage
    
    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

# Logging functions
log_info() { echo -e "${BLUE}[*] $1${NC}"; }
log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
log_error() { echo -e "${RED}[!] $1${NC}"; }

# Banner
display_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗  ║
║  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝██║  ║
║  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║   ██║  ║
║  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║   ╚═╝  ║
║  ██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║   ██╗  ║
║  ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ║
║                                                                              ║
║                  B U G   B O U N T Y   V P S   S E T U P                     ║
║                         Ultimate Edition - v2025.3                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# System update
system_update() {
    log_info "Updating system packages..."
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    apt-get install -y sudo curl wget git unzip build-essential libssl-dev libffi-dev \
        python3-dev python3-pip python3-venv tmux htop net-tools nmap jq netcat-traditional \
        dnsutils whois apt-transport-https ca-certificates gnupg lsb-release \
        software-properties-common vim nano tree screen rsync ruby ruby-dev \
        nodejs npm default-jdk zsh
    log_success "System updated"
}

# Create user
create_user() {
    log_info "Creating bug bounty user..."
    if id "$USER_NAME" &>/dev/null; then
        log_warning "User $USER_NAME already exists"
    else
        useradd -m -s /bin/bash "$USER_NAME"
        echo "$USER_NAME:$(openssl rand -base64 32)" | chpasswd
        usermod -aG sudo "$USER_NAME"
        log_success "User $USER_NAME created"
    fi
    
    mkdir -p "/home/$USER_NAME/.ssh"
    chmod 700 "/home/$USER_NAME/.ssh"
    chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh"
}

# Harden SSH
harden_ssh() {
    log_info "Hardening SSH..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    cat << EOF > /etc/ssh/sshd_config
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60
AllowUsers $USER_NAME
AddressFamily inet
ListenAddress 0.0.0.0
SyslogFacility AUTH
LogLevel VERBOSE
PermitUserEnvironment no
Compression no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
Banner /etc/ssh/banner
EOF

    cat << 'EOF' > /etc/ssh/banner
╔══════════════════════════════════════════════════════════════════╗
║                      UNAUTHORIZED ACCESS PROHIBITED              ║
║                                                                  ║
║ All activities are monitored and logged. Disconnect immediately   ║
║ if you are not an authorized user.                               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF

    systemctl restart sshd
    log_success "SSH hardened on port $SSH_PORT"
}

# Setup firewall
setup_firewall() {
    log_info "Configuring UFW firewall..."
    apt-get install -y ufw
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SSH_PORT/tcp"
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    log_success "Firewall configured"
}

# Install security tools
install_security_tools() {
    log_info "Installing security tools..."
    apt-get install -y fail2ban rkhunter chkrootkit clamav clamav-daemon aide
    
    # Configure fail2ban
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 24h
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    
    # Update rkhunter
    rkhunter --update
    rkhunter --propupd
    
    # Update ClamAV
    freshclam
    systemctl enable clamav-daemon
    
    log_success "Security tools installed"
}

# Install programming languages
install_languages() {
    log_info "Installing programming languages..."
    
    # Golang
    GO_VERSION="1.22.5"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    cat << 'EOF' > /etc/profile.d/golang.sh
export GOROOT=/usr/local/go
export GOPATH=/opt/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
EOF
    
    mkdir -p /opt/go
    chown -R "$USER_NAME:$USER_NAME" /opt/go
    
    # Rust
    sudo -u "$USER_NAME" bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
    
    log_success "Programming languages installed"
}

# Install Docker
install_docker() {
    if [ "$INSTALL_DOCKER" = "yes" ]; then
        log_info "Installing Docker..."
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update -y
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        usermod -aG docker "$USER_NAME"
        
        # Docker daemon config
        cat << EOF > /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}
EOF
        
        systemctl enable docker
        systemctl restart docker
        log_success "Docker installed"
    fi
}

# Create directory structure
create_directories() {
    log_info "Creating directory structure..."
    mkdir -p "$TOOLS_DIR" "$WORDLISTS_DIR"
    chown -R "$USER_NAME:$USER_NAME" "$TOOLS_DIR" "$WORDLISTS_DIR"
    
    sudo -u "$USER_NAME" mkdir -p "/home/$USER_NAME"/{tools,wordlists,scripts,projects,recon}
    log_success "Directory structure created"
}

# Install bug bounty tools
install_bugbounty_tools() {
    log_info "Installing bug bounty tools..."
    
    # Source Go environment
    source /etc/profile.d/golang.sh
    
    # Subdomain tools
    log_info "Installing subdomain tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/tomnomnom/assetfinder@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/owasp-amass/amass/v4/...@master'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest'
    wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
    chmod +x /usr/local/bin/findomain
    #Masscan
echo -e "${YELLOW}[*] Installing Masscan${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/robertdavidgraham/masscan > /dev/null 2>&1 && cd masscan && make > /dev/null 2>&1 && make install > /dev/null 2>&1 && mv bin/masscan /usr/local/bin/;
echo -e "${GREEN}[+] Masscan installed${NC}"; echo "";
sleep 1.5
#Naabu
echo -e "${YELLOW}[*] Installing Naabu${NC}";
sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest > /dev/null 2>&1 && ln -s ~/go/bin/naabu /usr/local/bin/';
echo -e "${GREEN}[+] Naabu installed${NC}"; echo "";
sleep 1.5

#---------Install subdomain enumeration and DNS Resolver
#dnsutils
apt-get install -y dnsutils > /dev/null 2>&1;
sleep 1.5
#Massdns
echo -e "${YELLOW}[*] Installing massdns${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/blechschmidt/massdns.git > /dev/null 2>&1;
cd "$TOOLS_DIR/massdns"
make > /dev/null 2>&1;
cd "$TOOLS_DIR"
echo -e "${GREEN}[+] Massdns installed${NC}"; echo "";
sleep 1.5
#Subfinder
echo -e "${YELLOW}[*] Installing Subfinder${NC}";
sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1 && ln -s ~/go/bin/subfinder /usr/local/bin/';
echo -e "${GREEN}[+] Subfinder installed${NC}"; echo "";
sleep 1.5
#Knock
echo -e "${YELLOW}[*] Installing Knock${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/guelfoweb/knock.git > /dev/null 2>&1;
echo -e "${GREEN}[+] Knock installed${NC}"; echo "";
sleep 1.5
#Lazyrecon
echo -e "${YELLOW}[*] Installing LazyRecon${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/nahamsec/lazyrecon.git > /dev/null 2>&1;
echo -e "${GREEN}[+] LazyRecon installed${NC}"; echo "";
sleep 1.5
#Github-subdomains
echo -e "${YELLOW}[*] Installing Github-subdomains${NC}";
sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -u github.com/gwen001/github-subdomains@latest > /dev/null 2>&1 && ln -s ~/go/bin/github-subdomains /usr/local/bin/';
echo -e "${GREEN}[+] Github-subdomains installed${NC}"; echo "";
sleep 1.5
#Sublist3r
echo -e "${YELLOW}[*] Installing Sublist3r${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/aboul3la/Sublist3r.git > /dev/null 2>&1;
cd "$TOOLS_DIR/Sublist3r"
pip3 install -r requirements.txt
cd "$TOOLS_DIR"
echo -e "${GREEN}[+] Sublist3r installed${NC}"; echo "";
sleep 1.5
#Crtndstry
echo -e "${YELLOW}[*] Installing Crtndstry${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/nahamsec/crtndstry.git > /dev/null 2>&1;
echo -e "${GREEN}[+] Crtndstry installed${NC}"; echo "";
sleep 1.5
#Assetfinder
echo -e "${YELLOW}[*] Installing Assetfinder${NC}";
sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -u github.com/tomnomnom/assetfinder@latest > /dev/null 2>&1 && ln -s ~/go/bin/assetfinder /usr/local/bin/';
echo -e "${GREEN}[+] Assetfinder installed${NC}"; echo "";
sleep 1.5
#dnsx
echo -e "${YELLOW}[*] Installing Dnsx${NC}";
sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest > /dev/null 2>&1 && ln -s ~/go/bin/dnsx /usr/local/bin/';
echo -e "${GREEN}[+] Dnsx installed${NC}"; echo "";
sleep 1.5
#dnsgen
echo -e "${YELLOW}[*] Installing Dnsgen${NC}";
pip3 install dnsgen > /dev/null 2>&1;
echo -e "${GREEN}[+] Dnsgen installed${NC}"; echo "";
sleep 1.5

#---------Install subdomain takeovers
#SubOver
echo -e "${YELLOW}[*] Installing SubOver${NC}";
sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/Ice3man543/SubOver@latest > /dev/null 2>&1 && ln -s ~/go/bin/subover /usr/local/bin/';
echo -e "${GREEN}[+] SubOver installed${NC}"; echo "";
sleep 1.5

#---------Install Fuzzing Tools
#Dirsearch
echo -e "${YELLOW}[*] Installing dirsearch${NC}";
cd "$TOOLS_DIR" && git clone https://github.com/maurosoria/dirsearch.git > /dev/null 2>&1;
cd "$TOOLS_DIR/dirsearch"
pip3 install -r requirements.txt
cd "$TOOLS_DIR"
echo -e "${GREEN}[+] Dirsearch installed${NC}"; echo "";
sleep 1.5

	#Lilly
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Lilly installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/Dheerajmadhukar/Lilly.git  > /dev/null 2>&1 && cd Lilly && chmod +x lilly.sh;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Lilly installation is done !"; echo "";
	#Crobat
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Crobat installation in progress ...";
	go install github.com/cgboal/sonarsearch/cmd/crobat@latest > /dev/null 2>&1 && ln -s ~/go/bin/crobat /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Crobat installation is done !"; echo "";
	#Sudomy
	echo -e ${BLUE}"[DNS RESOLVER]" ${RED}"Sudomy installation in progress ...";
	cd "$TOOLS_DIR" && git clone --recursive https://github.com/screetsec/Sudomy.git > /dev/null 2>&1 && cd Sudomy && python3 -m pip install -r requirements.txt && apt-get install npm && apt-get install jq && npm install -g phantomjs && apt-get install jq nmap phantomjs npm chromium parallel -y && npm i -g wappalyzer wscat && cp sudomy /usr/local/bin && cp sudomy.api /usr/local/bin && cp slack.conf /usr/local/bin && cp sudomy.conf /usr/local/bin > /dev/null 2>&1 && ln -s "$TOOLS_DIR/Sudomy/sudomy" /usr/local/bin/;
	echo -e ${BLUE}"[DNS RESOLVER]" ${GREEN}"Sudomy installation is done !"; echo "";
	#mapcidr
	echo -e ${BLUE}"[DNS RESOLVER]" ${RED}"Mapcidr installation in progress ...";
	go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest > /dev/null 2>&1 && ln -s ~/go/bin/mapcidr /usr/local/bin/;
	echo -e ${BLUE}"[DNS RESOLVER]" ${GREEN}"Mapcidr installation is done !"; echo "";
	#AltDns
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}AltDns installation in progress ...";
	cd "$TOOLS_DIR" && mkdir -p file && cd file && git clone https://github.com/infosec-au/altdns.git && cd altdns && pip install --upgrade pip setuptools pyopenssl requests urllib3 cachecontrol && pip install -r requirements.txt;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}AltDns installation is done !"; echo "";
	#CertCrunchy
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}CertCrunchy installation in progress ...";
	cd "$TOOLS_DIR/file" && git clone https://github.com/joda32/CertCrunchy.git > /dev/null 2>&1 && cd CertCrunchy && pip3 install -r requirements.txt;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}CertCrunchy installation is done !"; echo "";
	#chaos
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"chaos installation in progress ...";
	go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest > /dev/null 2>&1 && ln -s ~/go/bin/chaos /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"chaos installation is done !"; echo "";
	#shodan
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"shodan installation in progress ...";
	apt install python3-shodan && shodan init Dw9DTE811cfQ6j59jGLfVAWAMDr0MCTT;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"shodan installation is done !"; echo "";
	#gotator
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"gotator installation in progress ...";
	go install github.com/Josue87/gotator@latest > /dev/null 2>&1 && ln -s ~/go/bin/gotator /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"gotator installation is done !"; echo "";
        #ctfr
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"ctfr installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/UnaPibaGeek/ctfr.git && cd ctfr/ && pip3 install -r requirements.txt;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"ctfr installation is done !"; echo "";
        #cero
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"cero installation in progress ...";
	go install github.com/glebarez/cero@latest > /dev/null 2>&1 && ln -s ~/go/bin/cero /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"cero installation is done !"; echo "";
	#AnalyticsRelationships
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"AnalyticsRelationships installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/Josue87/AnalyticsRelationships.git  > /dev/null 2>&1 && cd AnalyticsRelationships && go build -ldflags "-s -w" && cp -r analyticsrelationships /usr/local/bin; 
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"AnalyticsRelationships installation is done !"; echo "";
	#Galer
	echo -e ${BLUE}"[DNS RESOLVER]" ${RED}"Galer installation in progress ...";
	GO111MODULE=on go install -v github.com/dwisiswant0/galer@latest > /dev/null 2>&1 && ln -s ~/go/bin/galer /usr/local/bin/;
	echo -e ${BLUE}"[DNS RESOLVER]" ${GREEN}"Galer installation is done !"; echo "";
        #Haktrails
	echo -e ${BLUE}"[DNS RESOLVER]" ${RED}"Haktrails installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && GO111MODULE=on go install -v github.com/hakluke/haktrails@latest > /dev/null 2>&1 && ln -s ~/go/bin/haktrails /usr/local/bin/';
	sudo -u "$USER_NAME" mkdir -p "/home/$USER_NAME/.config/haktools" && sudo -u "$USER_NAME" touch "/home/$USER_NAME/.config/haktools/haktrails-config.yml";
	echo -e ${BLUE}"[DNS RESOLVER]" ${GREEN}"Haktrails installation is done !"; echo "";
        #knockpy
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"knockpy installation in progress ...";
        cd "$TOOLS_DIR/file" && wget https://github.com/guelfoweb/knock/archive/refs/tags/5.4.0.zip && unzip 5.4.0.zip && cd knock-5.4.0 && python3 setup.py install && knockpy --set apikey-virustotal=fbbb048214f36feb32fcf7e8aa262c26b2dfe5051d02de7d85da6b3acbbed778;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"knockpy installation is done !"; echo "";
        #censys
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Censys installation in progress ...";
	cd "$TOOLS_DIR" && export CENSYS_API_ID=303b2554-31b0-4e2d-a036-c869f23bfb76 && export CENSYS_API_SECRET=sB8T2K8en7LW6GHOkKPOfEDVpdmaDj6t && git clone https://github.com/christophetd/censys-subdomain-finder.git > /dev/null 2>&1 && cd censys-subdomain-finder && apt install python3.8-venv -y && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt; 
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Censys installation is done !"; echo ""
        #quickcert
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"quickcert installation in progress ...";
        GO111MODULE=on go install -v github.com/c3l3si4n/quickcert@HEAD > /dev/null 2>&1 && ln -s ~/go/bin/quickcert /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"quickcert installation is done !"; echo ""
}

        #Waymore
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"Waymore installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/xnl-h4ck3r/waymore.git /opt/waymore || git -C /opt/waymore pull && pip3 install -r /opt/waymore/requirements.txt && ln -s /opt/waymore/waymore.py /usr/local/bin/waymore && chmod +x /usr/local/bin/waymore > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"Waymore installation is done !"; echo "";
        #Parameters
	echo -e ${BLUE}"[WEB CRAWLING]" ${RED}"Parameters installation in progress ...";
	go install github.com/mrco24/parameters@latest > /dev/null 2>&1 && ln -s ~/go/bin/parameters /usr/local/bin/;
	echo -e ${BLUE}"[WEB CRAWLING]" ${GREEN}"Parameters installation is done !"; echo "";
    #xnLinkFinder
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"xnLinkFinder installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git && cd xnLinkFinder && python setup.py install > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"xnLinkFinder installation is done !"; echo "";
	#Nikto
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"Nikto installation in progress ...";
	apt-get install -y nikto > /dev/null 2>&1;
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"Nikto installation is done !"; echo "";
    #Xray
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"Xray installation in progress ...";
	cd "$TOOLS_DIR" && mkdir xray && cd xray && wget https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip && unzip xray_linux_amd64.zip && mv xray_linux_amd64 xray && wget https://github.com/mrco24/xray-config/raw/main/n.zip && unzip n.zip && cd n && cp -r *.yaml "$TOOLS_DIR/xray";
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"Xray installation is done !"; echo "";
    #Afrog
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"Afrog installation in progress ...";
	go install -v github.com/zan8in/afrog/v2/cmd/afrog@latest > /dev/null 2>&1 && ln -s ~/go/bin/afrog /usr/local/bin/;
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"Afrog installation is done !"; echo "";
    #POC-bomber
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"POC-bomber installation in progress ..."; 
        cd "$TOOLS_DIR" && git clone https://github.com/tr0uble-mAker/POC-bomber.git && cd POC-bomber && pip install -r requirements.txt;
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"POC-bomber installation is done !"; echo "";
	#x8
	echo -e ${BLUE}"[HTTP PARAMETER DISCOVERY]" ${RED}"x8 installation in progress ...";
	cd "$TOOLS_DIR" && wget https://github.com/mrco24/x8/raw/main/x8 && chmod +x x8 && mv x8 /usr/local/bin/x8;
	echo -e ${BLUE}"[HTTP PARAMETER DISCOVERY]" ${GREEN}"x8 installation is done !"; echo "";
        #openredirect
	echo -e ${BLUE}"[Open Redirect]" ${RED}"Open Redirect installation in progress ...";
	go install github.com/mrco24/open-redirect@latest > /dev/null 2>&1 && ln -s ~/go/bin/open-redirect /usr/local/bin/;
	echo -e ${BLUE}"[Open Redirect]" ${GREEN}"Open Redirect installation is done !"; echo "";
    	#Gopherus
	echo -e ${BLUE}"[SSRF TOOLS]" ${RED}"Gopherus installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/tarunkant/Gopherus.git > /dev/null 2>&1 && cd Gopherus && chmod +x install.sh && ./install.sh > /dev/null 2>&1;
	echo -e ${BLUE}"[SSRF TOOLS]" ${GREEN}"Gopherus installation is done !"; echo "";
    	#Request-Smuggling
	echo -e ${BLUE}"[SSTI TOOLS]" ${RED}"Http-Request-Smuggling installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/anshumanpattnaik/http-request-smuggling.git > /dev/null 2>&1 && cd http-request-smuggling && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[SSTI TOOLS]" ${GREEN}"Http-Request-Smuggling installation is done !"; echo "";
    	#Kiterunner
	echo -e ${BLUE}"[API TOOLS]" ${RED}"Kiterunner installation in progress ...";
	cd "$TOOLS_DIR/file" && wget https://github.com/assetnote/kiterunner/releases/download/v"$KITERUNNERVER"/kiterunner_"$KITERUNNERVER"_linux_amd64.tar.gz > /dev/null 2>&1 && tar xvf kiterunner_"$KITERUNNERVER"_linux_amd64.tar.gz > /dev/null 2>&1 && mv kr /usr/local/bin;
	cd "$TOOLS_DIR" && mkdir -p kiterunner-wordlists && cd kiterunner-wordlists && wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz > /dev/null 2>&1 && wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz > /dev/null 2>&1 && for f in *.tar.gz; do tar xf "$f"; rm -Rf "$f"; done
	echo -e ${BLUE}"[API TOOLS]" ${GREEN}"Kiterunner installation is done !"; echo "";
            #Cookieless
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${RED}"Cookieless installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && GO111MODULE=on go install -v github.com/RealLinkers/cookieless@latest > /dev/null 2>&1 && ln -s ~/go/bin/cookieless /usr/local/bin/';
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${GREEN}"Cookieless installation is done !"; echo "";
    	#Gxssgo
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${RED}"Gxss installation in progress ...";
	go install github.com/KathanP19/Gxss@latest > /dev/null 2>&1 && ln -s ~/go/bin/Gxss /usr/local/bin/; 
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${GREEN}"Gxss installation is done !"; echo "";
	#Findom-xss
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${RED}"findom-xss installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/dwisiswant0/findom-xss.git > /dev/null 2>&1 && cd findom-xss && chmod +x findom-xss.sh && rm -r LinkFinder && git clone https://github.com/GerbenJavado/LinkFinder.git > /dev/null 2>&1;
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${GREEN}"findom-xss installation is done !"; echo "";
        #Knoxnl
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${RED}"Knoxnl installation in progress ...";
	pip install git+https://github.com/xnl-h4ck3r/knoxnl.git;
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${GREEN}"Knoxnl installation is done !"; echo "";
        #Bxss
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${RED}"Bxss installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/ethicalhackingplayground/bxss@latest > /dev/null 2>&1 && ln -s ~/go/bin/bxss /usr/local/bin/';
	echo -e ${BLUE}"[VULNERABILITY - XSS]" ${GREEN}"Bxss installation is done !"; echo "";
    	#ghauri
	echo -e ${BLUE}"[VULNERABILITY - SQL Injection]" ${RED}"NoSQLMap installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/r0oth3x49/ghauri.git > /dev/null 2>&1 && cd ghauri && python3 -m pip install --upgrade -r requirements.txt && python3 -m pip install -e . > /dev/null 2>&1;
	echo -e ${BLUE}"[VULNERABILITY - SQL Injection]" ${GREEN}"NoSQLMap installation is done !"; echo "";
    	#time-sql
	echo -e ${BLUE}"[VULNERABILITY - SQL]" ${RED}"time-sql installation in progress ...";
	go install github.com/mrco24/time-sql@latest > /dev/null 2>&1 && ln -s ~/go/bin/time-sql /usr/local/bin/; 
	echo -e ${BLUE}"[VULNERABILITY - SQL]" ${GREEN}"time-sql installation is done !"; echo "";
        #mrco24-error-sql
	echo -e ${BLUE}"[VULNERABILITY - SQL]" ${RED}"error-sql installation in progress ...";
	go install github.com/mrco24/mrco24-error-sql@latest > /dev/null 2>&1 && ln -s ~/go/bin/mrco24-error-sql /usr/local/bin/; 
	echo -e ${BLUE}"[VULNERABILITY - SQL]" ${GREEN}"error-sql installation is done !"; echo "";
        #Nrich
	echo -e ${BLUE}"[CMS SCANNER]" ${RED}"Nrich installation in progress ...";
	wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb && dpkg -i nrich_latest_amd64.deb > /dev/null 2>&1;
	echo -e ${BLUE}"[CMS SCANNER]" ${GREEN}"Nrich installation is done !"; echo "";
	#AEM-Hacking
	echo -e ${BLUE}"[CMS SCANNER]" ${RED}"AEM-Hacking installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/0ang3el/aem-hacker.git > /dev/null 2>&1 && cd aem-hacker && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[CMS SCANNER]" ${GREEN}"AEM-Hacking installation is done !"; echo "";
 	#WhatWaf
	echo -e ${BLUE}"[CMS SCANNER]" ${RED}"WhatWaf installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/Ekultek/WhatWaf.git > /dev/null 2>&1 && cd WhatWaf && cp -r whatwaf /usr/local/bin;
	echo -e ${BLUE}"[CMS SCANNER]" ${GREEN}"WhatWaf installation is done !"; echo "";
    	#subjs
	echo -e ${BLUE}"[JS FILES HUNTING]" ${RED}"subjs installation in progress ...";
	wget https://github.com/lc/subjs/releases/download/v1.0.1/subjs_1.0.1_linux_amd64.tar.gz && tar xvf subjs_1.0.1_linux_amd64.tar.gz && mv subjs /usr/bin/subjs;
	echo -e ${BLUE}"[JS FILES HUNTING]" ${GREEN}"subjs installation is done !"; echo "";
	#Getjs
	echo -e ${BLUE}"[JS FILES HUNTING]" ${RED}"Getjs installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/003random/getJS@latest > /dev/null 2>&1 && ln -s ~/go/bin/getJS /usr/local/bin/';
	echo -e ${BLUE}"[JS FILES HUNTING]" ${GREEN}"Getjs installation is done !"; echo "";
	#jsscanner
	echo -e ${BLUE}"[JS FILES HUNTING]" ${RED}"Jsscanner installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/dark-warlord14/JSScanner > /dev/null 2>&1 && cd JSScanner/ && bash install.sh > /dev/null 2>&1;
	echo -e ${BLUE}"[JS FILES HUNTING]" ${GREEN}"Jsscanner installation is done !"; echo "";
    	#GitDorker
	echo -e ${BLUE}"[GIT HUNTING]" ${RED}"GitDorker installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/obheda12/GitDorker.git > /dev/null 2>&1 && cd GitDorker && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[GIT HUNTING]" ${GREEN}"GitDorker installation is done !"; echo "";
	#gitGraber
	echo -e ${BLUE}"[GIT HUNTING]" ${RED}"gitGraber installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/hisxo/gitGraber.git > /dev/null 2>&1 && cd gitGraber && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[GIT HUNTING]" ${GREEN}"gitGraber installation is done !"; echo "";
	#GitHacker
	echo -e ${BLUE}"[GIT HUNTING]" ${RED}"GitHacker installation in progress ...";
	pip3 install GitHacker > /dev/null 2>&1;
	echo -e ${BLUE}"[GIT HUNTING]" ${GREEN}"GitHacker installation is done !"; echo "";
	#GitTools
	echo -e ${BLUE}"[GIT HUNTING]" ${RED}"GitTools installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/internetwache/GitTools.git > /dev/null 2>&1;
	echo -e ${BLUE}"[GIT HUNTING]" ${GREEN}"GitTools installation is done !"; echo "";
    	#DumpsterDiver
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"DumpsterDiver installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/securing/DumpsterDiver.git > /dev/null 2>&1 && cd DumpsterDiver && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"DumpsterDiver installation is done !"; echo "";
	#EarlyBird
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"EarlyBird installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/americanexpress/earlybird.git > /dev/null 2>&1 && cd earlybird && ./build.sh > /dev/null 2>&1 && ./install.sh > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"EarlyBird installation is done !"; echo "";
	#Ripgrep
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"Ripgrep installation in progress ...";
	apt-get install -y ripgrep > /dev/null 2>&1
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"Ripgrep installation is done !"; echo "";
	#Gau-Expose
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"Gau-Expose installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/tamimhasan404/Gau-Expose.git > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"Gau-Expose installation is done !"; echo "";
        #Mantra
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"Mantra installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/MrEmpy/mantra@latest > /dev/null 2>&1 && cp -r ~/go/bin/mantra /usr/local/bin';
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"Mantra installation is done !"; echo "";
    #wappalyzer-cli
echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"wappalyzer-cli installation in progress ...";
cd "$TOOLS_DIR" && git clone https://github.com/gokulapap/wappalyzer-cli  > /dev/null 2>&1 && cd wappalyzer-cli && pip3 install . > /dev/null 2>&1;
echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"wappalyzer-cli installation is done !"; echo "";
        #Oralyzer
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Oralyzer installation in progress ...";
	cd "$TOOLS_DIR" &&  git clone https://github.com/r0075h3ll/Oralyzer.git && cd Oralyzer && pip3 install -r requirements.txt;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Oralyzer installation is done !"; echo "";
        #Cf-hero
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Cf-hero installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/musana/cf-hero/cmd/cf-hero@latest > /dev/null 2>&1 && ln -s ~/go/bin/cf-hero /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Cf-hero installation is done !"; echo "";
        #Notify
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Notify installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/notify/cmd/notify@latest > /dev/null 2>&1 && ln -s ~/go/bin/notify /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Notify installation is done !"; echo "";
        #tok
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"tok installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/mrco24/tok@latest > /dev/null 2>&1 && ln -s ~/go/bin/tok /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"tok installation is done !"; echo "";
	#installallurls
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Gau installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && GO111MODULE=on go install -v github.com/lc/gau@latest > /dev/null 2>&1 && ln -s ~/go/bin/gau /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Gau installation is done !"; echo "";
	#anti-burl
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"anti-burl installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/tomnomnom/hacks/anti-burl@latest > /dev/null 2>&1 && ln -s ~/go/bin/anti-burl /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"anti-burl installation is done !"; echo "";
    	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Fff installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/tomnomnom/fff@latest > /dev/null 2>&1 && ln -s ~/go/bin/fff /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Fff installation is done !"; echo "";
    	#gron
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"gron installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/tomnomnom/gron@latest > /dev/null 2>&1 && ln -s ~/go/bin/gron /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"gron installation is done !"; echo "";
    	#qsreplace
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"qsreplace installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/tomnomnom/qsreplace@latest > /dev/null 2>&1 && ln -s ~/go/bin/qsreplace /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"qsreplace installation is done !"; echo "";
	#Interlace
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Interlace installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/codingo/Interlace.git > /dev/null 2>&1 && cd Interlace && python3 setup.py install > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Interlace installation is done !"; echo "";
	#Jq
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"jq installation in progress ...";
	apt-get install -y jq > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"jq installation is done !"; echo "";
	#cf_check
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"cf-check installation in progress ...";
	sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install github.com/dwisiswant0/cf-check@latest > /dev/null 2>&1 && ln -s ~/go/bin/cf-check /usr/local/bin/';
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"cf-check installation is done !"; echo "";
	#Tmux
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Tmux installation in progress ...";
	apt-get install tmux -y > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Tmux installation is done !"; echo "";
	#Uro
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Uro installation in progress ...";
	pip3 install uro > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Uro installation is done !"; echo "";
    #SploitScan
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"SploitScan installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/xaitax/SploitScan.git > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"SploitScan installation is done !"; echo "";
    #Nuclei-Clone
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"Nuclei-Clone installation in progress ...";
	cd "$TOOLS_DIR" && git clone https://github.com/mrco24/nuclei-templates-clone.git && cd nuclei-templates-clone && chmod +x c.sh;
    cd
	"$TOOLS_DIR/nuclei-templates-clone/./c.sh" -f repo.txt
	"$TOOLS_DIR/nuclei-templates-clone/./c.sh" -d
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"Nuclei-Clone installation is done !"; echo "";
    }
    # HTTP tools
    log_info "Installing HTTP tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/katana/cmd/katana@latest'
    
    # Web crawling
    log_info "Installing web crawling tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/hakluke/hakrawler@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/tomnomnom/waybackurls@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/lc/gau/v2/cmd/gau@latest'
    
    # Fuzzing tools
    log_info "Installing fuzzing tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/ffuf/ffuf/v2@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/OJ/gobuster/v3@latest'
    wget -q https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz -O /tmp/feroxbuster.tar.gz
    tar -xzf /tmp/feroxbuster.tar.gz -C /tmp/
    mv /tmp/feroxbuster /usr/local/bin/
    chmod +x /usr/local/bin/feroxbuster
    
    # DNS tools
    log_info "Installing DNS tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/d3mondev/puredns/v2@latest'
    
    # Network tools
    log_info "Installing network tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'
    cd "$TOOLS_DIR"
    git clone https://github.com/robertdavidgraham/masscan
    cd masscan && make && make install
    
    # Vulnerability scanners
    log_info "Installing vulnerability scanners..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/hahwul/dalfox/v2@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/KathanP19/Gxss@latest'
    apt-get install -y sqlmap
    
    # XSS tools
    log_info "Installing XSS tools..."
    cd "$TOOLS_DIR"
    git clone https://github.com/s0md3v/XSStrike
    cd XSStrike && pip3 install -r requirements.txt
    ln -sf "$(pwd)/xsstrike.py" /usr/local/bin/xsstrike
    
    # Utility tools
    log_info "Installing utility tools..."
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/tomnomnom/gf@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/tomnomnom/unfurl@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/tomnomnom/anew@latest'
    sudo -u "$USER_NAME" bash -c 'source /etc/profile.d/golang.sh && go install -v github.com/tomnomnom/qsreplace@latest'
    
    # Install additional Python tools
    pip3 install arjun dirsearch requests beautifulsoup4 lxml selenium pyOpenSSL
    
    log_success "Bug bounty tools installed"
}

# Install wordlists
install_wordlists() {
    log_info "Installing wordlists..."
    cd "$WORDLISTS_DIR"
    
    git clone https://github.com/danielmiessler/SecLists.git
    git clone https://github.com/fuzzdb-project/fuzzdb.git
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
    
    wget -q https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O all-subdomains.txt
    wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O best-dns-wordlist.txt
    
    chown -R "$USER_NAME:$USER_NAME" "$WORDLISTS_DIR"
    log_success "Wordlists installed"
}

# Install Metasploit
install_metasploit() {
    if [ "$INSTALL_METASPLOIT" = "yes" ]; then
        log_info "Installing Metasploit Framework..."
        apt-get install -y postgresql postgresql-contrib
        systemctl start postgresql
        systemctl enable postgresql
        
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod 755 /tmp/msfinstall
        /tmp/msfinstall
        
        sudo -u postgres createuser -DdR msf
        sudo -u postgres createdb -O msf msf
        
        sudo -u "$USER_NAME" bash -c 'echo "production:" > ~/.msf4/database.yml'
        sudo -u "$USER_NAME" bash -c 'echo "  adapter: postgresql" >> ~/.msf4/database.yml'
        sudo -u "$USER_NAME" bash -c 'echo "  database: msf" >> ~/.msf4/database.yml'
        sudo -u "$USER_NAME" bash -c 'echo "  username: msf" >> ~/.msf4/database.yml'
        sudo -u "$USER_NAME" bash -c 'echo "  password:" >> ~/.msf4/database.yml'
        sudo -u "$USER_NAME" bash -c 'echo "  host: 127.0.0.1" >> ~/.msf4/database.yml'
        sudo -u "$USER_NAME" bash -c 'echo "  port: 5432" >> ~/.msf4/database.yml'
        
        log_success "Metasploit Framework installed"
    fi
}

# Setup dotfiles
setup_dotfiles() {
    if [ -n "$DOTFILES_REPO" ]; then
        log_info "Setting up dotfiles..."
        sudo -u "$USER_NAME" git clone "$DOTFILES_REPO" "/home/$USER_NAME/dotfiles"
        
        # Install Zsh and Oh My Zsh
        apt-get install -y zsh
        sudo -u "$USER_NAME" bash -c 'sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended'
        
        # Install Zsh plugins
        sudo -u "$USER_NAME" git clone https://github.com/zsh-users/zsh-syntax-highlighting.git "/home/$USER_NAME/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting"
        sudo -u "$USER_NAME" git clone https://github.com/zsh-users/zsh-autosuggestions "/home/$USER_NAME/.oh-my-zsh/custom/plugins/zsh-autosuggestions"
        
        # Install dotfiles
        if [ -f "/home/$USER_NAME/dotfiles/install.sh" ]; then
            sudo -u "$USER_NAME" bash -c 'cd ~/dotfiles && ./install.sh'
        else
            sudo -u "$USER_NAME" cp -r "/home/$USER_NAME/dotfiles/." "/home/$USER_NAME/"
        fi
        
        # Set Zsh as default shell
        chsh -s /usr/bin/zsh "$USER_NAME"
        
        log_success "Dotfiles installed"
    fi
}

# Create configuration files
create_configs() {
    log_info "Creating configuration files..."
    
    # Create .zshrc with pentest aliases
    cat << 'EOF' > "/home/$USER_NAME/.zshrc_pentest"
# Pentest-specific configuration
export PATH=$PATH:/usr/local/go/bin:/opt/go/bin
export GOPATH=/opt/go
export WORDLISTS=/opt/wordlists
export TOOLS_DIR=/opt/tools

# Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'

# Tool aliases
alias subfinder-enum='subfinder -silent'
alias amass-enum='amass enum -passive'
alias httpx-probe='httpx -silent -title -tech-detect -status-code'
alias nuclei-scan='nuclei -severity critical,high,medium'
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias gobuster-dir='gobuster dir -w /opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u'
alias ffuf-dir='ffuf -w /opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u'

# Functions
recon() {
    if [ -z "$1" ]; then
        echo "Usage: recon <domain>"
        return 1
    fi
    local domain="$1"
    local output_dir="recon_${domain}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    cd "$output_dir"
    echo "[*] Starting reconnaissance for $domain"
    subfinder -d "$domain" -silent > subdomains_subfinder.txt
    assetfinder --subs-only "$domain" > subdomains_assetfinder.txt
    amass enum -passive -d "$domain" > subdomains_amass.txt
    cat subdomains_*.txt | sort -u > all_subdomains.txt
    cat all_subdomains.txt | httpx -silent -title -tech-detect -status-code > live_hosts.txt
    echo "[*] Reconnaissance completed"
}
EOF

    # Append to existing .zshrc
    echo "source ~/.zshrc_pentest" >> "/home/$USER_NAME/.zshrc"
    
    # Create tmux config
    cat << 'EOF' > "/home/$USER_NAME/.tmux.conf"
set -g prefix C-a
unbind C-b
bind-key C-a send-prefix
bind | split-window -h
bind - split-window -v
bind -r j resize-pane -D 5
bind -r k resize-pane -U 5
bind -r l resize-pane -R 5
bind -r h resize-pane -L 5
bind -r m resize-pane -Z
set -g mouse on
set-window-option -g mode-keys vi
bind-key -T copy-mode-vi 'v' send -X begin-selection
bind-key -T copy-mode-vi 'y' send -X copy-selection
set -g status-bg colour235
set -g status-fg colour136
set -g status-left '#[fg=colour166]#S #[fg=colour39]» '
set -g status-right '#[fg=colour166]%d/%m #[fg=colour136]%H:%M:%S'
set -g base-index 1
set -g pane-base-index 1
set-window-option -g pane-base-index 1
set-option -g renumber-windows on
EOF

    chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.zshrc" "/home/$USER_NAME/.tmux.conf"
    log_success "Configuration files created"
}

# Create automation scripts
create_scripts() {
    log_info "Creating automation scripts..."
    
    # Auto-recon script
    cat << 'EOF' > "/home/$USER_NAME/scripts/auto-recon.sh"
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "[*] Starting reconnaissance for $DOMAIN"
echo "[*] Output directory: $OUTPUT_DIR"

subfinder -d "$DOMAIN" -silent > subdomains_subfinder.txt
assetfinder --subs-only "$DOMAIN" > subdomains_assetfinder.txt
amass enum -passive -d "$DOMAIN" > subdomains_amass.txt
cat subdomains_*.txt | sort -u > all_subdomains.txt
cat all_subdomains.txt | httpx -silent -title -tech-detect -status-code > live_hosts.txt
cat live_hosts.txt | cut -d' ' -f1 | naabu -top-ports 1000 -silent > open_ports.txt
cat live_hosts.txt | cut -d' ' -f1 | hakrawler -plain 2>/dev/null | sort -u > crawled_urls.txt
cat live_hosts.txt | cut -d' ' -f1 | waybackurls 2>/dev/null | sort -u > wayback_urls.txt
cat crawled_urls.txt wayback_urls.txt | sort -u > all_urls.txt

echo "[*] Reconnaissance completed"
EOF

    chmod +x "/home/$USER_NAME/scripts/auto-recon.sh"
    ln -sf "/home/$USER_NAME/scripts/auto-recon.sh" /usr/local/bin/auto-recon
    
    # Tool update script
    cat << 'EOF' > "/home/$USER_NAME/scripts/update-tools.sh"
#!/bin/bash

echo "[*] Updating tools..."
nuclei -update-templates
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
cd /opt/wordlists/SecLists && git pull
echo "[*] Tools updated"
EOF

    chmod +x "/home/$USER_NAME/scripts/update-tools.sh"
    ln -sf "/home/$USER_NAME/scripts/update-tools.sh" /usr/local/bin/update-tools
    
    chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME/scripts"
    log_success "Automation scripts created"
}

# Setup 2FA
setup_2fa() {
    if [ "$ENABLE_2FA" = "yes" ]; then
        log_info "Setting up 2FA..."
        apt-get install -y libpam-google-authenticator
        echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
        sed -i 's/^ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^AuthenticationMethods publickey/AuthenticationMethods publickey,keyboard-interactive/' /etc/ssh/sshd_config
        sudo -u "$USER_NAME" google-authenticator -t -d -f -r 3 -R 30 -W -Q UTF8
        systemctl restart sshd
        log_success "2FA configured"
    fi
}

# Create installation summary
create_summary() {
    log_info "Creating installation summary..."
    
    cat << EOF > "/home/$USER_NAME/INSTALLATION_SUMMARY.txt"
╔══════════════════════════════════════════════════════════════╗
║                 VPS SETUP SUMMARY                            ║
╚══════════════════════════════════════════════════════════════╝

Installation Date: $(date)
Username: $USER_NAME
SSH Port: $SSH_PORT
2FA Enabled: $(if [ "$ENABLE_2FA" = "yes" ]; then echo "Yes"; else echo "No"; fi)
Docker Installed: $(if [ "$INSTALL_DOCKER" = "yes" ]; then echo "Yes"; else echo "No"; fi)
Metasploit Installed: $(if [ "$INSTALL_METASPLOIT" = "yes" ]; then echo "Yes"; else echo "No"; fi)

DIRECTORIES:
- Tools: $TOOLS_DIR
- Wordlists: $WORDLISTS_DIR
- User Home: /home/$USER_NAME
- Scripts: /home/$USER_NAME/scripts

INSTALLED TOOLS:
Subdomain Enumeration:
- subfinder, assetfinder, amass, findomain, massdns, knock, lazyrecon
- github-subdomains, sublist3r, crtndstry, dnsx, dnsgen, subover
- chaos, shodan, gotator, ctfr, cero, analyticsrelationships
- galer, haktrails, knockpy, censys, quickcert

Vulnerability Scanners:
- nuclei, nikto, xray, afrog, poc-bomber, x8, open-redirect
- gopherus, request-smuggling, kiterunner

XSS Tools:
- cookieless, gxss, findom-xss, knoxnl, bxss

SQL Injection Tools:
- ghauri, time-sql, error-sql

CMS Scanners:
- nrich, aem-hacking, whatwaf

JavaScript Tools:
- subjs, getjs, jsscanner

Git Hunting:
- gitdorker, gitgraber, githacker, gittools

Sensitive Data Finding:
- waymore, parameters, xnlinkfinder, dumpsterdiver
- earlybird, ripgrep, gau-expose, mantra

Useful Tools:
- wappalyzer-cli, oralyzer, cf-hero, notify, tok, gau
- anti-burl, fff, gron, qsreplace, interlace, jq
- cf-check, tmux, uro, sploitscan

HTTP Tools:
- httpx, katana, hakrawler, waybackurls, gau

Fuzzing Tools:
- ffuf, gobuster, feroxbuster

DNS Tools:
- dnsx, shuffledns, puredns

Network Tools:
- naabu, masscan

Utility Tools:
- gf, unfurl, anew, qsreplace

Wordlists:
- SecLists, fuzzdb, PayloadsAllTheThings
- all-subdomains.txt, best-dns-wordlist.txt

AUTOMATION SCRIPTS:
- auto-recon.sh: Automated reconnaissance workflow
- update-tools.sh: Update all installed tools

USEFUL COMMANDS:
- auto-recon <domain>: Start reconnaissance
- update-tools: Update all tools
- nuclei -update-templates: Update nuclei templates

SSH CONNECTION:
ssh -p $SSH_PORT $USER_NAME@your-server-ip

SECURITY NOTES:
- SSH is hardened and running on port $SSH_PORT
- UFW firewall is configured
- Fail2ban is active
- Root login is disabled
- Password authentication is disabled (key-based only)
$(if [ "$ENABLE_2FA" = "yes" ]; then echo "- 2FA is enabled for additional security"; fi)

EOF

    chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/INSTALLATION_SUMMARY.txt"
    log_success "Installation summary created"
}

# Final setup
final_setup() {
    log_info "Running final setup..."
    
    # Update all tools
    sudo -u "$USER_NAME" nuclei -update-templates
    
    # Clean up
    apt-get autoremove -y
    apt-get clean
    
    # Set permissions
    chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME"
    
    # Create summary
    create_summary
    
    log_success "Setup complete!"
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 SETUP COMPLETE!                              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo "║  Your bug bounty VPS is now ready.                           ║"
    echo "║                                                              ║"
    echo "║  Important details:                                          ║"
    echo "║  - SSH Port: $SSH_PORT                                      ║"
    echo "║  - User: $USER_NAME                                        ║"
    echo "║  - 2FA: $(if [ "$ENABLE_2FA" = "yes" ]; then echo "Enabled"; else echo "Disabled"; fi)"
    echo "║                                                              ║"
    echo "║  Next steps:                                                 ║"
    echo "║  1. SSH to the server using:                                 ║"
    echo "║     ssh -p $SSH_PORT $USER_NAME@your-server-ip              ║"
    echo "║  2. Run 'auto-recon <domain>' to start reconnaissance       ║"
    echo "║  3. Run 'update-tools' to keep tools updated                ║"
    echo "║  4. Check INSTALLATION_SUMMARY.txt for details              ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Main execution
display_banner
check_internet
get_user_input
system_update
create_user
harden_ssh
setup_firewall
install_security_tools
install_languages
install_docker
create_directories
install_bugbounty_tools
install_wordlists
install_metasploit
setup_dotfiles
create_configs
create_scripts
setup_2fa
final_setup