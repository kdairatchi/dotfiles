#!/usr/bin/env bash
# VPS Ultimate Interactive Menu — Harden, Deploy, and Operate with OpenRouter & Advanced Security
# Author: kdairatchi + assistant
# Version: 4.2 (2025-08-15)

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

# ========= CONFIGURATION =========
# --- Paths ---
ROOT_DIR="/opt/vps-ultimate"
AI_DIR="$ROOT_DIR/ai"
COMPOSE_DIR="$ROOT_DIR/compose"
BACKUP_DIR="$ROOT_DIR/backups"
MON_DIR="$ROOT_DIR/monitoring"
LOG_DIR="$ROOT_DIR/logs"
# --- Security ---
DEFAULT_SSH_PORT="2222"
# --- Behavior ---
USE_DEFAULTS=0 # Set to 1 to auto-accept defaults for non-interactive use

# ========= STYLING & LOGGING =========
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; B='\033[0;34m'; M='\033[0;35m'; N='\033[0m'
ok() { echo -e "${G}[✓]${N} $*"; }
info() { echo -e "${Y}[i]${N} $*"; }
warn() { echo -e "${M}[!]${N} $*"; }
die() { echo -e "${R}[✗]${N} $*" >&2; exit 1; }
prompt() {
    local prompt_text="$1"
    local var_name="$2"
    local default_value="${3:-}"
    local user_input
    if (( USE_DEFAULTS == 1 )); then
        eval "$var_name=\"$default_value\""
        info "$prompt_text: using default '$default_value'"
        return
    fi
    read -rp "$prompt_text [$default_value]: " user_input
    eval "$var_name=\"${user_input:-$default_value}\""
}
banner(){ cat <<'ASCII'
██╗   ██╗██████╗ ███████╗    ██╗   ██╗██████╗ ███████╗
██║   ██║██╔══██╗██╔════╝    ██║   ██║██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗      ██║   ██║██████╔╝█████╗  
╚██╗ ██╔╝██╔══██╗██╔══╝      ╚██╗ ██╔╝██╔══██╗██╔══╝  
 ╚████╔╝ ██║  ██║███████╗      ╚████╔╝ ██║  ██║███████╗
  ╚═══╝  ╚═╝  ╚═╝╚══════╝       ╚═══╝  ╚═╝  ╚═╝╚══════╝
VPS Ultimate Menu — Secure Deployment & AI Operations
ASCII
}

# ========= GLOBALS =========
OS_ID=""; OS_CODENAME=""
export DEBIAN_FRONTEND=noninteractive
trap 'echo -e "${R}Error on line $LINENO (exit code $?).${N}"' ERR

# ========= CORE UTILITIES =========
need_root(){ [[ $EUID -eq 0 ]] || die "This script must be run as root (or with sudo)."; }
detect_os(){
  [[ -f /etc/os-release ]] || die "Unsupported OS: /etc/os-release not found."
  . /etc/os-release
  OS_ID="$ID"; OS_CODENAME="${VERSION_CODENAME:-stable}"
  info "Detected ${PRETTY_NAME:-$OS_ID} (${OS_CODENAME})."
}
apt_install(){
    info "Installing packages: $*"
    if ! apt-get install -y "$@"; then
        warn "Initial install failed. Running update and retrying..."
        apt-get update -qq
        if ! apt-get install -y "$@"; then
            die "Failed to install packages: $*"
        fi
    fi
}
safe_reload(){
    info "Reloading service: $1"
    if ! systemctl reload "$1"; then
        warn "Reload failed for $1, attempting restart."
        if ! systemctl restart "$1"; then
            warn "Restart also failed for $1. Please check service status."
        fi
    fi
}
confirm() {
    local message="$1"
    local default_choice="${2:-n}"
    if (( USE_DEFAULTS == 1 )); then
        info "$message: auto-selecting 'yes'"
        return 0
    fi
    read -rp "$message [y/N]: " choice
    case "${choice,,}" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# ========= INITIAL SETUP =========
ensure_dirs(){
  info "Ensuring base directories exist under $ROOT_DIR"
  mkdir -p "$ROOT_DIR" "$COMPOSE_DIR" "$BACKUP_DIR" "$MON_DIR" "$LOG_DIR" "$AI_DIR"
  chmod 700 "$BACKUP_DIR"
  ok "Directories created."
}

ensure_base(){
  info "Ensuring base system packages are installed."
  apt_install ca-certificates curl gnupg lsb-release software-properties-common \
    ufw fail2ban unattended-upgrades htop chrony git jq nano unzip dnsutils \
    auditd aide libpam-google-authenticator openssl haveged net-tools bc \
    sysstat zram-tools psmisc lsof strace tmux zip rsync
  if systemctl list-units --type=service | grep -q 'chrony'; then
    systemctl enable --now chrony
  elif systemctl list-units --type=service | grep -q 'chronyd'; then
    systemctl enable --now chronyd
  fi
  ok "Base packages installed."
}

# ===== SECURITY HARDENING =====
sysctl_hardening(){
  info "Applying kernel hardening via sysctl."
  local conf_file="/etc/sysctl.d/99-vps-hardening.conf"
  cat >"$conf_file" <<'EOF'
# === Network Security ===
# Mitigate SYN flood attacks
net.ipv4.tcp_syncookies=1
# Enable reverse path filtering to prevent IP spoofing
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
# Disable source routing
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
# Ignore broadcast ICMP requests
net.ipv4.icmp_echo_ignore_broadcasts=1
# Disable TCP timestamps to reduce vulnerability to timing attacks
net.ipv4.tcp_timestamps=0

# === IPv6 Security ===
# Disable IPv6 if not in use
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1

# === Kernel Security ===
# Restrict access to kernel pointers
kernel.kptr_restrict=2
# Restrict access to dmesg
kernel.dmesg_restrict=1
# Protect against hardlink and symlink attacks
fs.protected_hardlinks=1
fs.protected_symlinks=1
# Disable unprivileged BPF
kernel.unprivileged_bpf_disabled=1
# Restrict ptrace to prevent process snooping
kernel.yama.ptrace_scope=2
# Control core dumps
fs.suid_dumpable=0
# Set a lower swappiness value
vm.swappiness=10
EOF
  if sysctl --system >/dev/null; then
    ok "Kernel parameters hardened."
  else
    warn "Failed to apply some sysctl settings."
  fi
}

create_admin_user(){
  info "Setting up a new administrative user."
  prompt "Enter new sudo username" ADMIN_USER ""
  [[ -z "$ADMIN_USER" ]] && { info "Skipped user creation."; return; }

  if id -u "$ADMIN_USER" >/dev/null 2>&1; then
    info "User '$ADMIN_USER' already exists."
  else
    adduser --disabled-password --gecos "" "$ADMIN_USER" || die "Failed to create user '$ADMIN_USER'."
    usermod -aG sudo "$ADMIN_USER" || warn "Couldn't add '$ADMIN_USER' to sudo group."
    ok "User '$ADMIN_USER' created and added to sudo group."
  fi

  local ssh_dir="/home/$ADMIN_USER/.ssh"
  local key_file="$ssh_dir/authorized_keys"
  mkdir -p "$ssh_dir" && chmod 700 "$ssh_dir"
  touch "$key_file" && chmod 600 "$key_file"
  chown -R "$ADMIN_USER:$ADMIN_USER" "$ssh_dir"

  if confirm "Add a public SSH key for '$ADMIN_USER'?" "y"; then
      read -rp "Paste public key: " PUB_KEY
      if [[ -n "$PUB_KEY" ]]; then
          echo "$PUB_KEY" >> "$key_file"
          ok "Public key added for $ADMIN_USER."
      else
          warn "No key provided."
      fi
  fi
}

ssh_hardening(){
  info "Hardening SSH server configuration."
  local CFG="/etc/ssh/sshd_config"
  [[ -f "$CFG" ]] || { warn "SSH config not found at $CFG"; return; }

  prompt "Enter new SSH port" SSH_PORT "$DEFAULT_SSH_PORT"
  cp -n "$CFG" "${CFG}.bak.$(date +%s)" # Backup if not already done

  # Use sed to update settings, making it idempotent
  sed -i -E "s/^#?Port .*/Port $SSH_PORT/" "$CFG"
  sed -i -E "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" "$CFG"
  sed -i -E "s/^#?PermitRootLogin .*/PermitRootLogin no/" "$CFG"
  sed -i -E "s/^#?X11Forwarding .*/X11Forwarding no/" "$CFG"
  sed -i -E "s/^#?MaxAuthTries .*/MaxAuthTries 3/" "$CFG"
  sed -i -E "s/^#?LoginGraceTime .*/LoginGraceTime 30/" "$CFG"
  sed -i -E "s/^#?AllowAgentForwarding .*/AllowAgentForwarding no/" "$CFG"
  sed -i -E "s/^#?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" "$CFG"

  # Add a security banner
  cat > /etc/issue.net <<'BANNER'
********************************************************************
* WARNING: Unauthorized access to this system is prohibited.       *
* All activities are monitored and logged.                         *
********************************************************************
BANNER
  grep -qF "Banner /etc/issue.net" "$CFG" || echo "Banner /etc/issue.net" >> "$CFG"

  safe_reload sshd
  ok "SSH hardened on port $SSH_PORT. Remember to allow it in the firewall."
  warn "Test new SSH connection in a separate terminal before disconnecting!"
}

# ===== NETWORK & MAINTENANCE =====
ufw_config(){
  info "Configuring UFW firewall."
  command -v ufw >/dev/null || apt_install ufw

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  local ssh_port
  ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}')
  prompt "Allow SSH on port" UFW_SSH_PORT "${ssh_port:-$DEFAULT_SSH_PORT}"
  ufw allow "${UFW_SSH_PORT}/tcp"
  ufw limit "${UFW_SSH_PORT}/tcp"
  ok "Firewall configured to allow SSH on port $UFW_SSH_PORT."

  if confirm "Allow HTTP/HTTPS (80/443)?" "y"; then
    ufw allow http/tcp
    ufw allow https/tcp
    ok "Allowed HTTP and HTTPS."
  fi

  ufw --force enable
  safe_reload ufw
  ok "UFW is now active. Current rules:"
  ufw status verbose | sed '/^Status:/d'
}

unattended_upgrades(){
  info "Setting up unattended security upgrades."
  apt_install unattended-upgrades
  dpkg-reconfigure -f noninteractive unattended-upgrades

  cat >/etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "
${distro_id}:${distro_codename}";
    "
${distro_id}:${distro_codename}-security";
    "
${distro_id}ESMApps:${distro_codename}";
    "
${distro_id}ESM:${distro_codename}";
};
Unattended-Upgrade::Package-Blacklist {
    "docker-ce";
    "docker-ce-cli";
    "containerd.io";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
EOF
  systemctl enable --now unattended-upgrades
  ok "Unattended upgrades configured for daily checks and reboots at 03:30 if needed."
}

# ===== DOCKER MANAGEMENT =====
install_docker(){
  info "Installing Docker Engine."
  if command -v docker >/dev/null; then
    ok "Docker is already installed."
    docker --version
    return
  fi

  apt-get remove -y docker docker-engine docker.io containerd runc || true
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS_ID $OS_CODENAME stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  mkdir -p /etc/docker
  cat >/etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "storage-driver": "overlay2",
  "ipv6": false,
  "userland-proxy": false
}
JSON
  systemctl enable --now docker
  ok "Docker Engine installed and configured."
}

# ===== WIREGUARD MANAGEMENT =====
WG_DIR="/etc/wireguard"
WG_IFACE="wg0"

wireguard_menu() {
    while true; do
        clear; banner
        echo -e "${B}=== WireGuard VPN Management ===${N}"
        if [[ -f "$WG_DIR/$WG_IFACE.conf" ]]; then
            echo "Status: ${G}INSTALLED${N}"
            echo " 1) Add New Client"
            echo " 2) List Clients"
            echo " 3) Uninstall WireGuard"
            echo " 4) Start/Stop/Restart Service"
            echo " 0) Back to Main Menu"
        else
            echo "Status: ${R}NOT INSTALLED${N}"
            echo " 1) Install WireGuard"
            echo " 0) Back to Main Menu"
        fi
        read -rp "Select an option: " choice

        if [[ -f "$WG_DIR/$WG_IFACE.conf" ]]; then
            case "$choice" in
                1) wg_add_client ;;
                2) wg_list_clients ;;
                3) wg_uninstall ;;
                4) wg_manage_service ;;
                0|q) break ;;
                *) warn "Invalid option" ;;
            esac
        else
            case "$choice" in
                1) wg_install ;;
                0|q) break ;;
                *) warn "Invalid option" ;;
            esac
        fi
        press_enter
    done
}

wg_install() {
    info "Installing WireGuard..."
    apt_install wireguard qrencode

    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"
    
    # Generate server keys
    local s_priv; s_priv=$(wg genkey)
    local s_pub; s_pub=$(echo "$s_priv" | wg pubkey)

    # Get public interface and IP
    local pub_iface; pub_iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    local pub_ip; pub_ip=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    
    prompt "Enter server public IP" SERVER_PUB_IP "$pub_ip"
    prompt "Enter WireGuard UDP port" WG_PORT "51820"

    # Create server config
    cat > "$WG_DIR/$WG_IFACE.conf" << EOF
[Interface]
Address = 10.10.10.1/24
ListenPort = $WG_PORT
PrivateKey = $s_priv
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $pub_iface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $pub_iface -j MASQUERADE
EOF

    # Enable IP forwarding
    sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
    sysctl -p
    
    systemctl enable --now "wg-quick@$WG_IFACE"
    ufw allow "$WG_PORT/udp"
    
    ok "WireGuard installed and started."
    info "Now, add a client to get a configuration file."
}

wg_add_client() {
    info "Adding a new WireGuard client."
    prompt "Enter client name (no spaces)" CLIENT_NAME "client1"

    local c_priv; c_priv=$(wg genkey)
    local c_pub; c_pub=$(echo "$c_priv" | wg pubkey)
    local c_psk; c_psk=$(wg genpsk)

    # Find next available IP
    local last_ip; last_ip=$(grep -E "AllowedIPs.*10\.10\.10\." "$WG_DIR/$WG_IFACE.conf" | sed -E 's/.*10\.10\.10\.([0-9]+)\/32.*/\1/' | sort -n | tail -1)
    local next_ip=$((last_ip + 1))
    
    # Add peer to server config
    cat >> "$WG_DIR/$WG_IFACE.conf" << EOF

[Peer]
# Client: $CLIENT_NAME
PublicKey = $c_pub
PresharedKey = $c_psk
AllowedIPs = 10.10.10.$next_ip/32
EOF

    # Get server info for client config
    local s_pub; s_pub=$(grep 'PrivateKey' "$WG_DIR/$WG_IFACE.conf" | awk '{print $3}' | wg pubkey)
    local s_endpoint; s_endpoint=$(grep 'ListenPort' "$WG_DIR/$WG_IFACE.conf" | awk '{print $3}')
    local pub_ip; pub_ip=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

    # Create client config file
    local client_conf_dir="$ROOT_DIR/wireguard_clients"
    mkdir -p "$client_conf_dir"
    cat > "$client_conf_dir/$CLIENT_NAME.conf" << EOF
[Interface]
PrivateKey = $c_priv
Address = 10.10.10.$next_ip/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $s_pub
PresharedKey = $c_psk
Endpoint = $pub_ip:$s_endpoint
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Restart WireGuard to apply changes
    systemctl restart "wg-quick@$WG_IFACE"
    
    ok "Client '$CLIENT_NAME' added."
    info "Config file: $client_conf_dir/$CLIENT_NAME.conf"
    echo -e "${Y}Scan this QR code with the WireGuard app:${N}"
    qrencode -t ansiutf8 < "$client_conf_dir/$CLIENT_NAME.conf"
}

wg_list_clients() {
    info "Listing configured WireGuard clients:"
    grep '# Client:' "$WG_DIR/$WG_IFACE.conf" | sed 's/# Client: / - /'
}

wg_uninstall() {
    if confirm "This will completely remove WireGuard and all configurations. Continue?" "n"; then
        systemctl stop "wg-quick@$WG_IFACE"
        systemctl disable "wg-quick@$WG_IFACE"
        local wg_port; wg_port=$(grep ListenPort "$WG_DIR/$WG_IFACE.conf" | awk '{print $3}')
        ufw delete allow "$wg_port/udp"
        rm -rf "$WG_DIR"
        apt-get purge -y wireguard
        ok "WireGuard has been uninstalled."
    else
        info "Uninstallation aborted."
    fi
}

wg_manage_service() {
    read -rp "Action [start/stop/restart]: " action
    case "$action" in
        start|stop|restart)
            systemctl "$action" "wg-quick@$WG_IFACE"
            ok "WireGuard service $action'ed."
            ;;
        *) warn "Invalid action." ;;
    esac
}



# ===== FULL SYSTEM HARDENING WORKFLOW =====
run_full_hardening() {
    info "Starting full system hardening process..."
    if ! confirm "This will apply major security changes. Continue?" "n"; then
        info "Hardening process aborted by user."
        return
    fi
    ensure_base
    sysctl_hardening
    create_admin_user
    ssh_hardening
    ufw_config
    unattended_upgrades
    ok "Full system hardening process completed."
    warn "A reboot is recommended to ensure all changes take effect."
    if confirm "Reboot now?" "n"; then
        info "Rebooting system in 10 seconds..."
        sleep 10
        reboot
    fi
}

# ===== MENU SYSTEM =====
show_status(){
  clear; banner
  echo -e "\n${B}=== System Status ===${N}"
  # Resources
  echo -e "\n${C}Resources:${N}"
  htop | head -n 10
  echo; free -h; echo
  df -hP / /var /home | grep -v tmpfs
  # Network
  echo -e "\n${C}Network & Services:${N}"
  ss -tuln
  echo; ufw status numbered
  # Docker
  if command -v docker &>/dev/null; then
    echo -e "\n${C}Docker Containers:${N}"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
  fi
}

main_menu(){
  while true; do
    clear; banner
    echo -e "${B}=== Main Menu ===${N}"
    echo " 1) ${G}Full System Hardening (Recommended First Step)${N}"
    echo " 2) Create Admin User"
    echo " 3) Harden SSH"
    echo " 4) Configure Firewall (UFW)"
    echo " 5) Install Docker"
    echo " 6) Manage WireGuard VPN"
    echo " 7) Show System Status"
    echo " 0) ${R}Exit${N}"
    echo
    read -rp "Select an option: " choice

    case "$choice" in
      1) run_full_hardening; press_enter ;;
      2) create_admin_user; press_enter ;;
      3) ssh_hardening; press_enter ;;
      4) ufw_config; press_enter ;;
      5) install_docker; press_enter ;;
      6) wireguard_menu; press_enter ;;
      7) show_status; press_enter ;;
      0|q) exit 0 ;;
      *) warn "Invalid option"; sleep 1 ;; 
    esac
  done
}

press_enter() {
    (( USE_DEFAULTS == 1 )) || read -rp $'/\nPress [Enter] to continue...'
}

# ===== MAIN EXECUTION =====
main() {
    need_root
    ensure_dirs
    detect_os

    if [[ $# -gt 0 ]]; then
        USE_DEFAULTS=1
        info "Non-interactive mode enabled with --defaults."
        case "$1" in
            --harden) run_full_hardening ;; 
            --install-docker) install_docker ;; 
            --create-user) create_admin_user ;; 
            --setup-ufw) ufw_config ;; 
            *) die "Unknown command: $1. Supported: --harden, --install-docker, --create-user, --setup-ufw" ;; 
        esac
        ok "Script finished in non-interactive mode."
    else
        main_menu
    fi
}

main "$@"