#!/usr/bin/env bash
# vps-sqry.sh - Shodan/VPS Reconnaissance Framework
# Version: 5.0.0 - Enhanced Edition
# Author: Kdairatchi
# ====================================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ========= CONFIGURATION =========
VERSION="6.0.0"
DEFAULT_OUTPUT_DIR="$HOME/sqry_out/runs/manual_$(date +%Y%m%d_%H%M%S)"
CREDENTIAL_LISTS_DIR="$HOME/sqry_out/wordlists"
DEFAULT_USERLIST="$CREDENTIAL_LISTS_DIR/users.txt"
DEFAULT_PASSLIST="$CREDENTIAL_LISTS_DIR/passwords.txt"
DEFAULT_PORTS="21,22,23,53,80,135,139,443,445,993,995,1723,3306,3389,5900,8080,8443,9000"
DEFAULT_THREADS=100
MAX_PARALLEL_JOBS=9000
CONNECTION_TIMEOUT=10
RETRY_COUNT=3
RATE_LIMIT=500

# ========= SECURITY CONFIGURATION =========
TOR_ENABLED=0
TOR_PROXY="127.0.0.1:9050"
SOCKS_PROXY="127.0.0.1:9050"
AUTHORIZED_NETWORKS_FILE="$HOME/.sqry_authorized_networks"
SECURE_LOG_FILE="$HOME/.sqry_secure.log"
PRIVATE_RANGES=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "127.0.0.0/8" "169.254.0.0/16")
RESTRICTED_RANGES=("0.0.0.0/8" "224.0.0.0/4" "240.0.0.0/4")
MAX_SCAN_RATE=100  # requests per second
REQUIRE_AUTHORIZATION=1
LOG_ALL_ACTIVITIES=1

# Global associative arrays for argument handling
declare -gA ARG_PARAMS
declare -gA ARG_FLAGS

# Security state tracking
declare -gA SECURITY_STATE
SECURITY_STATE["tor_verified"]=0
SECURITY_STATE["auth_verified"]=0
SECURITY_STATE["target_verified"]=0
SECURITY_STATE["logging_enabled"]=0

# ========= COLOR DEFINITIONS =========
N="\033[0m"      # Normal
R="\033[0;31m"   # Red
G="\033[0;32m"   # Green
Y="\033[1;33m"   # Yellow
B="\033[1;34m"   # Blue
P="\033[0;35m"   # Purple
C="\033[0;36m"   # Cyan
W="\033[1;37m"   # White
BR="\033[1;31m"  # Bright Red
BG="\033[1;32m"  # Bright Green
BY="\033[1;33m"  # Bright Yellow
BB="\033[1;34m"  # Bright Blue
BP="\033[1;35m"  # Bright Purple
BC="\033[1;36m"  # Bright Cyan

# ========= EMOJI DEFINITIONS =========
EMOJI_ROCKET="🚀"
EMOJI_TARGET="🎯"
EMOJI_SEARCH="🔍"
EMOJI_SHIELD="🛡️"
EMOJI_FIRE="🔥"
EMOJI_BOLT="⚡"
EMOJI_GEAR="⚙️"
EMOJI_CHART="📊"
EMOJI_SUCCESS="✅"
EMOJI_WARNING="⚠️"
EMOJI_ERROR="❌"
EMOJI_INFO="ℹ️"
EMOJI_HOURGLASS="⏳"
EMOJI_CHECKMARK="✓"
EMOJI_CROSSMARK="✗"

# ========= SECURE LOGGING FUNCTIONS =========
sanitize_log() {
    local message="$*"
    # Remove dangerous characters and potential injection attempts
    message="${message//[$'\n\r\t']/ }"
    message="${message//[\\\$\`]/_}"
    message="${message//[<>|&;]/_}"
    echo "$message"
}

secure_log() {
    local level="$1"
    shift
    local message="$(sanitize_log "$@")"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local source_ip="$(get_current_ip)"
    
    if (( LOG_ALL_ACTIVITIES )); then
        echo "[$timestamp] [$level] [IP:$source_ip] $message" >> "$SECURE_LOG_FILE"
    fi
}

info() { 
    echo -e "${BC}${EMOJI_INFO} [INFO]${N} $*"
    secure_log "INFO" "$@"
}
warn() { 
    echo -e "${BY}${EMOJI_WARNING} [WARN]${N} $*"
    secure_log "WARN" "$@"
}
error() { 
    echo -e "${BR}${EMOJI_ERROR} [ERROR]${N} $*"
    secure_log "ERROR" "$@"
}
die() { 
    error "$*"
    secure_log "FATAL" "$@"
    exit 1
}
ok() { 
    echo -e "${BG}${EMOJI_SUCCESS} [SUCCESS]${N} $*"
    secure_log "SUCCESS" "$@"
}
status() { 
    echo -e "${BB}${EMOJI_GEAR} [STATUS]${N} $*"
    secure_log "STATUS" "$@"
}
result() { 
    echo -e "${BP}${EMOJI_CHART} [RESULT]${N} $*"
    secure_log "RESULT" "$@"
}
scan() { 
    echo -e "${BC}${EMOJI_SEARCH} [SCAN]${N} $*"
    secure_log "SCAN" "$@"
}
target() { 
    echo -e "${BY}${EMOJI_TARGET} [TARGET]${N} $*"
    secure_log "TARGET" "$@"
}
security() {
    echo -e "${BR}${EMOJI_SHIELD} [SECURITY]${N} $*"
    secure_log "SECURITY" "$@"
}

# ========= SECURITY VALIDATION FUNCTIONS =========
get_current_ip() {
    local current_ip
    if (( TOR_ENABLED )); then
        current_ip=$(curl -s --socks5-hostname "$SOCKS_PROXY" https://icanhazip.com 2>/dev/null || echo "unknown")
    else
        current_ip=$(curl -s https://icanhazip.com 2>/dev/null || echo "unknown")
    fi
    echo "$current_ip"
}

verify_tor_connection() {
    local tor_test_ip
    security "Verifying Tor connection..."
    
    if ! command -v tor &>/dev/null; then
        error "Tor is not installed. Install with: sudo apt install tor"
        return 1
    fi
    
    if ! pgrep -x "tor" >/dev/null; then
        error "Tor service is not running. Start with: sudo systemctl start tor"
        return 1
    fi
    
    # Test SOCKS proxy connectivity
    if ! curl -s --socks5-hostname "$SOCKS_PROXY" --connect-timeout 10 https://check.torproject.org/api/ip 2>/dev/null | grep -q "true"; then
        error "Tor SOCKS proxy test failed on $SOCKS_PROXY"
        return 1
    fi
    
    tor_test_ip=$(curl -s --socks5-hostname "$SOCKS_PROXY" https://icanhazip.com 2>/dev/null)
    local regular_ip=$(curl -s https://icanhazip.com 2>/dev/null)
    
    if [[ "$tor_test_ip" == "$regular_ip" ]]; then
        error "Tor connection verification failed - same IP detected"
        return 1
    fi
    
    ok "Tor connection verified - Exit IP: $tor_test_ip"
    SECURITY_STATE["tor_verified"]=1
    return 0
}

validate_ip_address() {
    local ip="$1"
    local allow_private="${2:-0}"
    
    # Basic IP format validation
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # Validate octets
    local IFS='.'
    local octets=($ip)
    for octet in "${octets[@]}"; do
        if (( octet > 255 )); then
            return 1
        fi
    done
    
    # Check for restricted ranges
    for range in "${RESTRICTED_RANGES[@]}"; do
        if ip_in_range "$ip" "$range"; then
            warn "IP $ip is in restricted range $range"
            return 1
        fi
    done
    
    # Check for private ranges (unless explicitly allowed)
    if (( ! allow_private )); then
        for range in "${PRIVATE_RANGES[@]}"; do
            if ip_in_range "$ip" "$range"; then
                warn "IP $ip is in private range $range - requires explicit authorization"
                return 1
            fi
        done
    fi
    
    return 0
}

ip_in_range() {
    local ip="$1"
    local range="$2"
    
    if command -v python3 &>/dev/null; then
        python3 -c "
import ipaddress
try:
    network = ipaddress.ip_network('$range', strict=False)
    ip_addr = ipaddress.ip_address('$ip')
    exit(0 if ip_addr in network else 1)
except:
    exit(1)
" 2>/dev/null
    else
        # Basic subnet check for common ranges
        case "$range" in
            "10.0.0.0/8")     [[ "$ip" =~ ^10\. ]] ;;
            "172.16.0.0/12")  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] ;;
            "192.168.0.0/16") [[ "$ip" =~ ^192\.168\. ]] ;;
            "127.0.0.0/8")    [[ "$ip" =~ ^127\. ]] ;;
            *) return 1 ;;
        esac
    fi
}

validate_target_authorization() {
    local target="$1"
    
    if (( ! REQUIRE_AUTHORIZATION )); then
        warn "Authorization requirement is disabled - proceeding without validation"
        return 0
    fi
    
    if [[ ! -f "$AUTHORIZED_NETWORKS_FILE" ]]; then
        error "Authorized networks file not found: $AUTHORIZED_NETWORKS_FILE"
        error "Create this file with authorized IP ranges/domains (one per line)"
        return 1
    fi
    
    security "Checking target authorization for: $target"
    
    # Check if target is explicitly authorized
    if grep -Fxq "$target" "$AUTHORIZED_NETWORKS_FILE"; then
        ok "Target '$target' found in authorized networks"
        SECURITY_STATE["target_verified"]=1
        return 0
    fi
    
    # Check if target matches any authorized pattern
    while IFS= read -r authorized_pattern; do
        [[ -z "$authorized_pattern" || "$authorized_pattern" =~ ^# ]] && continue
        
        if [[ "$target" == *"$authorized_pattern"* ]]; then
            ok "Target '$target' matches authorized pattern: $authorized_pattern"
            SECURITY_STATE["target_verified"]=1
            return 0
        fi
    done < "$AUTHORIZED_NETWORKS_FILE"
    
    error "Target '$target' is not in authorized networks file"
    error "Add target to $AUTHORIZED_NETWORKS_FILE or disable authorization with --disable-auth"
    return 1
}

sanitize_input() {
    local input="$1"
    # Remove dangerous characters
    input="${input//[\\$\`|&;<>(){}[\]]/}"
    input="${input//[$'\n\r\t']/ }"
    # Limit length
    if (( ${#input} > 1000 )); then
        input="${input:0:1000}"
    fi
    echo "$input"
}

check_privilege_escalation() {
    local warnings=()
    
    security "Performing privilege escalation checks..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        warnings+=("Running as root - consider using a regular user account")
    fi
    
    # Check sudo access
    if sudo -n true 2>/dev/null; then
        warnings+=("Passwordless sudo access detected")
    fi
    
    # Check for suspicious environment variables
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        warnings+=("LD_PRELOAD is set - potential privilege escalation risk")
    fi
    
    # Check for writable system directories
    for dir in /usr/bin /usr/sbin /bin /sbin; do
        if [[ -w "$dir" ]]; then
            warnings+=("System directory $dir is writable - security risk")
        fi
    done
    
    if (( ${#warnings[@]} > 0 )); then
        warn "Security warnings detected:"
        for warning in "${warnings[@]}"; do
            warn "  - $warning"
        done
        
        if (( ${#warnings[@]} > 2 )); then
            error "Multiple security risks detected - aborting for safety"
            return 1
        fi
    fi
    
    return 0
}

verify_tool_integrity() {
    local required_tools=("curl" "ping" "host" "timeout" "nmap" "nc")
    local missing_tools=()
    local suspicious_tools=()
    
    security "Verifying tool integrity and availability..."
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        else
            # Check if tool is in expected location
            local tool_path=$(command -v "$tool")
            case "$tool" in
                "curl"|"ping"|"host"|"timeout")
                    if [[ ! "$tool_path" =~ ^/(usr/)?bin/ ]]; then
                        suspicious_tools+=("$tool at $tool_path")
                    fi
                    ;;
            esac
        fi
    done
    
    if (( ${#missing_tools[@]} > 0 )); then
        error "Missing required tools: ${missing_tools[*]}"
        error "Install missing tools and retry"
        return 1
    fi
    
    if (( ${#suspicious_tools[@]} > 0 )); then
        warn "Suspicious tool locations detected:"
        for tool in "${suspicious_tools[@]}"; do
            warn "  - $tool"
        done
    fi
    
    return 0
}

setup_tor_proxy() {
    if (( ! TOR_ENABLED )); then
        return 0
    fi
    
    security "Setting up Tor proxy configuration..."
    
    if ! verify_tor_connection; then
        error "Tor verification failed"
        return 1
    fi
    
    # Set proxy for curl commands
    export CURL_OPTS="--socks5-hostname $SOCKS_PROXY"
    
    ok "Tor proxy configured successfully"
    return 0
}

create_authorized_networks_template() {
    if [[ ! -f "$AUTHORIZED_NETWORKS_FILE" ]]; then
        info "Creating authorized networks template at $AUTHORIZED_NETWORKS_FILE"
        
        cat > "$AUTHORIZED_NETWORKS_FILE" <<EOF
# Authorized Networks Configuration for VPS-SQRY
# Add one network/domain per line that you have explicit permission to scan
# 
# Examples:
# example.com
# 192.168.1.0/24
# 10.0.0.0/8
# testdomain.net
#
# Remove this comment block and add your authorized targets below:

EOF
        warn "Please add authorized targets to $AUTHORIZED_NETWORKS_FILE before scanning"
        return 1
    fi
    return 0
}

# ========= PROGRESS AND ANIMATION FUNCTIONS =========
show_spinner() {
    local pid="$1"
    local message="$2"
    local spinstr='|/-\\'
    local i=0
    
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${BC}${spinstr:i++%${#spinstr}:1} ${message}${N}"
        sleep 0.1
    done
    printf "\r${BG}${EMOJI_SUCCESS} ${message} - Complete!${N}\n"
}

print_progress_bar() {
    local current="$1"
    local total="$2"
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${BC}[${N}"
    printf "%*s" "$filled" | tr ' ' '█'
    printf "%*s" "$empty" | tr ' ' '░'
    printf "${BC}] ${BY}%3d%%${N} ${BC}(%d/%d)${N}" "$percentage" "$current" "$total"
}

print_section_header() {
    local title="$1"
    local icon="$2"
    echo
    echo -e "${BP}═══════════════════════════════════════════════════════════════${N}"
    echo -e "${BG} ${icon} ${title}${N}"
    echo -e "${BP}═══════════════════════════════════════════════════════════════${N}"
}

print_subsection() {
    local title="$1"
    local icon="$2"
    echo
    echo -e "${BC}┌─ ${icon} ${title}${N}"
    echo -e "${BC}└────────────────────────────────────────────────────────────${N}"
}

show_live_stats() {
    local stats_file="$1"
    local refresh_rate="${2:-1}"
    
    while [[ -f "$stats_file" ]]; do
        if [[ -s "$stats_file" ]]; then
            clear
            echo -e "${BG}${EMOJI_CHART} LIVE SCAN STATISTICS ${EMOJI_CHART}${N}"
            echo -e "${BC}═══════════════════════════════════════════════════════════════${N}"
            cat "$stats_file"
            echo -e "${BC}═══════════════════════════════════════════════════════════════${N}"
            echo -e "${BY}${EMOJI_HOURGLASS} Refreshing every ${refresh_rate}s... Press Ctrl+C to stop monitoring${N}"
        fi
        sleep "$refresh_rate"
    done
}

update_stats() {
    local stats_file="$1"
    local operation="$2"
    local current="$3"
    local total="$4"
    local start_time="$5"
    
    local elapsed=$(($(date +%s) - start_time))
    local rate=$((current / (elapsed + 1)))
    local eta=$((total > current ? (total - current) / (rate + 1) : 0))
    
    {
        echo -e "${BC}Operation:${N} $operation"
        echo -e "${BC}Progress:${N} $current/$total ($(( current * 100 / total ))%)"
        echo -e "${BC}Elapsed:${N} ${elapsed}s"
        echo -e "${BC}Rate:${N} $rate/s"
        echo -e "${BC}ETA:${N} ${eta}s"
        echo -e "${BC}Timestamp:${N} $(date '+%H:%M:%S')"
    } > "$stats_file"
}

# ========= ASCII ART HEADER =========
print_banner() {
    clear
    echo -e "${BP}"
    echo -e "╔═══════════════════════════════════════════════════════════════╗"
    echo -e "║   ██╗   ██╗██████╗ ███████╗      ███████╗ ██████╗ ██████╗ ██╗   ║"
    echo -e "║   ██║   ██║██╔══██╗██╔════╝      ██╔════╝██╔═══██╗██╔══██╗╚██╗  ║"
    echo -e "║   ██║   ██║██████╔╝███████╗█████╗███████╗██║   ██║██████╔╝ ╚██╗ ║"
    echo -e "║   ╚██╗ ██╔╝██╔═══╝ ╚════██║╚════╝╚════██║██║▄▄ ██║██╔══██╗ ██╔╝ ║"
    echo -e "║    ╚████╔╝ ██║     ███████║      ███████║╚██████╔╝██║  ██║██╔╝  ║"
    echo -e "║     ╚═══╝  ╚═╝     ╚══════╝      ╚══════╝ ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝   ║"
    echo -e "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${N}"
    echo -e "${BG}${EMOJI_ROCKET} VPS Recon Framework v${VERSION} - Enhanced Edition ${EMOJI_ROCKET}${N}"
    echo -e "${BC}${EMOJI_BOLT} Intelligent Scanning + Advanced Detection + Beautiful Output ${EMOJI_BOLT}${N}"
    echo -e "${BY}${EMOJI_FIRE} Performance Optimized + Real-time Progress + Live Stats ${EMOJI_FIRE}${N}"
    echo -e "${BP}═══════════════════════════════════════════════════════════════${N}"
    echo
}

# ========= ENHANCED RESOURCE MONITORING =========
get_system_resources() {
    local cpus=$(nproc 2>/dev/null || echo 4)
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local mem_available=$(free -m | awk '/^Mem:/{print $7}')
    local mem_gb=$((mem_total / 1024))
    local fd_limit=$(ulimit -n 2>/dev/null || echo 1024)
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    
    # Create associative array for system info
    echo "cpus:$cpus mem_total:$mem_total mem_available:$mem_available mem_gb:$mem_gb fd_limit:$fd_limit load_avg:$load_avg"
}

calc_optimal_threads() {
    local verbose="${1:-0}"
    local sys_info=$(get_system_resources)
    
    # Parse system info
    local cpus=$(echo "$sys_info" | grep -o 'cpus:[0-9]*' | cut -d: -f2)
    local mem_gb=$(echo "$sys_info" | grep -o 'mem_gb:[0-9]*' | cut -d: -f2)
    local fd_limit=$(echo "$sys_info" | grep -o 'fd_limit:[0-9]*' | cut -d: -f2)
    local load_avg=$(echo "$sys_info" | grep -o 'load_avg:[0-9.]*' | cut -d: -f2)
    
    if (( verbose )); then
        print_subsection "System Resource Analysis" "${EMOJI_GEAR}"
        echo -e "  ${BC}${EMOJI_CHART} CPU cores: $cpus${N}"
        echo -e "  ${BC}${EMOJI_CHART} Memory: ${mem_gb}GB${N}"
        echo -e "  ${BC}${EMOJI_CHART} File descriptors: $fd_limit${N}"
        echo -e "  ${BC}${EMOJI_CHART} Load average: $load_avg${N}"
    fi
    
    # Enhanced calculation algorithm
    local base_multiplier=25
    local target=$((cpus * base_multiplier))
    
    # Memory-based scaling with better logic
    if (( mem_gb >= 32 )); then
        target=$((target * 3))  # High-memory systems
    elif (( mem_gb >= 16 )); then
        target=$((target * 2))  # Mid-range systems
    elif (( mem_gb >= 8 )); then
        target=$((target * 150 / 100))  # Standard systems
    else
        target=$((target * 75 / 100))   # Low-memory systems
    fi
    
    # Load average adjustment
    if command -v bc &>/dev/null && [[ -n "$load_avg" ]]; then
        local load_factor=$(echo "scale=2; if ($load_avg > $cpus) 0.5 else 1.0" | bc)
        target=$(echo "scale=0; $target * $load_factor" | bc | cut -d. -f1)
    fi
    
    # File descriptor limit (conservative 70%)
    local fd_cap=$((fd_limit * 70 / 100))
    
    # Apply safety caps
    if (( fd_cap < 100 )); then fd_cap=100; fi
    if (( target > fd_cap )); then target=$fd_cap; fi
    if (( target > MAX_PARALLEL_JOBS )); then target=$MAX_PARALLEL_JOBS; fi
    if (( target < 50 )); then target=50; fi
    
    if (( verbose )); then
        echo -e "  ${BG}${EMOJI_SUCCESS} Optimal threads calculated: $target${N}"
        echo -e "  ${BC}${EMOJI_INFO} Based on: CPU($cpus) × Memory(${mem_gb}GB) × Load($load_avg)${N}"
        echo -e "  ${BC}${EMOJI_INFO} FD limit constraint: $fd_cap/${fd_limit}${N}"
    fi
    
    echo $target
}

monitor_system_performance() {
    local monitor_file="$1"
    local interval="${2:-2}"
    local max_duration="${3:-300}"  # 5 minutes max
    
    local start_time=$(date +%s)
    
    while [[ -f "$monitor_file" ]]; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Stop monitoring after max duration
        if (( elapsed > max_duration )); then
            break
        fi
        
        # Collect system metrics
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
        local mem_usage=$(free | awk '/Mem:/ {printf "%.1f", $3/$2 * 100}')
        local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
        local active_jobs=$(jobs -r | wc -l 2>/dev/null || echo 0)
        
        {
            echo "=== SYSTEM PERFORMANCE MONITOR ==="
            echo "Timestamp: $(date '+%H:%M:%S')"
            echo "Elapsed: ${elapsed}s"
            echo "CPU Usage: ${cpu_usage}%"
            echo "Memory Usage: ${mem_usage}%"
            echo "Load Average: $load_avg"
            echo "Active Jobs: $active_jobs"
            echo "==================================="
        } > "${monitor_file}.perf"
        
        sleep "$interval"
    done
    
    # Cleanup
    rm -f "${monitor_file}.perf"
}

optimize_system_limits() {
  local verbose="${1:-0}"
  (( verbose )) && print_subsection "System Optimization" "${EMOJI_GEAR}"

  # ---------- Helpers ----------
  _ok(){ (( verbose )) && ok "$*"; }
  _warn(){ (( verbose )) && warn "$*"; }
  _has(){ command -v "$1" &>/dev/null; }

  # ---------- File descriptors (process-local) ----------
  local current_fd
  current_fd="$(ulimit -n)"
  local desired_fd="${FD_DESIRED:-65536}"
  if [[ "$current_fd" =~ ^[0-9]+$ ]] && (( current_fd < desired_fd )); then
    if ulimit -n "$desired_fd" 2>/dev/null; then
      _ok "Raised soft NOFILE: $current_fd → $desired_fd"
    else
      _warn "Could not increase NOFILE (soft=$current_fd); try running as root or with prlimit"
    fi
  fi

  # ---------- Persisted limits (if root) ----------
  if [[ $EUID -eq 0 ]]; then
    if _has prlimit; then
      prlimit --pid $$ --nofile="$desired_fd":"$desired_fd" &>/dev/null || true
    fi
    # System-wide target (safe, non-destructive drop-in)
    mkdir -p /etc/security/limits.d
    cat >/etc/security/limits.d/99-sqry.conf <<EOF
* soft nofile ${desired_fd}
* hard nofile ${desired_fd}
root soft nofile ${desired_fd}
root hard nofile ${desired_fd}
EOF
    _ok "Persisted NOFILE to /etc/security/limits.d/99-sqry.conf"
  fi

  # ---------- Network buffers & queues (runtime; persisted if root) ----------
  _apply_sysctl() {
    local key="$1" val="$2"
    sysctl -w "$key=$val" &>/dev/null || echo "$val" >"/proc/sys/${key//./\/}" 2>/dev/null || true
  }

  _apply_sysctl net/core/rmem_max 134217728
  _apply_sysctl net/core/wmem_max 134217728
  _apply_sysctl net/core/somaxconn 4096
  _apply_sysctl net/ipv4/tcp_max_syn_backlog 4096
  _apply_sysctl net/ipv4/ip_local_port_range "20000 65000"

  # Conservative TCP opts (skip anything risky on shared VPS)
  _apply_sysctl net/ipv4/tcp_fin_timeout 15
  _apply_sysctl net/ipv4/tcp_tw_reuse 1

  # Enable BBR if available (won’t fail if not supported)
  if [[ -r /proc/sys/net/ipv4/tcp_available_congestion_control ]] && \
     grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
    _apply_sysctl net/ipv4/tcp_congestion_control bbr
    _apply_sysctl net/core/default_qdisc fq
  fi
  _ok "Network parameters optimized (runtime)"

  # Persist sysctls if root
  if [[ $EUID -eq 0 ]]; then
    cat >/etc/sysctl.d/99-sqry.conf <<'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 20000 65000
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
# Enable if supported:
# net.ipv4.tcp_congestion_control = bbr
# net.core.default_qdisc = fq
EOF
    sysctl --system &>/dev/null || true
    _ok "Persisted sysctl to /etc/sysctl.d/99-sqry.conf"
  fi

  # ---------- Process scheduling niceness ----------
  if command -v renice &>/dev/null; then
    renice -n -5 $$ &>/dev/null || true
    _ok "Process priority optimized (renice -5)"
  fi
}


# ========= NETWORK CONNECTIVITY TESTS =========
rate_limit_sleep() {
    local current_time=$(date +%s.%N)
    local time_diff=$(echo "$current_time - ${LAST_REQUEST_TIME:-0}" | bc -l 2>/dev/null || echo "1")
    local min_interval=$(echo "scale=3; 1.0 / $MAX_SCAN_RATE" | bc -l 2>/dev/null || echo "0.01")
    
    if (( $(echo "$time_diff < $min_interval" | bc -l 2>/dev/null || echo 0) )); then
        local sleep_time=$(echo "$min_interval - $time_diff" | bc -l 2>/dev/null || echo "0.01")
        sleep "$sleep_time" 2>/dev/null || sleep 1
    fi
    
    LAST_REQUEST_TIME=$(date +%s.%N)
}

secure_curl() {
    local url="$1"
    shift
    local additional_opts=("$@")
    
    rate_limit_sleep
    
    local curl_cmd=("curl" "-s" "--max-time" "10" "--retry" "2" "--retry-delay" "1")
    
    if (( TOR_ENABLED )); then
        curl_cmd+=("--socks5-hostname" "$SOCKS_PROXY")
    fi
    
    curl_cmd+=("${additional_opts[@]}" "$url")
    
    # Execute with timeout and error handling
    timeout 15 "${curl_cmd[@]}" 2>/dev/null || return 1
}

test_basic_connectivity() {
  local ip="$1"
  local results_dir="$2"
  local verbose="${3:-0}"
  local external_checks="${4:-0}"
  local connectivity_file="$results_dir/connectivity_${ip//[.:]/_}.txt"
  
  # Validate IP before testing
  if ! validate_ip_address "$ip" "${ARG_FLAGS["allow_private"]:-0}"; then
      warn "Skipping invalid or unauthorized IP: $ip"
      return 1
  fi
  
  mkdir -p "$results_dir"

  # ----- helpers -----
  _has(){ command -v "$1" &>/dev/null; }
  _section(){ (( verbose )) && echo -e "\n\033[1;36m[+] $1\033[0m"; }
  _v(){ (( verbose )) && echo -e "$*"; }

  local start_time end_time duration
  start_time=$(date +%s)

  (( verbose )) && target "Testing connectivity to $ip"

  {
    echo "=== ENHANCED CONNECTIVITY TEST FOR $ip ==="
    echo "Timestamp: $(date)"
    echo "Framework: VPS-SQRY v5.0.0 Enhanced"
    echo "-----------------------------------"

    # ---------- Reachability: ICMP ----------
    _section "ICMP (Ping)"
    echo "[PING] Testing ICMP connectivity..."
    if ping -c 3 -W 2 "$ip" &>/dev/null; then
      local ping_time
      ping_time=$(ping -c 1 -W 2 "$ip" 2>/dev/null | awk -F'time=' '/time=/{print $2}' | awk '{print $1}' | head -1)
      echo "[${EMOJI_SUCCESS}] ICMP ping successful (${ping_time:-unknown}ms)"
      _v "  ${BG}${EMOJI_CHECKMARK} Ping response: ${ping_time:-N/A}ms${N}"
    else
      echo "[${EMOJI_WARNING}] ICMP ping failed (may be filtered)"
      _v "  ${BY}${EMOJI_WARNING} ICMP may be blocked${N}"
    fi

    # ---------- DNS / Reverse ----------
    _section "DNS / Reverse Lookup"
    echo "[DNS] Testing reverse DNS lookup..."
    local hostname
    hostname=$(host "$ip" 2>/dev/null | awk '/domain name pointer/{print $5}' | sed 's/\.$//' | head -1)
    if [[ -n "$hostname" ]]; then
      echo "[${EMOJI_SUCCESS}] PTR: $hostname"
      _v "  ${BG}${EMOJI_CHECKMARK} Hostname: $hostname${N}"
    else
      echo "[${EMOJI_INFO}] No reverse DNS (PTR) record"
      _v "  ${BC}${EMOJI_INFO} No PTR found${N}"
    fi

    # ---------- TCP common ports ----------
    _section "TCP Connectivity (Common Ports)"
    local open_ports=()
    for port in 22 23 53 80 443 993 995 8080 8443 3389; do
      if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
        echo "[${EMOJI_SUCCESS}] Port $port/tcp is open"
        _v "  ${BG}${EMOJI_TARGET} Service likely on $port${N}"
        open_ports+=("$port")
      else
        _v "  ${EMOJI_INFO} $port/tcp closed or filtered"
      fi
    done

    # ---------- HTTP(S) HEAD tech detection ----------
    if _has curl; then
      _section "HTTP(S) Tech Signals"
      if curl -fsSI --connect-timeout 3 "http://$ip" 2>/dev/null | tee >(sed 's/^/HTTP: /') >/tmp/sqry_http_headers_$$; then
        local server=$(grep -i '^Server:' /tmp/sqry_http_headers_$$ | head -1 | cut -d' ' -f2-)
        local powered=$(grep -i '^X-Powered-By:' /tmp/sqry_http_headers_$$ | head -1 | cut -d' ' -f2-)
        [[ -n "$server" ]]  && echo "[${EMOJI_INFO}] http Server: ${server%$'\r'}"
        [[ -n "$powered" ]] && echo "[${EMOJI_INFO}] http X-Powered-By: ${powered%$'\r'}"
      else
        echo "[${EMOJI_INFO}] http HEAD not available"
      fi

      if curl -fsSI --connect-timeout 4 "https://$ip" 2>/dev/null | tee >(sed 's/^/HTTPS: /') >/tmp/sqry_https_headers_$$; then
        local sserver=$(grep -i '^Server:' /tmp/sqry_https_headers_$$ | head -1 | cut -d' ' -f2-)
        local spowered=$(grep -i '^X-Powered-By:' /tmp/sqry_https_headers_$$ | head -1 | cut -d' ' -f2-)
        [[ -n "$sserver" ]]  && echo "[${EMOJI_INFO}] https Server: ${sserver%$'\r'}"
        [[ -n "$spowered" ]] && echo "[${EMOJI_INFO}] https X-Powered-By: ${spowered%$'\r'}"
      else
        echo "[${EMOJI_INFO}] https HEAD not available"
      fi
      rm -f /tmp/sqry_http_headers_$$ /tmp/sqry_https_headers_$$
    fi

    # ---------- TLS Certificate (Org/CN/Issuer) ----------
    if _has openssl; then
      _section "TLS Certificate (Org/CN/Issuer)"
      local cert
      cert="$(echo | timeout 4 openssl s_client -connect "${ip}:443" -servername "$hostname" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null || true)"
      if [[ -n "$cert" ]]; then
        echo "$cert" | sed 's/^/[CERT] /'
      else
        echo "[${EMOJI_INFO}] No TLS cert info (no 443 or TLS blocked)"
      fi
    fi

    # ---------- Simple banner grabs on open ports ----------
    if ((${#open_ports[@]})); then
      _section "Banner Grabs (quick)"
      for p in "${open_ports[@]}"; do
        _v "  Grabbing banner on $ip:$p"
        timeout 2 bash -c "exec 3<>/dev/tcp/$ip/$p; echo -e 'HEAD / HTTP/1.0\r\n\r\n' >&3; cat <&3 | head -n 2" 2>/dev/null \
          | sed "s/^/[BANNER ${p}] /"
      done
    fi

    # ---------- Owner/Org (no-key public endpoints) ----------
    _section "Owner / Org (No-Key)"
    if _has curl; then
      # ipinfo (no key needed for light usage)
      local IPINFO
      IPINFO="$(secure_curl "https://ipinfo.io/${ip}/json" || true)"
      local org city region country
      org="$(echo "$IPINFO" | awk -F'"' '/"org":/ {print $4}' | head -1)"
      city="$(echo "$IPINFO" | awk -F'"' '/"city":/ {print $4}' | head -1)"
      region="$(echo "$IPINFO" | awk -F'"' '/"region":/ {print $4}' | head -1)"
      country="$(echo "$IPINFO" | awk -F'"' '/"country":/ {print $4}' | head -1)"
      org="$(sanitize_input "$org")"
      city="$(sanitize_input "$city")"
      region="$(sanitize_input "$region")"
      country="$(sanitize_input "$country")"
      [[ -n "$org" ]]     && echo "[${EMOJI_INFO}] Org: $org"
      [[ -n "$city$region$country" ]] && echo "[${EMOJI_INFO}] Geo: ${city:-?}, ${region:-?}, ${country:-?}"

      # RDAP (ARIN) – often returns a name, handle, remarks
      local RDAP
      RDAP="$(secure_curl "https://rdap.arin.net/registry/ip/${ip}" || true)"
      local rdap_name
      rdap_name="$(echo "$RDAP" | awk -F'"' '/"name":/ {print $4}' | head -1)"
      rdap_name="$(sanitize_input "$rdap_name")"
      [[ -n "$rdap_name" ]] && echo "[${EMOJI_INFO}] RDAP Name: $rdap_name"
    fi

    # ---------- Summary ----------
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "-----------------------------------"
    echo "[SUMMARY] Open TCP ports: ${#open_ports[@]} found (${open_ports[*]:-none})"
    echo "[TIMING]  Completed in ${duration}s"
    echo "-----------------------------------"
  } >"$connectivity_file"

  # quick alive flag re-use
  local is_alive=0
  if ping -c 1 -W 2 "$ip" &>/dev/null \
     || timeout 2 bash -c "echo >/dev/tcp/$ip/80" &>/dev/null \
     || timeout 2 bash -c "echo >/dev/tcp/$ip/443" &>/dev/null; then
    is_alive=1
    (( verbose )) && echo -e "  ${BG}${EMOJI_SUCCESS} $ip appears reachable${N}"
  else
    (( verbose )) && echo -e "  ${BR}${EMOJI_CROSSMARK} $ip appears unreachable${N}"
  fi

  # Optional external check (same style as your host_alive external probe)
  if (( !is_alive )) && (( external_checks == 1 )) && _has curl; then
    _section "External Remote Checks (check-host.net)"
    local reqid
    reqid="$(curl -fsS -H 'Accept: application/json' "https://check-host.net/check-ping?host=${ip}&max_nodes=3" \
      | grep -oE '"request_id":"[^"]+"' | cut -d: -f2 | tr -d '"')"
    if [[ -n "$reqid" ]]; then
      sleep 1
      if curl -fsS -H 'Accept: application/json' "https://check-host.net/check-result/${reqid}" | grep -q '"OK"'; then
        is_alive=1
        (( verbose )) && echo -e "  ${BG}${EMOJI_SUCCESS} Remote nodes report ICMP reachable${N}"
      fi
    fi
  fi

  return $((1 - is_alive))
}

# ========= ENHANCED IP EXTRACTION =========
is_host_dead() {
    local ip="$1"
    local verbose="${2:-0}"
    local is_alive=0
    
    # 1. Traditional network checks
    
    if ping -c 1 -W 2 "$ip" &>/dev/null; then
        is_alive=1
        if (( verbose )); then
            echo -e "  ${BG}${EMOJI_SUCCESS} $ip is reachable via ICMP${N}"
        fi
    elif timeout 3 bash -c "echo >/dev/tcp/$ip/80" 2>/dev/null; then
        is_alive=1
        if (( verbose )); then
            echo -e "  ${BG}${EMOJI_SUCCESS} $ip is reachable via HTTP${N}"
        fi
    elif timeout 3 bash -c "echo >/dev/tcp/$ip/443" 2>/dev/null; then
        is_alive=1
        if (( verbose )); then
            echo -e "  ${BG}${EMOJI_SUCCESS} $ip is reachable via HTTPS${N}"
        fi
    
    # 2. Common service ports check
    else
        local common_ports=({22,21,23,25,110,143,993,995,3306,3389,5900,8080})
        for port in "${common_ports[@]}"; do
            if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
                is_alive=1
                if (( verbose )); then
                    echo -e "  ${BG}${EMOJI_SUCCESS} $ip is reachable via port $port${N}"
                fi
                break
            fi
        done
    fi

    # 3. DNS-based verification
    if (( !is_alive )); then
        if host "$ip" >/dev/null 2>&1; then
            is_alive=1
            if (( verbose )); then
                echo -e "  ${BG}${EMOJI_SUCCESS} $ip has valid DNS records${N}"
            fi
        fi
    fi

    # 4. Free API checks (no keys required)
    if (( !is_alive )); then
        # Check via ipinfo.io API with rate limiting
        if secure_curl "https://ipinfo.io/$ip" | grep -q '"country":'; then
            is_alive=1
            if (( verbose )); then
                echo -e "  ${BG}${EMOJI_SUCCESS} $ip is alive via ipinfo.io API${N}"
            fi
        # Check via ipapi.co API with rate limiting
        elif secure_curl "https://ipapi.co/$ip/json/" | grep -q '"country":'; then
            is_alive=1
            if (( verbose )); then
                echo -e "  ${BG}${EMOJI_SUCCESS} $ip is alive via ipapi.co API${N}"
            fi
        # Check via hackertarget.com API with rate limiting
        elif secure_curl "https://api.hackertarget.com/geoip/?q=$ip" | grep -q 'Country:'; then
            is_alive=1
            if (( verbose )); then
                echo -e "  ${BG}${EMOJI_SUCCESS} $ip is alive via hackertarget.com API${N}"
            fi
        fi
    fi

    # 5. HTTP-based checks for web services
    if (( !is_alive )); then
        # Check common HTTP paths
        local paths=("/" "/robots.txt" "/favicon.ico" "/index.html")
        for path in "${paths[@]}"; do
            if curl -s --max-time 3 -I "http://$ip$path" | grep -q 'HTTP/.* 200'; then
                is_alive=1
                if (( verbose )); then
                    echo -e "  ${BG}${EMOJI_SUCCESS} $ip responded on HTTP path $path${N}"
                fi
                break
            fi
        done
    fi

    # 6. WHOIS verification
    if (( !is_alive )); then
        if whois "$ip" | grep -q 'inetnum\|netrange'; then
            is_alive=1
            if (( verbose )); then
                echo -e "  ${BG}${EMOJI_SUCCESS} $ip has valid WHOIS records${N}"
            fi
        fi
    fi

    # Final fallback check (requires nmap and root privileges)
    if (( !is_alive )) && command -v nmap &>/dev/null && [[ $EUID -eq 0 ]]; then
        # Last-resort TCP SYN scan (requires root)
        if sudo nmap -sn -PS "$ip" | grep -q 'Host is up'; then
            is_alive=1
            if (( verbose )); then
                echo -e "  ${BG}${EMOJI_SUCCESS} $ip is alive via TCP SYN scan${N}"
            fi
        fi
    fi

    if (( !is_alive )) && (( verbose )); then
        echo -e "  ${BR}${EMOJI_CROSSMARK} $ip appears unreachable${N}"
    fi
    
    return $((1 - is_alive))
}

extract_ips() {
  local raw_file="$1"
  local out_ips_file="$2"          # plain list of unique IPs
  local verbose="${3:-0}"
  local max_ips="${4:-2000}"

  local start_time=$(date +%s)
  local temp_ips
  temp_ips="$(mktemp)"
  local out_meta_csv="${out_ips_file%.*}_meta.csv"

  (( verbose )) && print_subsection "IP & Domain Extraction" "${EMOJI_SEARCH}"
  (( verbose )) && scan "Parsing input for IPs/domains..."

  [[ -s "$raw_file" ]] || { warn "No input: $raw_file"; return 1; }

  # ---------- Pull raw IPs + domains ----------
  # Domains: simple heuristic (you can tighten with a full PSL-based validator if needed)
  local temp_domains; temp_domains="$(mktemp)"
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$raw_file" > "$temp_ips" || true
  grep -Eoi '\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b' "$raw_file" \
    | sed 's/\.$//' | sort -u > "$temp_domains" || true

  # ---------- Validate IP octets + limit ----------
  awk -v MAX="$max_ips" '
    function valid(o){ return (o>=0 && o<=255) }
    {
      split($0, a, ".")
      if (valid(a[1]) && valid(a[2]) && valid(a[3]) && valid(a[4])) {
        print $0
      }
    }
  ' "$temp_ips" | sort -u | head -n "$max_ips" > "$out_ips_file"

  (( verbose )) && status "IPs found: $(wc -l <"$out_ips_file")"
  (( verbose )) && status "Domains found: $(wc -l <"$temp_domains")"

  # ---------- Optional enrichment (no keys) ----------
  # Creates CSV: ip,ptr,org,rdap_name,http_server,tls_cn
  echo "ip,ptr,org,rdap_name,http_server,tls_cn" > "$out_meta_csv"
  while read -r ip; do
    [[ -n "$ip" ]] || continue

    # PTR
    local ptr; ptr="$(host "$ip" 2>/dev/null | awk '/pointer/{print $5}' | sed 's/\.$//' | head -1)"

    # ipinfo org with secure curl and rate limiting
    local org=""; local rdap=""
    if command -v curl &>/dev/null; then
      local IPINFO; IPINFO="$(secure_curl "https://ipinfo.io/${ip}/json" || true)"
      org="$(echo "$IPINFO" | awk -F'"' '/"org":/ {print $4}' | head -1)"
      org="$(sanitize_input "$org")"
      local RDAP; RDAP="$(secure_curl "https://rdap.arin.net/registry/ip/${ip}" || true)"
      rdap="$(echo "$RDAP" | awk -F'"' '/"name":/ {print $4}' | head -1)"
      rdap="$(sanitize_input "$rdap")"
    fi

    # Quick HTTP server header with secure curl
    local http_server=""
    if command -v curl &>/dev/null; then
      http_server="$(secure_curl "http://${ip}" -I | awk -F': ' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')"
      http_server="$(sanitize_input "$http_server")"
    fi

    # TLS CN (from cert subject)
    local tls_cn=""
    if command -v openssl &>/dev/null; then
      tls_cn="$(echo | timeout 3 openssl s_client -connect "${ip}:443" 2>/dev/null \
                | openssl x509 -noout -subject 2>/dev/null \
                | sed -n 's/.*CN=//p' | sed 's,/.*,,; s/^[[:space:]]*//; s/[[:space:]]*$//' )"
    fi

    printf '%s,%s,%s,%s,%s,%s\n' \
      "$ip" "${ptr:-}" "${org:-}" "${rdap:-}" "${http_server:-}" "${tls_cn:-}" >> "$out_meta_csv"

    (( verbose )) && echo -e "  ${EMOJI_CHECKMARK} $ip → PTR=${ptr:--} | ORG=${org:--} | RDAP=${rdap:--} | HTTP=${http_server:--} | TLS_CN=${tls_cn:--}"
  done < "$out_ips_file"

  # dump domains next to the IP list (separate file)
  cp -f "$temp_domains" "${out_ips_file%.*}_domains.txt"

  rm -f "$temp_ips" "$temp_domains"
  local end_time=$(date +%s); local duration=$((end_time - start_time))
  (( verbose )) && ok "Extraction complete in ${duration}s → IPs:${out_ips_file}, Domains:${out_ips_file%.*}_domains.txt, Meta:${out_meta_csv}"
}

# ========= ENHANCED USAGE =========
usage() {
    print_banner
    echo -e "${G}Usage:${N} $0 [OPTIONS] | [CHEATSHEET COMMAND] | [INSTALL MODE]"
    echo
    echo -e "${BY}Enhanced Features in v5.0.0:${N}"
    echo -e "  ${EMOJI_ROCKET} Fixed sqry IP extraction with validation"
    echo -e "  ${EMOJI_FIRE} Intelligent parallel processing (up to 9000 jobs)"
    echo -e "  ${EMOJI_BOLT} Network connectivity pre-testing with verbose output"
    echo -e "  ${EMOJI_TARGET} Enhanced brute-force with service-specific credentials"
    echo -e "  ${EMOJI_SHIELD} Comprehensive nuclei scanning with multiple templates"
    echo -e "  ${EMOJI_GEAR} Smart rate limiting and real-time resource monitoring"
    echo -e "  ${EMOJI_CHART} Interactive HTML dashboard with live statistics"
    echo -e "  ${EMOJI_SUCCESS} Beautiful progress bars and loading animations"
    echo -e "  ${EMOJI_HOURGLASS} Performance metrics and timing analysis"
    echo
    echo -e "${Y}Reconnaissance Mode:${N}"
    echo -e "  -q, --query <query>    The Shodan query to execute (enclose in quotes)"
    echo -e "  -o, --output <dir>     Output directory (default: ${DEFAULT_OUTPUT_DIR})"
    echo -e "  -t, --threads <num>    Set concurrency threads (default: auto-calculated)"
    echo -e "  -v, --verbose          Enable verbose output"
    echo -e "  -d, --debug            Enable debug mode (very verbose)"
    echo -e "  --ports <ports>        Comma-separated ports to scan (default: ${DEFAULT_PORTS})"
    echo -e "  --userlist <file>      Custom username list for brute-force"
    echo -e "  --passlist <file>      Custom password list for brute-force"
    echo
    echo -e "${Y}Advanced Scanning Options:${N}"
    echo -e "  --smart-scan           Enable smart detection scan"
    echo -e "  --full-scan            Enable full intensive scan"
    echo -e "  --no-nmap              Skip nmap scanning"
    echo -e "  --no-nuclei            Skip nuclei scanning"
    echo -e "  --no-brutex            Skip brute force checks"
    echo -e "  --no-screenshots       Skip screenshot capture"
    echo
    echo -e "${Y}Security Options:${N}"
    echo -e "  --tor                  Enable Tor proxy for anonymous scanning"
    echo -e "  --disable-auth         Disable target authorization checks"
    echo -e "  --allow-private        Allow scanning of private IP ranges"
    echo -e "  --create-auth-template Create authorized networks template file"
    echo -e "  --max-rate <num>       Set maximum scan rate (1-1000 req/sec, default: 100)"
    echo
    echo -e "${Y}Info:${N}"
    echo -e "  -h, --help             Show this help message"
    echo -e "  --version              Show version information"
    echo
    echo -e "${Y}Examples:${N}"
    echo -e "  ${C}$0 -q \"apache\" -o ./scan_results --smart-scan${N}      # Smart reconnaissance with HTML dashboard"
    echo -e "  ${C}$0 --query \"nginx\" --full-scan${N}                     # Full comprehensive scan"
    echo -e "  ${C}$0 -q \"tomcat\" --full-scan -t 200${N}                # Full scan with 200 threads"
    echo -e "  ${C}$0 --version${N}                                    # Show enhanced version info"
}

# ========= VERSION FUNCTION =========
version() {
    print_banner
    echo -e "${G}VPS-SCAN Framework v${VERSION} - Enhanced Security Edition${N}"
    echo -e "  • Fixed sqry IP extraction with validation"
    echo -e "  • Intelligent parallel processing (up to 9000 jobs)"
    echo -e "  • Network connectivity pre-testing"
    echo -e "  • Enhanced brute-force with service-specific credentials"
    echo -e "  • Comprehensive nuclei scanning with multiple templates"
    echo -e "  • Smart rate limiting and resource monitoring"
    echo -e "  • Interactive HTML dashboard generation"
    echo -e "  • Improved error handling and reporting"
    echo -e "  ${EMOJI_SHIELD} IP address validation and authorization checks"
    echo -e "  ${EMOJI_SHIELD} Tor proxy integration for anonymous scanning"
    echo -e "  ${EMOJI_SHIELD} Secure logging with input sanitization"
    echo -e "  ${EMOJI_SHIELD} Privilege escalation and tool integrity checks"
    echo -e "  ${EMOJI_SHIELD} Enhanced rate limiting and respectful scanning"
    echo
    echo -e "${Y}Enhanced Security by:${N} Claude AI"
}

# ========= ARGUMENT PARSER =========
parse_arguments() {
    local query=""
    local output_dir="$DEFAULT_OUTPUT_DIR"
    local threads=""
    local ports=""
    local userlist=""
    local passlist=""
    local flags=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            # Recon mode options
            -q|--query)
                if [[ -z "$2" ]]; then
                    die "Query cannot be empty"
                fi
                query="$2"
                shift 2
                ;;
            -o|--output)
                if [[ -z "$2" ]]; then
                    die "Output directory cannot be empty"
                fi
                output_dir="$2"
                shift 2
                ;;
            -t|--threads)
                if [[ "$2" =~ ^[0-9]+$ ]] && (( $2 > 0 && $2 <= MAX_PARALLEL_JOBS )); then
                    threads="$2"
                elif [[ "$2" == "auto" ]]; then
                    threads=""  # Will be calculated automatically
                else
                    die "Threads must be between 1 and $MAX_PARALLEL_JOBS, or 'auto' for automatic calculation"
                fi
                shift 2
                ;;
            --ports)
                if [[ -z "$2" ]]; then
                    die "Ports cannot be empty"
                fi
                ports="$2"
                shift 2
                ;;
            --userlist)
                if [[ ! -f "$2" ]]; then
                    die "Userlist file does not exist"
                fi
                userlist="$2"
                shift 2
                ;;
            --passlist)
                if [[ ! -f "$2" ]]; then
                    die "Password list file does not exist"
                fi
                passlist="$2"
                shift 2
                ;;
            -v|--verbose) flags+=("verbose"); shift ;;
            -d|--debug) flags+=("debug"); shift ;;
            --no-nmap) flags+=("no_nmap"); shift ;;
            --no-nuclei) flags+=("no_nuclei"); shift ;;
            --no-brutex) flags+=("no_brutex"); shift ;;
            --no-screenshots) flags+=("no_screenshots"); shift ;;
            --smart-scan) flags+=("smart_scan"); shift ;;
            --full-scan) flags+=("full_scan"); shift ;;
            
            # Security options
            --tor) flags+=("tor_enabled"); shift ;;
            --disable-auth) flags+=("disable_auth"); shift ;;
            --allow-private) flags+=("allow_private"); shift ;;
            --create-auth-template) flags+=("create_auth_template"); shift ;;
            --max-rate)
                if [[ "$2" =~ ^[0-9]+$ ]] && (( $2 > 0 && $2 <= 1000 )); then
                    ARG_PARAMS["max_rate"]="$2"
                else
                    die "Max rate must be between 1 and 1000 requests per second"
                fi
                shift 2
                ;;

            # Info options
            -h|--help) usage; exit 0 ;;
            --version) version; exit 0 ;;

            *) die "Unknown argument: $1" ;;
        esac
    done

    [[ -z "$query" ]] && { usage; exit 1; }

    # Sanitize query input
    query="$(sanitize_input "$query")"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir" || die "Failed to create output directory: $output_dir"

    # Save parameters to global associative array
    ARG_PARAMS["query"]="$query"
    ARG_PARAMS["output_dir"]="$output_dir"
    ARG_PARAMS["threads"]="$threads"
    ARG_PARAMS["ports"]="$ports"
    ARG_PARAMS["userlist"]="$userlist"
    ARG_PARAMS["passlist"]="$passlist"
    
    # Set security configuration based on flags
    if [[ -n "${ARG_FLAGS["tor_enabled"]:-}" ]]; then
        TOR_ENABLED=1
    fi
    
    if [[ -n "${ARG_FLAGS["disable_auth"]:-}" ]]; then
        REQUIRE_AUTHORIZATION=0
    fi
    
    if [[ -n "${ARG_FLAGS["allow_private"]:-}" ]]; then
        ARG_FLAGS["allow_private"]=1
    fi
    
    if [[ -n "${ARG_PARAMS["max_rate"]:-}" ]]; then
        MAX_SCAN_RATE="${ARG_PARAMS["max_rate"]}"
    fi

    # Convert flags to associative array
    for flag in "${flags[@]}"; do
        ARG_FLAGS["$flag"]=1
    done
    
    # Handle special flags first (before query validation)
    if [[ -n "${ARG_FLAGS["create_auth_template"]:-}" ]]; then
        create_authorized_networks_template
        exit $?
    fi
}

# ========= RECONNAISSANCE FUNCTION =========
run_recon() {
    local query="$1"
    local output_dir="$2"
    local threads="${3:-$(calc_optimal_threads)}"
    local ports="${4:-$DEFAULT_PORTS}"
    local verbose="${ARG_FLAGS["verbose"]:-0}"
    local debug="${ARG_FLAGS["debug"]:-0}"
    
    local start_time=$(date +%s)
    local session_id="recon_$(date +%Y%m%d_%H%M%S)"
    
    mkdir -p "$output_dir"
    
    # Output for scan initialization
    print_section_header "VPS RECONNAISSANCE INITIALIZATION" "${EMOJI_ROCKET}"
    
    status "Session ID: $session_id"
    status "Query: \"$query\""
    status "Output directory: $output_dir"
    status "Threads: $threads (optimized for system)"
    status "Target ports: $ports"
    status "Verbose mode: $([[ $verbose -eq 1 ]] && echo "Enabled" || echo "Disabled")"
    
    # File definitions
    local raw_file="$output_dir/sqry_raw.txt"
    local ips_file="$output_dir/ips.txt"
    local summary_file="$output_dir/summary.txt"
    local performance_log="$output_dir/performance.log"
    local stats_file="$output_dir/live_stats.txt"
    
    # Initialize performance logging
    {
        echo "=== VPS-SQRY PERFORMANCE LOG ==="
        echo "Session: $session_id"
        echo "Start time: $(date)"
        echo "Query: $query"
        echo "Threads: $threads"
        echo "==================================="
    } > "$performance_log"

    # Phase 1: SQRY Execution with enhanced monitoring
    print_section_header "PHASE 1: SQRY DATA COLLECTION" "${EMOJI_SEARCH}"
    
    # Test sqry command availability
    if ! command -v sqry &>/dev/null; then
        error "sqry command not found. Please install sqry first."
        echo "sqry command not found" > "$summary_file"
        return 1
    fi
    
    scan "Executing sqry with query: \"$query\""
    
    # Enhanced sqry execution with progress monitoring
    local sqry_start=$(date +%s)
    
    # Show spinner for sqry execution
    {
        if ! timeout 300 sqry -q "$query" > "$raw_file" 2>/dev/null; then
            warn "Primary sqry syntax failed, trying alternative..."
            
            # Try alternative sqry syntax
            if ! timeout 300 sqry "$query" > "$raw_file" 2>/dev/null; then
                error "sqry failed with both syntax attempts"
                echo "sqry failed for query: $query" > "$summary_file"
                exit 1
            fi
        fi
    } &
    
    local sqry_pid=$!
    show_spinner "$sqry_pid" "Querying Shodan database..."
    wait "$sqry_pid"
    local sqry_status=$?
    
    local sqry_end=$(date +%s)
    local sqry_duration=$((sqry_end - sqry_start))
    
    # Log sqry performance
    echo "[$(date)] SQRY execution: ${sqry_duration}s" >> "$performance_log"
    
    if [[ $sqry_status -ne 0 ]] || [[ ! -s "$raw_file" ]]; then
        error "sqry query failed or returned no results"
        echo "No results from sqry for query: $query" > "$summary_file"
        return 1
    fi
    
    local raw_lines=$(wc -l < "$raw_file")
    local raw_size=$(du -h "$raw_file" | cut -f1)
    
    result "SQRY completed in ${sqry_duration}s"
    if (( verbose )); then
        echo -e "  ${BC}${EMOJI_CHART} Raw output: $raw_lines lines ($raw_size)${N}"
        echo -e "  ${BC}${EMOJI_CHART} File location: $raw_file${N}"
        echo -e "  ${BC}${EMOJI_CHART} Query processing rate: $((raw_lines / (sqry_duration + 1))) lines/s${N}"
    fi

    # Phase 2: Enhanced IP Extraction
    print_section_header "PHASE 2: IP EXTRACTION & VALIDATION" "${EMOJI_TARGET}"
    
    local extraction_start=$(date +%s)
    
    if ! extract_ips "$raw_file" "$ips_file" "$verbose" 2000; then
        error "No valid IPs found in the sqry output"
        echo "No IPs found for query: $query" > "$summary_file"
        return 1
    fi
    
    local extraction_end=$(date +%s)
    local extraction_duration=$((extraction_end - extraction_start))
    local ip_count=$(wc -l < "$ips_file")
    
    echo "[$(date)] IP extraction: ${extraction_duration}s, $ip_count IPs" >> "$performance_log"
    
    result "Extracted $ip_count unique public IPs in ${extraction_duration}s"
    
    # Phase 3: Enhanced Connectivity Testing
    print_section_header "PHASE 3: CONNECTIVITY ASSESSMENT" "${EMOJI_BOLT}"
    
    local connectivity_dir="$output_dir/connectivity"
    mkdir -p "$connectivity_dir"
    local live_ips_file="$output_dir/live_ips.txt"
    local connectivity_start=$(date +%s)
    
    scan "Testing connectivity to $ip_count discovered IPs..."
    
    # Enhanced parallel connectivity testing with progress
    local tested=0
    local alive=0
    > "$live_ips_file"  # Clear file
    
    {
        while IFS= read -r ip; do
            {
                if test_basic_connectivity "$ip" "$connectivity_dir" "$verbose"; then
                    echo "$ip" >> "$live_ips_file"
                    ((alive++))
                fi
                ((tested++))
                
                # Update progress
                if (( verbose )); then
                    print_progress_bar "$tested" "$ip_count"
                fi
                
                # Update stats for live monitoring
                update_stats "$stats_file" "Connectivity Testing" "$tested" "$ip_count" "$connectivity_start"
                
            } &
            
            # Enhanced job management
            if (( $(jobs -r | wc -l) >= threads )); then
                wait -n  # Wait for next job to complete
            fi
        done < "$ips_file"
        wait  # Wait for all background processes
    }
    
    if (( verbose )); then
        echo  # New line after progress bar
    fi
    
    local connectivity_end=$(date +%s)
    local connectivity_duration=$((connectivity_end - connectivity_start))
    local live_count=0
    
    if [[ -s "$live_ips_file" ]]; then
        live_count=$(wc -l < "$live_ips_file")
        result "Found $live_count responsive IPs out of $ip_count total (${connectivity_duration}s)"
        
        # Use only live IPs for efficiency
        cp "$live_ips_file" "$ips_file"
        ip_count=$live_count
        
        if (( verbose )); then
            echo -e "  ${BC}${EMOJI_CHART} Response rate: $((live_count * 100 / ip_count))%${N}"
            echo -e "  ${BC}${EMOJI_CHART} Testing speed: $((ip_count / (connectivity_duration + 1))) IPs/s${N}"
        fi
    else
        warn "No responsive IPs found during connectivity testing"
        warn "Proceeding with all $ip_count discovered IPs"
        live_count=$ip_count
    fi
    
    echo "[$(date)] Connectivity testing: ${connectivity_duration}s, $live_count live IPs" >> "$performance_log"
    
    # Clean up stats file
    rm -f "$stats_file"
    
    # Phase 4: Generate comprehensive summary
    print_section_header "PHASE 4: REPORT GENERATION" "${EMOJI_CHART}"
    
    local report_start=$(date +%s)
    generate_summary "$query" "$output_dir" "$ip_count" "" "" "$summary_file" "$session_id"
    local report_end=$(date +%s)
    local report_duration=$((report_end - report_start))
    
    # Final performance summary
    local total_duration=$(($(date +%s) - start_time))
    
    {
        echo "[$(date)] Report generation: ${report_duration}s"
        echo "[$(date)] Total session time: ${total_duration}s"
        echo "=============================="
        echo "PERFORMANCE SUMMARY:"
        echo "- SQRY execution: ${sqry_duration}s"
        echo "- IP extraction: ${extraction_duration}s"
        echo "- Connectivity testing: ${connectivity_duration}s"
        echo "- Report generation: ${report_duration}s"
        echo "- Total time: ${total_duration}s"
        echo "- IPs discovered: $ip_count"
        echo "- IPs alive: $live_count"
        echo "- Overall rate: $((ip_count / (total_duration + 1))) IPs/s"
    } >> "$performance_log"
    
    print_section_header "RECONNAISSANCE COMPLETE" "${EMOJI_SUCCESS}"
    
    result "Session $session_id completed in ${total_duration}s"
    if (( verbose )); then
        echo -e "  ${BC}${EMOJI_CHART} Total IPs processed: $ip_count${N}"
        echo -e "  ${BC}${EMOJI_CHART} Live IPs found: $live_count${N}"
        echo -e "  ${BC}${EMOJI_CHART} Processing efficiency: $((ip_count / (total_duration + 1))) IPs/s${N}"
        echo -e "  ${BC}${EMOJI_CHART} Performance log: $performance_log${N}"
    fi
}

# ========= HTML DASHBOARD GENERATION =========
generate_html_dashboard() {
    local query="$1"
    local output_dir="$2" 
    local ip_count="$3"
    local session_id="${4:-unknown}"
    local dashboard_file="$output_dir/dashboard.html"
    
    scan "Generating interactive HTML dashboard..."
    
    # Extract performance data if available
    local performance_log="$output_dir/performance.log"
    local total_time="N/A"
    local sqry_time="N/A"
    local extraction_time="N/A"
    local connectivity_time="N/A"
    
    if [[ -f "$performance_log" ]]; then
        total_time=$(grep "Total session time:" "$performance_log" | awk '{print $4}' | head -1 || echo "N/A")
        sqry_time=$(grep "SQRY execution:" "$performance_log" | awk '{print $3}' | head -1 || echo "N/A")
        extraction_time=$(grep "IP extraction:" "$performance_log" | awk '{print $3}' | head -1 || echo "N/A")
        connectivity_time=$(grep "Connectivity testing:" "$performance_log" | awk '{print $3}' | head -1 || echo "N/A")
    fi
    
    cat > "$dashboard_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS Reconnaissance Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e1a; color: #e0e6ed; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #00d4aa; font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { color: #8892b0; font-size: 1.2em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: linear-gradient(135deg, #1a1f36 0%, #262c49 100%); padding: 20px; border-radius: 10px; border: 1px solid #334155; }
        .stat-card h3 { color: #00d4aa; margin-bottom: 10px; }
        .stat-card .number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .stat-card .label { color: #8892b0; }
        .success { color: #50fa7b; }
        .info { color: #8be9fd; }
        .section { background: #1a1f36; padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #334155; }
        .section h2 { color: #00d4aa; margin-bottom: 15px; }
        .timestamp { text-align: center; color: #8892b0; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #334155; }
        th { background: #262c49; color: #00d4aa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ VPS Reconnaissance Dashboard</h1>
            <div class="subtitle">Enhanced Security Assessment Results v5.0.0</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>🎯 Total Targets</h3>
                <div class="number info">$ip_count</div>
                <div class="label">Unique IP Addresses</div>
            </div>
            <div class="stat-card">
                <h3>🚀 Performance</h3>
                <div class="number success">$total_time</div>
                <div class="label">Total Execution Time</div>
            </div>
            <div class="stat-card">
                <h3>🔥 Intelligence</h3>
                <div class="number success">Enhanced</div>
                <div class="label">Auto-optimized scanning</div>
            </div>
            <div class="stat-card">
                <h3>⚡ Session</h3>
                <div class="number info">${session_id##*_}</div>
                <div class="label">Scan Session ID</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Scan Overview</h2>
            <table>
                <tr><th>Parameter</th><th>Value</th></tr>
                <tr><td>Query</td><td><code>$query</code></td></tr>
                <tr><td>Session ID</td><td><code>$session_id</code></td></tr>
                <tr><td>Scan Date</td><td>$(date)</td></tr>
                <tr><td>Total Runtime</td><td><strong>$total_time</strong></td></tr>
                <tr><td>Output Directory</td><td><code>$output_dir</code></td></tr>
                <tr><td>Framework Version</td><td>VPS-SQRY v5.0.0 Enhanced</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>📁 File Locations</h2>
            <table>
                <tr><th>Report Type</th><th>Location</th></tr>
                <tr><td>Raw SQRY Output</td><td><code>$output_dir/sqry_raw.txt</code></td></tr>
                <tr><td>Validated IP List</td><td><code>$output_dir/ips.txt</code></td></tr>
                <tr><td>Connectivity Tests</td><td><code>$output_dir/connectivity/</code></td></tr>
                <tr><td>Performance Log</td><td><code>$output_dir/performance.log</code></td></tr>
                <tr><td>Summary Report</td><td><code>$output_dir/summary.txt</code></td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>⏱️ Performance Metrics</h2>
            <table>
                <tr><th>Operation</th><th>Duration</th></tr>
                <tr><td>SQRY Execution</td><td>$sqry_time</td></tr>
                <tr><td>IP Extraction</td><td>$extraction_time</td></tr>
                <tr><td>Connectivity Testing</td><td>$connectivity_time</td></tr>
                <tr><td><strong>Total Runtime</strong></td><td><strong>$total_time</strong></td></tr>
            </table>
        </div>
        
        <div class="timestamp">
            🕰️ Generated on $(date) | VPS-SQRY Framework v5.0.0 Enhanced Edition
        </div>
    </div>
</body>
</html>
EOF

    ok "Interactive HTML dashboard generated: $dashboard_file"
    info "Open in browser: file://$dashboard_file"
}

generate_summary() {
    local query="$1"
    local output_dir="$2"
    local ip_count="$3"
    local httpx_file="$4"
    local nuclei_file="$5"
    local summary_file="$6"
    local session_id="${7:-unknown}"

    scan "Generating comprehensive summary report..."
    
    local performance_log="$output_dir/performance.log"
    local total_time="N/A"
    
    # Extract total time from performance log if available
    if [[ -f "$performance_log" ]]; then
        total_time=$(grep "Total session time:" "$performance_log" | awk '{print $4}' || echo "N/A")
    fi
    
    {
        echo "${EMOJI_CHART}${EMOJI_CHART}${EMOJI_CHART} VPS RECONNAISSANCE REPORT ${EMOJI_CHART}${EMOJI_CHART}${EMOJI_CHART}"
        echo "================================================================"
        echo "${EMOJI_TARGET} Query: $query"
        echo "${EMOJI_HOURGLASS} Timestamp: $(date)"
        echo "${EMOJI_ROCKET} Session ID: $session_id"
        echo "${EMOJI_GEAR} Framework Version: VPS-SQRY v5.0.0 Enhanced Edition"
        echo "${EMOJI_BOLT} Total Execution Time: $total_time"
        echo "================================================================"
        echo
        echo "${EMOJI_SUCCESS} === SCAN RESULTS SUMMARY ==="
        echo "${EMOJI_CHART} Total Unique IPs Discovered: $ip_count"
        echo "${EMOJI_FIRE} Enhanced Features Utilized:"
        echo "  ${EMOJI_CHECKMARK} Intelligent IP extraction with real-time validation"
        echo "  ${EMOJI_CHECKMARK} Enhanced network connectivity pre-testing"
        echo "  ${EMOJI_CHECKMARK} Auto-optimized thread calculation based on system resources"
        echo "  ${EMOJI_CHECKMARK} Beautiful progress bars and loading animations"
        echo "  ${EMOJI_CHECKMARK} Real-time performance monitoring and statistics"
        echo "  ${EMOJI_CHECKMARK} Interactive HTML dashboard generation"
        echo "  ${EMOJI_CHECKMARK} Comprehensive verbose output and detailed logging"
        echo
        echo "${EMOJI_CHART} === FILE LOCATIONS ==="
        echo "${EMOJI_SEARCH} Raw sqry output: $output_dir/sqry_raw.txt"
        echo "${EMOJI_TARGET} Validated IP list: $output_dir/ips.txt"
        echo "${EMOJI_BOLT} Connectivity tests: $output_dir/connectivity/"
        echo "${EMOJI_CHART} HTML dashboard: $output_dir/dashboard.html"
        echo "${EMOJI_GEAR} Performance log: $output_dir/performance.log"
        echo "${EMOJI_SUCCESS} Summary report: $output_dir/summary.txt"
        echo
        echo "${EMOJI_ROCKET} === NEXT STEPS ==="
        echo "${EMOJI_INFO} 1. Review interactive HTML dashboard for visual analysis"
        echo "${EMOJI_INFO} 2. Examine detailed connectivity test results"
        echo "${EMOJI_INFO} 3. Use discovered IPs for advanced security testing"
        echo "${EMOJI_INFO} 4. Analyze performance metrics for optimization"
        echo "${EMOJI_INFO} 5. Open HTML dashboard: file://$output_dir/dashboard.html"
        echo
        echo "================================================================"
        echo "${EMOJI_SUCCESS} VPS-SQRY Enhanced Edition - Reconnaissance Complete!"
        echo "================================================================"
    } > "$summary_file"

    # Generate enhanced HTML dashboard
    generate_html_dashboard "$query" "$output_dir" "$ip_count" "$session_id"
    generate_security_report "$output_dir" "$session_id"

    result "Comprehensive summary report generated: $summary_file"
}

# ========= SECURITY REPORT GENERATION =========
generate_security_report() {
    local output_dir="$1"
    local session_id="$2"
    local security_report="$output_dir/security_report.txt"
    
    scan "Generating security compliance report..."
    
    {
        echo "=== VPS-SQRY SECURITY COMPLIANCE REPORT ==="
        echo "Session ID: $session_id"
        echo "Timestamp: $(date)"
        echo "Framework Version: VPS-SQRY v6.0.0 Enhanced Security Edition"
        echo "========================================="
        echo
        echo "SECURITY FEATURES ACTIVE:"
        echo
        
        # Security state reporting
        if (( ${SECURITY_STATE["tor_verified"]} )); then
            echo "[✓] Tor anonymization: ACTIVE"
            echo "    Exit IP: $(get_current_ip)"
        else
            echo "[✗] Tor anonymization: DISABLED"
            echo "    Direct IP: $(get_current_ip)"
        fi
        
        if (( ${SECURITY_STATE["auth_verified"]} )); then
            echo "[✓] Target authorization: VERIFIED"
        elif (( ! REQUIRE_AUTHORIZATION )); then
            echo "[⚠] Target authorization: DISABLED"
        else
            echo "[✗] Target authorization: FAILED"
        fi
        
        if (( ${SECURITY_STATE["logging_enabled"]} )); then
            echo "[✓] Secure logging: ENABLED"
            echo "    Log file: $SECURE_LOG_FILE"
        else
            echo "[✗] Secure logging: DISABLED"
        fi
        
        echo "[✓] Input sanitization: ACTIVE"
        echo "[✓] Rate limiting: ACTIVE ($MAX_SCAN_RATE req/sec)"
        echo "[✓] IP validation: ACTIVE"
        echo "[✓] Privilege escalation checks: PASSED"
        echo "[✓] Tool integrity verification: PASSED"
        
        echo
        echo "SCAN PARAMETERS:"
        echo "- Query: $(sanitize_log \"${ARG_PARAMS["query"]}\")"
        echo "- Output directory: ${ARG_PARAMS["output_dir"]}"
        echo "- Max scan rate: $MAX_SCAN_RATE req/sec"
        echo "- Private IP scanning: $([[ -n "${ARG_FLAGS["allow_private"]}" ]] && echo "ENABLED" || echo "DISABLED")"
        echo "- Authorization required: $([[ $REQUIRE_AUTHORIZATION -eq 1 ]] && echo "YES" || echo "NO")"
        
        echo
        echo "RESPONSIBLE DISCLOSURE:"
        echo "- This tool is intended for authorized security testing only"
        echo "- Users must obtain explicit permission before scanning targets"
        echo "- Results should be handled according to responsible disclosure practices"
        echo "- Comply with all applicable laws and regulations"
        
        echo
        echo "========================================="
        echo "Report generated by VPS-SQRY v6.0.0 Enhanced Security Edition"
        echo "========================================="
        
    } > "$security_report"
    
    ok "Security compliance report generated: $security_report"
}

# ========= ENHANCED MAIN EXECUTION =========
main() {
    # Parse command line arguments
    parse_arguments "$@"

    # Load parameters
    local query="${ARG_PARAMS["query"]}"
    local output_dir="${ARG_PARAMS["output_dir"]}"
    local ports="${ARG_PARAMS["ports"]:-$DEFAULT_PORTS}"

    # Check flags
    local verbose=${ARG_FLAGS["verbose"]:-0}
    local debug=${ARG_FLAGS["debug"]:-0}
    local smart_scan=${ARG_FLAGS["smart_scan"]:-0}
    local full_scan=${ARG_FLAGS["full_scan"]:-0}

    # Set debug mode if enabled
    if (( debug )); then
        set -x
        verbose=1
    fi

    # Display enhanced banner
    print_banner
    
    # ========= SECURITY INITIALIZATION =========
    print_section_header "SECURITY VALIDATION SUITE" "${EMOJI_SHIELD}"
    
    # Initialize secure logging
    if (( LOG_ALL_ACTIVITIES )); then
        mkdir -p "$(dirname "$SECURE_LOG_FILE")"
        touch "$SECURE_LOG_FILE"
        chmod 600 "$SECURE_LOG_FILE"
        SECURITY_STATE["logging_enabled"]=1
        ok "Secure logging initialized: $SECURE_LOG_FILE"
    fi
    
    # Perform security checks
    security "Performing comprehensive security validation..."
    
    if ! check_privilege_escalation; then
        die "Security validation failed - aborting for safety"
    fi
    
    if ! verify_tool_integrity; then
        die "Tool integrity check failed - aborting"
    fi
    
    # Setup Tor if enabled
    if ! setup_tor_proxy; then
        die "Tor proxy setup failed"
    fi
    
    # Validate target authorization
    if ! create_authorized_networks_template; then
        if (( REQUIRE_AUTHORIZATION )); then
            die "Please configure authorized networks before proceeding"
        fi
    fi
    
    if ! validate_target_authorization "$query"; then
        die "Target authorization validation failed"
    fi
    
    security "All security checks passed - proceeding with scan"
    
    # Display current IP for verification
    local current_ip=$(get_current_ip)
    status "Current scanning IP: $current_ip"
    
    if (( TOR_ENABLED )); then
        ok "Tor anonymization is active"
    else
        warn "Scanning from direct IP connection"
    fi
    
    # System optimization
    optimize_system_limits "$verbose"
    
    # Calculate optimal threads with verbose output if requested
    local threads="${ARG_PARAMS["threads"]:-$(calc_optimal_threads "$verbose")}"
    
    # Enhanced startup information
    print_section_header "VPS RECONNAISSANCE MISSION INITIATED" "${EMOJI_ROCKET}"
    
    status "Mission parameters configured:"
    echo -e "  ${BC}${EMOJI_TARGET} Target query: \"$query\"${N}"
    echo -e "  ${BC}${EMOJI_CHART} Output directory: $output_dir${N}"
    echo -e "  ${BC}${EMOJI_BOLT} Parallel threads: $threads (system-optimized)${N}"
    echo -e "  ${BC}${EMOJI_GEAR} Target ports: $ports${N}"
    echo -e "  ${BC}${EMOJI_INFO} Verbose mode: $([[ $verbose -eq 1 ]] && echo "${BG}Enabled${N}" || echo "${BR}Disabled${N}")${N}"
    echo -e "  ${BC}${EMOJI_INFO} Debug mode: $([[ $debug -eq 1 ]] && echo "${BG}Enabled${N}" || echo "${BR}Disabled${N}")${N}"
    
    if (( verbose )); then
        echo
        status "Enhanced features active:"
        echo -e "  ${BG}${EMOJI_SUCCESS} Real-time progress monitoring${N}"
        echo -e "  ${BG}${EMOJI_SUCCESS} Beautiful loading animations${N}"
        echo -e "  ${BG}${EMOJI_SUCCESS} Live performance statistics${N}"
        echo -e "  ${BG}${EMOJI_SUCCESS} Intelligent resource optimization${N}"
        echo -e "  ${BG}${EMOJI_SUCCESS} Comprehensive verbose output${N}"
    fi
    
    # Start performance monitoring if verbose
    local monitor_file="$output_dir/.monitor"
    if (( verbose )); then
        touch "$monitor_file"
        monitor_system_performance "$monitor_file" 2 &
        local monitor_pid=$!
    fi
    
    # Execute enhanced reconnaissance
    local scan_start=$(date +%s)
    
    run_recon "$query" "$output_dir" "$threads" "$ports"
    local scan_status=$?
    
    local scan_end=$(date +%s)
    local total_duration=$((scan_end - scan_start))
    
    # Stop performance monitoring
    if (( verbose )); then
        rm -f "$monitor_file"
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
    fi
    
    # Enhanced completion summary
    if [[ $scan_status -eq 0 ]]; then
        print_section_header "MISSION ACCOMPLISHED" "${EMOJI_SUCCESS}"
        
        result "VPS reconnaissance completed successfully in ${total_duration}s!"
        
        if (( verbose )); then
            echo -e "  ${BC}${EMOJI_CHART} Performance: $(($(wc -l < "$output_dir/ips.txt" 2>/dev/null || echo 0) / (total_duration + 1))) IPs/s${N}"
            echo -e "  ${BC}${EMOJI_CHART} Efficiency: Optimized for maximum throughput${N}"
        fi
        
        echo
        status "Generated reports and dashboards:"
        
        # Show comprehensive file listing
        if [[ -f "$output_dir/summary.txt" ]]; then
            echo -e "  ${BG}${EMOJI_CHART} Comprehensive summary: ${BC}cat $output_dir/summary.txt${N}"
        fi
        
        if [[ -f "$output_dir/dashboard.html" ]]; then
            echo -e "  ${BG}${EMOJI_CHART} Interactive dashboard: ${BC}file://$output_dir/dashboard.html${N}"
            echo -e "  ${BG}${EMOJI_ROCKET} Quick open: ${BC}xdg-open $output_dir/dashboard.html${N}"
        fi
        
        if [[ -f "$output_dir/performance.log" ]]; then
            echo -e "  ${BG}${EMOJI_GEAR} Performance metrics: ${BC}cat $output_dir/performance.log${N}"
        fi
        
        echo
        print_section_header "THANK YOU FOR USING VPS-SQRY v${VERSION}" "${EMOJI_FIRE}"
        echo -e "${BG}${EMOJI_ROCKET} Enhanced Edition - Built for Speed, Designed for Beauty ${EMOJI_ROCKET}${N}"
        
    else
        print_section_header "MISSION ENCOUNTERED ISSUES" "${EMOJI_WARNING}"
        error "VPS reconnaissance completed with errors after ${total_duration}s"
        echo -e "${BY}${EMOJI_INFO} Check output files for details: $output_dir${N}"
    fi
}

# ========= MAIN EXECUTION =========
main "$@"
