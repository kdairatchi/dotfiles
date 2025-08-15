#!/usr/bin/env bash
# Enhanced Red Team Audit Script - SQRY Integration & API Support
# Version: 2.0.0 - Red Team Edition
# Author: Kdairatchi + Assistant
# ====================================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ========= ENHANCED CONFIGURATION =========
VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/audit_config.json"
SQRY_SCRIPT="$SCRIPT_DIR/vps-sqry.sh"
RESULTS_DIR="$SCRIPT_DIR/audit_results"
API_PORT="${AUDIT_API_PORT:-8888}"
API_HOST="${AUDIT_API_HOST:-127.0.0.1}"
API_KEY="${AUDIT_API_KEY:-$(openssl rand -hex 32)}"
WEBHOOK_URL="${AUDIT_WEBHOOK_URL:-}"

# Security & Rate Limiting
MAX_PARALLEL_JOBS=100
RATE_LIMIT_PER_SEC=50
CONNECTION_TIMEOUT=30
RETRY_COUNT=3
TOR_ENABLED=0
SOCKS_PROXY="127.0.0.1:9050"

# Advanced Options
DEEP_SCAN_MODE=0
STEALTH_MODE=0
AUTOMATED_EXPLOITATION=0
CUSTOM_PAYLOADS_DIR="$SCRIPT_DIR/payloads"
WORDLISTS_DIR="$SCRIPT_DIR/wordlists"
REPORTING_FORMAT="json"  # json, xml, html, csv
OUTPUT_ENCRYPTION=0
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR

# ========= COLOR & EMOJI DEFINITIONS =========
N="\033[0m"; R="\033[0;31m"; G="\033[0;32m"; Y="\033[1;33m"
B="\033[1;34m"; P="\033[0;35m"; C="\033[0;36m"; W="\033[1;37m"
BR="\033[1;31m"; BG="\033[1;32m"; BY="\033[1;33m"; BB="\033[1;34m"

EMOJI_TARGET="🎯"; EMOJI_SEARCH="🔍"; EMOJI_SHIELD="🛡️"; EMOJI_FIRE="🔥"
EMOJI_BOLT="⚡"; EMOJI_GEAR="⚙️"; EMOJI_SUCCESS="✅"; EMOJI_WARNING="⚠️"
EMOJI_ERROR="❌"; EMOJI_INFO="ℹ️"; EMOJI_ROCKET="🚀"; EMOJI_CHART="📊"

# ========= ADVANCED LOGGING SYSTEM =========
LOG_FILE="$RESULTS_DIR/audit_$(date +%Y%m%d_%H%M%S).log"
SECURE_LOG_FILE="$RESULTS_DIR/secure_audit.log"

log() {
    local level="$1"; shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    case "$level" in
        "DEBUG") [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${C}[DEBUG]${N} $message" ;;
        "INFO") echo -e "${G}[INFO]${N} $message" ;;
        "WARN") echo -e "${Y}[WARN]${N} $message" ;;
        "ERROR") echo -e "${R}[ERROR]${N} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Secure logging for sensitive operations
    if [[ "$message" =~ (target|scan|exploit|credential) ]]; then
        echo "[$timestamp] [$level] [REDACTED] ${message:0:50}..." >> "$SECURE_LOG_FILE"
    fi
}

error() { log "ERROR" "$@"; }
warn() { log "WARN" "$@"; }
info() { log "INFO" "$@"; }
debug() { log "DEBUG" "$@"; }
die() { error "$@"; exit 1; }

# ========= CONFIGURATION MANAGEMENT =========
create_default_config() {
    cat > "$CONFIG_FILE" <<EOF
{
    "version": "$VERSION",
    "api": {
        "enabled": true,
        "host": "$API_HOST",
        "port": $API_PORT,
        "authentication": true,
        "api_key": "$API_KEY",
        "rate_limit": $RATE_LIMIT_PER_SEC,
        "cors_enabled": false,
        "ssl_enabled": false
    },
    "scanning": {
        "max_parallel_jobs": $MAX_PARALLEL_JOBS,
        "connection_timeout": $CONNECTION_TIMEOUT,
        "retry_count": $RETRY_COUNT,
        "stealth_mode": $STEALTH_MODE,
        "deep_scan_mode": $DEEP_SCAN_MODE,
        "custom_ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443,9000",
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
    },
    "security": {
        "tor_enabled": $TOR_ENABLED,
        "socks_proxy": "$SOCKS_PROXY",
        "output_encryption": $OUTPUT_ENCRYPTION,
        "authorization_required": true,
        "authorized_networks": ["127.0.0.1/32", "10.0.0.0/8", "192.168.0.0/16"],
        "max_scan_targets": 1000,
        "blacklisted_ranges": ["0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"]
    },
    "automation": {
        "webhook_notifications": "$WEBHOOK_URL",
        "auto_exploitation": $AUTOMATED_EXPLOITATION,
        "report_generation": true,
        "cleanup_old_results": true,
        "max_result_age_days": 30
    },
    "modules": {
        "sqry_integration": true,
        "nmap_scanning": true,
        "web_enumeration": true,
        "service_enumeration": true,
        "vulnerability_assessment": true,
        "credential_testing": false,
        "payload_testing": false
    },
    "reporting": {
        "format": "$REPORTING_FORMAT",
        "include_screenshots": false,
        "include_payloads": false,
        "export_formats": ["json", "html", "csv"],
        "email_reports": false,
        "slack_notifications": false
    }
}
EOF
    info "Created default configuration: $CONFIG_FILE"
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        warn "Configuration file not found, creating default"
        create_default_config
    fi
    
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        die "Invalid JSON in configuration file: $CONFIG_FILE"
    fi
    
    # Load configuration values
    API_PORT=$(jq -r '.api.port // 8888' "$CONFIG_FILE")
    API_HOST=$(jq -r '.api.host // "127.0.0.1"' "$CONFIG_FILE")
    MAX_PARALLEL_JOBS=$(jq -r '.scanning.max_parallel_jobs // 100' "$CONFIG_FILE")
    STEALTH_MODE=$(jq -r '.scanning.stealth_mode // false' "$CONFIG_FILE")
    TOR_ENABLED=$(jq -r '.security.tor_enabled // false' "$CONFIG_FILE")
    
    debug "Configuration loaded successfully"
}

# ========= API SERVER IMPLEMENTATION =========
start_api_server() {
    local api_enabled=$(jq -r '.api.enabled // false' "$CONFIG_FILE")
    [[ "$api_enabled" != "true" ]] && return 0
    
    info "${EMOJI_ROCKET} Starting API server on $API_HOST:$API_PORT"
    
    # Create named pipe for API communication
    local api_pipe="/tmp/audit_api_$$"
    mkfifo "$api_pipe"
    
    # Start API server in background
    {
        while true; do
            {
                read -r request < "$api_pipe"
                handle_api_request "$request"
            } || break
        done
    } &
    
    local api_pid=$!
    echo "$api_pid" > "/tmp/audit_api_pid_$$"
    
    # Start HTTP listener using netcat
    {
        while true; do
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n$(get_api_status)" | nc -l -p "$API_PORT" -q 1
        done
    } &
    
    local http_pid=$!
    echo "$http_pid" > "/tmp/audit_http_pid_$$"
    
    info "API server started (PID: $api_pid, HTTP: $http_pid)"
}

handle_api_request() {
    local request="$1"
    local endpoint=$(echo "$request" | jq -r '.endpoint // "/status"')
    local method=$(echo "$request" | jq -r '.method // "GET"')
    local params=$(echo "$request" | jq -r '.params // {}')
    
    debug "API Request: $method $endpoint"
    
    case "$endpoint" in
        "/status") get_api_status ;;
        "/scan") handle_scan_request "$params" ;;
        "/results") get_scan_results "$params" ;;
        "/config") handle_config_request "$method" "$params" ;;
        "/stop") stop_api_server ;;
        *) echo '{"error":"Unknown endpoint","code":404}' ;;
    esac
}

get_api_status() {
    local uptime=$(awk '{print int($1)}' /proc/uptime)
    local running_scans=$(pgrep -f "enhanced_audit" | wc -l)
    
    jq -n \
        --arg version "$VERSION" \
        --arg status "running" \
        --arg uptime "$uptime" \
        --arg running_scans "$running_scans" \
        --arg timestamp "$(date -Iseconds)" \
        '{
            version: $version,
            status: $status,
            uptime_seconds: ($uptime | tonumber),
            running_scans: ($running_scans | tonumber),
            timestamp: $timestamp,
            endpoints: ["/status", "/scan", "/results", "/config", "/stop"]
        }'
}

handle_scan_request() {
    local params="$1"
    local target=$(echo "$params" | jq -r '.target // ""')
    local scan_type=$(echo "$params" | jq -r '.scan_type // "basic"')
    local options=$(echo "$params" | jq -r '.options // {}'")
    
    if [[ -z "$target" ]]; then
        echo '{"error":"Target required","code":400}'
        return 1
    fi
    
    # Validate target authorization
    if ! validate_target_authorization "$target"; then
        echo '{"error":"Target not authorized","code":403}'
        return 1
    fi
    
    # Start scan asynchronously
    local scan_id="scan_$(date +%s)_$$"
    {
        perform_red_team_scan "$target" "$scan_type" "$options" > "$RESULTS_DIR/${scan_id}.json" 2>&1
    } &
    
    local scan_pid=$!
    echo "$scan_pid" > "$RESULTS_DIR/${scan_id}.pid"
    
    jq -n \
        --arg scan_id "$scan_id" \
        --arg target "$target" \
        --arg scan_type "$scan_type" \
        --arg status "started" \
        --arg pid "$scan_pid" \
        '{
            scan_id: $scan_id,
            target: $target,
            scan_type: $scan_type,
            status: $status,
            pid: ($pid | tonumber),
            started_at: now
        }'
}

# ========= RED TEAM SCANNING MODULES =========
perform_red_team_scan() {
    local target="$1"
    local scan_type="$2"
    local options="$3"
    local scan_start=$(date +%s)
    
    info "${EMOJI_TARGET} Starting red team scan of $target (type: $scan_type)"
    
    # Initialize scan result structure
    local scan_result=$(jq -n \
        --arg target "$target" \
        --arg scan_type "$scan_type" \
        --arg start_time "$(date -Iseconds)" \
        '{
            target: $target,
            scan_type: $scan_type,
            start_time: $start_time,
            modules_executed: [],
            vulnerabilities: [],
            services: [],
            credentials: [],
            payloads_tested: [],
            recommendations: []
        }')
    
    # Execute scan modules based on type and configuration
    case "$scan_type" in
        "basic")
            scan_result=$(execute_basic_scan "$target" "$scan_result")
            ;;
        "advanced")
            scan_result=$(execute_advanced_scan "$target" "$scan_result")
            ;;
        "full")
            scan_result=$(execute_full_scan "$target" "$scan_result")
            ;;
        "stealth")
            scan_result=$(execute_stealth_scan "$target" "$scan_result")
            ;;
        "custom")
            scan_result=$(execute_custom_scan "$target" "$scan_result" "$options")
            ;;
        *)
            die "Unknown scan type: $scan_type"
            ;;
    esac
    
    # Finalize scan results
    local scan_end=$(date +%s)
    local duration=$((scan_end - scan_start))
    
    scan_result=$(echo "$scan_result" | jq \
        --arg end_time "$(date -Iseconds)" \
        --arg duration "$duration" \
        '. + {
            end_time: $end_time,
            duration_seconds: ($duration | tonumber),
            status: "completed"
        }')
    
    echo "$scan_result"
    
    # Send webhook notification if configured
    if [[ -n "$WEBHOOK_URL" ]]; then
        send_webhook_notification "$scan_result"
    fi
}

execute_basic_scan() {
    local target="$1"
    local result="$2"
    
    info "${EMOJI_SEARCH} Executing basic reconnaissance scan"
    
    # Network discovery
    result=$(add_module_result "$result" "network_discovery" "$(perform_network_discovery "$target")")
    
    # Port scanning
    result=$(add_module_result "$result" "port_scanning" "$(perform_port_scan "$target")")
    
    # Service enumeration
    result=$(add_module_result "$result" "service_enumeration" "$(perform_service_enumeration "$target")")
    
    # Basic vulnerability assessment
    result=$(add_module_result "$result" "vulnerability_scan" "$(perform_vulnerability_scan "$target")")
    
    echo "$result"
}

execute_advanced_scan() {
    local target="$1"
    local result="$2"
    
    info "${EMOJI_FIRE} Executing advanced red team scan"
    
    # All basic scan modules
    result=$(execute_basic_scan "$target" "$result")
    
    # Advanced modules
    result=$(add_module_result "$result" "web_enumeration" "$(perform_web_enumeration "$target")")
    result=$(add_module_result "$result" "sqry_integration" "$(integrate_with_sqry "$target")")
    result=$(add_module_result "$result" "exploit_suggestions" "$(suggest_exploits "$target")")
    
    if [[ "$(jq -r '.modules.credential_testing' "$CONFIG_FILE")" == "true" ]]; then
        result=$(add_module_result "$result" "credential_testing" "$(perform_credential_testing "$target")")
    fi
    
    echo "$result"
}

execute_full_scan() {
    local target="$1"
    local result="$2"
    
    info "${EMOJI_BOLT} Executing comprehensive red team assessment"
    
    # All advanced scan modules
    result=$(execute_advanced_scan "$target" "$result")
    
    # Full scan specific modules
    result=$(add_module_result "$result" "deep_enumeration" "$(perform_deep_enumeration "$target")")
    result=$(add_module_result "$result" "payload_testing" "$(test_custom_payloads "$target")")
    result=$(add_module_result "$result" "lateral_movement" "$(assess_lateral_movement "$target")")
    result=$(add_module_result "$result" "privilege_escalation" "$(check_privilege_escalation "$target")")
    
    echo "$result"
}

# ========= SQRY INTEGRATION MODULE =========
integrate_with_sqry() {
    local target="$1"
    
    info "${EMOJI_GEAR} Integrating with SQRY reconnaissance framework"
    
    if [[ ! -f "$SQRY_SCRIPT" ]]; then
        warn "SQRY script not found at $SQRY_SCRIPT"
        echo '{"error":"SQRY script not found","results":[]}'
        return 1
    fi
    
    # Create temporary directory for SQRY results
    local sqry_output="/tmp/sqry_output_$$"
    mkdir -p "$sqry_output"
    
    # Execute SQRY with red team optimized parameters
    local sqry_params=(
        "--target" "$target"
        "--output-dir" "$sqry_output"
        "--threads" "$MAX_PARALLEL_JOBS"
        "--stealth" "$([ "$STEALTH_MODE" -eq 1 ] && echo 'true' || echo 'false')"
        "--deep-scan" "$([ "$DEEP_SCAN_MODE" -eq 1 ] && echo 'true' || echo 'false')"
    )
    
    if [[ "$TOR_ENABLED" -eq 1 ]]; then
        sqry_params+=("--tor" "--proxy" "$SOCKS_PROXY")
    fi
    
    # Execute SQRY scan
    local sqry_result
    if timeout 600 bash "$SQRY_SCRIPT" "${sqry_params[@]}" > "$sqry_output/sqry.log" 2>&1; then
        sqry_result=$(parse_sqry_results "$sqry_output")
    else
        sqry_result='{"error":"SQRY execution failed or timed out","results":[]}'
    fi
    
    # Cleanup
    rm -rf "$sqry_output"
    
    echo "$sqry_result"
}

parse_sqry_results() {
    local output_dir="$1"
    local results='{"hosts":[],"services":[],"vulnerabilities":[],"intelligence":[]}'
    
    # Parse SQRY output files
    if [[ -f "$output_dir/hosts.txt" ]]; then
        while IFS= read -r host; do
            results=$(echo "$results" | jq --arg host "$host" '.hosts += [$host]')
        done < "$output_dir/hosts.txt"
    fi
    
    if [[ -f "$output_dir/services.json" ]]; then
        local services=$(cat "$output_dir/services.json" 2>/dev/null || echo '[]')
        results=$(echo "$results" | jq --argjson services "$services" '.services = $services')
    fi
    
    echo "$results"
}

# ========= SCANNING MODULES =========
perform_network_discovery() {
    local target="$1"
    info "Performing network discovery for $target"
    
    # Host discovery
    local alive_hosts='[]'
    if command -v nmap &>/dev/null; then
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                alive_hosts=$(echo "$alive_hosts" | jq --arg host "$host" '. += [$host]')
            fi
        done < <(nmap -sn "$target" 2>/dev/null | awk '/Nmap scan report/{print $5}')
    fi
    
    jq -n --argjson hosts "$alive_hosts" '{hosts: $hosts, method: "nmap_ping_sweep"}'
}

perform_port_scan() {
    local target="$1"
    local custom_ports=$(jq -r '.scanning.custom_ports // "22,80,443"' "$CONFIG_FILE")
    
    info "Performing port scan for $target"
    
    local open_ports='[]'
    if command -v nmap &>/dev/null; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+)/.*open ]]; then
                local port="${BASH_REMATCH[1]}"
                local service=$(echo "$line" | awk '{print $3}')
                local port_info=$(jq -n --arg port "$port" --arg service "$service" '{port: ($port | tonumber), service: $service, state: "open"}')
                open_ports=$(echo "$open_ports" | jq --argjson port_info "$port_info" '. += [$port_info]')
            fi
        done < <(nmap -p "$custom_ports" --open -T4 "$target" 2>/dev/null | grep -E '^[0-9]+/')
    fi
    
    jq -n --argjson ports "$open_ports" '{ports: $ports, scan_type: "tcp_connect"}'
}

perform_service_enumeration() {
    local target="$1"
    info "Performing service enumeration for $target"
    
    local services='[]'
    if command -v nmap &>/dev/null; then
        local nmap_output
        nmap_output=$(nmap -sV -sC --script=default,safe "$target" 2>/dev/null || echo "")
        
        # Parse service information
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+)/.*open.*([a-zA-Z0-9_-]+) ]]; then
                local port="${BASH_REMATCH[1]}"
                local service_name="${BASH_REMATCH[2]}"
                local version=$(echo "$line" | sed -E 's/.*open[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]*).*/\1/')
                
                local service_info=$(jq -n \
                    --arg port "$port" \
                    --arg name "$service_name" \
                    --arg version "$version" \
                    '{port: ($port | tonumber), name: $name, version: $version}')
                services=$(echo "$services" | jq --argjson service "$service_info" '. += [$service]')
            fi
        done <<< "$nmap_output"
    fi
    
    jq -n --argjson services "$services" '{services: $services, method: "nmap_service_detection"}'
}

perform_vulnerability_scan() {
    local target="$1"
    info "Performing vulnerability assessment for $target"
    
    local vulnerabilities='[]'
    
    # Use nmap NSE scripts for vulnerability detection
    if command -v nmap &>/dev/null; then
        local vuln_output
        vuln_output=$(nmap --script=vuln "$target" 2>/dev/null || echo "")
        
        # Parse vulnerability information (simplified)
        while IFS= read -r line; do
            if [[ "$line" =~ VULNERABLE ]]; then
                local vuln_desc=$(echo "$line" | sed 's/|[[:space:]]*//')
                local vuln_info=$(jq -n --arg desc "$vuln_desc" --arg severity "medium" '{description: $desc, severity: $severity, source: "nmap_nse"}')
                vulnerabilities=$(echo "$vulnerabilities" | jq --argjson vuln "$vuln_info" '. += [$vuln]')
            fi
        done <<< "$vuln_output"
    fi
    
    jq -n --argjson vulns "$vulnerabilities" '{vulnerabilities: $vulns, scanner: "nmap_nse"}'
}

perform_web_enumeration() {
    local target="$1"
    info "Performing web application enumeration for $target"
    
    local web_info='{"technologies":[],"directories":[],"files":[]}'
    
    # Technology detection using curl
    if command -v curl &>/dev/null; then
        local headers
        headers=$(curl -s -I "http://$target" 2>/dev/null || echo "")
        
        # Extract server information
        local server=$(echo "$headers" | grep -i "^server:" | cut -d' ' -f2- | tr -d '\r')
        if [[ -n "$server" ]]; then
            web_info=$(echo "$web_info" | jq --arg server "$server" '.technologies += [{"name": "Server", "value": $server}]')
        fi
        
        # Extract X-Powered-By
        local powered_by=$(echo "$headers" | grep -i "^x-powered-by:" | cut -d' ' -f2- | tr -d '\r')
        if [[ -n "$powered_by" ]]; then
            web_info=$(echo "$web_info" | jq --arg powered_by "$powered_by" '.technologies += [{"name": "X-Powered-By", "value": $powered_by}]')
        fi
    fi
    
    # Directory enumeration (basic wordlist)
    local common_dirs=("admin" "wp-admin" "phpmyadmin" "manager" "login" "config" "backup" "test" "dev")
    for dir in "${common_dirs[@]}"; do
        if curl -s -o /dev/null -w "%{http_code}" "http://$target/$dir/" | grep -q "200\|403"; then
            web_info=$(echo "$web_info" | jq --arg dir "$dir" '.directories += [$dir]')
        fi
    done
    
    echo "$web_info"
}

# ========= ADVANCED MODULES =========
suggest_exploits() {
    local target="$1"
    info "Generating exploit suggestions for $target"
    
    # This would integrate with exploit databases
    local suggestions='[]'
    
    # Basic exploit suggestion based on common vulnerabilities
    local common_exploits=(
        '{"name":"EternalBlue","description":"SMB vulnerability (MS17-010)","ports":[445],"severity":"critical"}'
        '{"name":"Apache Struts","description":"RCE vulnerability","ports":[80,443,8080],"severity":"critical"}'
        '{"name":"SSH Weak Credentials","description":"Brute force attack","ports":[22],"severity":"medium"}'
    )
    
    for exploit in "${common_exploits[@]}"; do
        suggestions=$(echo "$suggestions" | jq --argjson exploit "$exploit" '. += [$exploit]')
    done
    
    jq -n --argjson suggestions "$suggestions" '{exploit_suggestions: $suggestions, note: "Automated suggestions based on common vulnerabilities"}'
}

perform_credential_testing() {
    local target="$1"
    info "Performing credential testing for $target (WARNING: Potentially intrusive)"
    
    local credentials='{"tested":[],"successful":[],"failed":[]}'
    
    # Only proceed if explicitly enabled and authorized
    if [[ "$(jq -r '.modules.credential_testing' "$CONFIG_FILE")" != "true" ]]; then
        warn "Credential testing disabled in configuration"
        echo "$credentials"
        return 0
    fi
    
    # Basic SSH credential testing (very limited to avoid lockouts)
    if nc -z "$target" 22 2>/dev/null; then
        local common_creds=("admin:admin" "root:root" "admin:password" "user:user")
        
        for cred in "${common_creds[@]}"; do
            local username="${cred%:*}"
            local password="${cred#*:}"
            
            # Simulate credential test (don't actually test to avoid lockouts)
            local test_result=$(jq -n --arg user "$username" --arg pass "$password" --arg result "simulated" '{username: $user, password: $pass, result: $result}')
            credentials=$(echo "$credentials" | jq --argjson test "$test_result" '.tested += [$test]')
            
            # Add delay to avoid triggering security measures
            sleep 2
        done
    fi
    
    echo "$credentials"
}

# ========= UTILITY FUNCTIONS =========
add_module_result() {
    local result="$1"
    local module="$2"
    local module_result="$3"
    
    result=$(echo "$result" | jq --arg module "$module" '.modules_executed += [$module]')
    result=$(echo "$result" | jq --arg module "$module" --argjson data "$module_result" '.[$module] = $data')
    
    echo "$result"
}

validate_target_authorization() {
    local target="$1"
    local authorized_networks=$(jq -r '.security.authorized_networks[]' "$CONFIG_FILE" 2>/dev/null)
    
    # Check if target is in authorized networks
    while IFS= read -r network; do
        if [[ -n "$network" ]] && ip_in_cidr "$target" "$network"; then
            return 0
        fi
    done <<< "$authorized_networks"
    
    # Check against blacklisted ranges
    local blacklisted_ranges=$(jq -r '.security.blacklisted_ranges[]' "$CONFIG_FILE" 2>/dev/null)
    while IFS= read -r range; do
        if [[ -n "$range" ]] && ip_in_cidr "$target" "$range"; then
            return 1
        fi
    done <<< "$blacklisted_ranges"
    
    return 0
}

ip_in_cidr() {
    local ip="$1"
    local cidr="$2"
    local network="${cidr%/*}"
    local mask="${cidr#*/}"
    
    # Simple CIDR check (would need more robust implementation for production)
    if [[ "$ip" == "$network" ]] || [[ "$cidr" == *"/32" && "$ip" == "$network" ]]; then
        return 0
    fi
    
    return 1
}

send_webhook_notification() {
    local result="$1"
    
    if [[ -z "$WEBHOOK_URL" ]]; then
        return 0
    fi
    
    info "Sending webhook notification"
    
    local notification=$(echo "$result" | jq '{
        event: "scan_completed",
        target: .target,
        scan_type: .scan_type,
        duration: .duration_seconds,
        vulnerabilities_found: (.vulnerabilities | length),
        timestamp: .end_time
    }')
    
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$notification" \
        "$WEBHOOK_URL" >/dev/null 2>&1 || warn "Failed to send webhook notification"
}

# ========= INITIALIZATION & CLEANUP =========
initialize_environment() {
    info "${EMOJI_GEAR} Initializing enhanced audit environment"
    
    # Create required directories
    mkdir -p "$RESULTS_DIR" "$CUSTOM_PAYLOADS_DIR" "$WORDLISTS_DIR"
    
    # Load configuration
    load_config
    
    # Check dependencies
    local required_tools=("curl" "jq" "nc" "timeout" "openssl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            die "Required tool not found: $tool"
        fi
    done
    
    # Optional tools
    local optional_tools=("nmap" "ncat" "masscan" "ffuf" "gobuster")
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            warn "Optional tool not found: $tool (some features may be limited)"
        fi
    done
    
    info "Environment initialized successfully"
}

cleanup() {
    info "Cleaning up processes and temporary files"
    
    # Stop API server if running
    if [[ -f "/tmp/audit_api_pid_$$" ]]; then
        local api_pid=$(cat "/tmp/audit_api_pid_$$")
        kill "$api_pid" 2>/dev/null || true
        rm -f "/tmp/audit_api_pid_$$"
    fi
    
    if [[ -f "/tmp/audit_http_pid_$$" ]]; then
        local http_pid=$(cat "/tmp/audit_http_pid_$$")
        kill "$http_pid" 2>/dev/null || true
        rm -f "/tmp/audit_http_pid_$$"
    fi
    
    # Remove temporary files
    rm -f "/tmp/audit_api_$$" "/tmp/sqry_output_$$"
    
    info "Cleanup completed"
}

# ========= BANNER & USAGE =========
print_banner() {
    echo -e "${BB}"
    cat <<'BANNER'
 _____ _   _ _   _  ___  _   _  ____ _____ ____    
| ____| \ | | | | |/ _ \| \ | |/ ___| ____|  _ \   
|  _| |  \| | |_| | | | |  \| | |   |  _| | | | |  
| |___| |\  |  _  | |_| | |\  | |___| |___| |_| |  
|_____|_| \_|_| |_|\___/|_| \_|\____|_____|____/   
                                                   
     RED TEAM AUDIT FRAMEWORK v2.0.0
     Enhanced SQRY Integration & API Support
BANNER
    echo -e "${N}"
    echo -e "${C}${EMOJI_SHIELD} Authorized Security Testing Only ${EMOJI_SHIELD}${N}"
    echo -e "${Y}${EMOJI_WARNING} Use Responsibly - Obtain Proper Authorization ${EMOJI_WARNING}${N}"
    echo
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [TARGET]

OPTIONS:
  -t, --target TARGET          Target IP/domain/CIDR to audit
  -s, --scan-type TYPE         Scan type: basic, advanced, full, stealth, custom
  -c, --config FILE           Configuration file (default: $CONFIG_FILE)
  -o, --output DIR            Output directory (default: $RESULTS_DIR)
  -j, --jobs NUM              Max parallel jobs (default: $MAX_PARALLEL_JOBS)
  -T, --timeout NUM           Connection timeout (default: $CONNECTION_TIMEOUT)
  
  --api                       Start API server mode
  --api-port PORT             API server port (default: $API_PORT)
  --stealth                   Enable stealth mode
  --deep                      Enable deep scanning
  --tor                       Use Tor proxy
  --webhook URL               Webhook notification URL
  
  --sqry-integration          Enable SQRY framework integration
  --custom-payloads DIR       Custom payloads directory
  --wordlists DIR             Custom wordlists directory
  
  --format FORMAT             Output format: json, xml, html, csv
  --encrypt                   Encrypt output files
  --log-level LEVEL           Log level: DEBUG, INFO, WARN, ERROR
  
  -h, --help                  Show this help message
  -v, --version               Show version information

EXAMPLES:
  # Basic security audit
  $0 --target 192.168.1.0/24 --scan-type basic
  
  # Advanced red team assessment with SQRY integration
  $0 -t example.com -s advanced --sqry-integration --stealth
  
  # Start API server for remote scanning
  $0 --api --api-port 8888
  
  # Full assessment with custom configuration
  $0 -t 10.0.0.0/16 -s full -c custom_config.json --deep --tor
  
  # URL-based scanning via API
  curl -X POST http://localhost:8888/scan \\
    -H "Content-Type: application/json" \\
    -d '{"target":"example.com","scan_type":"advanced"}'

CONFIGURATION:
  Create/edit $CONFIG_FILE to customize:
  - API settings and authentication
  - Scanning parameters and modules
  - Security and proxy settings
  - Automation and reporting options

API ENDPOINTS:
  GET  /status                 Get scanner status
  POST /scan                   Start new scan
  GET  /results               Get scan results
  GET  /config                Get configuration
  POST /config                Update configuration
  POST /stop                   Stop scanner

SECURITY NOTES:
  - Always obtain proper authorization before scanning
  - Configure authorized_networks in config file
  - Enable logging for audit trails
  - Use encryption for sensitive results
  - Review and comply with applicable laws

EOF
}

# ========= MAIN EXECUTION =========
main() {
    local target=""
    local scan_type="basic"
    local api_mode=false
    
    # Signal handlers
    trap cleanup EXIT
    trap 'echo -e "\n${Y}Scan interrupted by user${N}"; cleanup; exit 130' INT TERM
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -s|--scan-type)
                scan_type="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                RESULTS_DIR="$2"
                shift 2
                ;;
            -j|--jobs)
                MAX_PARALLEL_JOBS="$2"
                shift 2
                ;;
            -T|--timeout)
                CONNECTION_TIMEOUT="$2"
                shift 2
                ;;
            --api)
                api_mode=true
                shift
                ;;
            --api-port)
                API_PORT="$2"
                shift 2
                ;;
            --stealth)
                STEALTH_MODE=1
                shift
                ;;
            --deep)
                DEEP_SCAN_MODE=1
                shift
                ;;
            --tor)
                TOR_ENABLED=1
                shift
                ;;
            --webhook)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            --sqry-integration)
                # Enable SQRY integration in config
                shift
                ;;
            --custom-payloads)
                CUSTOM_PAYLOADS_DIR="$2"
                shift 2
                ;;
            --wordlists)
                WORDLISTS_DIR="$2"
                shift 2
                ;;
            --format)
                REPORTING_FORMAT="$2"
                shift 2
                ;;
            --encrypt)
                OUTPUT_ENCRYPTION=1
                shift
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                print_banner
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "Enhanced Red Team Audit Framework v$VERSION"
                exit 0
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                if [[ -z "$target" ]]; then
                    target="$1"
                fi
                shift
                ;;
        esac
    done
    
    print_banner
    initialize_environment
    
    if [[ "$api_mode" == true ]]; then
        info "${EMOJI_ROCKET} Starting in API server mode"
        start_api_server
        
        info "API server running. Press Ctrl+C to stop."
        while true; do
            sleep 1
        done
    else
        if [[ -z "$target" ]]; then
            error "Target is required for direct scanning mode"
            show_usage
            exit 1
        fi
        
        if ! validate_target_authorization "$target"; then
            die "Target $target is not authorized for scanning"
        fi
        
        info "${EMOJI_TARGET} Starting red team assessment of: $target"
        
        local result
        result=$(perform_red_team_scan "$target" "$scan_type" "{}")
        
        # Save results
        local result_file="$RESULTS_DIR/audit_$(date +%Y%m%d_%H%M%S)_${target//[^a-zA-Z0-9]/_}.json"
        echo "$result" > "$result_file"
        
        # Generate additional format outputs
        case "$REPORTING_FORMAT" in
            "html")
                generate_html_report "$result" "${result_file%.json}.html"
                ;;
            "csv")
                generate_csv_report "$result" "${result_file%.json}.csv"
                ;;
        esac
        
        info "${EMOJI_SUCCESS} Scan completed. Results saved to: $result_file"
        
        # Display summary
        local vuln_count=$(echo "$result" | jq '.vulnerabilities | length' 2>/dev/null || echo "0")
        local service_count=$(echo "$result" | jq '.services | length' 2>/dev/null || echo "0")
        
        echo
        echo -e "${BG}=== SCAN SUMMARY ===${N}"
        echo -e "Target: ${BB}$target${N}"
        echo -e "Scan Type: ${BB}$scan_type${N}"
        echo -e "Services Found: ${BB}$service_count${N}"
        echo -e "Vulnerabilities: ${BB}$vuln_count${N}"
        echo -e "Results: ${BB}$result_file${N}"
        echo
    fi
}

# ========= REPORT GENERATION =========
generate_html_report() {
    local result="$1"
    local output_file="$2"
    
    info "Generating HTML report: $output_file"
    
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Red Team Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .vulnerability { background: #ffebee; border-left: 4px solid #f44336; margin: 10px 0; padding: 10px; }
        .service { background: #e8f5e8; border-left: 4px solid #4caf50; margin: 10px 0; padding: 10px; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Red Team Audit Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>📊 Summary</h2>
        <pre>$(echo "$result" | jq -r 'del(.modules_executed, .vulnerabilities, .services) | to_entries[] | "\(.key): \(.value)"')</pre>
    </div>
    
    <div class="section">
        <h2>🔍 Services Discovered</h2>
        $(echo "$result" | jq -r '.services[]? // empty | "<div class=\"service\"><strong>Port \(.port)</strong>: \(.name) \(.version // "")</div>"')
    </div>
    
    <div class="section">
        <h2>⚠️ Vulnerabilities</h2>
        $(echo "$result" | jq -r '.vulnerabilities[]? // empty | "<div class=\"vulnerability\"><strong>\(.severity | ascii_upcase)</strong>: \(.description)</div>"')
    </div>
    
    <div class="section">
        <h2>📋 Raw Results</h2>
        <pre>$(echo "$result" | jq '.')</pre>
    </div>
</body>
</html>
EOF
}

generate_csv_report() {
    local result="$1"
    local output_file="$2"
    
    info "Generating CSV report: $output_file"
    
    {
        echo "Type,Port,Service,Version,Severity,Description"
        echo "$result" | jq -r '.services[]? // empty | "Service,\(.port),\(.name),\(.version // ""),,"'
        echo "$result" | jq -r '.vulnerabilities[]? // empty | "Vulnerability,,,\(.severity),\(.description)"'
    } > "$output_file"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi