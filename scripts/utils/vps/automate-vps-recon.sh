#!/usr/bin/env bash
# VPS Automation Script - Automated reconnaissance workflow orchestrator
# Author: Kdairatchi + Assistant
# Usage: ./automate-vps-recon.sh [options]

set -Eeuo pipefail
IFS=$'\n\t'

# ========= CONFIGURATION =========
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQRY_SCRIPT="$SCRIPT_DIR/vps-sqry.sh"
DEFAULT_QUERIES_FILE="$SCRIPT_DIR/vps_queries.txt"
OUTPUT_DIR="$HOME/vps_automation_results"
AUDIT_SCRIPT="$SCRIPT_DIR/audit.sh"

# ========= STYLING & LOGGING =========
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; N='\033[0m'
info() { echo -e "${G}[INFO]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
error() { echo -e "${R}[ERROR]${N} $*"; }
die() { error "$*"; exit 1; }
ok() { echo -e "${G}[OK]${N} $*"; }

# ========= CORE FUNCTIONS =========
check_dependencies() {
    info "Checking for dependencies..."
    if [[ ! -f "$SQRY_SCRIPT" ]]; then
        die "The main script '$SQRY_SCRIPT' was not found. Please ensure it's in the same directory."
    fi
    if [[ ! -x "$SQRY_SCRIPT" ]]; then
        warn "The main script '$SQRY_SCRIPT' is not executable. Attempting to fix..."
        chmod +x "$SQRY_SCRIPT" || die "Failed to make '$SQRY_SCRIPT' executable. Please do it manually."
        ok "Made '$SQRY_SCRIPT' executable."
    fi
    ok "Dependency check passed."
}

create_default_queries_file() {
    if [[ -f "$DEFAULT_QUERIES_FILE" ]]; then
        info "Default queries file already exists: $DEFAULT_QUERIES_FILE"
    else
        info "Creating default queries file: $DEFAULT_QUERIES_FILE"
        cat > "$DEFAULT_QUERIES_FILE" <<'EOF'
# === Default Shodan Queries for VPS Reconnaissance ===
# Lines starting with # are ignored. Add your own queries here.

# --- Common Web Server Default Pages ---
http.title:"Welcome to nginx"
http.title:"Apache2 Ubuntu Default Page"

# --- Common Admin Panels & Dashboards ---
http.title:"Portainer"
http.title:"Grafana"
http.title:"Jenkins"
http.title:"phpMyAdmin"
http.title:"Webmin"

# --- Exposed Services ---
port:22 "SSH-2.0-OpenSSH"
port:3389 "Terminal Services" product:"Microsoft"

# --- Container & Database Services ---
port:2375 "docker"
port:3306 "mysql"
port:5432 "postgresql"
port:27017 "mongodb"
port:6379 "redis"

# --- Monitoring & Metrics ---
port:9090 "prometheus"
port:9200 "elasticsearch"
EOF
        ok "Default queries file created successfully."
    fi
}

run_automated_recon() {
    local queries_file="${1:-$DEFAULT_QUERIES_FILE}"
    
    if [[ ! -f "$queries_file" ]]; then
        die "Queries file not found: $queries_file"
    fi

    info "Starting automated reconnaissance using query file: $queries_file"
    warn "This process may take a long time depending on the number of queries."

    local base_run_dir="$OUTPUT_DIR/batch_recon_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$base_run_dir"
    info "All results for this batch run will be stored in: $base_run_dir"
    
    local query_num=0
    while IFS= read -r query || [[ -n "$query" ]]; do
        # Skip empty lines and comments
        [[ -z "$query" ]] || [[ "$query" =~ ^\s*# ]] && continue
        
        query_num=$((query_num + 1))
        local query_slug
        query_slug=$(echo "$query" | tr -cs 'a-zA-Z0-9' '_' | head -c 50)
        local query_log_dir="$base_run_dir/query_${query_num}_${query_slug}"
        
        info "Executing query #$query_num: ${C}$query${N}"
        
        # Execute the main script non-interactively for each query
        if "$SQRY_SCRIPT" --query "$query" --output "$query_log_dir"; then
            ok "Query '$query' completed. Results are in $query_log_dir"
        else
            warn "Query '$query' failed or returned no results. Check logs in $query_log_dir"
        fi
        
        info "Waiting a moment before the next query..."
        sleep 3
        
    done < "$queries_file"

    ok "Automated reconnaissance run finished."
    info "Results for this batch are in: ${C}$base_run_dir${N}"

    # Ask user if they want to run the audit
    read -rp "${Y}[ACTION]${N} Do you want to run the audit script on the results now? (y/N) " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        run_audit "$base_run_dir"
    else
        info "To run the audit later, use the command:"
        echo -e "${C}./audit.sh \"$base_run_dir\"${N}"
    fi
}

run_audit() {
    local target_dir="$1"
    if [[ ! -f "$AUDIT_SCRIPT" ]]; then
        warn "Audit script ($AUDIT_SCRIPT) not found. Skipping audit."
        return
    fi
    if [[ ! -x "$AUDIT_SCRIPT" ]]; then
        chmod +x "$AUDIT_SCRIPT"
    fi

    info "Running audit on results directory: $target_dir"
    "$AUDIT_SCRIPT" "$target_dir"
}

# ===== UI & ENTRY POINT =====
usage() {
    echo "Usage: $0 [COMMAND] [ARGUMENT]"
    echo
    echo "A wrapper script to automate running reconnaissance using vps-sqry.sh."
    echo
    echo "Commands:"
    echo "  run [queries_file]    - Run automated recon using a query file (default: $DEFAULT_QUERIES_FILE)."
    echo "  init                  - Create the default queries file if it doesn't exist."
    echo "  check                 - Check for required dependencies."
    echo "  audit [results_dir]   - Run the audit script on a specific results directory."
    echo "  help                  - Show this help message."
    echo
}

main() {
    mkdir -p "$OUTPUT_DIR"
    local cmd="${1:-run}"
    
    case "$cmd" in
        run)
            check_dependencies
            create_default_queries_file
            run_automated_recon "${2:-}"
            ;;
        init)
            create_default_queries_file
            ;;
        check)
            check_dependencies
            ;;
        audit)
            if [[ -z "${2:-}" ]]; then
                die "You must provide a results directory to audit."
            fi
            run_audit "$2"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            error "Unknown command: $cmd"
            usage
            exit 1
            ;;
    esac
}

main "$@"