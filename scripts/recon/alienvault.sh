#!/usr/bin/env bash
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  alienvault.sh
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  “real never lies.”  |  Support: buymeacoffee.com/kdairatchi
# =========================================================

set -Eeuo pipefail
IFS=$'\n\t'

# Source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/banner.sh"
source "${SCRIPT_DIR}/lib/log.sh"

# ============================================================================
# SCRIPT CONFIGURATION
# ============================================================================

readonly SCRIPT_NAME="alienvault"
readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_DESCRIPTION="AlienVault OTX URL Intelligence Gatherer"

# Default settings
TARGETS=()
OUTPUT_DIR=""
LIMIT=500
MAX_PAGES=20
TIMEOUT=30
DELAY=1
FORMAT="txt"
JSON_OUTPUT=0
DRY_RUN=0
NO_COLOR=0
VERBOSE=0
THREADS=1

# ============================================================================
# HELP FUNCTION
# ============================================================================

show_help() {
    kd_banner "$SCRIPT_NAME" "$SCRIPT_VERSION"
    echo "Usage: ${SCRIPT_NAME} [OPTIONS] -t <targets>"
    echo ""
    echo "OPTIONS:"
    echo "  -t, --targets <file|->   File of domains to scan (or stdin)"
    echo "  -o, --output <dir>        Output directory (default: reports/YYYYMMDD/HHMMSS/<tool>)"
    echo "  -l, --limit <num>         URLs per page (default: ${LIMIT})"
    echo "  -p, --pages <num>         Maximum pages to fetch (default: ${MAX_PAGES})"
    echo "  --timeout <sec>           Request timeout in seconds (default: ${TIMEOUT})"
    echo "  --delay <num>             Delay between requests (default: ${DELAY})"
    echo "  --format <format>         Output format: txt, json, csv (default: ${FORMAT})"
    echo "  --json                    Write structured JSON summary to stdout"
    echo "  --threads <N>             Number of parallel threads (default: ${THREADS})"
    echo "  -v, --verbose             Enable verbose output"
    echo "  --no-color                Disable colorized output"
    echo "  --dry-run                 Show actions without executing them"
    echo "  --banner                  Print the banner and exit"
    echo "  --version                 Show version information"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  ${SCRIPT_NAME} -t domains.txt"
    echo "  cat domains.txt | ${SCRIPT_NAME} -t -"
    echo "  ${SCRIPT_NAME} -t domains.txt -o my_reports --limit 1000"
    echo "  ${SCRIPT_NAME} -t domains.txt --format json --json"
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--targets)
                if [[ "$2" == "-" ]]; then
                    readarray -t TARGETS
                else
                    readarray -t TARGETS < "$2"
                fi
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -l|--limit)
                LIMIT="$2"
                shift 2
                ;;
            -p|--pages)
                MAX_PAGES="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --delay)
                DELAY="$2"
                shift 2
                ;;
            --format)
                FORMAT="$2"
                shift 2
                ;;
            --json)
                JSON_OUTPUT=1
                shift
                ;;
            --threads)
                THREADS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --banner)
                kd_banner "$SCRIPT_NAME" "$SCRIPT_VERSION"
                exit 0
                ;;
            --version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_err "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# VALIDATION
# ============================================================================

validate_arguments() {
    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        die "No targets specified. Use -t <file> or pipe from stdin." 2
    fi

    if ! [[ "$LIMIT" =~ ^[0-9]+$ ]] || [[ "$LIMIT" -le 0 ]] || [[ "$LIMIT" -gt 10000 ]]; then
        die "Invalid limit: $LIMIT (must be 1-10000)" 2
    fi

    if ! [[ "$MAX_PAGES" =~ ^[0-9]+$ ]] || [[ "$MAX_PAGES" -le 0 ]] || [[ "$MAX_PAGES" -gt 100 ]]; then
        die "Invalid max pages: $MAX_PAGES (must be 1-100)" 2
    fi

    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -le 0 ]] || [[ "$TIMEOUT" -gt 300 ]]; then
        die "Invalid timeout: $TIMEOUT (must be 1-300)" 2
    fi

    if ! [[ "$DELAY" =~ ^[0-9]+$ ]] || [[ "$DELAY" -lt 0 ]] || [[ "$DELAY" -gt 10 ]]; then
        die "Invalid delay: $DELAY (must be 0-10)" 2
    fi

    if [[ ! "$FORMAT" =~ ^(txt|json|csv)$ ]]; then
        die "Invalid format: $FORMAT (must be txt, json, or csv)" 2
    fi

    ensure_bin "jq"
    ensure_bin "curl"
}

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

fetch_alienvault_urls() {
    local domain="$1"
    local page=1
    local total_urls=0
    local all_urls=()

    log_info "Fetching URLs from AlienVault OTX for domain: $domain"

    while [[ $page -le $MAX_PAGES ]]; do
        log_debug "Fetching page $page..."
        local url="https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=${LIMIT}&page=${page}"

        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY RUN] Would fetch: $url"
            break
        fi

        local response
        response=$(curl --silent --max-time "$TIMEOUT" "$url")

        if ! echo "$response" | jq empty 2>/dev/null; then
            log_warn "Invalid JSON response on page $page, stopping"
            break
        fi

        local urls
        urls=$(echo "$response" | jq -r '.url_list[]?.url // empty' 2>/dev/null)

        if [[ -z "$urls" ]]; then
            log_info "No more URLs found on page $page, finishing"
            break
        fi

        local count
        count=$(echo "$urls" | wc -l)
        total_urls=$((total_urls + count))

        log_info "Found $count URLs on page $page (total: $total_urls)"

        while IFS= read -r url_entry; do
            [[ -n "$url_entry" ]] && all_urls+=("$url_entry")
        done <<< "$urls"

        if [[ $count -lt $LIMIT ]]; then
            log_info "Reached the last page ($count < $LIMIT)"
            break
        fi

        if [[ $DELAY -gt 0 ]]; then
            sleep "$DELAY"
        fi

        page=$((page + 1))
    done

    echo "${all_urls[@]}"
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

main() {
    trap 'die "Script interrupted." 130' INT TERM
    
    parse_arguments "$@"
    validate_arguments

    # Setup output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="reports/$(date +%Y%m%d)/$(date +%H%M%S)/${SCRIPT_NAME}"
    fi
    mkdir -p "$OUTPUT_DIR"
    log_info "Output will be saved to: $OUTPUT_DIR"

    local start_time
    start_time=$(date +%s)
    local all_findings=()
    local error_count=0

    for target in "${TARGETS[@]}"; do
        if [[ "$DRY_RUN" -eq 1 ]]; then
            fetch_alienvault_urls "$target"
            continue
        fi

        local urls
        if ! urls=$(fetch_alienvault_urls "$target"); then
            log_err "Failed to fetch URLs for $target"
            error_count=$((error_count + 1))
            continue
        fi

        if [[ -n "$urls" ]]; then
            local finding
            finding=$(jq -n --arg target "$target" --arg type "alienvault_url" --arg severity "info" --argjson data "{\"urls\": $(echo "$urls" | jq -R . | jq -s .)}" \
                '{"target": $target, "type": $type, "severity": $severity, "data": $data}')
            all_findings+=("$finding")

            # Save results to file
            local filename
            filename=$(echo "$target" | tr -cd '[:alnum:]._-')
            echo "$urls" > "$OUTPUT_DIR/${filename}_urls.txt"
        fi
    done

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Create summary.json
    if [[ "$DRY_RUN" -ne 1 ]]; then
        local stats_json
        stats_json=$(jq -n --arg processed "${#TARGETS[@]}" --arg errors "$error_count" --arg duration_sec "$duration" 
            '{"processed": $processed, "errors": $errors, "duration_sec": $duration_sec}')

        local summary
        summary=$(jq -n \
            --arg tool "$SCRIPT_NAME" \
            --arg version "$SCRIPT_VERSION" \
            --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --argjson targets "$(printf '%s\n' "${TARGETS[@]}" | jq -R . | jq -s .)" \
            --argjson findings "$(printf '%s\n' "${all_findings[@]}" | jq -s .)" \
            --argjson stats "$stats_json" \
            '{"tool": $tool, "version": $version, "timestamp": $timestamp, "targets": $targets, "findings": $findings, "stats": $stats}')

        echo "$summary" > "$OUTPUT_DIR/summary.json"

        if [[ "$JSON_OUTPUT" -eq 1 ]]; then
            echo "$summary"
        fi
    fi

    log_ok "Scan complete. Report saved to $OUTPUT_DIR/summary.json"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
