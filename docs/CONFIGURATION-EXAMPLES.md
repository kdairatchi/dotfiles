# ⚙️ Configuration Examples & Best Practices

This document provides practical configuration examples and best practices for maximizing the effectiveness of your bug bounty dotfiles setup.

## 🚀 Quick Configuration Templates

### Beginner Configuration

Perfect for those new to bug bounty hunting:

```bash
# ~/.env - Beginner Setup
export J=1000                           # Conservative parallel jobs
export BB_WORKSPACE="$HOME/bug_bounty"  # Simple workspace
export BB_TIMEOUT=30                    # Conservative timeouts

# Focus on essential tools
export NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"
export BB_WORDLIST="$HOME/dotfiles/tools/wordlists/SecLists/Discovery/Web-Content/common.txt"

# Simple notifications
export ENABLE_DESKTOP_NOTIFICATIONS=true
```

```bash
# ~/.bash_aliases - Beginner Aliases
alias bb='cd $BB_WORKSPACE'
alias scan='./scripts/recon/bug_bounty_framework/quick_scan.sh'
alias results='ls -la *.txt *.json *.html 2>/dev/null'
alias help='bbhelp'

# Simple workflow functions
learn() {
    echo "🎓 Learning Resources:"
    echo "  - Type 'bbhelp' for available commands"
    echo "  - Check docs/USAGE.md for detailed guides"
    echo "  - Visit https://portswigger.net/web-security for learning"
}

practice() {
    local target="${1:-testphp.vulnweb.com}"
    echo "🎯 Practice target: $target"
    quick_scan "$target"
}
```

### Intermediate Configuration

For users comfortable with security tools:

```bash
# ~/.env - Intermediate Setup
export J=3000                           # Moderate parallel jobs
export BB_WORKSPACE="$HOME/targets"     # Organized workspace
export BB_RESULTS_DIR="$HOME/bb_results"

# API integrations
export SHODAN_API_KEY="your_key"        # Optional but recommended
export VT_API_KEY="your_key"           

# Customized tool settings
export NUCLEI_TEMPLATES_DIR="$HOME/.nuclei-templates"
export HTTPX_THREADS=150
export SUBFINDER_TIMEOUT=45

# Workflow preferences
export AUTO_SCREENSHOT=true
export AUTO_NOTIFY=true
export SAVE_RAW_OUTPUT=true
```

```bash
# ~/.bash_aliases - Intermediate Aliases
# Target management
alias targets='ls -1 $BB_WORKSPACE'
alias newtarget='init_target'
alias switch='target'

# Enhanced scanning
alias quickscan='triage_profile'
alias deepscan='comprehensive_profile'
alias stealthscan='stealth_profile'

# Analysis helpers
alias criticals='grep -i critical *.txt 2>/dev/null'
alias highs='grep -i high *.txt 2>/dev/null'
alias summary='cat *.txt | wc -l; echo "Total findings"'

# Workflow functions
mscan() {
    # Multi-target scanning
    local targets_file="$1"
    [ ! -f "$targets_file" ] && { echo "Usage: mscan targets.txt"; return 1; }
    
    while read -r target; do
        [ -z "$target" ] && continue
        echo "[+] Scanning: $target"
        quickscan "$target" > "results_${target}_$(date +%Y%m%d).txt" &
    done < "$targets_file"
    
    wait
    echo "[+] All scans completed"
}

organize() {
    # Organize results by date
    local date_dir="organized_$(date +%Y%m%d)"
    mkdir -p "$date_dir"
    mv *.txt *.json *.html "$date_dir/" 2>/dev/null
    echo "[+] Results organized in: $date_dir"
}
```

### Advanced Configuration

For experienced bug bounty hunters and pentesters:

```bash
# ~/.env - Advanced Setup
export J=6000                           # High parallel jobs
export BB_WORKSPACE="$HOME/hunting"     # Professional workspace
export BB_RESULTS_DIR="$HOME/results"
export BB_ARCHIVE_DIR="$HOME/archive"

# Full API suite
export SHODAN_API_KEY="your_key"
export VT_API_KEY="your_key"
export GITHUB_TOKEN="your_token"
export URLSCAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"

# Advanced notifications
export SLACK_WEBHOOK="your_webhook"
export DISCORD_WEBHOOK="your_webhook"
export TELEGRAM_BOT_TOKEN="your_token"
export TELEGRAM_CHAT_ID="your_chat_id"

# Performance tuning
export NUCLEI_BULK_SIZE=100
export HTTPX_THREADS=300
export SUBFINDER_TIMEOUT=60
export MAX_RECURSIVE_DEPTH=3

# Automation settings
export AUTO_ARCHIVE=true
export AUTO_REPORT=true
export AUTO_GIT_COMMIT=true
export CONTINUOUS_MONITORING=false
```

```bash
# ~/.bash_aliases - Advanced Aliases
# Professional workflow
alias hunt='cd $BB_WORKSPACE && source ~/.env'
alias archive='archive_target'
alias sync='git_track_results'
alias deploy='./install/enhanced_setup.sh quick'

# Advanced scanning modes
alias blitz='ctf_profile'              # Competition mode
alias ghost='stealth_profile'          # OPSEC mode  
alias siege='comprehensive_profile'    # Full assessment
alias recon='advanced_recon_pipeline'  # Custom pipeline

# Intelligence gathering
alias intel='quick_intel'
alias osint='full_osint_profile'
alias social='social_media_recon'

# Reporting and analysis
alias genpdf='generate_pdf_report'
alias genhtml='generate_personal_report'
alias stats='show_hunt_statistics'

# Advanced functions
advanced_recon_pipeline() {
    local target="$1"
    local output_dir="recon_$(date +%Y%m%d_%H%M%S)_$target"
    
    mkdir -p "$output_dir"
    cd "$output_dir"
    
    # Phase 1: Passive reconnaissance
    parallel -j"$J" ::: \
        "subfinder -d $target -all -silent > subs_subfinder.txt" \
        "assetfinder --subs-only $target > subs_assetfinder.txt" \
        "crtsh $target > subs_crtsh.txt" \
        "waybackurls $target > wayback_urls.txt" \
        "gau $target > gau_urls.txt"
    
    # Phase 2: Active enumeration
    cat subs_*.txt | sort -u > all_subdomains.txt
    httpx -l all_subdomains.txt -tech-detect -title -status-code -threads "$HTTPX_THREADS" > live_analysis.txt
    
    # Phase 3: Content discovery
    awk '/\[200\]/{print $1}' live_analysis.txt | head -50 | \
        parallel -j"$((J/4))" 'ffuf -u {}/FUZZ -w $BB_WORDLIST -ac -t 100 -o ffuf_{#}.json'
    
    # Phase 4: Vulnerability assessment
    awk '/\[200\]/{print $1}' live_analysis.txt | \
        nuclei -l /dev/stdin -severity critical,high,medium -j "$J" -o vulnerabilities.txt
    
    # Phase 5: Specialized scans
    grep -E '\.(js|json)' gau_urls.txt wayback_urls.txt | sort -u | head -100 | \
        parallel -j"$((J/2))" 'echo {} | nuclei -t $NUCLEI_TEMPLATES_DIR/exposures/'
    
    # Notifications
    local critical_count=$(grep -ci critical vulnerabilities.txt)
    [ "$critical_count" -gt 0 ] && notify_finding "critical" "$critical_count critical findings" "$target"
    
    # Generate reports
    generate_personal_report "$target" "$(pwd)"
    generate_json_report "$target" "$(pwd)"
    
    echo "[+] Advanced reconnaissance completed: $output_dir"
}

full_osint_profile() {
    local target="$1"
    local company="${2:-$target}"
    
    echo "[+] Full OSINT on: $target (Company: $company)"
    
    # DNS intelligence
    dig "$target" ANY +short
    nslookup "$target"
    
    # Certificate transparency
    crtsh "$target" | head -100
    
    # Social media and public info
    [ -n "$GITHUB_TOKEN" ] && gh-code "$company api_key password secret" | head -20
    
    # Infrastructure intelligence
    [ -n "$SHODAN_API_KEY" ] && shodan-search "hostname:$target"
    [ -n "$CENSYS_API_ID" ] && censys-search "$target"
    
    # Archive analysis
    waybackurls "$target" | head -200 | unfurl domains | sort -u
}

show_hunt_statistics() {
    echo "📊 Bug Bounty Statistics"
    echo "========================"
    
    # Scan statistics
    local total_scans=$(find "$BB_RESULTS_DIR" -name "*.txt" 2>/dev/null | wc -l)
    local total_vulns=$(find "$BB_RESULTS_DIR" -name "*vulner*" -exec cat {} \; 2>/dev/null | wc -l)
    local critical_vulns=$(find "$BB_RESULTS_DIR" -name "*vulner*" -exec grep -i critical {} \; 2>/dev/null | wc -l)
    
    echo "Total scans performed: $total_scans"
    echo "Total vulnerabilities: $total_vulns"  
    echo "Critical findings: $critical_vulns"
    
    # Recent activity
    echo -e "\n📅 Recent Activity:"
    find "$BB_RESULTS_DIR" -name "*.txt" -mtime -7 2>/dev/null | sort -r | head -5 | \
        while read -r file; do
            echo "  $(basename "$file") - $(stat -c %y "$file" | cut -d' ' -f1)"
        done
    
    # Top targets
    echo -e "\n🎯 Most Scanned Targets:"
    find "$BB_RESULTS_DIR" -name "*.txt" 2>/dev/null | \
        sed 's/.*results_\([^_]*\)_.*/\1/' | sort | uniq -c | sort -nr | head -5
}
```

## 🛠️ Tool-Specific Configurations

### Nuclei Optimization

```bash
# ~/.nuclei-config.yaml
# Custom Nuclei configuration

# Create optimized nuclei wrapper
nuclei_optimized() {
    local target="$1"
    local severity="${2:-critical,high,medium}"
    local template_dir="${3:-$NUCLEI_TEMPLATES_DIR}"
    
    nuclei \
        -u "$target" \
        -t "$template_dir/cves/" \
        -t "$template_dir/vulnerabilities/" \
        -t "$template_dir/misconfiguration/" \
        -severity "$severity" \
        -j "$J" \
        -rate-limit 500 \
        -bulk-size "$NUCLEI_BULK_SIZE" \
        -timeout 10 \
        -retries 1 \
        -o "nuclei_$(date +%Y%m%d_%H%M%S).txt" \
        -stats \
        -silent
}

# Custom template management
update_nuclei_templates() {
    echo "[+] Updating Nuclei templates..."
    nuclei -update-templates
    
    # Add custom templates
    if [ -d "$HOME/.nuclei-templates/personal" ]; then
        echo "[+] Personal templates found"
    fi
    
    # Template statistics
    local total_templates=$(find "$NUCLEI_TEMPLATES_DIR" -name "*.yaml" | wc -l)
    echo "[+] Total templates available: $total_templates"
}
```

### HTTPx Configuration

```bash
# Optimized HTTPx wrapper
httpx_smart() {
    local input="$1"
    local threads="${2:-$HTTPX_THREADS}"
    local output="${3:-httpx_$(date +%Y%m%d_%H%M%S).txt}"
    
    if [ -f "$input" ]; then
        # File input
        httpx -l "$input" \
            -title -tech-detect -status-code \
            -threads "$threads" \
            -timeout 10 \
            -retries 2 \
            -rate-limit 100 \
            -follow-redirects \
            -random-agent \
            -o "$output"
    else
        # Single URL
        echo "$input" | httpx \
            -title -tech-detect -status-code \
            -threads "$threads" \
            -timeout 10 \
            -retries 2 \
            -follow-redirects \
            -random-agent
    fi
}

# Mass HTTP probing
mass_httpx() {
    local input_file="$1"
    local chunk_size="${2:-1000}"
    
    split -l "$chunk_size" "$input_file" chunks_
    
    for chunk in chunks_*; do
        httpx_smart "$chunk" > "httpx_$(basename "$chunk").txt" &
    done
    
    wait
    cat httpx_chunks_*.txt > merged_httpx_results.txt
    rm -f chunks_* httpx_chunks_*.txt
    
    echo "[+] Mass HTTPx completed: merged_httpx_results.txt"
}
```

### Subfinder Optimization

```bash
# Enhanced subfinder configuration
subfinder_all_sources() {
    local domain="$1"
    local output="${2:-subs_${domain}_$(date +%Y%m%d_%H%M%S).txt}"
    
    subfinder -d "$domain" \
        -all \
        -recursive \
        -timeout "$SUBFINDER_TIMEOUT" \
        -max-time 10 \
        -silent \
        -o "$output"
    
    # Deduplicate and clean
    sort -u "$output" | grep -E "^[a-zA-Z0-9]" > "${output}.clean"
    mv "${output}.clean" "$output"
    
    echo "[+] Subfinder completed: $output ($(wc -l < "$output") subdomains)"
}

# Multi-source subdomain enumeration
multi_source_subs() {
    local domain="$1"
    local output_dir="subs_$(date +%Y%m%d_%H%M%S)_$domain"
    
    mkdir -p "$output_dir"
    cd "$output_dir"
    
    # Run multiple tools in parallel
    parallel -j4 ::: \
        "subfinder -d $domain -silent > subfinder.txt" \
        "assetfinder --subs-only $domain > assetfinder.txt" \
        "crtsh $domain > crtsh.txt" \
        "certspotter $domain > certspotter.txt"
    
    # Merge and deduplicate
    cat *.txt | sort -u > all_subdomains.txt
    
    local total=$(wc -l < all_subdomains.txt)
    echo "[+] Multi-source enumeration completed: $total unique subdomains"
    
    cd ..
}
```

## 🎯 Workflow Templates

### Bug Bounty Program Workflow

```bash
# Complete bug bounty program assessment
bb_program_assessment() {
    local program_name="$1"
    local scope_file="$2"  # File containing in-scope domains
    
    if [ ! -f "$scope_file" ]; then
        echo "Usage: bb_program_assessment program_name scope_file.txt"
        return 1
    fi
    
    local workspace="$BB_WORKSPACE/programs/$program_name"
    mkdir -p "$workspace"
    cd "$workspace"
    
    echo "[+] Starting assessment for: $program_name"
    
    # Phase 1: Scope analysis
    echo "[+] Phase 1: Scope Analysis"
    cp "$scope_file" scope.txt
    wc -l scope.txt
    
    # Phase 2: Subdomain enumeration for all scope
    echo "[+] Phase 2: Subdomain Enumeration"
    while read -r domain; do
        [ -z "$domain" ] && continue
        echo "  [+] Enumerating: $domain"
        subfinder_all_sources "$domain" > "subs_$domain.txt" &
    done < scope.txt
    wait
    
    # Merge all subdomains
    cat subs_*.txt | sort -u > all_subdomains.txt
    
    # Phase 3: Live host detection
    echo "[+] Phase 3: Live Host Detection"
    httpx_smart all_subdomains.txt > live_hosts.txt
    
    # Phase 4: Vulnerability assessment
    echo "[+] Phase 4: Vulnerability Assessment"
    awk '/\[200\]/{print $1}' live_hosts.txt | \
        nuclei_optimized /dev/stdin "critical,high,medium" > vulnerabilities.txt
    
    # Phase 5: Manual testing targets
    echo "[+] Phase 5: Preparing Manual Testing Targets"
    awk '/\[200\]/{print $1}' live_hosts.txt | head -20 > manual_testing_targets.txt
    
    # Generate program report
    generate_program_report "$program_name"
    
    echo "[+] Assessment completed for: $program_name"
    echo "    Results in: $workspace"
}

generate_program_report() {
    local program="$1"
    local report_file="REPORT_${program}_$(date +%Y%m%d).md"
    
    cat > "$report_file" << EOF
# Bug Bounty Assessment Report: $program

**Date:** $(date)  
**Operator:** $(whoami)@$(hostname)  
**Framework:** Bug Bounty Dotfiles

## Executive Summary

- **Total Scope:** $(wc -l < scope.txt) domains
- **Subdomains Found:** $(wc -l < all_subdomains.txt)
- **Live Hosts:** $(grep -c "\[200\]" live_hosts.txt)
- **Vulnerabilities:** $(wc -l < vulnerabilities.txt)

## Critical Findings

\`\`\`
$(grep -i critical vulnerabilities.txt | head -10)
\`\`\`

## High Severity Findings

\`\`\`
$(grep -i high vulnerabilities.txt | head -10)
\`\`\`

## Recommended Manual Testing Targets

\`\`\`
$(cat manual_testing_targets.txt)
\`\`\`

## Methodology

1. Subdomain enumeration using multiple sources
2. Live host detection with HTTPx
3. Automated vulnerability scanning with Nuclei
4. Manual testing target identification

## Next Steps

1. Manual testing of identified targets
2. Deep dive into interesting findings
3. Responsible disclosure of confirmed vulnerabilities

---
*Generated with Bug Bounty Dotfiles Framework*
EOF

    echo "[+] Report generated: $report_file"
}
```

### Continuous Monitoring Workflow

```bash
# Setup continuous monitoring for a target
setup_monitoring() {
    local target="$1"
    local interval="${2:-3600}"  # 1 hour default
    
    local monitor_dir="$BB_WORKSPACE/monitoring/$target"
    mkdir -p "$monitor_dir"
    
    # Create monitoring script
    cat > "$monitor_dir/monitor.sh" << EOF
#!/bin/bash
cd "\$(dirname "\$0")"

while true; do
    timestamp=\$(date +%Y%m%d_%H%M%S)
    
    # Quick scan
    triage_profile "$target" > "scan_\$timestamp.txt" 2>&1
    
    # Compare with previous
    prev_scan=\$(ls scan_*.txt 2>/dev/null | tail -2 | head -1)
    
    if [ -n "\$prev_scan" ] && [ "\$prev_scan" != "scan_\$timestamp.txt" ]; then
        new_findings=\$(comm -13 <(sort "\$prev_scan") <(sort "scan_\$timestamp.txt"))
        
        if [ -n "\$new_findings" ]; then
            echo "\$new_findings" > "new_\$timestamp.txt"
            notify_finding "info" "New findings in monitoring" "$target"
        fi
    fi
    
    sleep "$interval"
done
EOF

    chmod +x "$monitor_dir/monitor.sh"
    
    echo "[+] Monitoring setup for $target"
    echo "    Directory: $monitor_dir"
    echo "    Start with: nohup $monitor_dir/monitor.sh &"
}
```

### Competition/CTF Workflow

```bash
# Rapid assessment for competitions
ctf_rapid_assessment() {
    local target="$1"
    local time_limit="${2:-30}"  # 30 minutes default
    
    echo "[+] CTF Rapid Assessment: $target (${time_limit}m limit)"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + time_limit * 60))
    
    # Parallel aggressive scanning
    {
        # Quick subdomain enum
        subfinder -d "$target" -silent | head -50
        echo "$target"
    } | httpx -threads 500 -silent | \
    parallel -j"$J" 'echo {} | nuclei -severity critical,high -silent' &
    
    # Directory brute force on main domain
    ffuf -u "https://$target/FUZZ" -w "$BB_WORDLIST" -ac -t 200 &
    
    # Port scan
    naabu -host "$target" -top-ports 1000 -rate 5000 -silent &
    
    # Monitor time limit
    while [ "$(date +%s)" -lt "$end_time" ]; do
        sleep 10
        echo "[+] Time remaining: $(( (end_time - $(date +%s)) / 60 ))m"
    done
    
    # Kill all background jobs
    jobs -p | xargs kill 2>/dev/null
    
    echo "[+] Rapid assessment completed"
}
```

## 📊 Monitoring and Analytics

### Performance Monitoring

```bash
# System performance monitoring during scans
monitor_performance() {
    local log_file="${1:-performance.log}"
    local interval="${2:-10}"  # 10 seconds
    
    echo "[+] Starting performance monitoring (log: $log_file)"
    
    {
        echo "Timestamp,CPU%,Memory%,Load,NetworkConnections,DiskIO"
        while true; do
            local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
            local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
            local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
            local load_avg=$(uptime | awk '{print $NF}')
            local net_connections=$(ss -t | wc -l)
            local disk_io=$(iostat -d 1 1 | awk '/Device/ {getline; print $4}' | head -1)
            
            echo "$timestamp,$cpu_usage,$mem_usage,$load_avg,$net_connections,$disk_io"
            sleep "$interval"
        done
    } > "$log_file" &
    
    echo $! > /tmp/perf_monitor_$$.pid
    echo "[+] Performance monitoring started (PID: $(cat /tmp/perf_monitor_$$.pid))"
}

stop_performance_monitoring() {
    if [ -f "/tmp/perf_monitor_$$.pid" ]; then
        kill "$(cat /tmp/perf_monitor_$$.pid)" 2>/dev/null
        rm -f "/tmp/perf_monitor_$$.pid"
        echo "[+] Performance monitoring stopped"
    fi
}

# Scan analytics
scan_analytics() {
    local results_dir="${1:-$BB_RESULTS_DIR}"
    
    echo "📊 Scan Analytics"
    echo "=================="
    
    # Vulnerability distribution
    echo -e "\n🔍 Vulnerability Distribution:"
    find "$results_dir" -name "*vulner*" -exec grep -h "severity" {} \; 2>/dev/null | \
        sort | uniq -c | sort -nr
    
    # Most productive tools
    echo -e "\n🛠️ Tool Productivity:"
    find "$results_dir" -name "*.txt" -exec basename {} \; 2>/dev/null | \
        sed 's/_[0-9]*.txt//' | sort | uniq -c | sort -nr | head -10
    
    # Timeline analysis
    echo -e "\n📅 Activity Timeline:"
    find "$results_dir" -name "*.txt" -mtime -30 2>/dev/null | \
        xargs stat -c %y | cut -d' ' -f1 | sort | uniq -c
    
    # Target analysis
    echo -e "\n🎯 Target Analysis:"
    find "$results_dir" -name "*.txt" 2>/dev/null | \
        grep -o "results_[^_]*" | sed 's/results_//' | sort | uniq -c | sort -nr | head -10
}
```

## 🔧 Best Practices

### Security Best Practices

```bash
# Secure configuration checker
check_security_config() {
    echo "🔒 Security Configuration Check"
    echo "==============================="
    
    # Check file permissions
    echo -e "\n📁 File Permissions:"
    [ -f ~/.env ] && echo "~/.env: $(stat -c %a ~/.env)" || echo "~/.env: Not found"
    [ -f ~/.ssh/config ] && echo "~/.ssh/config: $(stat -c %a ~/.ssh/config)" || echo "~/.ssh/config: Not found"
    
    # Check for exposed API keys in history
    echo -e "\n🔑 API Key Exposure Check:"
    if grep -qi "api.*key\|token\|secret" ~/.bash_history ~/.zsh_history 2>/dev/null; then
        echo "⚠️  Potential API keys found in shell history!"
        echo "   Consider: history -c && history -w"
    else
        echo "✅ No API keys found in shell history"
    fi
    
    # Check git configuration
    echo -e "\n📝 Git Configuration:"
    if git config --global user.email >/dev/null 2>&1; then
        echo "✅ Git email configured"
    else
        echo "⚠️  Git email not configured"
    fi
    
    # Check for secure defaults
    echo -e "\n🛡️ Security Defaults:"
    if [ "${BB_AUTO_ARCHIVE:-false}" = "true" ]; then
        echo "✅ Auto-archive enabled"
    else
        echo "ℹ️  Consider enabling auto-archive"
    fi
}

# Secure cleanup function
secure_cleanup() {
    echo "[+] Performing secure cleanup..."
    
    # Clean temporary files
    find /tmp -name "*nuclei*" -user "$(whoami)" -delete 2>/dev/null
    find /tmp -name "*httpx*" -user "$(whoami)" -delete 2>/dev/null
    find /tmp -name "*subfinder*" -user "$(whoami)" -delete 2>/dev/null
    
    # Clean shell history of sensitive data
    sed -i '/api.*key\|token\|secret\|password/Id' ~/.bash_history 2>/dev/null
    sed -i '/api.*key\|token\|secret\|password/Id' ~/.zsh_history 2>/dev/null
    
    # Secure delete of sensitive files if shred is available
    if command -v shred >/dev/null 2>&1; then
        find . -name "*.tmp" -exec shred -vfz -n 3 {} \; 2>/dev/null
    fi
    
    echo "[+] Secure cleanup completed"
}
```

### Performance Best Practices

```bash
# Automatic performance optimization
optimize_system() {
    echo "[+] Optimizing system for bug bounty operations..."
    
    # Increase file descriptor limits
    if [ "$(ulimit -n)" -lt 65536 ]; then
        ulimit -n 65536 2>/dev/null && echo "✅ File descriptor limit increased"
    fi
    
    # Optimize network settings
    if [ -w /proc/sys/net/ipv4/ip_local_port_range ]; then
        echo "15000 65000" | sudo tee /proc/sys/net/ipv4/ip_local_port_range >/dev/null
        echo "✅ Port range optimized"
    fi
    
    # Memory optimization
    if [ -w /proc/sys/vm/swappiness ]; then
        echo "10" | sudo tee /proc/sys/vm/swappiness >/dev/null
        echo "✅ Swappiness optimized"
    fi
    
    # Set optimal parallel jobs
    local optimal_j=$(calc_parallel_jobs)
    export J="$optimal_j"
    echo "✅ Parallel jobs set to: $J"
    
    echo "[+] System optimization completed"
}

# Resource monitoring
monitor_resources() {
    echo "💻 System Resources"
    echo "==================="
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2+$4}')
    echo "CPU Usage: ${cpu_usage}%"
    
    # Memory usage
    local mem_info=$(free -h | grep "Mem:")
    echo "Memory: $mem_info"
    
    # Disk usage
    local disk_usage=$(df -h / | tail -1 | awk '{print $5}')
    echo "Disk Usage: $disk_usage"
    
    # Network connections
    local connections=$(ss -t | wc -l)
    echo "Network Connections: $connections"
    
    # Load average
    local load=$(uptime | awk '{print $NF}')
    echo "Load Average: $load"
    
    # Recommendations
    echo -e "\n💡 Recommendations:"
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        echo "⚠️  High CPU usage - consider reducing parallel jobs"
    fi
    
    if [ "$connections" -gt 1000 ]; then
        echo "⚠️  High connection count - check for resource leaks"
    fi
}
```

### Maintenance Best Practices

```bash
# Regular maintenance routine
maintenance_routine() {
    echo "🔧 Performing maintenance routine..."
    
    # Update tools
    echo "[+] Updating security tools..."
    nuclei -update-templates -silent
    subfinder -update-data -silent
    
    # Clean old results
    echo "[+] Cleaning old results..."
    find "$BB_RESULTS_DIR" -type f -mtime +30 -name "*.txt" -delete 2>/dev/null
    find "$BB_RESULTS_DIR" -type f -mtime +7 -name "*.tmp" -delete 2>/dev/null
    
    # Update dotfiles
    echo "[+] Checking for dotfiles updates..."
    cd "$HOME/dotfiles"
    if git fetch && [ "$(git rev-list HEAD...origin/main --count)" -gt 0 ]; then
        echo "⚠️  Updates available. Run: git pull && ./install/enhanced_setup.sh quick"
    else
        echo "✅ Dotfiles up to date"
    fi
    
    # System cleanup
    echo "[+] System cleanup..."
    secure_cleanup
    
    # Performance check
    echo "[+] Performance check..."
    monitor_resources
    
    echo "[+] Maintenance routine completed"
}

# Backup configuration
backup_config() {
    local backup_dir="$HOME/bb_config_backup_$(date +%Y%m%d_%H%M%S)"
    
    mkdir -p "$backup_dir"
    
    # Backup important files
    cp ~/.env "$backup_dir/" 2>/dev/null
    cp ~/.bash_aliases "$backup_dir/" 2>/dev/null
    cp ~/.zsh_aliases "$backup_dir/" 2>/dev/null
    cp -r ~/.nuclei-templates/personal "$backup_dir/" 2>/dev/null
    
    # Create backup manifest
    cat > "$backup_dir/MANIFEST.txt" << EOF
Bug Bounty Configuration Backup
================================
Date: $(date)
System: $(uname -a)
User: $(whoami)

Files backed up:
$(ls -la "$backup_dir")

Restore instructions:
1. Copy files back to home directory
2. Source shell configuration
3. Verify API keys and permissions
EOF

    echo "[+] Configuration backed up to: $backup_dir"
}
```

This comprehensive configuration guide provides everything needed to set up, customize, and maintain an effective bug bounty environment using the dotfiles framework. From beginner-friendly setups to advanced enterprise configurations, these examples cover all use cases while maintaining security and performance best practices.