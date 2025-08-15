# 🎨 Dotfiles Customization Guide

This comprehensive guide shows you how to personalize and extend the bug bounty dotfiles framework to match your unique workflow, preferences, and requirements.

## 🚀 Quick Start Customization

### Your Personal Configuration File

Create a personal environment file that won't be overwritten by updates:

```bash
# Create ~/.env for your personal settings
cat > ~/.env << 'EOF'
# =============================================================================
# Personal Bug Bounty Environment Configuration
# =============================================================================

# API Keys (keep these secure!)
export SHODAN_API_KEY="your_shodan_api_key_here"
export VT_API_KEY="your_virustotal_api_key_here"
export GITHUB_TOKEN="your_github_token_here"
export URLSCAN_API_KEY="your_urlscan_api_key_here"

# Notification Webhooks
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK"
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

# Personal Preferences
export J=4000                           # Your optimal parallel jobs
export BB_DEFAULT_WORDLIST="$HOME/my_wordlists/custom.txt"
export MY_SCAN_OUTPUT_DIR="$HOME/bb_results"
export BB_WORKSPACE="$HOME/targets"

# Tool Preferences
export NUCLEI_TEMPLATES_DIR="$HOME/.nuclei-templates"
export GF_PATTERNS_DIR="$HOME/.gf-patterns"
export HTTPX_THREADS=100
export SUBFINDER_TIMEOUT=30

# Custom Colors (for terminal output)
export BB_COLOR_CRITICAL='\033[1;31m'  # Bright red
export BB_COLOR_HIGH='\033[1;33m'      # Bright yellow
export BB_COLOR_MEDIUM='\033[1;36m'    # Bright cyan
export BB_COLOR_INFO='\033[1;32m'      # Bright green
export BB_COLOR_RESET='\033[0m'        # Reset

# Personal Aliases Override
export ENABLE_PERSONAL_ALIASES=true
EOF

# Source it in your shell config
echo '[ -f ~/.env ] && source ~/.env' >> ~/.bashrc
echo '[ -f ~/.env ] && source ~/.env' >> ~/.zshrc
```

## 🔧 Shell Configuration Customization

### Bash Customization (`~/.bash_personal`)

Create a personal bash configuration that extends the default setup:

```bash
cat > ~/.bash_personal << 'EOF'
# Personal Bash Configuration

# Custom Prompt with Bug Bounty Info
if [ "$ENABLE_PERSONAL_ALIASES" = true ]; then
    # Show current target in prompt if in workspace
    update_bb_prompt() {
        if [[ "$PWD" =~ ^$BB_WORKSPACE/.* ]]; then
            local target=$(basename "$(dirname "$PWD" 2>/dev/null)" 2>/dev/null)
            [ -n "$target" ] && export BB_CURRENT_TARGET="[$target]"
        else
            export BB_CURRENT_TARGET=""
        fi
    }
    
    # Add to PROMPT_COMMAND
    PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }update_bb_prompt"
    
    # Custom PS1 with target info
    PS1='\[${BB_COLOR_INFO}\]${BB_CURRENT_TARGET}\[${BB_COLOR_RESET}\]${PS1}'
fi

# Personal Functions
bb_quick_setup() {
    echo "Setting up quick bug bounty session..."
    cd "$BB_WORKSPACE"
    source ~/.env
    alias ll='ls -la --color=auto'
    echo "Ready for bug bounty hunting! 🎯"
}

# Auto-completion for custom commands
_bb_targets_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=($(compgen -W "$(ls -1 $BB_WORKSPACE 2>/dev/null)" -- "$cur"))
}
complete -F _bb_targets_completion target

EOF

# Source it
echo '[ -f ~/.bash_personal ] && source ~/.bash_personal' >> ~/.bashrc
```

### Zsh Customization (`~/.zsh_personal`)

Extend zsh with personal configurations:

```bash
cat > ~/.zsh_personal << 'EOF'
# Personal Zsh Configuration

# Oh-My-Zsh Plugin Additions
plugins+=(
    docker
    kubectl
    aws
    terraform
    # Add your favorite plugins here
)

# Custom Zsh Functions
autoload -Uz compinit && compinit

# Smart target switching with fuzzy finding
target_fzf() {
    if command -v fzf >/dev/null 2>&1; then
        local selected=$(ls -1 "$BB_WORKSPACE" 2>/dev/null | fzf --prompt="Select target: ")
        [ -n "$selected" ] && target "$selected"
    else
        echo "fzf not installed. Install with: sudo apt install fzf"
    fi
}
alias tf='target_fzf'

# Enhanced directory navigation
setopt AUTO_CD              # cd by typing directory name
setopt AUTO_PUSHD           # pushd automatically
setopt PUSHD_IGNORE_DUPS    # don't push duplicates
setopt PUSHD_SILENT         # don't print stack

# History configuration
setopt EXTENDED_HISTORY     # save timestamp
setopt HIST_VERIFY         # verify before executing
setopt SHARE_HISTORY       # share between sessions
HISTSIZE=50000
SAVEHIST=50000

# Custom key bindings
bindkey '^[[A' history-substring-search-up
bindkey '^[[B' history-substring-search-down

EOF

echo '[ -f ~/.zsh_personal ] && source ~/.zsh_personal' >> ~/.zshrc
```

## 🛠️ Tool Integration

### Adding Your Favorite Tools

#### Method 1: Quick Tool Addition
```bash
# Add to ~/.bash_aliases or ~/.zsh_aliases
alias mytool="python3 $HOME/my_tools/scanner.py"
alias fastscan="$HOME/tools/my_scanner --fast"
alias customrecon="$HOME/scripts/my_recon.sh"

# For tools that need special handling
my_complex_tool() {
    local target="$1"
    local options="${2:---default}"
    
    echo "[+] Running my tool on $target with options: $options"
    cd "$HOME/my_tools"
    python3 scanner.py --target "$target" $options
    cd - >/dev/null
}
```

#### Method 2: Framework Integration
```bash
# Add to config/shell/common.sh for permanent integration
py_alias_if_exists mytool "$HOME/my_tools/scanner.py"
alias_if_exists mycustombin "$HOME/bin/custom_scanner"

# For complex tools
if [ -f "$HOME/my_tools/scanner.py" ]; then
    my_scanner() {
        python3 "$HOME/my_tools/scanner.py" "$@"
    }
fi
```

#### Method 3: Automatic Tool Discovery
```bash
# Add to your shell config for automatic tool discovery
if [ "$ENABLE_PERSONAL_ALIASES" = true ]; then
    # Auto-discover tools in personal directories
    for tool_dir in "$HOME/my_tools" "$HOME/custom_tools" "$HOME/personal_scripts"; do
        if [ -d "$tool_dir" ]; then
            for tool in "$tool_dir"/*; do
                if [ -x "$tool" ] && [ -f "$tool" ]; then
                    tool_name=$(basename "$tool" .py)
                    tool_name=$(basename "$tool_name" .sh)
                    
                    # Create alias if it doesn't conflict
                    if ! command -v "$tool_name" >/dev/null 2>&1; then
                        case "$tool" in
                            *.py) alias "$tool_name"="python3 '$tool'" ;;
                            *.sh) alias "$tool_name"="'$tool'" ;;
                            *) alias "$tool_name"="'$tool'" ;;
                        esac
                    fi
                fi
            done
        fi
    done
fi
```

### Custom Nuclei Templates

```bash
# Setup personal Nuclei templates
mkdir -p ~/.nuclei-templates/personal

# Create a custom template
cat > ~/.nuclei-templates/personal/my-custom-check.yaml << 'EOF'
id: my-custom-check

info:
  name: My Custom Security Check
  author: your-name
  severity: medium
  description: Custom security check for my targets
  tags: custom,personal

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/debug"
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/config.json"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "debug"
          - "password"
          - "secret"
        condition: or
EOF

# Add to your scanning function
nuclei_personal() {
    local target="$1"
    nuclei -u "$target" \
        -t "$NUCLEI_TEMPLATES_DIR/personal/" \
        -t "$NUCLEI_TEMPLATES_DIR/cves/" \
        -severity critical,high,medium \
        -o "nuclei_personal_$(date +%Y%m%d_%H%M%S).txt"
}
```

## 🎯 Workflow Customization

### Personal Scanning Profiles

Create scanning profiles that match your methodology:

```bash
# Add to your shell config

# Quick triage profile (2-5 minutes)
triage_profile() {
    local target="$1"
    echo "${BB_COLOR_INFO}[+] Quick triage: $target${BB_COLOR_RESET}"
    
    {
        subfinder -d "$target" -silent | head -20
        echo "$target"
    } | httpx -silent -status-code | grep "\[200\]" | head -10 | \
    nuclei -severity critical,high -silent -no-color
}

# Stealth profile (low noise)
stealth_profile() {
    local target="$1"
    echo "${BB_COLOR_INFO}[+] Stealth scan: $target${BB_COLOR_RESET}"
    
    # Use passive sources only
    {
        crtsh "$target"
        certspotter "$target"
        anubis "$target"
    } | sort -u | head -50 | \
    httpx -silent -rate-limit 1 -no-color
}

# Comprehensive profile (1+ hours)
comprehensive_profile() {
    local target="$1"
    local output_dir="comprehensive_$(date +%Y%m%d_%H%M%S)_$target"
    
    mkdir -p "$output_dir"
    echo "${BB_COLOR_INFO}[+] Comprehensive scan: $target -> $output_dir${BB_COLOR_RESET}"
    
    # Multi-source enumeration
    parallel -j$(calc_parallel_jobs) ::: \
        "subfinder -d $target -silent > $output_dir/subs_subfinder.txt" \
        "assetfinder --subs-only $target > $output_dir/subs_assetfinder.txt" \
        "crtsh $target > $output_dir/subs_crtsh.txt" \
        "waybackurls $target > $output_dir/wayback_urls.txt"
    
    # Analysis and scanning
    cat "$output_dir"/subs_*.txt | sort -u > "$output_dir/all_subdomains.txt"
    httpx -l "$output_dir/all_subdomains.txt" -tech-detect -title -status-code > "$output_dir/live_analysis.txt"
    awk '/\[200\]/{print $1}' "$output_dir/live_analysis.txt" | \
        nuclei -l /dev/stdin -severity critical,high,medium -j $(calc_parallel_jobs) \
        -o "$output_dir/vulnerabilities.txt"
    
    # Generate report
    generate_personal_report "$target" "$output_dir"
    
    echo "${BB_COLOR_INFO}[+] Comprehensive scan completed: $output_dir${BB_COLOR_RESET}"
}

# Bug bounty competition profile
ctf_profile() {
    local target="$1"
    echo "${BB_COLOR_INFO}[+] CTF/Competition mode: $target${BB_COLOR_RESET}"
    
    # Fast and aggressive
    export J=9000
    
    {
        echo "$target"
        subfinder -d "$target" -silent | head -100
    } | httpx -threads 500 -silent | \
    parallel -j"$J" 'echo {} | nuclei -severity critical,high,medium -silent'
    
    # Directory bruteforcing
    [ -f "$BB_DEFAULT_WORDLIST" ] && \
        ffuf -u "https://$target/FUZZ" -w "$BB_DEFAULT_WORDLIST" -ac -t 100
}
```

### Target Management System

```bash
# Advanced target management
init_target() {
    local target="$1"
    local workspace="$BB_WORKSPACE/$target"
    
    if [ -d "$workspace" ]; then
        echo "${BB_COLOR_HIGH}[!] Target workspace already exists: $workspace${BB_COLOR_RESET}"
        return 1
    fi
    
    mkdir -p "$workspace"/{recon,vulns,reports,notes,tools,payloads}
    cd "$workspace"
    
    # Initialize target files
    echo "$target" > target.txt
    echo "# $target Bug Bounty Notes" > notes/README.md
    echo "Initialized: $(date)" >> notes/README.md
    echo "Operator: $(whoami)@$(hostname)" >> notes/README.md
    
    # Create basic scripts
    cat > tools/quick_scan.sh << EOF
#!/bin/bash
# Quick scan for $target
cd "\$(dirname "\$0")/.."
triage_profile "$target" | tee "recon/quick_\$(date +%Y%m%d_%H%M%S).txt"
EOF
    chmod +x tools/quick_scan.sh
    
    echo "${BB_COLOR_INFO}[+] Target workspace initialized: $workspace${BB_COLOR_RESET}"
    echo "${BB_COLOR_INFO}[+] Use: target $target${BB_COLOR_RESET}"
}

# Enhanced target switching
target() {
    local target="$1"
    
    if [ -z "$target" ]; then
        echo "${BB_COLOR_INFO}Available targets:${BB_COLOR_RESET}"
        ls -1 "$BB_WORKSPACE/" 2>/dev/null | sed 's/^/  /'
        return 0
    fi
    
    local workspace="$BB_WORKSPACE/$target"
    
    if [ ! -d "$workspace" ]; then
        echo "${BB_COLOR_HIGH}[!] Target not found. Use: init_target $target${BB_COLOR_RESET}"
        return 1
    fi
    
    cd "$workspace"
    export BB_CURRENT_TARGET="$target"
    
    echo "${BB_COLOR_INFO}[+] Switched to target: $target${BB_COLOR_RESET}"
    echo "${BB_COLOR_INFO}[+] Workspace: $workspace${BB_COLOR_RESET}"
    
    # Show quick status
    [ -f "notes/README.md" ] && echo "${BB_COLOR_INFO}[+] Notes available${BB_COLOR_RESET}"
    [ -f "recon/*.txt" ] && echo "${BB_COLOR_INFO}[+] Previous recon data found${BB_COLOR_RESET}"
    
    # Set up convenience aliases for this target
    alias qq="./tools/quick_scan.sh"
    alias notes="$EDITOR notes/README.md"
    alias results="ls -la recon/ vulns/ reports/"
}

# Target archive and cleanup
archive_target() {
    local target="$1"
    local workspace="$BB_WORKSPACE/$target"
    
    if [ ! -d "$workspace" ]; then
        echo "${BB_COLOR_HIGH}[!] Target not found: $target${BB_COLOR_RESET}"
        return 1
    fi
    
    local archive_name="${target}_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    cd "$BB_WORKSPACE"
    tar -czf "archived/$archive_name" "$target"
    rm -rf "$target"
    
    echo "${BB_COLOR_INFO}[+] Target archived: archived/$archive_name${BB_COLOR_RESET}"
}
```

## 📊 Custom Reporting

### Personal Report Templates

```bash
# Advanced HTML report generator
generate_personal_report() {
    local target="$1"
    local data_dir="$2"
    local report_file="$data_dir/report_${target}_$(date +%Y%m%d_%H%M%S).html"
    
    # Count findings
    local critical_count=$(grep -ci critical "$data_dir/vulnerabilities.txt" 2>/dev/null || echo "0")
    local high_count=$(grep -ci high "$data_dir/vulnerabilities.txt" 2>/dev/null || echo "0")
    local medium_count=$(grep -ci medium "$data_dir/vulnerabilities.txt" 2>/dev/null || echo "0")
    local total_subs=$(wc -l < "$data_dir/all_subdomains.txt" 2>/dev/null || echo "0")
    local live_hosts=$(grep -c "\[200\]" "$data_dir/live_analysis.txt" 2>/dev/null || echo "0")
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment - $target</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #00ff00;
            line-height: 1.6;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { 
            text-align: center; 
            border-bottom: 3px solid #00ff00; 
            padding: 30px 0; 
            margin-bottom: 30px;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .meta { color: #888; font-size: 1.1em; }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: #1a1a1a; 
            border: 1px solid #333; 
            border-radius: 8px; 
            padding: 20px; 
            text-align: center; 
        }
        .stat-card h3 { color: #00ff00; margin-bottom: 10px; }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .section { 
            background: #1a1a1a; 
            border: 1px solid #333; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            padding: 20px; 
        }
        .section h2 { 
            color: #00ff00; 
            border-bottom: 1px solid #333; 
            padding-bottom: 10px; 
            margin-bottom: 15px; 
        }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff8800; font-weight: bold; }
        .medium { color: #ffff00; }
        .low { color: #88ff88; }
        pre { 
            background: #0a0a0a; 
            border: 1px solid #333; 
            border-radius: 4px; 
            padding: 15px; 
            overflow-x: auto; 
            font-size: 0.9em;
        }
        .finding { 
            margin-bottom: 15px; 
            padding: 10px; 
            background: #0a0a0a; 
            border-left: 4px solid #00ff00; 
        }
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 1px solid #333; 
            color: #888; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> $target</p>
                <p><strong>Generated:</strong> $(date)</p>
                <p><strong>Operator:</strong> $(whoami)@$(hostname)</p>
                <p><strong>Framework:</strong> Bug Bounty Dotfiles v2.0</p>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Subdomains</h3>
                <div class="number">$total_subs</div>
            </div>
            <div class="stat-card">
                <h3>Live Hosts</h3>
                <div class="number">$live_hosts</div>
            </div>
            <div class="stat-card critical">
                <h3>Critical Findings</h3>
                <div class="number">$critical_count</div>
            </div>
            <div class="stat-card high">
                <h3>High Severity</h3>
                <div class="number">$high_count</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🚨 Critical Findings</h2>
            <pre class="critical">$(grep -i critical "$data_dir/vulnerabilities.txt" 2>/dev/null | head -20 || echo "No critical vulnerabilities found")</pre>
        </div>
        
        <div class="section">
            <h2>⚠️ High Severity Findings</h2>
            <pre class="high">$(grep -i high "$data_dir/vulnerabilities.txt" 2>/dev/null | head -20 || echo "No high severity vulnerabilities found")</pre>
        </div>
        
        <div class="section">
            <h2>📋 All Vulnerabilities</h2>
            <pre>$(cat "$data_dir/vulnerabilities.txt" 2>/dev/null | head -100 || echo "No vulnerability data available")</pre>
        </div>
        
        <div class="section">
            <h2>🔍 Subdomain Discovery</h2>
            <pre>$(cat "$data_dir/all_subdomains.txt" 2>/dev/null | head -50 || echo "No subdomain data available")</pre>
        </div>
        
        <div class="section">
            <h2>🌐 Live Host Analysis</h2>
            <pre>$(cat "$data_dir/live_analysis.txt" 2>/dev/null | head -30 || echo "No live host data available")</pre>
        </div>
        
        <div class="footer">
            <p>Generated with Bug Bounty Dotfiles Framework</p>
            <p>🔒 Use responsibly and ethically</p>
        </div>
    </div>
</body>
</html>
EOF
    
    echo "${BB_COLOR_INFO}[+] HTML report generated: $report_file${BB_COLOR_RESET}"
    
    # Try to open in browser if available
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$report_file" 2>/dev/null &
    elif command -v open >/dev/null 2>&1; then
        open "$report_file" 2>/dev/null &
    fi
}

# JSON report for automation
generate_json_report() {
    local target="$1"
    local data_dir="$2"
    local json_file="$data_dir/report_${target}_$(date +%Y%m%d_%H%M%S).json"
    
    # Extract data and convert to JSON
    jq -n \
        --arg target "$target" \
        --arg timestamp "$(date -Iseconds)" \
        --arg operator "$(whoami)@$(hostname)" \
        --argjson subdomains "$(cat "$data_dir/all_subdomains.txt" 2>/dev/null | jq -R . | jq -s . || echo '[]')" \
        --argjson vulnerabilities "$(cat "$data_dir/vulnerabilities.txt" 2>/dev/null | jq -R . | jq -s . || echo '[]')" \
        '{
            scan_info: {
                target: $target,
                timestamp: $timestamp,
                operator: $operator,
                framework: "bug-bounty-dotfiles"
            },
            statistics: {
                subdomains_total: ($subdomains | length),
                vulnerabilities_total: ($vulnerabilities | length)
            },
            data: {
                subdomains: $subdomains,
                vulnerabilities: $vulnerabilities
            }
        }' > "$json_file"
    
    echo "${BB_COLOR_INFO}[+] JSON report generated: $json_file${BB_COLOR_RESET}"
}
```

## 🔔 Notification Systems

### Multi-Platform Notifications

```bash
# Universal notification system
notify_finding() {
    local severity="$1"
    local message="$2"
    local target="${3:-unknown}"
    
    local emoji
    case "$severity" in
        critical) emoji="🚨" ;;
        high) emoji="⚠️" ;;
        medium) emoji="📋" ;;
        *) emoji="ℹ️" ;;
    esac
    
    local full_message="$emoji [$severity] $target: $message"
    
    # Slack notification
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST "$SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"$full_message\"}" 2>/dev/null
    fi
    
    # Discord notification
    if [ -n "$DISCORD_WEBHOOK" ]; then
        curl -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"content\":\"$full_message\"}" 2>/dev/null
    fi
    
    # Telegram notification
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID&text=$full_message" >/dev/null
    fi
    
    # Local desktop notification
    if command -v notify-send >/dev/null 2>&1; then
        notify-send "Bug Bounty Alert" "$full_message"
    fi
    
    # Terminal bell and log
    echo -e "\a"
    echo "$(date): $full_message" >> "$HOME/.bb_notifications.log"
}

# Monitoring function for live scans
monitor_scan() {
    local log_file="$1"
    local target="$2"
    
    tail -f "$log_file" | while read -r line; do
        case "$line" in
            *critical*|*CRITICAL*)
                notify_finding "critical" "$line" "$target"
                ;;
            *high*|*HIGH*)
                notify_finding "high" "$line" "$target"
                ;;
        esac
    done &
    
    echo $! > /tmp/monitor_scan_$$.pid
    echo "${BB_COLOR_INFO}[+] Monitoring scan for $target (PID: $(cat /tmp/monitor_scan_$$.pid))${BB_COLOR_RESET}"
}

# Stop monitoring
stop_monitor() {
    if [ -f "/tmp/monitor_scan_$$.pid" ]; then
        kill "$(cat /tmp/monitor_scan_$$.pid)" 2>/dev/null
        rm -f "/tmp/monitor_scan_$$.pid"
        echo "${BB_COLOR_INFO}[+] Monitoring stopped${BB_COLOR_RESET}"
    fi
}
```

## 🚀 Advanced Automation

### Automated Workflows

```bash
# Daily automation script
daily_routine() {
    local targets_file="$BB_WORKSPACE/daily_targets.txt"
    
    if [ ! -f "$targets_file" ]; then
        echo "${BB_COLOR_HIGH}[!] Create $targets_file with your daily targets${BB_COLOR_RESET}"
        return 1
    fi
    
    echo "${BB_COLOR_INFO}[+] Starting daily routine...${BB_COLOR_RESET}"
    
    while read -r target; do
        [ -z "$target" ] && continue
        
        echo "${BB_COLOR_INFO}[+] Processing: $target${BB_COLOR_RESET}"
        
        # Create dated directory
        local daily_dir="$BB_WORKSPACE/daily/$(date +%Y%m%d)/$target"
        mkdir -p "$daily_dir"
        cd "$daily_dir"
        
        # Run quick scan
        triage_profile "$target" > "quick_scan.txt" 2>&1
        
        # Check for new findings
        if grep -qi critical "quick_scan.txt"; then
            notify_finding "critical" "New critical finding in daily scan" "$target"
        fi
        
    done < "$targets_file"
    
    echo "${BB_COLOR_INFO}[+] Daily routine completed${BB_COLOR_RESET}"
}

# Continuous monitoring
continuous_monitor() {
    local target="$1"
    local interval="${2:-3600}" # 1 hour default
    
    echo "${BB_COLOR_INFO}[+] Starting continuous monitoring for $target (interval: ${interval}s)${BB_COLOR_RESET}"
    
    while true; do
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local monitor_dir="$BB_WORKSPACE/monitoring/$target/$timestamp"
        
        mkdir -p "$monitor_dir"
        cd "$monitor_dir"
        
        # Quick scan for changes
        triage_profile "$target" > "scan_$timestamp.txt" 2>&1
        
        # Compare with previous scan
        local prev_scan=$(find "$BB_WORKSPACE/monitoring/$target" -name "scan_*.txt" -not -path "*/$timestamp/*" | sort | tail -1)
        
        if [ -n "$prev_scan" ] && [ -f "$prev_scan" ]; then
            local new_findings=$(comm -13 <(sort "$prev_scan") <(sort "scan_$timestamp.txt"))
            
            if [ -n "$new_findings" ]; then
                echo "$new_findings" > "new_findings_$timestamp.txt"
                notify_finding "info" "New findings detected in continuous monitoring" "$target"
            fi
        fi
        
        sleep "$interval"
    done
}
```

### Git Integration

```bash
# Automatic result versioning
git_track_results() {
    local target="$1"
    local workspace="$BB_WORKSPACE/$target"
    
    if [ ! -d "$workspace" ]; then
        echo "${BB_COLOR_HIGH}[!] Target workspace not found: $target${BB_COLOR_RESET}"
        return 1
    fi
    
    cd "$workspace"
    
    # Initialize git repo if needed
    if [ ! -d ".git" ]; then
        git init
        cat > .gitignore << 'EOF'
*.tmp
*.log
.env
*.pid
EOF
    fi
    
    # Add and commit changes
    git add .
    git commit -m "Scan results update: $(date)"
    
    echo "${BB_COLOR_INFO}[+] Results committed to git for $target${BB_COLOR_RESET}"
}

# Sync with remote repository
sync_results() {
    local target="$1"
    local remote_url="$2"
    local workspace="$BB_WORKSPACE/$target"
    
    cd "$workspace"
    
    # Add remote if not exists
    if ! git remote get-url origin >/dev/null 2>&1; then
        git remote add origin "$remote_url"
    fi
    
    # Push to remote
    git push -u origin main
    
    echo "${BB_COLOR_INFO}[+] Results synced to remote repository${BB_COLOR_RESET}"
}
```

## 🎨 Theme and Visual Customization

### Custom Prompt Themes

```bash
# Cyberpunk theme
setup_cyberpunk_theme() {
    export BB_COLOR_CRITICAL='\033[1;91m'    # Bright red
    export BB_COLOR_HIGH='\033[1;93m'        # Bright yellow
    export BB_COLOR_MEDIUM='\033[1;96m'      # Bright cyan
    export BB_COLOR_INFO='\033[1;92m'        # Bright green
    export BB_COLOR_ACCENT='\033[1;95m'      # Bright magenta
    export BB_COLOR_RESET='\033[0m'
    
    # Custom PS1 for bash
    if [ -n "$BASH_VERSION" ]; then
        PS1='\[${BB_COLOR_ACCENT}\]┌─[\[${BB_COLOR_INFO}\]\u\[${BB_COLOR_ACCENT}\]@\[${BB_COLOR_INFO}\]\h\[${BB_COLOR_ACCENT}\]]-[\[${BB_COLOR_CRITICAL}\]\w\[${BB_COLOR_ACCENT}\]]\n\[${BB_COLOR_ACCENT}\]└─\[${BB_COLOR_HIGH}\]\$ \[${BB_COLOR_RESET}\]'
    fi
}

# Matrix theme
setup_matrix_theme() {
    export BB_COLOR_CRITICAL='\033[1;31m'    # Red
    export BB_COLOR_HIGH='\033[1;33m'        # Yellow
    export BB_COLOR_MEDIUM='\033[1;32m'      # Green
    export BB_COLOR_INFO='\033[1;32m'        # Green
    export BB_COLOR_ACCENT='\033[1;32m'      # Green
    export BB_COLOR_RESET='\033[0m'
    
    # Custom matrix-style prompt
    if [ -n "$BASH_VERSION" ]; then
        PS1='\[${BB_COLOR_ACCENT}\]> \[${BB_COLOR_INFO}\]\u@\h:\w\[${BB_COLOR_ACCENT}\] $ \[${BB_COLOR_RESET}\]'
    fi
}

# Apply theme based on preference
case "${BB_THEME:-default}" in
    cyberpunk) setup_cyberpunk_theme ;;
    matrix) setup_matrix_theme ;;
esac
```

### Custom Banners

```bash
# Show custom banner on shell startup
show_bb_banner() {
    if [ "$ENABLE_PERSONAL_ALIASES" = true ]; then
        cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                     🎯 BUG BOUNTY TERMINAL 🎯                ║
║                                                               ║
║  Ready for ethical hacking and security research             ║
║  Type 'bbhelp' for available commands                       ║
║  Type 'menu' for interactive tool selection                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
        
        # Show current target if in workspace
        if [[ "$PWD" =~ ^$BB_WORKSPACE/.* ]]; then
            local current_target=$(basename "$(pwd)")
            echo "${BB_COLOR_INFO}🎯 Current target: $current_target${BB_COLOR_RESET}"
        fi
        
        # Show system status
        echo "${BB_COLOR_INFO}⚡ Parallel jobs: ${J:-auto}${BB_COLOR_RESET}"
        echo "${BB_COLOR_INFO}🛠️  Tools ready: $(alias | grep -c '^alias.*=')${BB_COLOR_RESET}"
        echo ""
    fi
}

# Add to shell startup
if [ -t 1 ]; then  # Only show in interactive terminals
    show_bb_banner
fi
```

## 🔧 Performance Optimization

### System-Specific Tuning

```bash
# Automatic performance tuning based on system
optimize_for_system() {
    local cpu_cores=$(nproc)
    local total_memory=$(free -m | awk '/^Mem:/{print $2}')
    local available_memory=$(free -m | awk '/^Available:/{print $2}')
    
    echo "${BB_COLOR_INFO}[+] System: ${cpu_cores} cores, ${total_memory}MB total memory${BB_COLOR_RESET}"
    
    # Set parallel jobs based on system capabilities
    if [ "$cpu_cores" -lt 4 ]; then
        export J=500
        echo "${BB_COLOR_INFO}[+] Low-power system detected, setting J=500${BB_COLOR_RESET}"
    elif [ "$cpu_cores" -lt 8 ]; then
        export J=2000
        echo "${BB_COLOR_INFO}[+] Mid-range system detected, setting J=2000${BB_COLOR_RESET}"
    elif [ "$cpu_cores" -lt 16 ]; then
        export J=5000
        echo "${BB_COLOR_INFO}[+] High-performance system detected, setting J=5000${BB_COLOR_RESET}"
    else
        export J=9000
        echo "${BB_COLOR_INFO}[+] Server-class system detected, setting J=9000${BB_COLOR_RESET}"
    fi
    
    # Memory-based optimizations
    if [ "$available_memory" -lt 2048 ]; then
        echo "${BB_COLOR_HIGH}[!] Low memory detected, consider closing other applications${BB_COLOR_RESET}"
        export HTTPX_THREADS=50
        export NUCLEI_BULK_SIZE=25
    else
        export HTTPX_THREADS=200
        export NUCLEI_BULK_SIZE=100
    fi
}

# Run optimization on startup
optimize_for_system
```

This comprehensive customization guide gives you everything you need to make the bug bounty dotfiles framework truly your own. From simple alias additions to complex automated workflows, you can adapt every aspect to match your unique style and requirements.

Remember: The best security setup is one that fits seamlessly into your workflow. Start with small customizations and gradually build up your personalized environment as you discover what works best for your methodology.