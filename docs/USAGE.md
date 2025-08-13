# Ultimate Security Research Environment - Usage Guide

## Overview
This environment provides a comprehensive set of tools and scripts for security research, bug bounty hunting, and penetration testing with optimized parallel processing capabilities supporting up to 9,000 concurrent jobs.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Scripts](#core-scripts)
- [Parallel Processing](#parallel-processing)
- [Built-in Functions](#built-in-functions)
- [Tool Integration](#tool-integration)
- [Advanced Workflows](#advanced-workflows)
- [Performance Optimization](#performance-optimization)
- [Best Practices](#best-practices)

## Installation

### Automated Setup
```bash
# Full installation with all components
./install/enhanced_setup.sh full

# Quick installation (essential tools only)
./install/enhanced_setup.sh quick

# Interactive installation (choose components)
./install/enhanced_setup.sh custom
```

### Manual Tool Installation
```bash
# Install specific tool categories
./install/enhanced_setup.sh
# Then select components: 1=System, 2=Go Tools, 3=Python Tools, etc.
```

## Quick Start

### 1. Basic Reconnaissance
```bash
# Quick scan - essential reconnaissance
./scripts/recon/bug_bounty_framework/quick_scan.sh example.com

# Advanced scan - comprehensive testing
./scripts/recon/bug_bounty_framework/advanced_scan.sh example.com

# Ultimate scan - full security assessment
./scripts/recon/bug_bounty_framework/ultimate_scan.sh -t comprehensive example.com
```

### 2. Load Security Functions
```bash
# Load all security aliases and functions
source ~/.security_aliases

# Verify functions are loaded
type quick_sub_enum recon_pipeline
```

### 3. Parallel Operations
```bash
# Check optimal parallel job count
echo "Optimal jobs: $(calc_parallel_jobs)"

# Run parallel subdomain enumeration
quick_sub_enum example.com

# Run comprehensive reconnaissance pipeline
recon_pipeline example.com 5000  # Use 5000 parallel jobs
```

## Core Scripts

### Quick Scan (`quick_scan.sh`)
**Purpose**: Fast reconnaissance for immediate results

**Features**:
- Subdomain enumeration (Subfinder)
- Live host detection (HTTPx)
- Port scanning (Naabu)
- URL discovery (Waybackurls, GAU, Katana)
- Vulnerability scanning (Nuclei)
- Directory fuzzing (FFuf)

**Usage**:
```bash
# Basic usage
./quick_scan.sh example.com

# With monitoring
./quick_scan.sh --monitor example.com

# With verbose output
./quick_scan.sh --verbose example.com

# Custom parallel jobs
J=2000 ./quick_scan.sh example.com
```

**Output Structure**:
```
results/YYYYMMDD_HHMMSS_example.com/
├── subdomains.txt          # All discovered subdomains
├── live_subdomains.txt     # Live/responding subdomains
├── ports.txt              # Open ports
├── urls.txt               # All discovered URLs
├── vulnerabilities.txt     # Nuclei findings
└── scan.log               # Detailed scan log
```

### Advanced Scan (`advanced_scan.sh`)
**Purpose**: Comprehensive testing with detailed analysis

**Additional Features**:
- Multiple subdomain sources (Subfinder, Assetfinder, crt.sh, Anubis)
- Detailed HTTP probing with tech detection
- Parameter discovery
- XSS testing (Dalfox)
- Open redirect detection
- Comprehensive reporting

**Usage**:
```bash
# Standard advanced scan
./advanced_scan.sh example.com

# With custom resolvers
RESOLVERS_FILE=/path/to/resolvers.txt ./advanced_scan.sh example.com

# Monitor resources during scan
./advanced_scan.sh --monitor example.com
```

**Output Structure**:
```
results/YYYYMMDD_HHMMSS_example.com/
├── all_subdomains.txt      # Combined subdomain results
├── live_detailed.txt       # Detailed HTTP probe results
├── all_urls.txt           # All discovered URLs
├── urls_with_params.txt    # URLs with parameters
├── xss_results.txt        # XSS testing results
├── report.html            # Interactive HTML report
└── various source files   # Individual tool outputs
```

### Ultimate Scan (`ultimate_scan.sh`)
**Purpose**: Full-spectrum security assessment

**All Previous Features Plus**:
- Certificate analysis
- Technology stack fingerprinting
- Advanced vulnerability scanning
- Custom payload testing
- Machine-readable JSON outputs
- Professional reporting

**Usage**:
```bash
# Comprehensive scan
./ultimate_scan.sh -t comprehensive example.com

# Quick scan mode
./ultimate_scan.sh -t quick example.com

# Advanced scan with custom settings
./ultimate_scan.sh -t advanced -j 3000 -w /path/to/wordlist.txt example.com

# Silent mode with custom output
./ultimate_scan.sh -t comprehensive -s -o /path/to/results example.com
```

**Command Line Options**:
- `-t, --type`: Scan type (quick|advanced|comprehensive)
- `-j, --jobs`: Max parallel jobs
- `-o, --output`: Output directory
- `-r, --resolvers`: Custom DNS resolvers file
- `-w, --wordlist`: Custom wordlist for fuzzing
- `-s, --silent`: Silent mode
- `-v, --verbose`: Verbose mode

## Parallel Processing

### Automatic Job Calculation
The framework automatically calculates optimal parallel jobs:

```bash
# View calculation details
calc_parallel_jobs

# Factors considered:
# - CPU cores (target: cores × 64)
# - File descriptor limits (70% utilization)
# - System memory and load
# - Hard cap at 9,000 jobs for stability
```

### Manual Job Control
```bash
# Set custom parallel job count
export J=1500

# Use parallel wrapper function
P() { parallel --bar -j"${J:-9000}" "$@"; }

# Example: Parallel subdomain enumeration
cat domains.txt | P 'subfinder -d {} -silent > subs_{}.txt'
```

### Resource Optimization
```bash
# Increase file descriptor limits
ulimit -n 65536

# Monitor system resources
htop &
watch -n1 'ss -s' &

# Use built-in monitoring
./ultimate_scan.sh --monitor example.com
```

## Built-in Functions

### Reconnaissance Functions

#### `quick_sub_enum domain.com`
Fast subdomain enumeration with parallel processing
```bash
quick_sub_enum example.com
# Creates timestamped results directory
# Uses multiple sources in parallel
# Generates summary statistics
```

#### `quick_vuln_scan target.com`
Fast vulnerability scanning
```bash
quick_vuln_scan https://example.com
# Checks if target is live
# Runs Nuclei with multiple severity levels
# Categorizes findings
```

#### `recon_pipeline domain.com [threads]`
Comprehensive reconnaissance pipeline
```bash
recon_pipeline example.com 5000
# Phase 1: Subdomain enumeration
# Phase 2: Live detection
# Phase 3: URL discovery
# Phase 4: Vulnerability scanning
```

### Bulk Operations

#### `bulk_http_check targets.txt`
Parallel HTTP status checking
```bash
echo -e "google.com\nexample.com\ngithub.com" > targets.txt
bulk_http_check targets.txt
```

#### `bulk_nuclei_scan targets.txt`
Mass vulnerability scanning
```bash
bulk_nuclei_scan live_targets.txt
# Scans all targets in parallel
# Uses high/critical/medium severity
```

### Parameter Testing Functions

#### `extract_params urls.txt`
Extract URL parameters for testing
```bash
extract_params wayback_urls.txt
# Outputs domain, path, and query parameters
# Useful for identifying injection points
```

#### `test_xss_params urls_with_params.txt`
Parallel XSS parameter testing
```bash
test_xss_params parameterized_urls.txt
# Tests all URLs with Dalfox
# Uses maximum parallel processing
```

## Tool Integration

### Subdomain Enumeration
```bash
# Multiple sources with parallel execution
parallel -j9000 ::: \
    "subfinder -d example.com -all -silent > subs1.txt" \
    "assetfinder --subs-only example.com > subs2.txt" \
    "chaos -d example.com -silent > subs3.txt"

# Combine and deduplicate
cat subs*.txt | sort -u > all_subdomains.txt
```

### HTTP Analysis
```bash
# Comprehensive HTTP probing
httpx -l subdomains.txt -tech-detect -status-code -content-length \
    -title -server -threads 9000 > detailed_results.txt

# Extract specific information
cut -d' ' -f1 detailed_results.txt > live_urls.txt
grep -E "(WordPress|Joomla|Drupal)" detailed_results.txt > cms_targets.txt
```

### Vulnerability Scanning
```bash
# Parallel Nuclei scanning with different templates
parallel -j9000 ::: \
    "nuclei -l targets.txt -t ~/nuclei-templates/cves/ -o cve_results.txt" \
    "nuclei -l targets.txt -t ~/nuclei-templates/vulnerabilities/ -o vuln_results.txt" \
    "nuclei -l targets.txt -t ~/nuclei-templates/misconfiguration/ -o misc_results.txt"
```

### Content Discovery
```bash
# Parallel directory fuzzing
head -20 live_subdomains.txt | parallel -j9000 \
    'ffuf -u {}/FUZZ -w /path/to/wordlist.txt -ac -o results/ffuf_{#}.json -of json'

# Parallel parameter discovery
cat live_urls.txt | parallel -j9000 \
    'arjun -u {} --get --post -o results/params_{#}.json'
```

## Advanced Workflows

### Custom Reconnaissance Pipeline
```bash
#!/bin/bash
advanced_recon() {
    local domain="$1"
    local threads="${2:-9000}"
    local output_dir="advanced_$(date +%Y%m%d_%H%M%S)_$domain"
    
    mkdir -p "$output_dir"
    
    echo "🎯 Advanced reconnaissance for $domain"
    
    # Phase 1: Multi-source subdomain enumeration
    parallel -j"$threads" ::: \
        "subfinder -d $domain -all -silent > $output_dir/subfinder.txt" \
        "assetfinder --subs-only $domain > $output_dir/assetfinder.txt" \
        "chaos -d $domain -silent > $output_dir/chaos.txt" \
        "amass enum -passive -d $domain > $output_dir/amass.txt"
    
    # Combine results
    cat "$output_dir"/{subfinder,assetfinder,chaos,amass}.txt | \
        sort -u > "$output_dir/all_subdomains.txt"
    
    # Phase 2: Advanced HTTP probing
    httpx -l "$output_dir/all_subdomains.txt" -tech-detect -status-code \
        -content-length -title -server -threads "$threads" \
        > "$output_dir/http_detailed.txt"
    
    # Phase 3: Port scanning
    cut -d' ' -f1 "$output_dir/http_detailed.txt" | \
        naabu -l /dev/stdin -top-ports 3000 -silent -rate "$threads" \
        > "$output_dir/open_ports.txt"
    
    # Phase 4: URL discovery
    parallel -j"$threads" ::: \
        "cat $output_dir/http_detailed.txt | cut -d' ' -f1 | waybackurls > $output_dir/wayback.txt" \
        "cat $output_dir/http_detailed.txt | cut -d' ' -f1 | gau > $output_dir/gau.txt" \
        "katana -list $output_dir/http_detailed.txt -silent > $output_dir/katana.txt"
    
    # Phase 5: Vulnerability assessment
    cut -d' ' -f1 "$output_dir/http_detailed.txt" | \
        nuclei -l /dev/stdin -severity critical,high,medium -j "$threads" \
        -o "$output_dir/vulnerabilities.txt"
    
    # Generate summary
    echo "📊 Advanced reconnaissance completed!"
    echo "   - Subdomains: $(wc -l < "$output_dir/all_subdomains.txt")"
    echo "   - Live hosts: $(wc -l < "$output_dir/http_detailed.txt")"
    echo "   - Open ports: $(wc -l < "$output_dir/open_ports.txt")"
    echo "   - Vulnerabilities: $(wc -l < "$output_dir/vulnerabilities.txt")"
}
```

### Mass Scanning Workflow
```bash
#!/bin/bash
mass_scan() {
    local targets_file="$1"
    local threads="${2:-9000}"
    local output_dir="mass_scan_$(date +%Y%m%d_%H%M%S)"
    
    mkdir -p "$output_dir"
    
    echo "🚀 Mass scanning $(wc -l < "$targets_file") targets"
    
    # Parallel subdomain enumeration
    cat "$targets_file" | parallel -j"$threads" --bar \
        'subfinder -d {} -silent > "'$output_dir'/subs_{}.txt"'
    
    # Combine all subdomains
    cat "$output_dir"/subs_*.txt | sort -u > "$output_dir/all_subdomains.txt"
    
    # Mass HTTP probing
    httpx -l "$output_dir/all_subdomains.txt" -threads "$threads" \
        > "$output_dir/live_subdomains.txt"
    
    # Mass vulnerability scanning
    nuclei -l "$output_dir/live_subdomains.txt" -severity critical,high \
        -j "$threads" -o "$output_dir/critical_vulns.txt"
    
    echo "✅ Mass scan completed: $output_dir"
}
```

## Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Increase network buffer sizes
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf

# Apply changes
sudo sysctl -p
```

### Memory Optimization
```bash
# Monitor memory usage during scans
watch -n1 'free -h && echo "--- Top Memory Users ---" && ps aux --sort=-%mem | head -10'

# Use memory-mapped files for large datasets
sort --buffer-size=1G --temporary-directory=/tmp large_file.txt
```

### Parallel Job Tuning
```bash
# Test optimal parallel jobs for your system
for jobs in 1000 2000 4000 6000 8000 9000; do
    echo "Testing $jobs parallel jobs..."
    time (seq 1 1000 | parallel -j$jobs 'sleep 0.01' 2>/dev/null)
done
```

### Network Optimization
```bash
# Use custom DNS resolvers for better performance
echo -e "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1" > /tmp/resolvers.txt
export RESOLVERS_FILE="/tmp/resolvers.txt"

# Monitor network connections
watch -n1 'ss -s && echo "Active connections: $(ss -t | wc -l)"'
```

## Best Practices

### 1. Authorization and Legal Compliance
```bash
# Always verify authorization before testing
echo "example.com" > authorized_targets.txt
# Only test domains in this file
```

### 2. Rate Limiting and Respectful Testing
```bash
# Use appropriate rate limits
subfinder -d example.com -rate-limit 10  # 10 requests per second
nuclei -l targets.txt -rate-limit 150    # 150 requests per second

# Add delays between requests
httpx -l targets.txt -delay 1s           # 1 second delay
```

### 3. Data Management
```bash
# Organize results by date and target
RESULTS_BASE="/path/to/results"
TODAY=$(date +%Y%m%d)
mkdir -p "$RESULTS_BASE/$TODAY"

# Compress old results
find "$RESULTS_BASE" -name "*.txt" -mtime +7 -exec gzip {} \;
```

### 4. Error Handling
```bash
# Use proper error handling in custom scripts
set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Log errors appropriately
exec 2> >(tee -a error.log >&2)

# Implement retries for network operations
retry_command() {
    local cmd="$1"
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if $cmd; then
            return 0
        fi
        echo "Attempt $attempt failed, retrying..."
        sleep $attempt
        ((attempt++))
    done
    
    echo "Command failed after $max_attempts attempts"
    return 1
}
```

### 5. Resource Monitoring
```bash
# Monitor system resources during intensive scans
monitor_resources() {
    local duration="${1:-300}"  # Monitor for 5 minutes by default
    local log_file="resource_monitor_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "=== Resource Monitor Started ==="
        echo "Duration: ${duration}s"
        echo "Log file: $log_file"
        echo "==================================="
    } | tee "$log_file"
    
    for ((i=0; i<duration; i+=10)); do
        {
            echo "--- $(date) ---"
            echo "CPU: $(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$3+$4)} END {print usage "%"}')"
            echo "Memory: $(free | awk 'NR==2{printf "%.1f%%\t", $3*100/$2}')"
            echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
            echo "Connections: $(ss -t | wc -l)"
            echo "File descriptors: $(ls /proc/$$/fd | wc -l)"
            echo
        } | tee -a "$log_file"
        sleep 10
    done
}
```

### 6. Result Validation
```bash
# Validate subdomain results
validate_subdomains() {
    local file="$1"
    echo "Validating subdomains in $file..."
    
    # Remove invalid entries
    grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$" "$file" > "${file}.clean"
    
    # Check for suspicious entries
    grep -E "(localhost|127\.0\.0\.1|internal)" "${file}.clean" > "${file}.suspicious" || true
    
    echo "Original: $(wc -l < "$file")"
    echo "Clean: $(wc -l < "${file}.clean")"
    echo "Suspicious: $(wc -l < "${file}.suspicious" 2>/dev/null || echo 0)"
}
```

## Troubleshooting

### Common Issues and Solutions

1. **Too many open files error**:
```bash
# Increase file descriptor limit
ulimit -n 65536
```

2. **Memory exhaustion**:
```bash
# Reduce parallel jobs
export J=1000
```

3. **Network timeouts**:
```bash
# Use custom timeout settings
httpx -l targets.txt -timeout 30
```

4. **Permission errors**:
```bash
# Fix ownership
sudo chown -R $USER:$USER ~/tools
```

For more detailed troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Getting Help

- Check tool documentation: `tool_name -h` or `man tool_name`
- Review script source code for understanding
- Test with small datasets first
- Monitor system resources during large scans
- Check logs for error messages
- Verify tool installation and versions

## Examples Repository

Find more examples and templates in the `examples/` directory:
- Custom workflow templates
- Integration scripts
- Automation examples
- Reporting templates

---

*This guide is continuously updated. Check back regularly for new features and improvements.*