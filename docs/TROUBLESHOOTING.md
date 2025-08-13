# Troubleshooting Guide - Ultimate Security Research Environment

## Table of Contents
- [Installation Issues](#installation-issues)
- [Performance Problems](#performance-problems)
- [Tool-Specific Issues](#tool-specific-issues)
- [Network and Connectivity](#network-and-connectivity)
- [System Resource Issues](#system-resource-issues)
- [Parallel Processing Problems](#parallel-processing-problems)
- [Reporting and Output Issues](#reporting-and-output-issues)
- [Configuration Problems](#configuration-problems)
- [Debugging Techniques](#debugging-techniques)

## Installation Issues

### Missing Dependencies

**Problem**: Installation fails due to missing system dependencies
```
E: Unable to locate package build-essential
E: Package 'golang-go' has no installation candidate
```

**Solutions**:
```bash
# Update package lists first
sudo apt update && sudo apt upgrade

# Install missing dependencies manually
sudo apt install -y curl wget git build-essential python3-pip python3-dev

# For Ubuntu/Debian systems
sudo apt install -y software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Add additional repositories if needed
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
```

### Go Installation Issues

**Problem**: Go tools fail to install or aren't found in PATH
```bash
go: command not found
-bash: /home/user/go/bin/nuclei: No such file or directory
```

**Solutions**:
```bash
# Install Go if not present
sudo apt install golang-go

# Or install latest Go manually
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz

# Set Go environment variables
export GOPATH="$HOME/go"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"
echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
echo 'export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"' >> ~/.bashrc

# Create Go directories
mkdir -p "$GOPATH"/{bin,src,pkg}

# Reinstall Go tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Python Tool Installation Issues

**Problem**: Python tools fail to install or have dependency conflicts
```
ERROR: Could not install packages due to an EnvironmentError
pip: error: Microsoft Visual C++ 14.0 is required
```

**Solutions**:
```bash
# Update pip and setuptools
python3 -m pip install --upgrade pip setuptools wheel

# Install with user flag if permission issues
pip3 install --user tool_name

# Use virtual environment to avoid conflicts
python3 -m venv venv
source venv/bin/activate
pip install tool_name

# Install system dependencies for Python compilation
sudo apt install -y python3-dev libffi-dev libssl-dev

# For specific tools like lxml
sudo apt install -y libxml2-dev libxslt1-dev

# Clear pip cache if corrupted
pip cache purge
```

### Permission Issues

**Problem**: Permission denied errors during installation
```
mkdir: cannot create directory '/usr/local/bin': Permission denied
cp: cannot create regular file '/usr/bin/tool': Permission denied
```

**Solutions**:
```bash
# Use sudo for system-wide installations
sudo ./install/enhanced_setup.sh

# Or install to user directories
export PATH="$HOME/.local/bin:$PATH"
pip3 install --user tool_name

# Fix ownership of existing directories
sudo chown -R $USER:$USER ~/tools ~/go ~/.local

# Create user bin directory
mkdir -p ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"
```

## Performance Problems

### High CPU Usage

**Problem**: System becomes unresponsive during scans
```
CPU usage: 100% across all cores
System load: 15.0+ (on 4-core system)
```

**Solutions**:
```bash
# Reduce parallel job count
export J=500  # Instead of default 9000

# Monitor CPU usage
htop
watch -n1 'grep "cpu " /proc/stat | awk "{usage=(\$2+\$4)*100/(\$2+\$3+\$4)} END {print usage \"%\"}"'

# Use CPU throttling
cpulimit -l 50 -e nuclei  # Limit nuclei to 50% CPU

# Set process priority
nice -n 10 ./scan_script.sh  # Lower priority

# Use systemd to limit resources
systemd-run --scope -p CPUQuota=50% ./scan_script.sh
```

### Memory Exhaustion

**Problem**: System runs out of memory during large scans
```
Out of memory: Kill process 1234 (nuclei)
Cannot allocate memory
```

**Solutions**:
```bash
# Monitor memory usage
free -h
watch -n1 'free -h && echo "=== Top Memory Users ===" && ps aux --sort=-%mem | head -5'

# Reduce parallel jobs
export J=100  # Significantly reduce

# Increase swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Add to /etc/fstab for persistence
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Use memory limits for processes
systemd-run --scope -p MemoryLimit=2G ./scan_script.sh

# Split large operations
split -l 1000 large_subdomain_list.txt chunk_
```

### File Descriptor Exhaustion

**Problem**: "Too many open files" error
```
socket: too many open files
accept: too many open files
nuclei: too many open files
```

**Solutions**:
```bash
# Check current limit
ulimit -n

# Increase temporarily
ulimit -n 65536

# Increase permanently for user
echo "$USER soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "$USER hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# System-wide limits
echo "fs.file-max = 1000000" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Check system limits
cat /proc/sys/fs/file-max
cat /proc/sys/fs/file-nr

# Monitor file descriptor usage
lsof | wc -l
ls /proc/$$/fd | wc -l
```

## Tool-Specific Issues

### Nuclei Template Issues

**Problem**: Nuclei templates are outdated or corrupted
```
WARN Could not load template
INFO no templates loaded for scan
```

**Solutions**:
```bash
# Update templates manually
nuclei -update-templates

# Check template directory
ls -la ~/.nuclei-templates/

# Reset templates completely
rm -rf ~/.nuclei-templates/
nuclei -update-templates

# Use specific template directory
nuclei -t ~/nuclei-templates/ -u target.com

# Verify template syntax
nuclei -t ~/nuclei-templates/cves/ -validate

# Use offline templates if network issues
git clone https://github.com/projectdiscovery/nuclei-templates.git
nuclei -t ./nuclei-templates/ -u target.com
```

### Subfinder Configuration

**Problem**: Subfinder returns limited results or fails to run
```
subfinder: no domains to enum
WARN Could not get sources
```

**Solutions**:
```bash
# Create config file
mkdir -p ~/.config/subfinder/
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
resolvers:
  - 8.8.8.8
  - 1.1.1.1
  - 8.8.4.4
  - 1.0.0.1
sources:
  - all
EOF

# Test with specific sources
subfinder -d example.com -sources crtsh,virustotal -v

# Check version and update
subfinder -version
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Use manual sources if API issues
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

### HTTPx Connection Issues

**Problem**: HTTPx fails to connect to targets or times out
```
ERR Could not connect to target
context deadline exceeded
connection refused
```

**Solutions**:
```bash
# Increase timeout values
httpx -l targets.txt -timeout 30

# Reduce concurrent connections
httpx -l targets.txt -threads 50

# Use custom user agent
httpx -l targets.txt -H "User-Agent: Mozilla/5.0..."

# Skip SSL verification if needed (testing only)
httpx -l targets.txt -verify-ssl=false

# Use different ports
httpx -l targets.txt -ports 80,443,8080,8443

# Test connectivity manually
curl -I --max-time 10 https://target.com
```

### FFuf Performance Issues

**Problem**: FFuf is too slow or produces too many false positives
```
ffuf: Progress: [0s] 0/1000 | Rate: 0 req/sec
Too many 404 responses
```

**Solutions**:
```bash
# Increase thread count
ffuf -u https://target.com/FUZZ -w wordlist.txt -t 100

# Use auto-calibration
ffuf -u https://target.com/FUZZ -w wordlist.txt -ac

# Filter by size or response codes
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234 -fc 404

# Use custom rate limiting
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 100

# Output to file for analysis
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json
```

## Network and Connectivity

### DNS Resolution Problems

**Problem**: DNS resolution is slow or fails
```
no such host
DNS resolution failed
getaddrinfo: Name or service not known
```

**Solutions**:
```bash
# Test DNS resolution
dig example.com
nslookup example.com

# Use different DNS servers
echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" | sudo tee /etc/resolv.conf

# Create custom resolver list
echo -e "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1" > /tmp/resolvers.txt
dnsx -l subdomains.txt -r /tmp/resolvers.txt

# Use massdns for large lists
echo "example.com" | massdns -r /tmp/resolvers.txt -t A

# Check system DNS configuration
systemd-resolve --status
```

### Proxy and Firewall Issues

**Problem**: Network requests are blocked or need to go through proxy
```
Connection refused
Proxy authentication required
```

**Solutions**:
```bash
# Set proxy environment variables
export http_proxy=http://proxy.example.com:8080
export https_proxy=http://proxy.example.com:8080
export no_proxy=localhost,127.0.0.1

# Use proxy with tools
nuclei -u target.com -proxy-url http://proxy:8080
httpx -l targets.txt -http-proxy http://proxy:8080

# Test proxy connectivity
curl -x http://proxy:8080 http://example.com

# Use SOCKS proxy
export ALL_PROXY=socks5://127.0.0.1:1080
```

### Rate Limiting and Blocking

**Problem**: Requests are being rate limited or blocked
```
429 Too Many Requests
403 Forbidden
IP address blocked
```

**Solutions**:
```bash
# Add delays between requests
nuclei -l targets.txt -rate-limit 10  # 10 requests per second
httpx -l targets.txt -delay 1s

# Use random user agents
httpx -l targets.txt -random-agent

# Rotate IP addresses (if available)
# Use different network interfaces or VPN

# Implement exponential backoff
retry_with_backoff() {
    local cmd="$1"
    local max_attempts=5
    local attempt=1
    local delay=1
    
    while [ $attempt -le $max_attempts ]; do
        if $cmd; then
            return 0
        fi
        echo "Attempt $attempt failed, waiting ${delay}s..."
        sleep $delay
        delay=$((delay * 2))
        ((attempt++))
    done
    return 1
}
```

## System Resource Issues

### Disk Space Problems

**Problem**: Running out of disk space during scans
```
No space left on device
df: /: 100% full
```

**Solutions**:
```bash
# Check disk usage
df -h
du -sh ~/results/ ~/tools/

# Clean up old results
find ~/results/ -name "*.txt" -mtime +7 -delete
find ~/results/ -name "*.json" -mtime +7 -delete

# Compress old files
find ~/results/ -name "*.txt" -mtime +3 -exec gzip {} \;

# Move to external storage
rsync -av ~/results/ /mnt/external/backup/

# Set up automatic cleanup
cat > ~/cleanup.sh << 'EOF'
#!/bin/bash
find ~/results/ -name "*.txt" -mtime +7 -delete
find /tmp/ -name "*scan*" -mtime +1 -delete
docker system prune -f
EOF

# Add to crontab
(crontab -l; echo "0 2 * * * ~/cleanup.sh") | crontab -
```

### I/O Performance Issues

**Problem**: Disk I/O is bottleneck for performance
```
High iowait in htop
Slow file operations
```

**Solutions**:
```bash
# Monitor I/O usage
iotop
iostat -x 1

# Use tmpfs for temporary files
sudo mount -t tmpfs -o size=2G tmpfs /tmp/fast_storage
export TMPDIR=/tmp/fast_storage

# Optimize file operations
# Use parallel processing for file operations
find results/ -name "*.txt" | parallel -j4 'gzip {}'

# Use SSD for output if available
mkdir -p /mnt/ssd/results/
ln -s /mnt/ssd/results ~/results

# Batch file operations
# Instead of many small writes, accumulate and write in batches
```

## Parallel Processing Problems

### GNU Parallel Issues

**Problem**: GNU parallel not working correctly or not installed
```
parallel: command not found
parallel: invalid option
```

**Solutions**:
```bash
# Install GNU parallel
sudo apt install parallel

# Accept citation notice
echo 'will cite' | parallel --citation > /dev/null 2>&1

# Test parallel installation
seq 1 10 | parallel echo

# Use alternative if parallel not available
xargs -P 10 -I {} bash -c 'echo {}'

# Manual parallel implementation
manual_parallel() {
    local jobs="$1"
    shift
    local cmd="$*"
    
    mkfifo /tmp/parallel_pipe
    exec 3<>/tmp/parallel_pipe
    
    for ((i=0; i<jobs; i++)); do
        echo >&3
    done
    
    while read -r item; do
        read -u3
        {
            eval "$cmd" "$item"
            echo >&3
        } &
    done
    
    wait
    exec 3>&-
    rm -f /tmp/parallel_pipe
}
```

### Job Control Issues

**Problem**: Parallel jobs not being controlled properly
```
System overload
Jobs not completing
Zombie processes
```

**Solutions**:
```bash
# Monitor active jobs
jobs -l
ps aux | grep -E "(subfinder|nuclei|httpx)"

# Kill runaway processes
pkill -f subfinder
killall nuclei

# Use job control
set -m  # Enable job control
trap 'kill $(jobs -p)' EXIT

# Limit jobs with process groups
{
    parallel -j100 command ::: input &
    JOB_PID=$!
    sleep 300  # Run for 5 minutes max
    kill $JOB_PID 2>/dev/null
    wait $JOB_PID 2>/dev/null
}

# Use systemd for better control
systemd-run --scope -p CPUQuota=50% -p MemoryLimit=2G parallel -j1000 command
```

## Reporting and Output Issues

### HTML Report Generation Problems

**Problem**: HTML reports are not generated or are corrupted
```
syntax error in HTML
report.html: No such file or directory
Invalid JSON in report
```

**Solutions**:
```bash
# Check if all output files exist
ls -la results/
test -s results/vulnerabilities.txt || echo "Empty vulnerability file"

# Validate JSON before processing
jq empty results/scan_results.json 2>/dev/null || echo "Invalid JSON"

# Manual report generation
generate_manual_report() {
    local output_dir="$1"
    local target="$2"
    
    cat > "$output_dir/manual_report.html" << EOF
<!DOCTYPE html>
<html><head><title>Scan Report - $target</title></head>
<body>
<h1>Security Scan Report</h1>
<h2>Target: $target</h2>
<h3>Subdomains ($(wc -l < "$output_dir/subdomains.txt" 2>/dev/null || echo 0))</h3>
<pre>$(head -50 "$output_dir/subdomains.txt" 2>/dev/null || echo "No subdomains found")</pre>
<h3>Vulnerabilities ($(wc -l < "$output_dir/vulnerabilities.txt" 2>/dev/null || echo 0))</h3>
<pre>$(head -50 "$output_dir/vulnerabilities.txt" 2>/dev/null || echo "No vulnerabilities found")</pre>
</body></html>
EOF
}

# Fix encoding issues
iconv -f utf-8 -t utf-8 -c results/report.html > results/report_clean.html
```

### Log File Issues

**Problem**: Log files are corrupted or too large
```
log file too large
binary data in text logs
Permission denied writing logs
```

**Solutions**:
```bash
# Rotate large log files
logrotate_manual() {
    local log_file="$1"
    local max_size="100M"
    
    if [[ $(stat -c%s "$log_file" 2>/dev/null || echo 0) -gt $(numfmt --from=iec $max_size) ]]; then
        mv "$log_file" "${log_file}.old"
        gzip "${log_file}.old"
        touch "$log_file"
    fi
}

# Clean up log files
find ~/results/ -name "*.log" -size +100M -exec gzip {} \;

# Filter binary data from logs
strings suspicious.log > clean.log

# Set proper log permissions
chmod 644 ~/results/*.log
```

## Configuration Problems

### Environment Variable Issues

**Problem**: Environment variables not set correctly
```
GOPATH not set
PATH missing tool directories
API keys not recognized
```

**Solutions**:
```bash
# Check current environment
env | grep -E "(PATH|GOPATH|HOME)"
echo $PATH | tr ':' '\n'

# Set essential variables
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

# Persistent environment setup
cat >> ~/.bashrc << 'EOF'
# Security tool environment
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"
export NUCLEI_TEMPLATES_PATH="$HOME/nuclei-templates"

# Tool configurations
export J=9000  # Default parallel jobs
export RESOLVERS_FILE="$HOME/.config/resolvers.txt"
EOF

# Reload environment
source ~/.bashrc

# Verify settings
which nuclei subfinder httpx
```

### Shell Configuration Issues

**Problem**: Shell aliases and functions not working
```
command not found: quick_sub_enum
function not defined: recon_pipeline
```

**Solutions**:
```bash
# Check if security aliases are loaded
type quick_sub_enum 2>/dev/null || echo "Functions not loaded"

# Load security aliases manually
source ~/.security_aliases

# Verify loading in shell config
grep -n "security_aliases" ~/.bashrc ~/.zshrc

# Debug function loading
set -x
source ~/.security_aliases
set +x

# Recreate aliases file if corrupted
./install/enhanced_setup.sh
# Select option to recreate security aliases
```

## Debugging Techniques

### Script Debugging

**Problem**: Scripts fail silently or with unclear errors
```
script exits without explanation
unclear error messages
```

**Solutions**:
```bash
# Enable debug mode
set -x          # Print commands as executed
set -e          # Exit on error
set -u          # Exit on undefined variables
set -o pipefail # Exit on pipe failures

# Debug specific sections
debug_section() {
    echo "DEBUG: Starting section $1" >&2
    set -x
    # Your commands here
    set +x
    echo "DEBUG: Completed section $1" >&2
}

# Add logging to scripts
log_debug() {
    echo "[DEBUG $(date '+%H:%M:%S')] $*" >&2
}

log_debug "Starting subdomain enumeration"

# Trace function calls
PS4='+ ${FUNCNAME[0]:+${FUNCNAME[0]}():}line ${LINENO}: '
set -x
```

### Network Debugging

**Problem**: Network requests failing mysteriously
```bash
# Test connectivity step by step
ping -c 1 8.8.8.8                    # Basic connectivity
dig example.com                       # DNS resolution
curl -I https://example.com          # HTTP connectivity
openssl s_client -connect example.com:443  # SSL connectivity

# Monitor network traffic
sudo tcpdump -i any -n host example.com
sudo netstat -tulpn | grep :443

# Test with verbose output
curl -v https://example.com
wget --debug https://example.com
```

### Performance Debugging

**Problem**: Scripts running slower than expected
```bash
# Time operations
time subfinder -d example.com -silent

# Profile with strace
strace -c -p $(pgrep nuclei)

# Monitor system calls
strace -e trace=network nuclei -u https://example.com

# Use profiling tools
perf record -g command
perf report
```

### Memory Debugging

**Problem**: Memory leaks or excessive memory usage
```bash
# Monitor memory usage over time
while true; do
    ps -p $PID -o pid,ppid,cmd,%mem,%cpu --no-headers
    sleep 10
done

# Check for memory leaks
valgrind --leak-check=full command

# Monitor specific processes
watch -n1 'ps aux --sort=-%mem | head -10'
```

## Getting Help

### Official Documentation
- Check tool help: `tool_name -h` or `tool_name --help`
- Read man pages: `man tool_name`
- Check GitHub repositories for issues and documentation

### Community Resources
- GitHub Issues for specific tools
- Discord servers for security communities
- Reddit communities (r/bugbounty, r/netsec)
- Twitter security community

### Creating Minimal Reproducible Examples
When reporting issues:

1. **Minimal test case**:
```bash
echo "example.com" > test.txt
subfinder -l test.txt -silent
```

2. **System information**:
```bash
uname -a
cat /etc/os-release
free -h
df -h
ulimit -a
```

3. **Tool versions**:
```bash
nuclei -version
subfinder -version
httpx -version
go version
python3 --version
```

4. **Error logs**:
```bash
# Run with maximum verbosity
tool_name -v -debug 2>&1 | tee debug.log
```

### Emergency Recovery
If system becomes completely unresponsive:

1. **Kill all security tools**:
```bash
sudo pkill -f "nuclei|subfinder|httpx|ffuf|naabu"
```

2. **Reset resource limits**:
```bash
sudo sysctl -w fs.file-max=1048576
echo 65536 | sudo tee /proc/sys/fs/nr_open
```

3. **Clear temporary files**:
```bash
sudo rm -rf /tmp/parallel*
sudo rm -rf /tmp/nuclei*
```

---

*This troubleshooting guide is continuously updated based on user feedback and new issues discovered. If you encounter a problem not covered here, please report it so we can add the solution.*