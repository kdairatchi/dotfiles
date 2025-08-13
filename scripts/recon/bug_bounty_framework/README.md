# Bug Bounty Framework - High-Performance Security Scanning

This is an enhanced version of the Bug Bounty Framework optimized for parallel processing with up to 9,000 concurrent jobs for maximum performance and efficiency.

## Key Features

🚀 **High-Performance Parallel Processing**: Up to 9,000 concurrent jobs
⚡ **Automatic Resource Optimization**: Intelligent job calculation based on system capabilities
🛡️ **Comprehensive Security Testing**: Advanced vulnerability scanning and reconnaissance
📊 **Enhanced Reporting**: HTML reports with detailed statistics and visualizations
🔧 **Improved Error Handling**: Robust error detection and recovery
📈 **Resource Monitoring**: Real-time monitoring of system resources during scans

## Available Scripts

### 1. Quick Scan (`quick_scan.sh`)
**Optimized for speed and basic reconnaissance**
- Fast subdomain enumeration with parallel processing
- Live subdomain checking with intelligent threading
- Basic port scanning using optimized concurrency
- URL discovery from multiple sources
- Essential vulnerability scanning with Nuclei
- **Performance**: Designed for completion in minutes

**Usage:**
```bash
./quick_scan.sh example.com
./quick_scan.sh -v --monitor example.com  # Verbose with resource monitoring
J=5000 ./quick_scan.sh example.com        # Custom parallel job count
```

### 2. Advanced Scan (`advanced_scan.sh`)
**Comprehensive analysis with maximum parallel efficiency**
- Multi-source subdomain enumeration (Subfinder, Assetfinder, Chaos, crt.sh)
- Detailed live subdomain analysis with technology detection
- Comprehensive port scanning (top 3000 ports)
- Advanced URL discovery (Wayback, GAU, Katana)
- In-depth vulnerability scanning with multiple Nuclei templates
- XSS testing on parameterized URLs with Dalfox
- Directory and content fuzzing with FFuf
- Interactive HTML report generation with charts
- **Performance**: Utilizes maximum system resources for thorough analysis

**Usage:**
```bash
./advanced_scan.sh example.com
./advanced_scan.sh -v --monitor example.com  # Verbose with system monitoring
J=9000 ./advanced_scan.sh example.com        # Maximum parallel processing
```

### 3. Ultimate Scan (`ultimate_scan.sh`)
**Complete security assessment framework**
- All features from Quick and Advanced scans
- Enhanced multi-phase scanning approach
- Comprehensive technology stack analysis
- Certificate analysis and subdomain validation
- Advanced SSRF and injection testing
- Custom wordlist integration
- JSON and HTML report generation
- **Performance**: Maximum thoroughness with optimized parallel execution

**Usage:**
```bash
./ultimate_scan.sh example.com
./ultimate_scan.sh -t comprehensive --verbose example.com
./ultimate_scan.sh -j 9000 -t advanced example.com
```

### 4. Docker Scan (`docker_scan.sh`)
**Containerized scanning environment**
- Isolated scanning environment with Docker
- Consistent results across different systems
- Pre-configured tool stack
- Enhanced parallel processing support

**Usage:**
```bash
./docker_scan.sh example.com
./docker_scan.sh -v --monitor example.com
```

## Parallel Processing Optimization

### Automatic Job Calculation
The framework automatically calculates optimal parallel jobs based on:
- CPU cores (target: cores × 64, max 9000)
- File descriptor limits (70% utilization)
- Available memory and system load

### Manual Job Control
```bash
# Set custom parallel job count
export J=5000

# Example usage with different job counts
J=1000 ./quick_scan.sh example.com     # Conservative (slow systems)
J=5000 ./advanced_scan.sh example.com  # Balanced (most systems)
J=9000 ./ultimate_scan.sh example.com  # Maximum (high-end systems)
```

### Performance Monitoring
```bash
# Enable resource monitoring during scans
./advanced_scan.sh --monitor example.com

# Monitor system resources manually
htop
watch 'ss -s'
watch 'lsof | wc -l'  # File descriptor usage
```

## Directory Structure

```
~/dotfiles/scripts/recon/bug_bounty_framework/
├── tools/              # Tool installations and binaries
├── wordlists/          # Wordlist files for fuzzing
│   ├── common.txt      # Common directories/files
│   ├── big.txt         # Large wordlist
│   └── subdomains-*.txt # Subdomain wordlists
├── results/            # Timestamped scan results
│   ├── YYYYMMDD_HHMMSS_domain.com/
│   │   ├── all_subdomains.txt
│   │   ├── live_subdomains.txt
│   │   ├── vulnerabilities.txt
│   │   ├── comprehensive_report.html
│   │   └── scan_results.json
├── quick_scan.sh       # Fast reconnaissance script
├── advanced_scan.sh    # Comprehensive analysis script
├── ultimate_scan.sh    # Complete security assessment
├── docker_scan.sh      # Containerized scanning
└── README.md          # This documentation
```

## High-Performance Tool Usage

### Parallel Subdomain Enumeration
```bash
# Multi-source enumeration with maximum concurrency
parallel -j9000 --bar ::: \
  "subfinder -d example.com -all -silent > subs1.txt" \
  "assetfinder --subs-only example.com > subs2.txt" \
  "chaos -d example.com -silent > subs3.txt"
```

### High-Speed HTTP Probing
```bash
# Fast HTTP analysis with technology detection
cat subdomains.txt | httpx -threads 9000 -tech-detect -status-code -title
```

### Mass Vulnerability Scanning
```bash
# Parallel Nuclei scanning with rate limiting
nuclei -list targets.txt -severity critical,high,medium -j 9000 -rate-limit 500
```

### Optimized Port Scanning
```bash
# High-speed port scanning
naabu -list hosts.txt -rate 9000 -top-ports 3000 -silent
```

### Parallel URL Discovery
```bash
# Multi-source URL discovery
parallel -j9000 --bar ::: \
  "cat domains.txt | waybackurls >> all_urls.txt" \
  "cat domains.txt | gau --threads 9000 >> all_urls.txt" \
  "katana -list domains.txt -d 3 -jc >> all_urls.txt"
```

### Bulk XSS Testing
```bash
# Parallel XSS testing on parameterized URLs
cat urls_with_params.txt | parallel -j5000 --bar \
  'echo {} | dalfox pipe --silence --no-color'
```

## Performance Optimization

### System Tuning for Maximum Performance
```bash
# Increase file descriptor limits
ulimit -n 65536
echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf

# Optimize network parameters
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
sysctl -p

# Monitor performance
watch -n1 'free -h; echo "---"; ss -s'
```

### Scaling Recommendations
| System Type | Recommended Jobs | Expected Performance |
|-------------|------------------|---------------------|
| Laptop (4 cores, 8GB) | 500-1000 | Good for small-medium targets |
| Desktop (8 cores, 16GB) | 2000-4000 | Excellent for medium-large targets |
| Server (16+ cores, 32GB+) | 6000-9000 | Optimal for enterprise-scale targets |

## Advanced Workflows

### Mass Reconnaissance Pipeline
```bash
#!/bin/bash
# Mass recon across multiple targets
while read -r domain; do
    {
        echo "Starting comprehensive scan for $domain"
        J=5000 ./ultimate_scan.sh "$domain"
        echo "Completed scan for $domain"
    } &
    
    # Limit concurrent domains to prevent resource exhaustion
    (($(jobs -r | wc -l) >= 3)) && wait
done < company_domains.txt
wait
```

### Continuous Monitoring Setup
```bash
# Set up continuous scanning with monitoring
while true; do
    ./advanced_scan.sh --monitor target.com
    sleep 3600  # Scan every hour
done
```

## Quick Start Guide

### 1. First-Time Setup
```bash
# Ensure all tools are installed and updated
source ~/.security_aliases
calc_parallel_jobs  # Check your system's optimal job count

# Update Nuclei templates
nuclei -update-templates
```

### 2. Basic Reconnaissance
```bash
# Start with a quick scan to get familiar
./quick_scan.sh example.com

# Review results
ls -la results/$(ls -t results/ | head -1)/
```

### 3. Comprehensive Analysis
```bash
# Run advanced scan for thorough testing
J=5000 ./advanced_scan.sh --verbose example.com

# View HTML report
firefox results/*/comprehensive_report.html
```

### 4. Production Scanning
```bash
# Ultimate scan for maximum coverage
./ultimate_scan.sh -t comprehensive -j 9000 example.com
```

## Security Best Practices

### Authorization and Ethics
- ⚠️ **Always obtain explicit written permission** before scanning any targets
- 📋 Follow responsible disclosure practices for discovered vulnerabilities
- 🎯 Respect rate limits and terms of service
- ⚖️ Ensure compliance with applicable laws and regulations

### Data Protection
- 🔒 Secure storage of scan results (contains sensitive information)
- 🗑️ Regular cleanup of temporary files and old results
- 🔐 Proper handling of discovered credentials or secrets
- 💾 Consider encrypted storage for long-term result retention

## Troubleshooting

### Common Issues and Solutions

#### Performance Issues
```bash
# Check system resources
free -h
df -h
ulimit -n

# Reduce parallel jobs if system is overwhelmed
export J=1000
```

#### Tool Installation Issues
```bash
# Manual tool installation
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
pip3 install sqlmap dirsearch arjun
```

#### Network Issues
```bash
# Test connectivity
ping -c 3 8.8.8.8
curl -I https://www.google.com

# Use custom DNS resolvers
echo -e "8.8.8.8\n1.1.1.1" > resolvers.txt
nuclei -target example.com -resolvers resolvers.txt
```

### Debug Mode
```bash
# Enable verbose debugging
DEBUG=1 VERBOSE=1 ./advanced_scan.sh example.com

# Monitor in real-time
./quick_scan.sh --monitor example.com
```

## Support and Community

### Getting Help
- 📚 **Documentation**: Check `/docs/USAGE.md` and `/docs/TROUBLESHOOTING.md`
- 🐛 **Issues**: Report bugs via GitHub Issues
- 💬 **Community**: Join bug bounty Discord servers and forums
- 📖 **Updates**: Keep tools and templates updated regularly

### Contributing
- 🔧 Contribute new features and optimizations
- 📝 Improve documentation and examples  
- 🐞 Report bugs and suggest improvements
- 🤝 Share performance optimization tips

---

**⚡ High-performance security scanning framework optimized for up to 9,000 parallel jobs**

*Remember: Use these tools responsibly and ethically. Always obtain proper authorization before testing.*
