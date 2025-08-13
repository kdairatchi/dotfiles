# Bug Bounty Framework - Quick Setup

This is a quick setup version of the Bug Bounty Framework. For the full version, use the complete installer.

## Available Scripts

### 1. Quick Scan (`quick_scan.sh`)
- Basic subdomain enumeration
- Live subdomain checking
- Port scanning
- URL discovery
- Basic vulnerability scanning

Usage: `./quick_scan.sh example.com`

### 2. Advanced Scan (`advanced_scan.sh`)
- Comprehensive subdomain enumeration
- Detailed live subdomain analysis
- Comprehensive port scanning
- Multi-source URL discovery
- Advanced vulnerability scanning
- XSS testing
- Directory fuzzing
- HTML report generation

Usage: `./advanced_scan.sh example.com`

### 3. Docker Scan (`docker_scan.sh`)
- Docker-based scanning
- Isolated environment
- Consistent results

Usage: `./docker_scan.sh example.com`

## Directory Structure

```
~/bug_bounty_framework/
├── tools/          # Tool installations
├── wordlists/      # Wordlist files
├── results/        # Scan results
├── quick_scan.sh   # Quick scan script
├── advanced_scan.sh # Advanced scan script
├── docker_scan.sh  # Docker scan script
└── README.md       # This file
```

## Manual Tool Usage

### Subfinder
```bash
subfinder -d example.com -silent
```

### Httpx
```bash
echo "example.com" | httpx -silent
```

### Nuclei
```bash
nuclei -u example.com -t ~/nuclei-templates/
```

### Naabu
```bash
naabu -host example.com -top-ports 1000
```

### Waybackurls
```bash
echo "example.com" | waybackurls
```

### Ffuf
```bash
ffuf -u http://example.com/FUZZ -w ~/bug_bounty_framework/wordlists/common.txt
```

### Dalfox
```bash
echo "http://example.com/?q=test" | dalfox pipe
```

## Next Steps

1. Run your first scan: `./quick_scan.sh example.com`
2. Try the advanced scan: `./advanced_scan.sh example.com`
3. Install the full framework for more features
4. Configure API keys for better results
5. Join the bug bounty community!

## Tips

- Always get permission before scanning
- Start with the quick scan to get familiar
- Use the advanced scan for comprehensive testing
- Check the results directory for detailed output
- Update nuclei templates regularly: `nuclei -update-templates`

## Support

- GitHub Issues: Report bugs and request features
- Documentation: Check the full framework documentation
- Community: Join bug bounty Discord servers and forums
