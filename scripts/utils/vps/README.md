# VPS Security & Reconnaissance Suite

A comprehensive collection of scripts for VPS security hardening and reconnaissance using the proper sqry workflow.

## 🚀 Quick Start

```bash
# Make scripts executable
chmod +x *.sh

# Install tools
./automate-vps-recon.sh --install

# Run automated reconnaissance
./automate-vps-recon.sh --recon

# Or use interactive menu
./automate-vps-recon.sh
```

## 📁 Scripts Overview

### 1. `vps-sqry.sh` - Fixed Shodan Query & Recon Tool

**FIXED ISSUES:**
- ✅ Now uses `sqry -q "query"` ONLY (no excess arguments)
- ✅ Proper workflow: sqry → extract IPs → run other tools
- ✅ Clean argument handling
- ✅ Automated pipeline with httpx, nmap, and nuclei

**Usage:**
```bash
# Single query
./vps-sqry.sh -q "http.title:\"Welcome to nginx\""

# Interactive menu
./vps-sqry.sh

# Help
./vps-sqry.sh -h
```

**Features:**
- Shodan queries via sqry
- IP extraction from results
- HTTP probing with httpx
- Port scanning with nmap
- Vulnerability scanning with nuclei
- Automated reporting

### 2. `vps-security.sh` - VPS Hardening & Management

Complete VPS security hardening and management suite.

**Features:**
- System hardening (kernel parameters, SSH, firewall)
- Docker deployment and management
- AI stack deployment (Ollama, OpenWebUI)
- WireGuard VPN setup
- Security monitoring (2FA, AIDE, auditd)
- Network configuration

**Usage:**
```bash
sudo ./vps-security.sh
```

### 3. `automate-vps-recon.sh` - Automation Suite

**NEW:** Comprehensive automation script for VPS reconnaissance.

**Features:**
- Automated tool installation
- Batch Shodan queries
- Results aggregation
- Summary reporting
- Sample query generation

**Usage:**
```bash
# Interactive mode
./automate-vps-recon.sh

# Command line mode
./automate-vps-recon.sh --recon
./automate-vps-recon.sh --install
./automate-vps-recon.sh --check
```

## 🔧 Dependencies

### Required Tools

The scripts will automatically install these if missing:

- **sqry** - Shodan query tool
- **httpx** - HTTP probing
- **nuclei** - Vulnerability scanner
- **nmap** - Port scanner
- **jq** - JSON processing

### Installation Commands

```bash
# Install Go tools
go install github.com/Karthik-HR0/sqry@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install system tools
sudo apt update
sudo apt install -y nmap jq curl git
```

## 🎯 Proper sqry Usage

**BEFORE (Broken):**
```bash
# ❌ WRONG - Too many arguments
sqry -q "query" --outroot /path --threads 50 --timeout 10 --nuclei --httpx
```

**AFTER (Fixed):**
```bash
# ✅ CORRECT - Simple query only
sqry -q "http.title:\"Welcome to nginx\""

# Then use other tools on the results
httpx -l ips.txt -tech-detect
nmap -iL ips.txt --top-ports 1000
nuclei -l ips.txt -severity critical,high
```

## 📋 Common Shodan Queries

### Web Services
```bash
http.title:"Welcome to nginx"
http.title:"Apache2 Ubuntu Default Page"
http.title:"Test Page for the Nginx HTTP Server"
```

### Admin Panels
```bash
http.title:"Portainer"
http.title:"Grafana"
http.title:"Kibana"
http.title:"Jenkins"
http.title:"phpMyAdmin"
```

### Services
```bash
port:22 "SSH-2.0-OpenSSH"
port:3389 "Terminal Services"
port:2375,2376 docker
port:3306 mysql
port:5432 postgresql
```

## 🔄 Workflow

1. **Query Shodan** - Use sqry with simple queries
2. **Extract IPs** - Parse results for IP addresses
3. **HTTP Probing** - Check for live web services
4. **Port Scanning** - Discover open ports
5. **Vulnerability Scanning** - Check for known issues
6. **Reporting** - Generate comprehensive reports

## 📊 Output Structure

```
~/sqry_out/runs/
├── manual-20240815_143022/
│   ├── sqry_raw.txt          # Raw sqry output
│   ├── ips.txt               # Extracted IP addresses
│   ├── httpx.txt             # Live HTTP services
│   ├── httpx.json            # Detailed HTTP data
│   ├── nmap.txt              # Port scan results
│   ├── nuclei.txt            # Vulnerability findings
│   └── summary.txt           # Scan summary
└── batch-1-20240815_143500/
    └── ...
```

## ⚠️ Security & Legal Notice

- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Responsible Disclosure**: Follow responsible disclosure practices for any findings
- **Rate Limiting**: Scripts include rate limiting to avoid overwhelming targets
- **Legal Compliance**: Users are responsible for compliance with applicable laws

## 🛠️ Troubleshooting

### Common Issues

1. **sqry not found**
   ```bash
   go install github.com/Karthik-HR0/sqry@latest
   ```

2. **Permission denied**
   ```bash
   chmod +x *.sh
   ```

3. **No results found**
   - Check Shodan API key configuration
   - Verify query syntax
   - Try broader queries

### Debug Mode

Enable verbose output:
```bash
VERBOSE=1 ./vps-sqry.sh -q "your query"
```

## 📈 Performance Tips

- Use specific queries to reduce API usage
- Implement rate limiting between requests
- Monitor system resources during scans
- Use parallel processing for large IP lists

## 🔮 Future Enhancements

- [ ] Integration with additional OSINT tools
- [ ] Custom report templates
- [ ] Database storage for results
- [ ] API endpoint for automation
- [ ] Real-time monitoring dashboard

## 🤝 Contributing

1. Test all changes thoroughly
2. Follow existing code style
3. Update documentation
4. Ensure security best practices

## 📄 License

This project is for educational and authorized security testing purposes only.