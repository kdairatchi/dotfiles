# 🕵️ Kdairatchi Security Research Tools

A comprehensive collection of enhanced bug bounty and security reconnaissance tools, completely refactored for security, reliability, and professional use.

## 🎯 Overview

This repository contains a suite of security research tools designed for ethical hacking, bug bounty hunting, and penetration testing. All tools have been enhanced with:

- **Standardized UX**: Consistent command-line interfaces, logging, and output formats
- **Security Hardening**: Input validation, timeouts, safe defaults, and least-privilege execution
- **Comprehensive Testing**: Unit tests for Python scripts and smoke tests for shell scripts  
- **Professional Reporting**: Structured output (JSON, CSV, TXT) and HTML reports
- **Idempotent Behavior**: Safe to re-run with predictable exit codes

## 🛠️ Tools Included

### Shell Scripts

| Tool | Description | Key Features |
|------|-------------|--------------|
| `alienvault.sh` | AlienVault OTX URL Intelligence Gatherer | Multi-format output, rate limiting, pagination |
| `bb-menu.sh` | Unified launcher for bug bounty tools | Interactive menu, tool availability checking |
| `bug.sh` | Complete bug bounty automation suite | Multi-phase scanning, HTML reports |
| `js_recon.sh` | JavaScript reconnaissance and analysis | Secret scanning, technology detection |
| `par-bounty.sh` | Parallel bug bounty launcher | GNU parallel powered execution |
| `sqry.sh` | OSINT search and intelligence wrapper | Free API integrations, export options |
| `swagger.sh` | Swagger/OpenAPI endpoint discovery | API documentation analysis |
| `vt.sh` | VirusTotal integration and analysis | Multi-source threat intelligence |
| `xss.sh` | XSS testing and payload injection | Visual reconnaissance, parameter mining |

### Python Scripts

| Tool | Description | Key Features |
|------|-------------|--------------|
| `bug_hunting_arsenal.py` | Comprehensive reconnaissance framework | crawl4ai integration, async processing |
| `cve-sqry.py` | CVE search and analysis tool | Vulnerability database queries |
| `embed.py` | Content embedding and analysis | Text processing, similarity analysis |
| `idor_scanner.py` | IDOR vulnerability scanner | Access control testing |
| `swaggerdorker.py` | Swagger endpoint discovery and testing | API security assessment |

## 🚀 Quick Start

### Prerequisites

```bash
# Required tools (install via package manager)
sudo apt-get update
sudo apt-get install curl jq python3 python3-pip bash parallel

# Bug bounty tools (install via go/cargo/pip)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip3 install aiofiles aiohttp crawl4ai
```

### Installation

```bash
# Clone the repository
git clone https://github.com/kdairatchi/security-tools.git
cd security-tools/scripts/recon

# Make scripts executable
chmod +x *.sh
chmod +x lib/*.sh
chmod +x tests/*.sh

# Install Python dependencies
pip3 install -r requirements.txt
```

## 🔧 Usage Examples

### Basic Reconnaissance

```bash
# Simple subdomain enumeration
./alienvault.sh -d example.com

# Comprehensive bug hunting
python3 bug_hunting_arsenal.py -d example.com --report ./reports

# Interactive tool launcher
./bb-menu.sh

# Parallel vulnerability scanning  
./par-bounty.sh
```

### Advanced Usage

```bash
# AlienVault with custom settings
./alienvault.sh -d example.com \
  --limit 1000 \
  --pages 10 \
  --format json \
  --report ./intel \
  --timeout 60 \
  --verbose

# Bug hunting with customization
python3 bug_hunting_arsenal.py \
  -d example.com \
  --max-crawl 50 \
  --max-subdomains 2000 \
  --threads 20 \
  --timeout 45 \
  --no-screenshots \
  --report ./detailed_scan

# JavaScript reconnaissance
./js_recon.sh example.com

# XSS testing pipeline
./xss.sh example.com
```

### JSON Output and API Integration

```bash
# JSON structured logging
./alienvault.sh -d example.com --json --quiet > results.jsonl

# Generate reports for CI/CD
python3 bug_hunting_arsenal.py -d example.com \
  --report ./ci_reports \
  --json \
  --no-vuln-scan \
  --timeout 30
```

## 📊 Output Formats

All tools support multiple output formats:

- **TXT**: Simple line-delimited text files
- **JSON**: Structured data with metadata
- **CSV**: Spreadsheet-compatible format
- **HTML**: Rich visual reports with charts

### Report Structure

```
output/
├── raw/                    # Raw tool outputs
├── processed/              # Cleaned and filtered data
├── logs/                   # Execution logs
├── screenshots/            # Visual captures (if enabled)
└── reports/                # Summary reports
    ├── summary.txt         # Text summary
    └── comprehensive.html  # Interactive HTML report
```

## 🧪 Testing

### Run Tests

```bash
# Shell script smoke tests
./tests/test_alienvault.sh

# Python unit tests
python3 -m pytest tests/ -v

# Full test suite
make test
```

### Test Coverage

- **Smoke Tests**: Basic functionality and error handling
- **Unit Tests**: Individual function testing with mocks
- **Integration Tests**: Tool chain validation
- **Security Tests**: Input validation and error boundaries

## 🔒 Security Features

### Input Validation
- Domain format validation using regex patterns
- URL sanitization and validation
- Parameter length limits and type checking
- Command injection prevention

### Safe Execution
- Timeouts for all network operations
- Rate limiting to respect target resources
- Subprocess sandboxing with resource limits
- Temporary file cleanup

### Least Privilege
- No unnecessary elevated permissions
- Configurable tool paths
- Environment variable isolation
- Safe default configurations

### Error Handling
- Graceful degradation when tools unavailable
- Comprehensive logging without sensitive data
- Proper exit codes for automation
- Signal handling for clean interruption

## 🎨 Configuration

### Environment Variables

```bash
export KDAI_TIMEOUT=30              # Default timeout
export KDAI_THREADS=10              # Default thread count
export KDAI_USER_AGENT="Custom/1.0" # Custom user agent
export KDAI_REPORTS_DIR="./reports" # Default report directory
```

### Configuration Files

Tools look for configuration in:
- `~/.config/kdai/`
- `./config/`
- Environment variables

## 📈 Performance Optimization

### Parallel Execution
- GNU parallel integration for shell scripts
- Asyncio for Python scripts
- Configurable worker pools
- Resource-aware scheduling

### Resource Management
- Memory usage monitoring
- Disk space checks
- Network bandwidth limiting
- CPU throttling options

### Caching
- DNS resolution caching
- HTTP response caching
- Tool availability caching
- Result deduplication

## 🛡️ Responsible Disclosure

These tools are designed for:
- **Authorized security testing**
- **Bug bounty programs with explicit scope**
- **Educational and research purposes**
- **Security assessments with proper permissions**

### Rate Limiting
All tools implement rate limiting to:
- Respect target server resources
- Avoid triggering security controls
- Maintain ethical testing practices
- Comply with terms of service

### Data Handling
- No storage of sensitive information
- Automatic cleanup of temporary files
- Configurable data retention
- Privacy-conscious logging

## 🤝 Contributing

### Development Setup

```bash
# Install development dependencies
pip3 install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run linting
flake8 *.py
shellcheck *.sh
```

### Code Standards

- **Python**: PEP 8 compliance with type hints
- **Shell**: POSIX compatibility with shellcheck validation  
- **Security**: SAST scanning with bandit/semgrep
- **Testing**: Minimum 80% code coverage

### Pull Request Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Ensure all tests pass
5. Update documentation
6. Submit pull request with clear description

## 📚 API Reference

### Common Arguments

All tools support these standard arguments:

| Argument | Description | Default |
|----------|-------------|---------|
| `-v, --verbose` | Verbose output | False |
| `--debug` | Debug mode with detailed logging | False |
| `-q, --quiet` | Minimal output | False |
| `--json` | JSON structured logging | False |
| `--report DIR` | Generate reports in directory | None |
| `--timeout NUM` | Request timeout in seconds | 30 |
| `--threads NUM` | Number of worker threads | 10 |
| `-h, --help` | Show help message | - |
| `--version` | Show version information | - |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Misuse (invalid arguments) |
| 3 | Network error |
| 10 | Timeout |
| 130 | User interrupted (Ctrl+C) |

## 🎓 Learning Resources

### Bug Bounty Methodology
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Resources](https://www.hackerone.com/resources)

### Tool-Specific Documentation
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Subfinder Usage](https://github.com/projectdiscovery/subfinder)
- [HTTPx Features](https://github.com/projectdiscovery/httpx)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before conducting security testing. The authors are not responsible for any misuse or damage caused by this software.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for excellent security tools
- [OWASP](https://owasp.org/) for security testing methodologies  
- Bug bounty community for inspiration and testing
- Open source contributors and security researchers

---

**Built by Kdairatchi Security Research** | [GitHub](https://github.com/kdairatchi) | [Website](https://kdairatchi.com)