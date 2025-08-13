<<<<<<< HEAD
# dotfiles
dot configuration tired of starting over towards bug bounty 
=======
# Bug Bounty Dotfiles & Security Framework

A comprehensive dotfiles setup optimized for bug bounty hunting and penetration testing on Kali Linux.

## Features

- **Optimized Zsh Configuration**: Custom aliases and functions for security tools
- **Bug Bounty Framework**: Complete reconnaissance and vulnerability scanning toolkit
- **Automated Setup**: One-command installation and configuration
- **Sanitized Configs**: No hardcoded credentials, ready for public repositories
- **Extensive Tool Collection**: Pre-configured access to 50+ security tools

## Quick Start

```bash
git clone https://github.com/yourusername/dotfiles.git
cd dotfiles
chmod +x install/setup.sh
./install/setup.sh
```

## Structure

```
dotfiles/
├── config/           # Configuration files
│   ├── shell/        # Zsh, Bash, and Powerlevel10k configs
│   ├── git/          # Git configuration
│   ├── ssh/          # SSH configuration templates
│   └── apps/         # Application-specific configs
├── scripts/          # Security and utility scripts
│   ├── recon/        # Reconnaissance scripts and frameworks
│   ├── security/     # Security testing scripts
│   └── utils/        # General utility scripts
├── tools/            # Security tools and payloads
│   ├── payloads/     # Attack payloads and wordlists
│   └── wordlists/    # Directory and subdomain wordlists
├── install/          # Installation and setup scripts
└── docs/             # Documentation
```

## Installation

### Prerequisites

- Kali Linux (recommended) or Debian-based system
- Internet connection for downloading tools
- Sudo privileges

### Basic Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/dotfiles.git
   cd dotfiles
   ```

2. **Run the main setup script:**
   ```bash
   ./install/setup.sh
   ```

3. **Install additional tools (optional):**
   ```bash
   ./install/tools.sh
   ```

4. **Reload your shell:**
   ```bash
   source ~/.zshrc
   # or restart your terminal
   ```

### Manual Configuration Steps

After installation, you'll need to:

1. **Update Git configuration:**
   ```bash
   git config --global user.email "your-email@example.com"
   git config --global user.name "Your Name"
   ```

2. **Configure Powerlevel10k prompt:**
   ```bash
   p10k configure
   ```

3. **Set up API keys (optional):**
   ```bash
   export SHODAN_API_KEY="your_shodan_key"
   export VIRUSTOTAL_API_KEY="your_vt_key"
   # Add to ~/.zshrc or use a .env file
   ```

## Key Features

### Shell Configuration

- **Zsh with Oh My Zsh**: Enhanced shell experience with plugins
- **Powerlevel10k Theme**: Beautiful and informative prompt
- **Custom Aliases**: 50+ aliases for security tools and workflows
- **Parallel Functions**: Multi-threaded tool execution for faster scans

### Bug Bounty Tools

The configuration includes aliases and functions for:

- **Reconnaissance**: subfinder, assetfinder, httpx, waybackurls
- **Vulnerability Scanning**: nuclei, nmap, masscan
- **Web Application Testing**: ffuf, gobuster, sqlmap, xsstrike
- **JavaScript Analysis**: linkfinder, getjs, secretfinder
- **OSINT**: shodan, censys, github dorking
- **Reporting**: automated HTML and JSON output

### Custom Scripts

#### Reconnaissance Scripts
- `recon.sh`: Comprehensive domain reconnaissance
- `wayback.sh`: Wayback machine URL extraction
- `ultibb.sh`: Ultimate bug bounty reconnaissance pipeline
- `luckyspin.sh`: Randomized reconnaissance with stealth features

#### Security Testing Scripts
- `sqli_test.sh`: SQL injection testing automation
- `kfuzzer.sh`: Custom fuzzing workflows
- `secure_comms.sh`: Secure communication setup

#### Utility Scripts
- `bug_bounty_menu.sh`: Interactive tool selection menu
- `dorking.py`: Automated Google dorking
- `punycode_gen.py`: Punycode domain generation

### Parallel Processing Functions

The configuration includes optimized parallel processing functions:

```bash
# Parallel subdomain enumeration
subfinder -d example.com | httpx-par

# Parallel nuclei scanning
nuclei-par urls.txt

# Parallel wayback URL fetching
wayback-par domains.txt

# Parallel XSS testing
xsstrike-par urls.txt
```

## Usage Examples

### Basic Reconnaissance Workflow

```bash
# Quick subdomain enumeration
subfinder -d target.com | httpx -title -status-code

# Comprehensive reconnaissance
recon target.com

# Wayback machine analysis
wayback target.com

# Vulnerability scanning
nuclei -u target.com -t ~/nuclei-templates/
```

### Advanced Workflows

```bash
# Ultimate reconnaissance pipeline
ultibb target.com

# Interactive bug bounty menu
menu

# Google dorking
dorking -d target.com -o results.txt

# SQL injection testing
sqli target.com/page?id=1
```

### Custom Functions

```bash
# Smart content grabbing (JSON-aware)
smartgrab https://api.target.com/endpoint

# Extract all absolute links from a page
linksabs https://target.com

# Convert HTML to readable text
htmltxt https://target.com
```

## Tool Categories

### Core Tools (Installed by setup.sh)
- Subfinder, HTTPx, Nuclei
- Waybackurls, Assetfinder
- FFuf, Dalfox
- Python security libraries

### Advanced Tools (Installed by tools.sh)
- Katana, Naabu, Uncover
- XSStrike, Corsy, GitDorker
- SQLMap, Arjun
- GF patterns and wordlists

### Payload Collections
- XSS payloads and bypasses
- SQL injection patterns
- Directory traversal wordlists
- SSRF testing payloads
- API fuzzing wordlists

## Customization

### Adding New Aliases

Edit `config/shell/zshrc` and add your aliases:

```bash
# Custom tool aliases
alias mytool="python3 $HOME/tools/mytool/mytool.py"
alias quickscan="nmap -sS -T4"
```

### Adding New Scripts

1. Place scripts in appropriate `scripts/` subdirectory
2. Make them executable: `chmod +x script.sh`
3. Add aliases in zshrc if needed

### Environment Variables

Set up environment variables in `~/.zshrc`:

```bash
# API Keys
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"

# Tool configurations
export NUCLEI_TEMPLATES_PATH="$HOME/nuclei-templates"
export WORDLIST_PATH="$HOME/wordlists"
```

## Security Considerations

- **No Hardcoded Credentials**: All API keys and sensitive data removed
- **Rate Limiting**: Tools configured with appropriate delays
- **Proxy Support**: Many tools support proxy configurations
- **Authorized Testing Only**: Tools for legitimate security testing only

## Troubleshooting

### Common Issues

1. **Tools not found in PATH:**
   ```bash
   source ~/.zshrc
   echo $PATH
   ```

2. **Go tools installation fails:**
   ```bash
   export GOPATH=$HOME/go
   export PATH=$GOPATH/bin:$PATH
   ```

3. **Permission errors:**
   ```bash
   sudo chown -R $USER:$USER $HOME/tools
   ```

### Updating Tools

```bash
# Update Nuclei templates
nuclei -update-templates

# Update Go tools
go install -a std
go clean -modcache

# Update Python tools
pip3 install --upgrade --user requests beautifulsoup4
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test thoroughly
4. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Disclaimer

These tools are for authorized security testing only. Users are responsible for complying with applicable laws and obtaining proper authorization before testing any systems.

## Support

- Create an issue for bugs or feature requests
- Check the docs/ directory for additional documentation
- Review tool-specific documentation in their respective directories

---

**Happy Bug Hunting! 🐛**
>>>>>>> c12fc8a (Initial commit: Ultimate Bug Bounty Dotfiles)
