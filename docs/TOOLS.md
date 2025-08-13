# Tools Documentation

## Core Security Tools

### Reconnaissance Tools

#### Subfinder
- **Purpose**: Subdomain discovery using passive sources
- **Usage**: `subfinder -d target.com -o subdomains.txt`
- **Alias**: Available in PATH after installation

#### HTTPx
- **Purpose**: Fast HTTP toolkit for probing live hosts
- **Usage**: `echo target.com | httpx -title -status-code -tech-detect`
- **Alias**: Available in PATH

#### Nuclei
- **Purpose**: Vulnerability scanner with extensive template library
- **Usage**: `nuclei -u target.com -t ~/nuclei-templates/`
- **Alias**: Available in PATH
- **Templates**: Updated automatically, custom templates in `~/nuclei-templates/customs/`

#### Waybackurls
- **Purpose**: Fetch URLs from Wayback Machine
- **Usage**: `echo target.com | waybackurls`
- **Alias**: Available in PATH

### Web Application Testing

#### FFuf
- **Purpose**: Fast web fuzzer
- **Usage**: `ffuf -u http://target.com/FUZZ -w wordlist.txt`
- **Location**: `~/go/bin/ffuf`
- **Alias**: Available in PATH

#### Dalfox
- **Purpose**: Parameter analysis and XSS scanner
- **Usage**: `echo "http://target.com/?q=test" | dalfox pipe`
- **Location**: `~/go/bin/dalfox`
- **Alias**: Available in PATH

#### XSStrike
- **Purpose**: Advanced XSS detection suite
- **Usage**: `xsstrike -u "http://target.com/?q=test"`
- **Location**: `~/tools/XSStrike/xsstrike.py`
- **Alias**: `xsstrike`

### OSINT and Data Collection

#### Assetfinder
- **Purpose**: Find domains and subdomains
- **Usage**: `assetfinder --subs-only target.com`
- **Alias**: Available in PATH

#### GitDorker
- **Purpose**: GitHub reconnaissance and secret scanning
- **Usage**: `gitdorker -d target.com -t YOUR_GITHUB_TOKEN`
- **Location**: `~/tools/GitDorker/GitDorker.py`
- **Alias**: `gitdorker`

## Custom Scripts

### Reconnaissance Scripts

#### recon.sh
- **Purpose**: Comprehensive domain reconnaissance
- **Features**:
  - Subdomain enumeration from multiple sources
  - Live host detection
  - Technology fingerprinting
  - URL discovery via Wayback Machine
  - Directory bruteforcing
- **Usage**: `recon target.com`
- **Output**: Organized results in timestamped directory

#### wayback.sh
- **Purpose**: Advanced Wayback Machine analysis
- **Features**:
  - URL extraction and filtering
  - Parameter discovery
  - Endpoint analysis
  - Historical data mining
- **Usage**: `wayback target.com`
- **Alias**: `wayback`

#### ultibb.sh
- **Purpose**: Ultimate bug bounty reconnaissance pipeline
- **Features**:
  - Multi-source subdomain enumeration
  - Advanced URL discovery
  - Vulnerability scanning
  - Report generation
- **Usage**: `ultibb target.com`
- **Alias**: `ultibb`

#### luckyspin.sh
- **Purpose**: Randomized reconnaissance with stealth features
- **Features**:
  - Random timing and delays
  - User-agent rotation
  - Proxy support
  - Distributed scanning
- **Usage**: `luckyspin target.com`
- **Alias**: `luckyspin`

### Security Testing Scripts

#### sqli_test.sh
- **Purpose**: SQL injection testing automation
- **Features**:
  - Parameter discovery
  - Injection testing
  - Database enumeration
  - Report generation
- **Usage**: `sqli http://target.com/page?id=1`
- **Alias**: `sqli`

#### kfuzzer.sh
- **Purpose**: Custom fuzzing workflows
- **Features**:
  - Multiple fuzzing techniques
  - Custom wordlists
  - Response analysis
  - Automated reporting
- **Usage**: `fuzz target.com`
- **Alias**: `fuzz`

### Utility Scripts

#### bug_bounty_menu.sh
- **Purpose**: Interactive tool selection and execution
- **Features**:
  - Tool categories
  - Quick execution
  - Configuration management
  - Result tracking
- **Usage**: `menu`
- **Alias**: `menu`

#### dorking.py
- **Purpose**: Automated Google dorking
- **Features**:
  - Custom dork database
  - Multi-site testing
  - Result filtering
  - Export options
- **Usage**: `dorking -d target.com -o results.txt`
- **Alias**: `dorking`

## Parallel Processing Functions

### nuclei-par
- **Purpose**: Parallel Nuclei scanning
- **Usage**: `nuclei-par urls.txt`
- **Description**: Runs Nuclei scans in parallel across multiple URLs

### httpx-par
- **Purpose**: Parallel HTTP probing
- **Usage**: `httpx-par urls.txt`
- **Description**: Fast parallel HTTP status, title, and technology detection

### wayback-par
- **Purpose**: Parallel Wayback URL fetching
- **Usage**: `wayback-par domains.txt`
- **Description**: Fetch Wayback URLs for multiple domains simultaneously

### xsstrike-par
- **Purpose**: Parallel XSS testing
- **Usage**: `xsstrike-par urls.txt`
- **Description**: Run XSStrike against multiple URLs in parallel

## Utility Functions

### smartgrab
- **Purpose**: Intelligent content fetching
- **Usage**: `smartgrab https://api.target.com/endpoint`
- **Description**: Automatically detects JSON APIs and formats output appropriately

### linksabs
- **Purpose**: Extract absolute links from web pages
- **Usage**: `linksabs https://target.com`
- **Description**: Extracts and converts all links to absolute URLs

### htmltxt
- **Purpose**: Convert HTML to readable text
- **Usage**: `htmltxt https://target.com`
- **Description**: Uses lynx to convert HTML pages to clean text format

## Wordlists and Payloads

### Directory Structure
```
tools/
├── payloads/
│   ├── xss.txt                    # XSS payloads
│   ├── sqli.txt                   # SQL injection patterns
│   ├── ssrf.txt                   # SSRF testing payloads
│   ├── directory_traversal.txt    # Path traversal patterns
│   └── api.txt                    # API endpoint wordlist
└── wordlists/
    ├── common.txt                 # Common directories/files
    ├── subdomains-top1million-5000.txt
    └── SecLists/                  # Complete SecLists collection
```

### Usage Examples

#### XSS Testing
```bash
# Manual XSS testing with payloads
cat ~/tools/payloads/xss.txt | while read payload; do
    echo "Testing: $payload"
    curl -s "http://target.com/search?q=$payload"
done

# Automated XSS with XSStrike
xsstrike -u "http://target.com/?q=test" --crawl
```

#### Directory Bruteforcing
```bash
# Using FFuf with custom wordlist
ffuf -u http://target.com/FUZZ -w ~/tools/wordlists/common.txt

# Using Gobuster
gobuster dir -u http://target.com -w ~/tools/wordlists/common.txt
```

## Configuration Files

### Nuclei Templates
- **Location**: `~/nuclei-templates/`
- **Custom Templates**: `~/nuclei-templates/customs/`
- **Update**: `nuclei -update-templates`

### Tool Configurations
Most tools use their default configurations. Custom configs are stored in:
- `~/.config/subfinder/config.yaml`
- `~/.config/nuclei/config.yaml`
- `~/.config/httpx/config.yaml`

## Environment Variables

### Required for Full Functionality
```bash
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_vt_key"
export GITHUB_TOKEN="your_github_token"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
```

### Tool Paths
```bash
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
export NUCLEI_TEMPLATES_PATH="$HOME/nuclei-templates"
export WORDLIST_PATH="$HOME/wordlists"
```

## Tool Installation Status

### ✅ Installed by setup.sh
- subfinder, httpx, nuclei
- waybackurls, assetfinder
- ffuf, dalfox
- Basic Python libraries

### ⚙️ Installed by tools.sh
- katana, naabu, uncover
- XSStrike, Corsy, GitDorker
- SQLMap, Arjun
- GF patterns, SecLists

### 🔧 Manual Installation Required
- Burp Suite Professional
- OWASP ZAP
- Custom proprietary tools

## Performance Optimization

### Parallel Processing
Most functions support parallel execution:
```bash
# Default parallel jobs
parallel -j10 'command {}' :::: input.txt

# Custom job count based on system
parallel -j$(nproc) 'command {}' :::: input.txt
```

### Rate Limiting
Many tools include built-in rate limiting:
```bash
# HTTPx with rate limit
httpx -rate-limit 100

# Nuclei with rate limit
nuclei -rate-limit 150
```

### Resource Management
Monitor system resources during intensive scans:
```bash
# Monitor CPU and memory
htop

# Monitor network usage
iftop

# Monitor disk I/O
iotop
```