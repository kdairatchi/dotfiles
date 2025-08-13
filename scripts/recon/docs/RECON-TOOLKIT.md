## Recon & Bug Bounty Toolkit — Script Catalog, Workflow, and Examples

This document centralizes all scripts in this toolkit with:
- Recommended run order (from recon to exploitation and reporting)
- Per-script purpose, dependencies, invocation syntax, and outputs
- Quick test commands you can run against example targets

All commands are intended for authorized security testing only.

### Quick prerequisites
- Core CLI: bash, curl, jq, parallel, awk, sed, grep, python3, pip3, go
- ProjectDiscovery: subfinder, httpx, nuclei, katana, naabu, urldedupe
- Utilities: gau or gauplus, assetfinder, waybackurls, ffuf, gf, qsreplace
- Optional: amass, waymore, whatweb, dalfox, gowitness, xsstrike, kxss, Gxss, arjun
- Python libs per-tool (see each tool’s section). For Playwright tools: `pip install playwright && playwright install`


## Recommended workflow (high-level)
1) Scope OSINT and URL harvesting
- `wayback.sh` or `recon.sh` (menu) for Wayback, OTX, CT, DNS
- `alienvault.sh` for OTX URLs from many domains in bulk
- `vt.sh` and `par-bounty.sh` for parallel URL/source collection

2) Subdomains, live hosts, URLs
- `ultibb.sh` end-to-end pipeline (subdomains → httpx → urls → nuclei → report)
- `bug_bounty_framework/quick_scan.sh` or `advanced_scan.sh` as simpler pipelines

3) JavaScript-focused recon
- `js_recon.sh` to find JS files, secrets, and XSS-y variables

4) API/Swagger discovery and exploitation research
- `swagger.sh` comprehensive Swagger hunter (UI/spec XSS, analysis, reports)
- `swaggerdorker.py` dork + direct scan to discover API docs globally or per domain

5) Deeper program-wide/OSINT automation
- `bb-menu.sh` master menu for running multiple helpers
- `luckyspin.sh` (+ `run_luckyspin.sh`) enhanced bug bounty OSINT platform
- `bug_hunting_arsenal.py` async recon + crawling + nuclei integration

6) Specialty scanners
- `idor_scanner.py` for IDOR/auth bypass, JWT/cookie analysis
- `cve_sqry.py` to combine sqry/IP results with Shodan CVE DB lookups
- `gov.sh`/`gov.py` .gov recon with MITRE mapping and multi-format reporting

7) Extras and reports
- `ultibb.sh` and `swagger.sh` generate HTML reports; others output JSON/CSV/text

Use the menus (`bb-menu.sh`, `recon.sh`) if you prefer interactive flows.


## Menus and launchers

### scripts/bb-menu.sh
- Purpose: Master launcher to run many tools with prompts and checks
- Usage:
```bash
./bb-menu.sh
```
- Notes: Paths to tools are defined at the top; ensure dependencies are installed.

### recon.sh (interactive)
- Purpose: Wayback, AlienVault, S3, CT, DNS, Subdomain, Google dorking, Shodan, Port scan, GitHub recon
- Usage:
```bash
./recon.sh
```
- Outputs go under `recon_output/`.


## End‑to‑end pipelines

### ultibb.sh
- Purpose: “Ultimate Bug Bounty Toolkit” end-to-end pipeline
- Requires: nmap, rustscan, sslscan, testssl.sh, httpx, nuclei, katana, gau, ffuf, subfinder, amass, gowitness, htmlq, jq, parallel, urlfinder, wpscan, assetfinder, urldedupe, subzy, gf, uro
- Usage:
```bash
./ultibb.sh <target-domain>
```
- Key outputs: `bb_scan_<timestamp>/` with subdomains, urls, httpx JSON, fuzzing, nuclei, screenshots, and an HTML report at `report/index.html`.
- Test:
```bash
./ultibb.sh example.com
```

### bug_bounty_framework/quick_scan.sh
- Purpose: Fast subdomains → live → ports → URLs → nuclei → ffuf
- Usage:
```bash
./bug_bounty_framework/quick_scan.sh example.com
```
- Results: `~/bug_bounty_framework/results/<timestamp>_example.com/`

### bug_bounty_framework/advanced_scan.sh
- Purpose: Richer version of quick scan with more sources, filters, and an HTML report
- Usage:
```bash
./bug_bounty_framework/advanced_scan.sh example.com
```

### bug_bounty_framework/docker_scan.sh
- Purpose: Run subfinder, httpx, nuclei via official docker images
- Usage:
```bash
./bug_bounty_framework/docker_scan.sh example.com
```


## OSINT collectors and URL harvesters

### alienvault.sh
- Purpose: Pull URLs for many domains from AlienVault OTX; structured outputs
- Usage (stdin or file):
```bash
# From file
./alienvault.sh -t domains.txt --json

# From stdin
cat domains.txt | ./alienvault.sh -t - -o outdir --limit 1000 --pages 10 --threads 4
```
- Output: `reports/YYYYMMDD/HHMMSS/alienvault/` with per-domain URLs and `summary.json`.

### vt.sh
- Purpose: Parallel URL aggregation from VT, AlienVault, Wayback, URLScan, crt.sh, Waymore, CommonCrawl
- Usage:
```bash
./vt.sh -d example.com -j 8 -t 100 --timeout 30 --max-waymore 20000
```
- Output: `<domain>_recon_<timestamp>/raw and /processed` plus a text report.

### wayback.sh
- Purpose: Enhanced Wayback Machine URL extraction with analysis + HTML report
- Usage:
```bash
# Interactive
./wayback.sh
# Non-interactive default comprehensive scan
./wayback.sh example.com
```
- Output: `wayback_<domain>_<timestamp>/` and `wayback_report.html`.

### par-bounty.sh
- Purpose: GNU parallel powered launcher for httpx/nuclei/wayback/gf/JSFinder/XSStrike/rustscan
- Usage:
```bash
./par-bounty.sh
```
- Choose task and provide input files interactively.


## JavaScript recon

### js_recon.sh
- Purpose: JS URLs discovery (hakrawler/gauplus) → fetch JS → secrets via jsninja → GF patterns → XSS variables
- Usage:
```bash
./js_recon.sh example.com
```
- Output: `ultimate_recon_<DOMAIN>_<timestamp>/` with JS files, secret findings.


## API and Swagger/OpenAPI

### swagger.sh
- Purpose: Advanced Swagger/OpenAPI hunter with discovery, XSS tests (CVE-2021-21374), API spec analysis, optional Playwright/Crawl4AI, HTML report
- Common usage:
```bash
# Interactive menu
./swagger.sh

# Direct
./swagger.sh -t https://api.example.com -o outdir --threads 80 --timeout 20 --subdomain-scan
# With configs
./swagger.sh -t https://api.example.com --xsscookie ./xsscookie.json --xsstest-json ./xsstest.json
```
- Outputs: `swagger_scan_<timestamp>/` with discovered endpoints, xss results, analysis, and `bug_bounty_report.html`.

### swaggerdorker.py
- Purpose: Discover Swagger/API endpoints via Google dorks + direct path checks; validate and report
- Usage:
```bash
# Domain scan (all phases)
python3 swaggerdorker.py -d example.com

# Global dorking mode
python3 swaggerdorker.py -m dork --max-dorks 20
```
- Output: `swagger_results/` with JSON and `.txt` report.


## Targeted scanners and frameworks

### idor_scanner.py
- Purpose: IDOR/auth bypass testing, JWT and cookie analysis, recon, methodology docs, and comprehensive report
- Usage:
```bash
# Quick IDOR scan
python3 idor_scanner.py -u "https://target.com/api/user?id=123"

# Comprehensive scan
python3 idor_scanner.py -u "https://target.com" --comprehensive -o report.txt

# Interactive menu
python3 idor_scanner.py --interactive
```
- Notes: Requires Playwright (`pip install playwright && playwright install`).

### bug_hunting_arsenal.py
- Purpose: Async recon: subdomains → alive → URLs (katana/waymore) → whatweb → crawl4ai → nuclei → enrichments → summary.json
- Usage:
```bash
python3 bug_hunting_arsenal.py -t example.com -o reports/$(date +%Y%m%d_%H%M%S)/bug_hunting_arsenal --threads 20 --timeout 30
```

### luckyspin.sh (+ run_luckyspin.sh)
- Purpose: Enhanced bug bounty OSINT platform (Python app named luckyspin.sh)
- Usage:
```bash
# Preferred launcher (handles venv/deps)
./run_luckyspin.sh --interactive
# Or
python3 luckyspin.sh --target example.com --output luckyspin_report
```

### gov.sh / gov.py
- Purpose: `.gov`-focused recon with MITRE ATT&CK mapping, browser automation optional, JSON/CSV/HTML/XML reports
- Usage:
```bash
# Shell wrapper with many flags (help)
./gov.sh --help
# Typical non-browser run
./gov.sh example.gov -o gov.json --format json,csv
# Direct Python
python3 gov.py example.gov --format html --browser --screenshot
```

### cve_sqry.py
- Purpose: Combine sqry-based target IPs or query CVE DB API; produce summary.json or console output
- Usage:
```bash
# Use sqry to fetch IPs for queries
python3 cve_sqry.py -t apache tomcat -o reports/cve

# Search CVEs
python3 cve_sqry.py --product openssl -o reports/cve
python3 cve_sqry.py --cve-id CVE-2023-XXXXX -o reports/cve
```


## Auxiliary helpers

### xss.sh
- Purpose: LazyXSS pipeline with subfinder → URLs → arjun/paramspider → kxss → BXSS injection → aquatone
- Usage:
```bash
./xss.sh example.com
```
- Requires: subfinder, urlfinder, katana, gau, waybackurls, waymore, arjun, paramspider, kxss, curl, aquatone, jq

### sqry.sh (sqry-wrapper)
- Purpose: Free-API OSINT/search helper: Org OSINT, search, filter IPs, httpx, nuclei, wayback, nmap, pipelines
- Usage:
```bash
./sqry.sh
```

### vt.sh, wayback.sh, par-bounty.sh
- See sections above for harvesting, enhanced Wayback and parallel runners.


## Example end-to-end sessions

### Fast sweep (quick visibility)
```bash
./bug_bounty_framework/quick_scan.sh example.com
cat ~/bug_bounty_framework/results/*_example.com/live_subdomains.txt | head
```

### Deep pipeline with reporting
```bash
./ultibb.sh example.com
xdg-open bb_scan_*/report/index.html
```

### API/Swagger hunt + XSS checks
```bash
./swagger.sh -t https://api.example.com -o swagger_out --subdomain-scan --threads 80 --timeout 15
xdg-open swagger_out/bug_bounty_report.html
```

### JS secrets sweep
```bash
./js_recon.sh example.com
rg -n "api[_-]?key|secret|token" ultimate_recon_*/* 2>/dev/null || true
```

### IDOR scan (quick) and cookie/JWT review
```bash
python3 idor_scanner.py -u "https://app.example.com/api/user?id=123"
```

### AlienVault OTX bulk harvesting
```bash
./alienvault.sh -t domains.txt --json
jq -r '.findings[].data.urls[]?' reports/*/*/alienvault/summary.json | head
```


## Tips
- Prefer running from a dedicated wordlists/tools environment and ensure `$PATH` has all CLI tools.
- For high-rate scans, add `--threads/--jobs` carefully and consider rate limits.
- Most scripts write into timestamped output folders—review per-tool outputs and reports.
- Use menus (`bb-menu.sh`, `recon.sh`, `swagger.sh -i`) to explore capabilities interactively.
