# Bug Hunting Arsenal

**Version:** 3.2.0
**Author:** Kdairatchi

`bug_hunting_arsenal.py` is a powerful, all-in-one reconnaissance and vulnerability assessment tool designed for bug bounty hunters and security professionals. It automates the process of gathering information and identifying potential vulnerabilities by integrating a suite of best-in-class open-source tools.

## Features

- **Comprehensive Subdomain Enumeration:** Uses `subfinder`, `assetfinder`, and `amass` to discover subdomains.
- **Live Host Probing:** Identifies live and responsive hosts from the list of subdomains using `httpx`.
- **URL Discovery:** Gathers URLs from various sources, including `katana` and `waymore`.
- **Technology Detection:** Identifies the technologies running on web applications with `whatweb`.
- **Advanced Web Crawling:** Leverages `crawl4ai` for intelligent, deep crawling of target websites.
- **Vulnerability Scanning:** Performs automated vulnerability scanning with `nuclei` using a curated list of templates.
- **Flexible & Modular:** Allows you to run or skip specific phases of the reconnaissance process.
- **Rich Reporting:** Generates both detailed JSON and easy-to-read Markdown reports.

## Prerequisites

### Python Dependencies

The script requires several Python libraries. You can install them using pip:

```bash
pip install -r requirements.txt
```

### External Tools

This script relies on several external tools that must be installed and available in your system's `PATH`. Please ensure the following tools are installed:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [amass](https://github.com/owasp-amass/amass)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [waymore](https://github.com/xnl-h4ck3r/waymore)
- [whatweb](https://github.com/urbanadventurer/WhatWeb)
- [nuclei](https://github.com/projectdiscovery/nuclei)

## Usage

Here is the basic command to run the tool:

```bash
python3 bug_hunting_arsenal.py -t <target_domain>
```

### Arguments

| Argument                | Description                                             | Default                               |
| ----------------------- | ------------------------------------------------------- | ------------------------------------- |
| `-t`, `--target`        | **Required.** The target domain to scan.                |                                       |
| `-o`, `--output`        | The directory to save reports to.                       | `reports/<target>/<timestamp>`        |
| `--json`                | Output the summary report as JSON to stdout.            | `False`                               |
| `-v`, `--verbose`       | Enable verbose logging for debugging.                   | `False`                               |
| `--no-color`            | Disable colorized output.                               | `False`                               |
| `--timeout`             | Timeout in seconds for network operations.              | `60`                                  |
| `--threads`             | Number of concurrent tasks to run.                      | `10`                                  |
| `--dry-run`             | Show the actions that would be performed without running. | `False`                               |
| `--banner`              | Print the banner and exit.                              | `False`                               |
| `--version`             | Show the script's version and exit.                     |                                       |
| `--email`               | Optional email for EmailRep enrichment.                 |                                       |
| `--no-subdomain-enum`   | Disable the subdomain enumeration phase.                | `False`                               |
| `--no-url-discovery`    | Disable the URL discovery phase.                        | `False`                               |
| `--no-tech-detection`   | Disable the technology detection phase.                 | `False`                               |
| `--no-crawl`            | Disable the crawling phase with `crawl4ai`.             | `False`                               |
| `--no-vuln-scan`        | Disable the vulnerability scanning phase.               | `False`                               |

### Example

To run a full scan on `example.com` and save the results to a custom directory:

```bash
python3 bug_hunting_arsenal.py -t example.com -o /path/to/reports/example
```

To run a quick scan without vulnerability scanning or crawling:

```bash
python3 bug_hunting_arsenal.py -t example.com --no-crawl --no-vuln-scan
```

## Reporting

The tool generates two types of reports in the output directory:

- `summary.json`: A detailed report in JSON format, suitable for programmatic access.
- `report.md`: A human-readable summary in Markdown format, perfect for a quick overview.
