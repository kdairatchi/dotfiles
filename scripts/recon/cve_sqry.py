#!/usr/bin/env python3
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  cve-sqry.py
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  “real never lies.”  |  Support: buymeacoffee.com/kdairatchi
# =========================================================
import argparse
import requests
import sys
import json
from datetime import datetime
import subprocess
import os
import logging
import time

# Import Kdairatchi framework
from lib.banner import kd_banner

# Configuration
SQRY_CMD = "sqry"  # Local CLI tool that outputs IPs for a query
CVEDB_API_URL = "https://cvedb.shodan.io"
DEFAULT_HEADERS = {"User-Agent": "Kdairatchi-CVE-SQRY/1.0"}

class CveSqryTool:
    def __init__(self, args):
        self.args = args
        self.name = "cve-sqry"
        self.version = "1.0.0"
        self.logger = self.setup_logging()

    def setup_logging(self):
        """Sets up logging."""
        log_level = logging.DEBUG if self.args.verbose else logging.INFO
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        return logging.getLogger(__name__)

    def run(self):
        """Main execution flow."""
        start_time = time.time()
        
        if self.args.dry_run:
            self.logger.info("[DRY RUN] Would execute with the following arguments:")
            self.logger.info(vars(self.args))
            return

        if self.args.cve_id or self.args.product or self.args.cpe23:
            results = self.handle_cve_search()
        elif self.args.targets:
            results = self.handle_sqry_search()
        else:
            self.logger.error("No valid query provided. Use -t for host search or --cve-id/--product/--cpe23 for CVE search.")
            return

        duration = time.time() - start_time
        self.generate_report(results, duration)

    def handle_sqry_search(self):
        """Handle SQry host/search queries by invoking the local CLI tool"""
        all_results = []
        for target in self.args.targets:
            try:
                self.logger.info(f"Querying sqry for: {target}")
                result = subprocess.run(
                    [SQRY_CMD, '-q', target],
                    capture_output=True,
                    text=True,
                    check=True
                )
                ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                all_results.extend([{"ip": ip, "query": target} for ip in ips])
            except FileNotFoundError:
                self.logger.error(f"'{SQRY_CMD}' tool not found in PATH.")
                return []
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error running sqry for '{target}': {e.stderr}")
                continue
        return all_results

    def handle_cve_search(self):
        """Handle CVEDB queries"""
        params = {}
        url = f"{CVEDB_API_URL}/cves"
        if self.args.cve_id:
            url = f"{CVEDB_API_URL}/cve/{self.args.cve_id}"
        else:
            if self.args.product:
                params['product'] = self.args.product
            if self.args.cpe23:
                params['cpe23'] = self.args.cpe23
        
        try:
            self.logger.info(f"Querying CVEDB: {url} with params: {params}")
            response = requests.get(url, params=params, headers=DEFAULT_HEADERS, timeout=self.args.timeout)
            response.raise_for_status()
            data = response.json()
            return [data] if isinstance(data, dict) else data
        except requests.RequestException as e:
            self.logger.error(f"Error querying CVEDB API: {e}")
            return []

    def generate_report(self, results, duration):
        """Generate and save the report."""
        report = {
            "tool": self.name,
            "version": self.version,
            "timestamp": datetime.utcnow().isoformat(),
            "targets": self.args.targets or [self.args.cve_id or self.args.product or self.args.cpe23],
            "findings": results,
            "stats": {
                "processed": len(self.args.targets) if self.args.targets else 1,
                "errors": 0,  # Basic error tracking, can be improved
                "duration_sec": round(duration, 2)
            }
        }

        if self.args.output:
            output_path = Path(self.args.output)
            output_path.mkdir(parents=True, exist_ok=True)
            summary_file = output_path / "summary.json"
            with open(summary_file, 'w') as f:
                json.dump(report, f, indent=2, sort_keys=True)
            self.logger.info(f"Report saved to {summary_file}")

        if self.args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            self.pretty_print_results(results)

    def pretty_print_results(self, results):
        """Pretty print results to the console."""
        if not results:
            self.logger.info("No results found.")
            return

        if "ip" in results[0]:  # sqry results
            for res in results:
                print(f"IP: {res['ip']} (Query: {res['query']})")
        else:  # CVE results
            for res in results:
                print(f"CVE: {res.get('cve', 'N/A')}")
                print(f"  CVSS: {res.get('cvss', 'N/A')}")
                print(f"  Summary: {res.get('summary', 'N/A')[:100]}...")
                print("-" * 20)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="CVE-SQRY Tool")
    parser.add_argument("-t", "--targets", nargs='+', help="List of targets for sqry search")
    parser.add_argument("-o", "--output", help="Output directory for reports")
    parser.add_argument("--json", action="store_true", help="Output summary as JSON to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--no-color", action="store_true", help="Disable colorized output")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout for network operations")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without executing them")
    parser.add_argument("--banner", action="store_true", help="Print banner and exit")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    
    cve_group = parser.add_argument_group('CVE Search Options')
    cve_group.add_argument('--cve-id', help='Get details for a specific CVE ID')
    cve_group.add_argument('--product', help='Search vulnerabilities by product name')
    cve_group.add_argument('--cpe23', help='Search vulnerabilities by CPE 2.3 string')

    args = parser.parse_args()

    if args.banner:
        kd_banner("cve-sqry", "1.0.0", color=not args.no_color)
        sys.exit(0)

    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"reports/{timestamp}/cve-sqry"

    tool = CveSqryTool(args)
    kd_banner(tool.name, tool.version, color=not args.no_color)
    tool.run()

if __name__ == "__main__":
    main()