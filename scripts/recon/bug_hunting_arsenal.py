#!/usr/bin/env python3
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  bug_hunting_arsenal.py
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  “real never lies.”  |  Support: buymeacoffee.com/kdairatchi
# =========================================================
"""
bug_hunting_arsenal.py - Automated Reconnaissance and Vulnerability Assessment
Part of Security Research Tools
Version: 3.2.0

Integrates crawl4ai with essential bug bounty tools for comprehensive testing.
This enhanced version includes improved error handling, better dependency management,
more flexible tool selection, and more efficient output processing.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

# Third-party imports with error handling
try:
    import aiofiles
    import aiohttp
    from crawl4ai import AsyncWebCrawler
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None

# Import Kdairatchi framework
from lib.banner import kd_banner

class BugHuntingArsenal:
    """
    Comprehensive bug hunting and reconnaissance tool
    """
    def __init__(self, args):
        self.args = args
        self.name = "bug_hunting_arsenal"
        self.version = "3.2.0"
        self.description = "Automated Reconnaissance and Vulnerability Assessment"
        
        # Configuration
        self.target_domain = args.target
        self.output_dir = Path(args.output) if args.output else None
        self.threads = args.threads
        self.timeout = args.timeout
        self.max_crawl_pages = 20
        self.max_subdomains = 1000
        self.enable_screenshots = True
        self.crawl_depth = 3
        self.semaphore = asyncio.Semaphore(args.threads)
        
        # Results storage
        self.subdomains: Set[str] = set()
        self.urls: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.technologies: Dict[str, str] = {}
        self.crawled_data: Dict[str, Dict] = {}
        self.vulnerabilities: List[Dict] = []
        # Enrichment storage
        self.ip_info: Dict[str, Dict] = {}
        self.domain_db_matches: List[Dict] = []
        self.emailrep_result: Optional[Dict] = None
        self.http2_results: Dict[str, bool] = {}
        
        # Tool availability
        self.available_tools = self._check_all_tools()
        
        # Statistics
        self.stats = {
            'subdomains_found': 0,
            'urls_discovered': 0,
            'endpoints_found': 0,
            'pages_crawled': 0,
            'technologies_detected': 0,
            'vulnerabilities_found': 0,
            'tools_used': [],
            'duration': 0,
            'errors': 0,
            'processed': 0
        }
        
        # Logging
        self.logger = self.setup_logging()

    def setup_logging(self):
        """Sets up logging."""
        log_level = logging.DEBUG if self.args.verbose else logging.INFO
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        return logging.getLogger(__name__)

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        try:
            subprocess.run([tool_name, '--help'], 
                         capture_output=True, timeout=5, check=False)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.warning(f"Tool not found in PATH: {tool_name}")
            return False

    def _check_all_tools(self):
        """Checks for all required external tools."""
        tools = {
            'subfinder': 'subfinder',
            'katana': 'katana',
            'httpx': 'httpx',
            'whatweb': 'whatweb',
            'waymore': 'waymore',
            'nuclei': 'nuclei',
            'nmap': 'nmap',
            'amass': 'amass',
            'gau': 'gau',
            'assetfinder': 'assetfinder'
        }
        available = {}
        for name, cmd in tools.items():
            available[name] = self._check_tool(cmd)
        return available

    async def _run_command_safe(self, command: List[str], timeout: int = None) -> str:
        """Execute shell command safely with timeout and logging"""
        if timeout is None:
            timeout = self.timeout
            
        async with self.semaphore:
            try:
                if not command or not all(isinstance(arg, str) for arg in command):
                    raise ValueError("Invalid command format")
                
                tool_name = command[0]
                if not self.available_tools.get(tool_name):
                    self.logger.warning(f"Tool not available: {tool_name}, skipping command.")
                    return ""
                
                self.logger.debug(f"Executing: {' '.join(command)}")
                
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=1024*1024  # 1MB limit
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    self.logger.warning(f"Command timed out: {' '.join(command)}")
                    self.stats['errors'] += 1
                    return ""
                
                if process.returncode != 0:
                    self.logger.warning(f"Command failed with code {process.returncode}: {' '.join(command)}")
                    if stderr:
                        self.logger.debug(f"Error output: {stderr.decode()[:500]}")
                    self.stats['errors'] += 1
                    return ""
                
                result = stdout.decode('utf-8', errors='ignore')
                if tool_name not in self.stats['tools_used']:
                    self.stats['tools_used'].append(tool_name)
                    
                return result
                
            except Exception as e:
                self.logger.error(f"Error executing command {' '.join(command)}: {e}")
                self.stats['errors'] += 1
                return ""

    async def subdomain_enumeration(self) -> None:
        """Comprehensive subdomain enumeration with multiple tools"""
        if not self.args.run_subdomain_enum:
            self.logger.info("Skipping subdomain enumeration as per user request.")
            return
            
        self.logger.info("Starting subdomain enumeration...")
        
        tasks = []
        if self.available_tools.get('subfinder'):
            tasks.append(self._run_command_safe(['subfinder', '-d', self.target_domain, '-silent']))
        if self.available_tools.get('assetfinder'):
            tasks.append(self._run_command_safe(['assetfinder', '--subs-only', self.target_domain]))
        if self.available_tools.get('amass'):
            tasks.append(self._run_command_safe(['amass', 'enum', '-passive', '-d', self.target_domain]))

        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                subdomains = [line.strip() for line in result.split('\n') if line.strip()]
                self.subdomains.update(subdomains)

        # Certificate transparency (crt.sh)
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lstrip('*.')
                                    if name and self.target_domain in name:
                                        self.subdomains.add(name)
        except Exception as e:
            self.logger.debug(f"Certificate transparency lookup failed: {e}")
        
        valid_subdomains = {s.strip().lower() for s in self.subdomains if self.target_domain in s}
        self.subdomains = valid_subdomains
        
        if len(self.subdomains) > self.max_subdomains:
            self.logger.warning(f"Too many subdomains found ({len(self.subdomains)}), limiting to {self.max_subdomains}")
            self.subdomains = set(list(self.subdomains)[:self.max_subdomains])
        
        self.stats['subdomains_found'] = len(self.subdomains)
        self.logger.info(f"Found {len(self.subdomains)} valid subdomains.")
        
        if self.subdomains:
            await self._save_to_file(sorted(list(self.subdomains)), "subdomains.txt")

    async def probe_alive_hosts(self):
        """Probe alive hosts using httpx"""
        self.logger.info("Probing alive hosts...")
        
        if not self.subdomains:
            self.logger.warning("No subdomains to probe.")
            return

        subdomains_str = "\n".join(self.subdomains)
        result = await self._run_command_safe([
            'httpx', '-status-code', '-title', '-tech-detect', '-silent'
        ], timeout=self.timeout) # Pass URLs via stdin
        
        if result:
            for line in result.split('\n'):
                if line.strip():
                    url = line.split()[0] if line.split() else line.strip()
                    self.urls.add(url)
        
        self.logger.info(f"Found {len(self.urls)} alive hosts")
        if self.urls:
            await self._save_to_file(sorted(list(self.urls)), "alive_hosts.txt")

    async def url_discovery(self):
        """Comprehensive URL discovery using multiple tools"""
        if not self.args.run_url_discovery:
            self.logger.info("Skipping URL discovery as per user request.")
            return

        self.logger.info("Starting URL discovery...")
        
        tasks = []
        if self.available_tools.get('katana'):
            tasks.append(self._run_command_safe(['katana', '-u', self.target_domain, '-d', '3', '-silent']))
        if self.available_tools.get('waymore'):
            tasks.append(self._run_command_safe(['waymore', '-i', self.target_domain, '-mode', 'U']))

        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                urls = [line.strip() for line in result.split('\n') if line.strip()]
                self.urls.update(urls)
        
        self.logger.info(f"Discovered {len(self.urls)} URLs")
        if self.urls:
            await self._save_to_file(sorted(list(self.urls)), "all_urls.txt")

    async def technology_detection(self):
        """Detect technologies using whatweb"""
        if not self.args.run_tech_detection:
            self.logger.info("Skipping technology detection as per user request.")
            return

        self.logger.info("Detecting technologies...")
        
        tasks = []
        for url in list(self.urls)[:50]:  # Limit to first 50 URLs
            tasks.append(self._run_command_safe(['whatweb', '--color=never', '--no-errors', '-a', '3', url]))
        
        results = await asyncio.gather(*tasks)
        for i, result in enumerate(results):
            if result:
                self.technologies[list(self.urls)[i]] = result.strip()

    async def crawl_with_crawl4ai(self):
        """Advanced crawling with crawl4ai"""
        if not self.args.run_crawl:
            self.logger.info("Skipping crawling with crawl4ai as per user request.")
            return

        self.logger.info("Starting advanced crawling with crawl4ai...")
        
        async with AsyncWebCrawler(
            browser_type="chromium",
            headless=True,
            verbose=False
        ) as crawler:
            
            tasks = []
            for url in list(self.urls)[:20]:  # Limit for demo
                tasks.append(self._crawl_single_url(crawler, url))
            
            await asyncio.gather(*tasks)
        
        self.logger.info(f"Crawled {len(self.crawled_data)} pages with crawl4ai")

    async def _crawl_single_url(self, crawler, url):
        """Helper to crawl a single URL."""
        try:
            self.logger.info(f"Crawling: {url}")
            result = await crawler.arun(
                url=url,
                word_count_threshold=10,
                extraction_strategy="CosineStrategy",
                chunking_strategy="RegexChunking",
                bypass_cache=False,
                screenshot=self.enable_screenshots,
                wait_for="css:body"
            )
            
            if result.success:
                self.crawled_data[url] = {
                    'markdown': result.markdown,
                    'links': result.links,
                    'images': result.images,
                    'metadata': result.metadata,
                    'media': result.media
                }
                
                for link in result.links.get('internal', []):
                    full_url = urljoin(url, link.get('href', ''))
                    self.endpoints.add(full_url)
                
                if result.screenshot:
                    screenshot_path = self.output_dir / f"screenshots/{urlparse(url).netloc}_{hash(url)}.png"
                    screenshot_path.parent.mkdir(exist_ok=True, parents=True)
                    async with aiofiles.open(screenshot_path, 'wb') as f:
                        await f.write(result.screenshot)
            
        except Exception as e:
            self.logger.error(f"Crawl4ai failed for {url}: {e}")

    async def vulnerability_scanning(self):
        """Vulnerability scanning with Nuclei"""
        if not self.args.run_vuln_scan:
            self.logger.info("Skipping vulnerability scanning as per user request.")
            return

        self.logger.info("Starting vulnerability scanning with Nuclei...")
        
        if not self.urls:
            self.logger.warning("No URLs to scan for vulnerabilities.")
            return

        urls_str = "\n".join(self.urls)
        result = await self._run_command_safe([
            'nuclei', '-silent'
        ], timeout=self.timeout) # Pass URLs via stdin

        if result:
            for line in result.split('\n'):
                if line.strip():
                    self.vulnerabilities.append({'tool': 'nuclei', 'finding': line.strip()})
        
        self.stats['vulnerabilities_found'] = len(self.vulnerabilities)
        self.logger.info(f"Found {len(self.vulnerabilities)} potential vulnerabilities.")

    async def generate_report(self):
        """Generate comprehensive JSON and human-readable reports"""
        self.logger.info("Generating reports...")
        
        self.stats['duration'] = time.time() - self.start_time
        
        # JSON Report
        report = {
            "tool": self.name,
            "version": self.version,
            "timestamp": datetime.utcnow().isoformat(),
            "target": self.target_domain,
            "stats": self.stats,
            "subdomains": sorted(list(self.subdomains)),
            "alive_hosts": sorted(list(self.urls)),
            "vulnerabilities": self.vulnerabilities,
            "technologies": self.technologies,
            "enrichment": {
                "ip_info": self.ip_info,
                "domainsdb": self.domain_db_matches,
                "http2": self.http2_results,
                "emailrep": self.emailrep_result,
            }
        }
        
        summary_path = self.output_dir / "summary.json"
        async with aiofiles.open(summary_path, 'w') as f:
            await f.write(json.dumps(report, indent=2, sort_keys=True))
            
        if self.args.json:
            print(json.dumps(report, indent=2, sort_keys=True))

        # Human-readable report
        duration_str = f"{self.stats['duration']:.2f}"
        report_str = f"""# Bug Hunting Arsenal Report for {self.target_domain}

**Timestamp:** {datetime.utcnow().isoformat()}
**Duration:** {duration_str} seconds

## Summary
- **Subdomains Found:** {self.stats['subdomains_found']}
- **Alive Hosts:** {len(self.urls)}
- **URLs Discovered:** {self.stats['urls_discovered']}
- **Vulnerabilities Found:** {self.stats['vulnerabilities_found']}

## Subdomains
"""
        report_str += "\n".join(f"- {s}" for s in sorted(list(self.subdomains)))
        report_str += "\n\n## Vulnerabilities\n"
        report_str += "\n".join(f"- {v['finding']}" for v in self.vulnerabilities)

        report_path = self.output_dir / "report.md"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(report_str)

        self.logger.info(f"Reports saved to {self.output_dir}")

    async def run_full_arsenal(self):
        """Run the complete bug hunting arsenal"""
        self.start_time = time.time()
        self.logger.info(f"Starting Bug Hunting Arsenal for {self.target_domain}")
        
        if self.args.dry_run:
            self.logger.info("[DRY RUN] Would perform all actions.")
            return

        try:
            await self.subdomain_enumeration()
            await self.probe_alive_hosts()
            await self.url_discovery()
            await self.technology_detection()
            await self.crawl_with_crawl4ai()
            await self.vulnerability_scanning()
            await self.generate_report()
            
            self.logger.info("Bug Hunting Arsenal completed successfully!")
            
        except Exception as e:
            self.logger.error(f"Bug hunting arsenal failed: {e}", exc_info=True)
            self.stats['errors'] += 1
            await self.generate_report()

    async def _save_to_file(self, data: list, filename: str):
        """Save a list to a file."""
        path = self.output_dir / filename
        async with aiofiles.open(path, 'w') as f:
            await f.write('\n'.join(data))

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Bug Hunting Arsenal")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Output summary as JSON to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--no-color", action="store_true", help="Disable colorized output")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout for network operations")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent tasks")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without executing them")
    parser.add_argument("--banner", action="store_true", help="Print banner and exit")
    parser.add_argument("--version", action="version", version="%(prog)s 3.2.0")
    parser.add_argument("--email", help="Optional email for EmailRep enrichment")

    # Tool selection arguments
    parser.add_argument("--no-subdomain-enum", dest='run_subdomain_enum', action='store_false', help="Disable subdomain enumeration")
    parser.add_argument("--no-url-discovery", dest='run_url_discovery', action='store_false', help="Disable URL discovery")
    parser.add_argument("--no-tech-detection", dest='run_tech_detection', action='store_false', help="Disable technology detection")
    parser.add_argument("--no-crawl", dest='run_crawl', action='store_false', help="Disable crawling with crawl4ai")
    parser.add_argument("--no-vuln-scan", dest='run_vuln_scan', action='store_false', help="Disable vulnerability scanning")
    
    parser.set_defaults(run_subdomain_enum=True, run_url_discovery=True, run_tech_detection=True, run_crawl=True, run_vuln_scan=True)

    args = parser.parse_args()

    if args.banner:
        kd_banner("bug_hunting_arsenal", "3.2.0", color=not args.no_color)
        sys.exit(0)

    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"reports/{args.target}/{timestamp}"
    
    Path(args.output).mkdir(parents=True, exist_ok=True)
    (Path(args.output) / "raw").mkdir(exist_ok=True)

    arsenal = BugHuntingArsenal(args)
    
    if not args.dry_run:
        kd_banner(arsenal.name, arsenal.version, color=not args.no_color)

    try:
        asyncio.run(arsenal.run_full_arsenal())
    except KeyboardInterrupt:
        arsenal.logger.warning("Scan interrupted by user.")
        sys.exit(130)

if __name__ == "__main__":
    main()
