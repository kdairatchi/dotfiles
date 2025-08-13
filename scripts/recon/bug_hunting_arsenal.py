#!/usr/bin/env python3
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  bug_hunting_arsenal.py
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  “real never lies.”  |  Support: buymeacoffee.com/kdairatchi
# =========================================================
"""
bug_hunting_arsenal.py - Automated Reconnaissance and Vulnerability Assessment
Part of Kdairatchi Security Research Tools
Version: 3.1.0

Integrates crawl4ai with essential bug bounty tools for comprehensive testing
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
    print("Install with: pip install aiofiles aiohttp crawl4ai")
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
        self.version = "3.1.0"
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
        
        # Results storage
        self.subdomains: Set[str] = set()
        self.urls: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.technologies: Dict[str, str] = {}
        self.crawled_data: Dict[str, Dict] = {}
        self.vulnerabilities: List[Dict] = []
        
        # Tool availability
        self.available_tools = {
            'subfinder': self._check_tool('subfinder'),
            'katana': self._check_tool('katana'),
            'httpx': self._check_tool('httpx'),
            'whatweb': self._check_tool('whatweb'),
            'waymore': self._check_tool('waymore'),
            'nuclei': self._check_tool('nuclei'),
            'nmap': self._check_tool('nmap'),
            'amass': self._check_tool('amass'),
            'gau': self._check_tool('gau'),
            'assetfinder': self._check_tool('assetfinder')
        }
        
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
            return False

    async def _run_command_safe(self, command: List[str], timeout: int = None) -> str:
        """Execute shell command safely with timeout and logging"""
        if timeout is None:
            timeout = self.timeout
            
        try:
            # Validate command
            if not command or not all(isinstance(arg, str) for arg in command):
                raise ValueError("Invalid command format")
            
            # Check if tool is available
            tool_name = command[0]
            if not self.available_tools.get(tool_name):
                self.logger.warning(f"Tool not available: {tool_name}")
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
        self.logger.info("Starting subdomain enumeration...")
        
        # Track successful tools
        successful_tools = []
        
        # Subfinder
        if self.available_tools.get('subfinder'):
            output_file = self.output_dir / "raw" / "subfinder.txt"
            result = await self._run_command_safe([
                'subfinder', '-d', self.target_domain, 
                '-o', str(output_file), '-silent'
            ])
            if output_file.exists():
                subdomains = await self._read_file_lines(output_file)
                self.subdomains.update(subdomains)
                successful_tools.append('subfinder')
        
        # Assetfinder
        if self.available_tools.get('assetfinder'):
            result = await self._run_command_safe(['assetfinder', self.target_domain])
            if result:
                subdomains = [line.strip() for line in result.split('\n') if line.strip()]
                self.subdomains.update(subdomains)
                successful_tools.append('assetfinder')
        
        # Amass passive enumeration
        if self.available_tools.get('amass'):
            output_file = self.output_dir / "raw" / "amass.txt"
            result = await self._run_command_safe([
                'amass', 'enum', '-passive', '-d', self.target_domain,
                '-o', str(output_file)
            ])
            if output_file.exists():
                subdomains = await self._read_file_lines(output_file)
                self.subdomains.update(subdomains)
                successful_tools.append('amass')
        
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
                        successful_tools.append('crt.sh')
        except Exception as e:
            self.logger.debug(f"Certificate transparency lookup failed: {e}")
        
        # Filter and validate subdomains
        valid_subdomains = {s.strip().lower() for s in self.subdomains if self.target_domain in s}
        self.subdomains = valid_subdomains
        
        # Limit subdomains for performance
        if len(self.subdomains) > self.max_subdomains:
            self.logger.warning(f"Too many subdomains found ({len(self.subdomains)}), limiting to {self.max_subdomains}")
            self.subdomains = set(list(self.subdomains)[:self.max_subdomains])
        
        self.stats['subdomains_found'] = len(self.subdomains)
        
        self.logger.info(f"Found {len(self.subdomains)} valid subdomains using: {', '.join(successful_tools)}")
        
        # Save results
        if self.subdomains:
            subdomain_list = sorted(list(self.subdomains))
            await self._save_to_file(subdomain_list, "subdomains.txt")

    async def probe_alive_hosts(self):
        """Probe alive hosts using httpx"""
        self.logger.info("Probing alive hosts...")
        
        subdomains_file = self.output_dir / "subdomains.txt"
        if not subdomains_file.exists():
            self.logger.warning("No subdomains file found, skipping host probing.")
            return

        # Probe with httpx
        alive_hosts_file = self.output_dir / "alive_hosts.txt"
        await self._run_command_safe([
            'httpx', '-l', str(subdomains_file), '-o', str(alive_hosts_file),
            '-status-code', '-title', '-tech-detect', '-silent'
        ])
        
        # Load alive hosts
        if alive_hosts_file.exists():
            content = await self._read_file_lines(alive_hosts_file)
            for line in content:
                if line.strip():
                    url = line.split()[0] if line.split() else line.strip()
                    self.urls.add(url)
        
        self.logger.info(f"Found {len(self.urls)} alive hosts")

    async def url_discovery(self):
        """Comprehensive URL discovery using multiple tools"""
        self.logger.info("Starting URL discovery...")
        
        alive_hosts_file = self.output_dir / "alive_hosts.txt"
        if not alive_hosts_file.exists():
            self.logger.warning("No alive hosts file found, skipping URL discovery.")
            return

        # Katana for crawling
        katana_urls_file = self.output_dir / "katana_urls.txt"
        await self._run_command_safe([
            'katana', '-list', str(alive_hosts_file), '-d', '3',
            '-o', str(katana_urls_file), '-silent'
        ])
        
        # Waymore for archived URLs
        waymore_urls_file = self.output_dir / "waymore_urls.txt"
        await self._run_command_safe([
            'waymore', '-i', self.target_domain, '-mode', 'U',
            '-oU', str(waymore_urls_file)
        ])
        
        # Load discovered URLs
        for url_file in [katana_urls_file, waymore_urls_file]:
            if url_file.exists():
                content = await self._read_file_lines(url_file)
                for url in content:
                    if url.strip():
                        self.urls.add(url.strip())
        
        self.logger.info(f"Discovered {len(self.urls)} URLs")

    async def technology_detection(self):
        """Detect technologies using whatweb"""
        self.logger.info("Detecting technologies...")
        
        for url in list(self.urls)[:50]:  # Limit to first 50 URLs
            try:
                result = await self._run_command_safe(['whatweb', '--color=never', '--no-errors', '-a', '3', url])
                if result:
                    self.technologies[url] = result.strip()
            except Exception as e:
                self.logger.warning(f"Technology detection failed for {url}: {e}")

    async def crawl_with_crawl4ai(self):
        """Advanced crawling with crawl4ai"""
        self.logger.info("Starting advanced crawling with crawl4ai...")
        
        async with AsyncWebCrawler(
            browser_type="chromium",
            headless=True,
            verbose=False
        ) as crawler:
            
            for url in list(self.urls)[:20]:  # Limit for demo
                try:
                    self.logger.info(f"Crawling: {url}")
                    
                    result = await crawler.arun(
                        url=url,
                        word_count_threshold=10,
                        extraction_strategy="CosineStrategy",
                        chunking_strategy="RegexChunking",
                        bypass_cache=False,
                        screenshot=True,
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
                            with open(screenshot_path, 'wb') as f:
                                f.write(result.screenshot)
                    
                except Exception as e:
                    self.logger.error(f"Crawl4ai failed for {url}: {e}")
        
        self.logger.info(f"Crawled {len(self.crawled_data)} pages with crawl4ai")

    async def vulnerability_scanning(self):
        """Vulnerability scanning with multiple tools"""
        self.logger.info("Starting vulnerability scanning...")
        
        urls_file = self.output_dir / "all_urls.txt"
        await self._save_to_file(list(self.urls), "all_urls.txt")
        
        nuclei_results_file = self.output_dir / "nuclei_results.txt"
        await self._run_command_safe([
            'nuclei', '-l', str(urls_file), '-o', str(nuclei_results_file), '-silent'
        ])
        
        if nuclei_results_file.exists():
            content = await self._read_file_lines(nuclei_results_file)
            for line in content:
                self.vulnerabilities.append({'tool': 'nuclei', 'finding': line})

    async def generate_report(self):
        """Generate comprehensive report"""
        self.logger.info("Generating comprehensive report...")
        
        self.stats['processed'] = 1
        self.stats['duration'] = time.time() - self.start_time
        
        report = {
            "tool": self.name,
            "version": self.version,
            "timestamp": datetime.utcnow().isoformat(),
            "targets": [self.target_domain],
            "findings": self.vulnerabilities,
            "stats": self.stats
        }
        
        summary_path = self.output_dir / "summary.json"
        with open(summary_path, 'w') as f:
            json.dump(report, f, indent=2, sort_keys=True)
            
        if self.args.json:
            print(json.dumps(report, indent=2, sort_keys=True))

        self.logger.info(f"Report saved to {summary_path}")

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
            self.logger.info(f"Results saved in: {self.output_dir}")
            
        except Exception as e:
            self.logger.error(f"Bug hunting arsenal failed: {e}", exc_info=True)
            self.stats['errors'] += 1
            await self.generate_report()

    async def _read_file_lines(self, file_path: Path) -> List[str]:
        """Read lines from a file safely"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                return [line.strip() for line in content.split('\n') if line.strip()]
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return []

    async def _save_to_file(self, data: list, filename: str):
        """Save a list to a file."""
        path = self.output_dir / filename
        async with aiofiles.open(path, 'w') as f:
            await f.write('\n'.join(data))

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Bug Hunting Arsenal")
    parser.add_argument("-t", "--target", help="Target domain")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Output summary as JSON to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--no-color", action="store_true", help="Disable colorized output")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout for network operations")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for parallel tasks")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without executing them")
    parser.add_argument("--banner", action="store_true", help="Print banner and exit")
    parser.add_argument("--version", action="version", version="%(prog)s 3.1.0")
    
    args = parser.parse_args()

    if args.banner:
        kd_banner("bug_hunting_arsenal", "3.1.0", color=not args.no_color)
        sys.exit(0)

    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"reports/{timestamp}/bug_hunting_arsenal"
    
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