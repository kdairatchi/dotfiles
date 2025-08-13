#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Google Dorking Tool with WAF Detection, Playwright, Crawl4AI & CVE Integration
Version: 7.0
Author: Enhanced Security Research Team
Description: Advanced Google dorking tool with headless browsing, content crawling,
             WAF detection & bypass testing, technology fingerprinting, and CVE scanning.
"""

from __future__ import print_function
import sys
import time
import random
import argparse
import asyncio
import logging
import hashlib
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, unquote
from collections import defaultdict
import json
import re
import subprocess
import os
import inspect

# --- Dependency Management ---
try:
    from googlesearch import search
    import requests
    from bs4 import BeautifulSoup
    import aiohttp
    import aiofiles
    from playwright.async_api import async_playwright, Browser, Page
    from crawl4ai import AsyncWebCrawler
except ImportError as e:
    print(f"\033[91m[ERROR] Missing core dependency: {e}\033[0m")
    print("\033[93m[INFO] Please install the required packages by running:\033[0m")
    print("\033[96m    pip install -r requirements.txt\033[0m")
    sys.exit(1)

# Optional anti-detection and proxy tools (best-effort imports)
try:
    from fake_useragent import UserAgent
except ImportError:
    UserAgent = None

try:
    import cloudscraper
except ImportError:
    cloudscraper = None

try:
    from playwright_stealth import stealth_async
except ImportError:
    stealth_async = None

try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options as ChromeOptions
except ImportError:
    uc = None
    By = None
    ChromeOptions = None

try:
    from random_headers import Headers as RandomHeaders
except ImportError:
    try:
        from random_headers.random_headers import Headers as RandomHeaders
    except ImportError:
        RandomHeaders = None

# Note: proxybroker is an optional dependency for advanced proxy discovery.
# It is not included in requirements.txt by default.
try:
    import proxybroker
except ImportError:
    proxybroker = None

# --- Constants and Configuration ---
class Colors:
    """ANSI color codes for console output."""
    RED = "\033[91m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# --- Helper Classes ---

class TechFingerprinter:
    """
    Identifies technologies used by a web page based on headers and content.
    """
    def __init__(self):
        self.tech_patterns = {
            # Web Servers
            'nginx': [r'nginx', r'X-Nginx'],
            'apache': [r'apache', r'X-Apache'],
            'iis': [r'microsoft-iis', r'X-AspNet-Version'],
            'cloudflare': [r'cloudflare', r'CF-Ray'],
            # Frameworks
            'django': [r'django', r'csrfmiddlewaretoken'],
            'rails': [r'ruby.*rails', r'authenticity_token'],
            'laravel': [r'laravel', r'laravel_session'],
            'spring': [r'spring', r'jsessionid'],
            'react': [r'react', r'__reactInternalInstance'],
            'vue': [r'vue\.js', r'v-'],
            'angular': [r'angular', r'ng-'],
            # CMS
            'wordpress': [r'wp-content', r'wp-includes', r'/wp-admin/'],
            'drupal': [r'drupal', r'sites/default'],
            'joomla': [r'joomla', r'com_content'],
            # Cloud/CDN
            'aws': [r'amazonaws', r's3\.amazonaws'],
            'azure': [r'azure', r'windows\.net'],
            'gcp': [r'googleapis', r'googleusercontent'],
        }

    def fingerprint(self, content: str, headers: Dict[str, str]) -> Dict[str, List[str]]:
        """Fingerprints technologies from response content and headers."""
        detected = defaultdict(list)
        # Check headers
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                for header, value in headers.items():
                    if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                        detected[tech].append(f"Header: {header}")
        # Check content
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected[tech].append("Content")
        return {k: list(set(v)) for k, v in detected.items()}


class WAFDetector:
    """
    Advanced WAF Detection and Bypass Module.
    Identifies WAF presence and tests for common bypass techniques.
    """
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger(f"{__name__}.WAFDetector")
        self.waf_signatures = self._load_waf_signatures()
        self.bypass_payloads = self._load_bypass_payloads()
        self.bypass_headers = self._load_bypass_headers()

    def _load_waf_signatures(self) -> Dict[str, Dict]:
        """Loads comprehensive WAF signatures."""
        return {
            'Cloudflare': {'headers': [r'cf-ray', r'cloudflare'], 'content': [r'cloudflare'], 'status': [403, 503]},
            'AWS WAF': {'headers': [r'x-amzn-waf'], 'content': [r'request blocked'], 'status': [403]},
            'Akamai': {'headers': [r'akamai'], 'content': [r'access denied'], 'status': [403]},
            'Imperva': {'headers': [r'x-iinfo'], 'content': [r'request unsuccessful'], 'status': [403]},
            'F5 BIG-IP': {'headers': [r'bigipserver'], 'content': [r'url was rejected'], 'status': [403]},
            'ModSecurity': {'headers': [r'mod_security'], 'content': [r'not acceptable'], 'status': [406]},
        }

    def _load_bypass_payloads(self) -> List[str]:
        """Loads a variety of WAF bypass payloads."""
        return [
            "?id=1'", "?id=1'/**/AND/**/1=1--",
            "?q=<script>alert('xss')</script>", "?q=javascript:alert('xss')",
            "?file=../../../../etc/passwd", "?cmd=;cat /etc/passwd",
        ]

    def _load_bypass_headers(self) -> Dict[str, List[str]]:
        """Loads headers commonly used for WAF bypasses."""
        return {
            'User-Agent': ['Googlebot/2.1', 'Mozilla/5.0 (compatible; Bingbot/2.0)'],
            'X-Forwarded-For': ['127.0.0.1', '8.8.8.8'],
            'X-Real-IP': ['127.0.0.1'],
        }

    async def detect(self, url: str) -> Dict[str, Any]:
        """Performs WAF detection and bypass testing."""
        result = {'detected': False, 'type': 'Unknown', 'bypass_possible': False}
        try:
            # Initial request to establish a baseline
            baseline_resp = await self._send_request(url)
            if not baseline_resp:
                return result

            # Analyze baseline response for WAF signatures
            for name, sigs in self.waf_signatures.items():
                if self._matches_signature(baseline_resp, sigs):
                    result.update({'detected': True, 'type': name})
                    break

            # If WAF detected, attempt bypasses
            if result['detected']:
                result['bypass_possible'] = await self._test_bypasses(url)

        except Exception as e:
            self.logger.warning(f"WAF detection for {url} failed: {e}")
        return result

    async def _send_request(self, url: str, headers: Optional[Dict] = None) -> Optional[Dict]:
        """Sends a single HTTP request."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10, allow_redirects=True) as resp:
                    content = await resp.text()
                    return {'status': resp.status, 'headers': resp.headers, 'content': content}
        except Exception as e:
            self.logger.debug(f"Request to {url} failed: {e}")
            return None

    def _matches_signature(self, response: Dict, signatures: Dict) -> bool:
        """Checks if a response matches WAF signatures."""
        if response['status'] in signatures.get('status', []):
            return True
        for pattern in signatures.get('headers', []):
            for h, v in response['headers'].items():
                if re.search(pattern, f"{h}: {v}", re.IGNORECASE):
                    return True
        for pattern in signatures.get('content', []):
            if re.search(pattern, response['content'], re.IGNORECASE):
                return True
        return False

    async def _test_bypasses(self, url: str) -> bool:
        """Tests various WAF bypass techniques."""
        # Test with different headers
        for header_name, values in self.bypass_headers.items():
            for value in values:
                resp = await self._send_request(url, headers={header_name: value})
                if resp and resp['status'] == 200:
                    return True # A simple 200 OK with a special header can indicate a bypass
        # Test with payloads
        for payload in self.bypass_payloads:
            test_url = urljoin(url, payload)
            resp = await self._send_request(test_url)
            if resp and resp['status'] == 200:
                return True
        return False


class CVEScanner:
    """
    Scans for potential vulnerabilities using pattern matching and Nuclei.
    """
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.CVEScanner")
        self.nuclei_available = self._check_nuclei()
        self.cve_patterns = {
            'SQLi': [r'SQL syntax.*MySQL', r'ORA-\d+'],
            'XSS': [r'<script.*?>.*?</script>', r'onerror\s*='],
            'Path Traversal': [r'/etc/passwd', r'boot\.ini'],
        }

    def _check_nuclei(self) -> bool:
        """Checks if Nuclei is installed and available in PATH."""
        try:
            subprocess.run(['nuclei', '-version'], capture_output=True, check=True, text=True)
            logging.info("Nuclei scanner found and available.")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.warning("Nuclei not found. Falling back to pattern-based CVE scanning.")
            return False

    async def scan(self, url: str, content: str) -> Dict[str, Any]:
        """Runs vulnerability scans."""
        results = {'patterns': defaultdict(list), 'nuclei': None}
        # Pattern-based scan
        for vuln, patterns in self.cve_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    results['patterns'][vuln].append(pattern)
        # Nuclei scan
        if self.nuclei_available:
            results['nuclei'] = await self._run_nuclei(url)
        return results

    async def _run_nuclei(self, url: str) -> Optional[str]:
        """Executes a Nuclei scan on the given URL."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'nuclei', '-u', url, '-silent', '-nc',
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0 and stdout:
                return stdout.decode().strip()
            if stderr:
                self.logger.debug(f"Nuclei scan stderr for {url}: {stderr.decode()}")
        except Exception as e:
            self.logger.error(f"Nuclei scan for {url} failed: {e}")
        return None


class EnhancedGoogleDorker:
    """
    Main class for the dorking tool. Manages search, analysis, and reporting.
    """
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.output_dir = Path("results")
        self.output_dir.mkdir(exist_ok=True)
        self._setup_logging()

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        self.ua_generator = UserAgent() if UserAgent else None
        self.dork_categories = self._load_dorks()

        self.session = self._create_session()
        self.seen_urls = set()
        self.tech_fingerprinter = TechFingerprinter()
        self.cve_scanner = CVEScanner()
        self.waf_detector = WAFDetector(verbose)
        self.browser: Optional[Browser] = None

        # Configuration
        self.search_provider = 'auto'
        self.max_retries = 3
        self.proxy_list: List[str] = []
        self._proxy_index = -1
        self.enable_stealth = True

    def _setup_logging(self):
        """Configures logging for the application."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'dorking.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_dorks(self) -> Dict[str, List[str]]:
        """Loads dork categories from an internal configuration."""
        return {
            'sensitive_files': [
                'site:{domain} filetype:log', 'site:{domain} filetype:sql',
                'site:{domain} \"BEGIN RSA PRIVATE KEY\"',
            ],
            'login_portals': [
                'site:{domain} intitle:\"login\"', 'site:{domain} inurl:admin',
                'site:{domain} intitle:\"phpMyAdmin\"',
            ],
            'api_endpoints': [
                'site:{domain} inurl:/api/v1', 'site:{domain} filetype:json \"api_key\"',
                'site:{domain} inurl:swagger.json',
            ],
        }

    def _create_session(self) -> requests.Session:
        """Creates a requests Session, using cloudscraper if available."""
        if cloudscraper:
            self.logger.info("Using cloudscraper for requests.")
            return cloudscraper.create_scraper()
        return requests.Session()

    def get_random_user_agent(self) -> str:
        """Returns a random User-Agent string."""
        if self.ua_generator:
            return self.ua_generator.random
        return random.choice(self.user_agents)

    def load_proxies(self, proxy_file: str):
        """Loads proxies from a file."""
        if not Path(proxy_file).exists():
            self.logger.warning(f"Proxy file not found: {proxy_file}")
            return
        with open(proxy_file, 'r') as f:
            self.proxy_list = [line.strip() for line in f if line.strip()]
        self.logger.info(f"Loaded {len(self.proxy_list)} proxies.")

    def _get_next_proxy(self) -> Optional[str]:
        """Rotates to the next proxy in the list."""
        if not self.proxy_list:
            return None
        self._proxy_index = (self._proxy_index + 1) % len(self.proxy_list)
        return self.proxy_list[self._proxy_index]

    async def _search_with_provider(self, query: str, num_results: int) -> List[str]:
        """Selects a search provider and executes the search."""
        # For simplicity, this example primarily uses googlesearch-python.
        # A real implementation would switch between providers based on availability and errors.
        self.logger.info(f"Searching with googlesearch-python for: {query}")
        proxy = self._get_next_proxy()
        sleep_val = random.uniform(5, 10)
        user_agent = self.get_random_user_agent()

        loop = asyncio.get_event_loop()

        def _attempt_search() -> List[str]:
            last_error: Optional[Exception] = None

            # Introspect the search() callable to build compatible kwargs
            try:
                sig = inspect.signature(search)
                accepted = set(sig.parameters.keys())
            except Exception:
                # If introspection fails, fall back to conservative set
                accepted = {"num_results", "sleep_interval", "tld", "lang", "proxy", "proxies"}

            # Map our desired settings to the accepted parameter names
            kwargs: Dict[str, Any] = {}

            # Sleep / rate limiting
            if "sleep_interval" in accepted:
                kwargs["sleep_interval"] = sleep_val
            elif "pause" in accepted:
                kwargs["pause"] = max(2.0, sleep_val)

            # Result count
            if "num_results" in accepted:
                kwargs["num_results"] = num_results
            else:
                # Older API uses num/stop
                if "num" in accepted:
                    kwargs["num"] = min(num_results, 10)
                if "stop" in accepted:
                    kwargs["stop"] = num_results

            # Locale
            if "tld" in accepted:
                kwargs["tld"] = "com"
            if "lang" in accepted:
                kwargs["lang"] = "en"

            # User agent (only if supported)
            if "user_agent" in accepted:
                kwargs["user_agent"] = user_agent

            # Proxy (use singular or plural depending on support)
            if proxy:
                if "proxies" in accepted:
                    kwargs["proxies"] = {"http": proxy, "https": proxy}
                elif "proxy" in accepted:
                    kwargs["proxy"] = proxy

            try:
                return list(search(query, **kwargs))
            except Exception as e:
                last_error = e
                # Try a very conservative minimal call as a last resort
                try:
                    minimal_kwargs = {}
                    if "num_results" in accepted:
                        minimal_kwargs["num_results"] = num_results
                    elif "stop" in accepted:
                        minimal_kwargs["stop"] = num_results
                    return list(search(query, **minimal_kwargs))
                except Exception as e2:
                    last_error = e2
            if last_error:
                raise last_error
            return []

        try:
            results = await loop.run_in_executor(None, _attempt_search)
            if results:
                return results[:num_results]
        except Exception as e:
            self.logger.error(f"googlesearch-python failed: {e}")

        # Fallback to alternative providers
        self.logger.info("Falling back to DuckDuckGo HTML...")
        ddg_results = await loop.run_in_executor(None, lambda: self._search_duckduckgo_html(query, num_results, proxy))
        if ddg_results:
            return ddg_results[:num_results]

        self.logger.info("Falling back to Bing...")
        bing_results = await loop.run_in_executor(None, lambda: self._search_bing(query, num_results, proxy))
        return bing_results[:num_results]

    def _search_duckduckgo_html(self, query: str, num_results: int, proxy: Optional[str]) -> List[str]:
        """Performs a search using DuckDuckGo's HTML endpoint and parses result URLs."""
        headers = {"User-Agent": self.get_random_user_agent()}
        proxies = {"http": proxy, "https": proxy} if proxy else None
        try:
            resp = self.session.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers=headers,
                proxies=proxies,
                timeout=15,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "lxml")
            urls: List[str] = []
            # Preferred anchors
            for a in soup.select("a.result__a"):
                href = a.get("href")
                if href:
                    real = self._resolve_ddg_redirect(href)
                    if real:
                        urls.append(real)
                if len(urls) >= num_results:
                    break
            # Fallback anchors
            if not urls:
                for a in soup.select('a[href^="/l/?"]'):
                    href = a.get("href")
                    real = self._resolve_ddg_redirect(href)
                    if real:
                        urls.append(real)
                    if len(urls) >= num_results:
                        break
            return urls
        except Exception as e:
            self.logger.warning(f"DuckDuckGo HTML fallback failed: {e}")
            return []

    def _resolve_ddg_redirect(self, href: str) -> Optional[str]:
        """Resolves DuckDuckGo redirect URLs to the actual target."""
        try:
            if href.startswith("/l/?") or href.startswith("https://duckduckgo.com/l/?"):
                parsed = urlparse(href)
                params = parse_qs(parsed.query)
                uddg = params.get("uddg", [None])[0]
                if uddg:
                    return unquote(uddg)
                return None
            return href
        except Exception:
            return None

    def _search_bing(self, query: str, num_results: int, proxy: Optional[str]) -> List[str]:
        """Performs a simple Bing web search and parses result URLs."""
        headers = {"User-Agent": self.get_random_user_agent()}
        proxies = {"http": proxy, "https": proxy} if proxy else None
        try:
            resp = self.session.get(
                "https://www.bing.com/search",
                params={"q": query, "count": min(num_results, 50)},
                headers=headers,
                proxies=proxies,
                timeout=15,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "lxml")
            urls: List[str] = []
            for a in soup.select("li.b_algo h2 a"):
                href = a.get("href")
                if href and href.startswith("http"):
                    urls.append(href)
                if len(urls) >= num_results:
                    break
            return urls
        except Exception as e:
            self.logger.warning(f"Bing fallback failed: {e}")
            return []

    async def _init_browser(self):
        """Initializes the Playwright browser instance if not already running."""
        if self.browser and self.browser.is_connected():
            return
        self.logger.info("Initializing Playwright browser...")
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=True)

    async def _close_browser(self):
        """Closes the Playwright browser instance."""
        if self.browser:
            await self.browser.close()
            self.browser = None
            self.logger.info("Playwright browser closed.")

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Performs in-depth analysis of a single URL."""
        self.logger.info(f"Analyzing URL: {url}")
        analysis = {'url': url, 'accessible': False}
        try:
            await self._init_browser()
            page = await self.browser.new_page()
            if self.enable_stealth and stealth_async:
                await stealth_async(page)
            
            resp = await page.goto(url, wait_until='domcontentloaded', timeout=20000)
            analysis['accessible'] = True
            analysis['status_code'] = resp.status
            content = await page.content()
            
            analysis['title'] = await page.title()
            analysis['technologies'] = self.tech_fingerprinter.fingerprint(content, resp.headers)
            analysis['waf'] = await self.waf_detector.detect(url)
            analysis['vulnerabilities'] = await self.cve_scanner.scan(url, content)
            
            await page.close()
        except Exception as e:
            self.logger.warning(f"Failed to analyze {url}: {e}")
            if 'page' in locals() and not page.is_closed():
                await page.close()
        return analysis

    async def search_dork(self, dork: str, num_results: int, analyze: bool) -> List[Dict]:
        """Executes a single dork search and optionally analyzes results."""
        self.logger.info(f"Executing dork: {dork}")
        urls = await self._search_with_provider(dork, num_results)
        unique_urls = [u for u in urls if u not in self.seen_urls]
        self.seen_urls.update(unique_urls)
        
        results = []
        if analyze:
            tasks = [self.analyze_url(url) for url in unique_urls]
            results = await asyncio.gather(*tasks)
        else:
            results = [{'url': url, 'accessible': 'N/A'} for url in unique_urls]
            
        self.logger.info(f"Found {len(unique_urls)} new results for dork: {dork}")
        return results

    async def batch_search(self, domain: str, categories: List[str], num_per_dork: int, analyze: bool):
        """Runs a batch search for a domain across multiple dork categories."""
        self.logger.info(f"Starting batch search for domain: {domain}")
        all_results = {}
        for cat in categories:
            if cat not in self.dork_categories:
                self.logger.warning(f"Category '{cat}' not found. Skipping.")
                continue
            
            self.logger.info(f"--- Processing category: {cat} ---")
            cat_results = []
            for dork_template in self.dork_categories[cat]:
                dork = dork_template.format(domain=domain)
                results = await self.search_dork(dork, num_per_dork, analyze)
                cat_results.extend(results)
                await asyncio.sleep(random.uniform(10, 20)) # Delay between dorks
            all_results[cat] = cat_results
        
        await self._generate_report(domain, all_results)
        self.logger.info(f"Batch search for {domain} complete.")

    async def _generate_report(self, domain: str, all_results: Dict[str, List[Dict]]):
        """Generates JSON, CSV, and HTML reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{domain}_report_{timestamp}"
        
        # Save JSON
        json_path = self.output_dir / f"{report_name}.json"
        with open(json_path, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        self.logger.info(f"JSON report saved to {json_path}")

        # Save CSV
        csv_path = self.output_dir / f"{report_name}.csv"
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'URL', 'Status', 'Title', 'Technologies', 'WAF Type', 'Nuclei Findings'])
            for cat, results in all_results.items():
                for res in results:
                    writer.writerow([
                        cat, res.get('url'), res.get('status_code', 'N/A'),
                        res.get('title', 'N/A'),
                        ', '.join(res.get('technologies', {}).keys()),
                        res.get('waf', {}).get('type', 'N/A'),
                        res.get('vulnerabilities', {}).get('nuclei', 'N/A')
                    ])
        self.logger.info(f"CSV report saved to {csv_path}")
        # HTML report generation can be added here as well.

async def main():
    """Main function to parse arguments and run the dorker."""
    parser = argparse.ArgumentParser(description="Enhanced Google Dorking Tool v7.0")
    parser.add_argument("-q", "--query", help="A single dork query to run.")
    parser.add_argument("-d", "--domain", help="Target domain for batch search.")
    parser.add_argument("-c", "--categories", help="Comma-separated dork categories for batch search (e.g., sensitive_files,login_portals).")
    parser.add_argument("-n", "--num-results", type=int, default=10, help="Number of results per dork.")
    parser.add_argument("-a", "--analyze", action="store_true", help="Enable in-depth analysis of found URLs.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output and debug logging.")
    parser.add_argument("--proxies", help="Path to a file containing a list of proxies.")
    parser.add_argument("--output-dir", default="results", help="Directory to save reports and logs.")
    
    args = parser.parse_args()

    dorker = EnhancedGoogleDorker(verbose=args.verbose)
    dorker.output_dir = Path(args.output_dir)
    dorker.output_dir.mkdir(exist_ok=True)

    if args.proxies:
        dorker.load_proxies(args.proxies)

    try:
        if args.query:
            results = await dorker.search_dork(args.query, args.num_results, args.analyze)
            print(json.dumps(results, indent=2, default=str))
        elif args.domain:
            categories = args.categories.split(',') if args.categories else list(dorker.dork_categories.keys())
            await dorker.batch_search(args.domain, categories, args.num_results, args.analyze)
        else:
            parser.print_help()
            # Here you could start an interactive mode
            print("\nInteractive mode not implemented in this version. Please use command-line arguments.")

    except KeyboardInterrupt:
        print("\n[INFO] User interrupted the process. Shutting down.")
    finally:
        await dorker._close_browser()

if __name__ == "__main__":
    asyncio.run(main())
