#!/usr/bin/env python3
"""
Government Domain OSINT Reconnaissance Script
Enhanced with MITRE ATT&CK Framework Techniques

DISCLAIMER: This script is for authorized security testing only.
Only use on domains you own or have explicit permission to test.
Unauthorized scanning of government systems is illegal.

Author: Security Research Team
Version: 2.0
"""

import requests
import dns.resolver
import whois
import socket
import subprocess
import json
import csv
import time
import random
import concurrent.futures
import re
import ssl
import datetime
import warnings
import logging
import os
import configparser
import urllib3
import asyncio
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
from dataclasses import dataclass
from typing import List, Dict, Optional
import argparse
import sys

# Browser automation imports (optional)
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MITRE ATT&CK Techniques Mapping - Enhanced Coverage
MITRE_TECHNIQUES = {
    # T1595 - Active Scanning
    'T1595.001': 'Active Scanning: Scanning IP Blocks',
    'T1595.002': 'Active Scanning: Vulnerability Scanning',
    'T1595.003': 'Active Scanning: Wordlist Scanning',
    
    # T1590 - Gather Victim Network Information
    'T1590.001': 'Gather Victim Network Information: Domain Properties',
    'T1590.002': 'Gather Victim Network Information: DNS',
    'T1590.003': 'Gather Victim Network Information: Network Trust Dependencies',
    'T1590.004': 'Gather Victim Network Information: Network Topology',
    'T1590.005': 'Gather Victim Network Information: IP Addresses',
    'T1590.006': 'Gather Victim Network Information: Network Security Appliances',
    
    # T1591 - Gather Victim Org Information
    'T1591.001': 'Gather Victim Org Information: Determine Physical Locations',
    'T1591.002': 'Gather Victim Org Information: Business Relationships',
    'T1591.003': 'Gather Victim Org Information: Identify Business Tempo',
    'T1591.004': 'Gather Victim Org Information: Identify Roles',
    
    # T1592 - Gather Victim Host Information
    'T1592.001': 'Gather Victim Host Information: Hardware',
    'T1592.002': 'Gather Victim Host Information: Software',
    'T1592.003': 'Gather Victim Host Information: Firmware',
    'T1592.004': 'Gather Victim Host Information: Client Configurations',
    
    # T1589 - Gather Victim Identity Information
    'T1589.001': 'Gather Victim Identity Information: Credentials',
    'T1589.002': 'Gather Victim Identity Information: Email Addresses',
    'T1589.003': 'Gather Victim Identity Information: Employee Names',
    
    # T1598 - Phishing for Information
    'T1598.001': 'Phishing for Information: Spearphishing Service',
    'T1598.002': 'Phishing for Information: Spearphishing Attachment',
    'T1598.003': 'Phishing for Information: Spearphishing Link',
    
    # T1597 - Search Closed Sources of Information
    'T1597.001': 'Search Closed Sources: Threat Intel Vendors',
    'T1597.002': 'Search Closed Sources: Purchase Technical Data',
    
    # T1596 - Search Open Technical Databases
    'T1596.001': 'Search Open Technical Databases: DNS/Passive DNS',
    'T1596.002': 'Search Open Technical Databases: WHOIS',
    'T1596.003': 'Search Open Technical Databases: Digital Certificates',
    'T1596.004': 'Search Open Technical Databases: CDNs',
    'T1596.005': 'Search Open Technical Databases: Scan Databases',
    
    # T1593 - Search Open Websites/Domains
    'T1593.001': 'Search Open Websites/Domains: Social Media',
    'T1593.002': 'Search Open Websites/Domains: Search Engines',
    'T1593.003': 'Search Open Websites/Domains: Code Repositories',
    
    # T1594 - Search Victim-Owned Websites
    'T1594': 'Search Victim-Owned Websites'
}

@dataclass
class Target:
    domain: str
    ip: str = ""
    status: str = ""
    technologies: List[str] = None
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []

class GovRecon:
    def __init__(self, target_domain: str, output_file: str = "gov_recon_results.json", config_file: str = None):
        self.target_domain = target_domain
        self.output_file = output_file
        self.config = self.load_config(config_file)
        self.logger = logging.getLogger(__name__)
        
        self.results = {
            'target': target_domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'mitre_techniques_used': [],
            'domains': [],
            'subdomains': [],
            'technologies': [],
            'vulnerabilities': [],
            'dns_records': {},
            'certificates': [],
            'employees': [],
            'social_media': [],
            'leaked_credentials': [],
            'shodan_results': [],
            'code_repositories': [],
            'business_relationships': [],
            'physical_locations': [],
            'network_topology': [],
            'network_security_appliances': [],
            'hardware_info': [],
            'firmware_info': [],
            'client_configurations': [],
            'cdn_info': [],
            'scan_database_results': [],
            'passive_dns': [],
            'config_used': self.config
        }
        
        # Enhanced user agents for better evasion
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        # Rate limiting with config support
        self.request_delay = random.uniform(
            self.config.getfloat('timing', 'min_delay', fallback=1.0),
            self.config.getfloat('timing', 'max_delay', fallback=3.0)
        )
        
        # Initialize session with better defaults
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Setup proxy if configured
        self.setup_proxy()
        
    def log_mitre_technique(self, technique_id: str):
        """Log MITRE ATT&CK technique usage"""
        if technique_id in MITRE_TECHNIQUES:
            technique_info = {
                'id': technique_id,
                'name': MITRE_TECHNIQUES[technique_id],
                'timestamp': datetime.datetime.now().isoformat()
            }
            self.results['mitre_techniques_used'].append(technique_info)
            print(f"[MITRE] {technique_id}: {MITRE_TECHNIQUES[technique_id]}")
    
    def safe_request(self, url: str, timeout: int = None, retries: int = 3) -> Optional[requests.Response]:
        """Make safe HTTP request with random user agent, delay, and retry logic"""
        if timeout is None:
            timeout = self.config.getint('timing', 'timeout', fallback=10)
        
        headers = {
            'User-Agent': random.choice(self.user_agents)
        }
        
        for attempt in range(retries):
            try:
                time.sleep(self.request_delay)
                
                response = self.session.get(
                    url, 
                    headers=headers, 
                    timeout=timeout,
                    verify=self.config.getboolean('scanning', 'verify_ssl', fallback=False),
                    allow_redirects=self.config.getboolean('scanning', 'follow_redirects', fallback=True)
                )
                
                return response
                
            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout for {url} (attempt {attempt + 1}/{retries})")
                if attempt == retries - 1:
                    self.logger.error(f"All attempts failed for {url} due to timeout")
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Connection error for {url} (attempt {attempt + 1}/{retries}): {e}")
                if attempt == retries - 1:
                    self.logger.error(f"All attempts failed for {url} due to connection error")
            except requests.exceptions.SSLError as e:
                self.logger.warning(f"SSL error for {url}: {e}")
                # Try without SSL verification on SSL errors
                try:
                    response = self.session.get(
                        url, 
                        headers=headers, 
                        timeout=timeout,
                        verify=False,
                        allow_redirects=self.config.getboolean('scanning', 'follow_redirects', fallback=True)
                    )
                    return response
                except Exception as e2:
                    self.logger.error(f"Request failed even without SSL verification: {e2}")
                break
            except Exception as e:
                self.logger.warning(f"Request failed for {url} (attempt {attempt + 1}/{retries}): {e}")
                if attempt == retries - 1:
                    self.logger.error(f"All attempts failed for {url}: {e}")
            
            # Exponential backoff for retries
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
        
        return None
    
    def discover_subdomains(self) -> List[str]:
        """T1590.002: Gather Victim Network Information: DNS"""
        self.log_mitre_technique('T1590.002')
        
        print(f"[+] Discovering subdomains for {self.target_domain}")
        subdomains = set()
        
        # Common government subdomains
        gov_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'portal', 'api', 'dev', 'test', 'staging',
            'secure', 'login', 'auth', 'sso', 'identity', 'id', 'accounts', 'account',
            'dashboard', 'console', 'panel', 'cpanel', 'webmail', 'email',
            'docs', 'help', 'support', 'kb', 'wiki', 'blog', 'news',
            'cdn', 'static', 'assets', 'media', 'images', 'files',
            'app', 'apps', 'mobile', 'beta', 'alpha', 'preview',
            'vpn', 'remote', 'citrix', 'owa', 'exchange',
            'db', 'database', 'sql', 'mysql', 'postgres',
            'monitor', 'monitoring', 'logs', 'metrics', 'stats',
            'backup', 'archive', 'old', 'legacy',
            'intranet', 'internal', 'private', 'corp', 'corporate'
        ]
        
        # DNS brute force
        for subdomain in gov_subdomains:
            full_domain = f"{subdomain}.{self.target_domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
                print(f"[FOUND] {full_domain}")
            except socket.gaierror:
                pass
        
        # Certificate transparency logs
        subdomains.update(self.check_certificate_transparency())
        
        # Search engine dorking
        subdomains.update(self.search_engine_dorking())
        
        self.results['subdomains'] = list(subdomains)
        return list(subdomains)
    
    def check_certificate_transparency(self) -> List[str]:
        """Search certificate transparency logs"""
        print("[+] Checking certificate transparency logs")
        subdomains = []
        
        try:
            # crt.sh API
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = self.safe_request(url)
            
            if response and response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name.endswith(f".{self.target_domain}"):
                                subdomains.append(name)
                                
        except Exception as e:
            print(f"[ERROR] Certificate transparency check failed: {e}")
            
        return subdomains
    
    def search_engine_dorking(self) -> List[str]:
        """T1593.002: Search Open Websites/Domains: Search Engines"""
        self.log_mitre_technique('T1593.002')
        
        print("[+] Performing search engine dorking")
        subdomains = []
        
        # Google dorking queries
        google_dorks = [
            f"site:{self.target_domain}",
            f"site:*.{self.target_domain}",
            f"inurl:{self.target_domain}",
            f"intitle:{self.target_domain}"
        ]
        
        # Note: In a real implementation, you'd use APIs or web scraping
        # This is a placeholder for the concept
        print("[INFO] Search engine dorking implemented (use APIs in production)")
        
        return subdomains
    
    def dns_enumeration(self, domain: str) -> Dict:
        """Comprehensive DNS enumeration"""
        print(f"[+] DNS enumeration for {domain}")
        dns_info = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_info[record_type] = [str(answer) for answer in answers]
            except Exception:
                dns_info[record_type] = []
        
        return dns_info
    
    def technology_detection(self, url: str) -> List[str]:
        """T1592.002: Gather Victim Host Information: Software"""
        self.log_mitre_technique('T1592.002')
        
        print(f"[+] Detecting technologies for {url}")
        technologies = []
        
        response = self.safe_request(url)
        if not response:
            return technologies
        
        # Server header analysis
        server = response.headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append(f"X-Powered-By: {powered_by}")
        
        # Content analysis
        content = response.text.lower()
        
        # Framework detection
        frameworks = {
            'wordpress': ['wp-content', 'wp-includes'],
            'drupal': ['drupal.js', 'sites/all/modules'],
            'joomla': ['joomla', 'option=com_'],
            'django': ['csrfmiddlewaretoken'],
            'rails': ['csrf-param', 'csrf-token'],
            'php': ['<?php', '.php'],
            'asp.net': ['__viewstate', 'asp.net'],
            'bootstrap': ['bootstrap.css', 'bootstrap.js'],
            'jquery': ['jquery', 'jquery.js']
        }
        
        for tech, indicators in frameworks.items():
            if any(indicator in content for indicator in indicators):
                technologies.append(tech)
        
        return technologies
    
    def vulnerability_scan(self, target: str) -> List[str]:
        """T1595.002: Active Scanning: Vulnerability Scanning"""
        self.log_mitre_technique('T1595.002')
        
        print(f"[+] Basic vulnerability scanning for {target}")
        vulnerabilities = []
        
        # Check for common vulnerabilities
        try:
            response = self.safe_request(f"http://{target}")
            if response:
                # Check for directory listing
                if 'Index of /' in response.text:
                    vulnerabilities.append("Directory listing enabled")
                
                # Check for default pages
                default_indicators = [
                    'Apache2 Default Page',
                    'IIS Windows Server',
                    'nginx default page',
                    'Welcome to nginx!'
                ]
                
                for indicator in default_indicators:
                    if indicator in response.text:
                        vulnerabilities.append(f"Default web server page: {indicator}")
                
                # Check security headers
                security_headers = [
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Strict-Transport-Security',
                    'Content-Security-Policy'
                ]
                
                missing_headers = []
                for header in security_headers:
                    if header not in response.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")
        
        except Exception as e:
            print(f"[ERROR] Vulnerability scan failed for {target}: {e}")
        
        return vulnerabilities
    
    def network_topology_discovery(self, target: str) -> Dict:
        """T1590.004: Gather Victim Network Information: Network Topology"""
        self.log_mitre_technique('T1590.004')
        
        print(f"[+] Network topology discovery for {target}")
        topology_info = {
            'traceroute': [],
            'adjacent_networks': [],
            'routing_info': []
        }
        
        try:
            # Traceroute analysis
            if hasattr(socket, 'IPPROTO_ICMP'):
                topology_info['traceroute'] = self._perform_traceroute(target)
            
            # Network range analysis
            ip = socket.gethostbyname(target)
            topology_info['target_ip'] = ip
            topology_info['network_class'] = self._determine_network_class(ip)
            
        except Exception as e:
            print(f"[ERROR] Network topology discovery failed: {e}")
        
        return topology_info
    
    def _perform_traceroute(self, target: str) -> List[Dict]:
        """Simple traceroute implementation"""
        traceroute_results = []
        
        try:
            # Use system traceroute if available
            result = subprocess.run(['traceroute', '-n', '-m', '15', target], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() and not line.startswith('traceroute'):
                        parts = line.split()
                        if len(parts) >= 2:
                            traceroute_results.append({
                                'hop': i,
                                'ip': parts[1] if parts[1] != '*' else 'timeout',
                                'response_time': parts[2] if len(parts) > 2 else 'unknown'
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[INFO] System traceroute not available or timed out")
        
        return traceroute_results
    
    def _determine_network_class(self, ip: str) -> str:
        """Determine network class and information"""
        octets = ip.split('.')
        first_octet = int(octets[0])
        
        if 1 <= first_octet <= 126:
            return f"Class A (/{first_octet}.0.0.0/8)"
        elif 128 <= first_octet <= 191:
            return f"Class B (/{first_octet}.{octets[1]}.0.0/16)"
        elif 192 <= first_octet <= 223:
            return f"Class C (/{first_octet}.{octets[1]}.{octets[2]}.0/24)"
        else:
            return "Special use or reserved"
    
    def network_security_appliances_detection(self, target: str) -> List[Dict]:
        """T1590.006: Gather Victim Network Information: Network Security Appliances"""
        self.log_mitre_technique('T1590.006')
        
        print(f"[+] Detecting network security appliances for {target}")
        appliances = []
        
        try:
            # Check for common security appliance indicators
            security_checks = {
                'WAF Detection': self._detect_waf(target),
                'Firewall Detection': self._detect_firewall(target),
                'Load Balancer': self._detect_load_balancer(target),
                'CDN Detection': self._detect_cdn(target)
            }
            
            for check_type, results in security_checks.items():
                if results:
                    appliances.append({
                        'type': check_type,
                        'details': results
                    })
        
        except Exception as e:
            print(f"[ERROR] Security appliance detection failed: {e}")
        
        return appliances
    
    def _detect_waf(self, target: str) -> List[str]:
        """Detect Web Application Firewall"""
        waf_indicators = []
        
        try:
            # Test with common WAF trigger patterns
            test_payloads = [
                "<script>alert('xss')</script>",
                "' OR '1'='1",
                "../../../etc/passwd",
                "<?php phpinfo(); ?>"
            ]
            
            for payload in test_payloads:
                test_url = f"http://{target}/?test={payload}"
                response = self.safe_request(test_url)
                
                if response:
                    # Check for WAF signatures in headers
                    waf_headers = [
                        'X-Sucuri-ID', 'X-Sucuri-Cache', 'Cf-Ray',
                        'X-Mod-Security', 'X-WAF-Event-Info',
                        'X-BIG-IP', 'X-Akamai', 'X-CDN'
                    ]
                    
                    for header in waf_headers:
                        if header in response.headers:
                            waf_indicators.append(f"WAF Header: {header}")
                    
                    # Check for WAF response patterns
                    if response.status_code in [403, 406, 429]:
                        if any(keyword in response.text.lower() for keyword in 
                               ['blocked', 'forbidden', 'security', 'firewall']):
                            waf_indicators.append(f"WAF Response Pattern (Status: {response.status_code})")
        
        except Exception:
            pass
        
        return waf_indicators
    
    def _detect_firewall(self, target: str) -> List[str]:
        """Detect network firewall"""
        firewall_indicators = []
        
        try:
            # Test connection to filtered ports
            filtered_ports = [135, 445, 1433, 3389]
            
            for port in filtered_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result != 0:
                        firewall_indicators.append(f"Port {port} filtered/blocked")
                except:
                    pass
        
        except Exception:
            pass
        
        return firewall_indicators
    
    def _detect_load_balancer(self, target: str) -> List[str]:
        """Detect load balancer"""
        lb_indicators = []
        
        try:
            # Multiple requests to detect load balancing
            server_headers = []
            
            for _ in range(5):
                response = self.safe_request(f"http://{target}")
                if response:
                    server = response.headers.get('Server', '')
                    if server:
                        server_headers.append(server)
                time.sleep(1)
            
            # Check for different server responses
            unique_servers = set(server_headers)
            if len(unique_servers) > 1:
                lb_indicators.append(f"Multiple servers detected: {', '.join(unique_servers)}")
            
            # Check for load balancer headers
            response = self.safe_request(f"http://{target}")
            if response:
                lb_headers = ['X-Load-Balancer', 'X-LB-IP', 'X-Forwarded-Server']
                for header in lb_headers:
                    if header in response.headers:
                        lb_indicators.append(f"Load Balancer Header: {header}")
        
        except Exception:
            pass
        
        return lb_indicators
    
    def _detect_cdn(self, target: str) -> List[str]:
        """Detect Content Delivery Network"""
        cdn_indicators = []
        
        try:
            response = self.safe_request(f"http://{target}")
            if response:
                # Check for CDN headers
                cdn_headers = {
                    'CF-RAY': 'Cloudflare',
                    'X-Akamai-Transformed': 'Akamai',
                    'X-Cache': 'Various CDN',
                    'X-CDN': 'Generic CDN',
                    'Server': 'CloudFront' if 'CloudFront' in response.headers.get('Server', '') else None
                }
                
                for header, cdn_name in cdn_headers.items():
                    if header in response.headers and cdn_name:
                        cdn_indicators.append(f"{cdn_name} CDN detected")
        
        except Exception:
            pass
        
        return cdn_indicators
    
    def gather_hardware_info(self, target: str) -> Dict:
        """T1592.001: Gather Victim Host Information: Hardware"""
        self.log_mitre_technique('T1592.001')
        
        print(f"[+] Gathering hardware information for {target}")
        hardware_info = {
            'server_headers': [],
            'ssl_certificate_info': {},
            'http_headers': {},
            'inferred_os': [],
            'load_times': []
        }
        
        try:
            # Analyze HTTP headers for hardware clues
            response = self.safe_request(f"http://{target}")
            if response:
                hardware_info['http_headers'] = dict(response.headers)
                
                # Server header analysis
                server_header = response.headers.get('Server', '').lower()
                if 'apache' in server_header:
                    hardware_info['server_headers'].append(f"Apache Server: {server_header}")
                elif 'nginx' in server_header:
                    hardware_info['server_headers'].append(f"Nginx Server: {server_header}")
                elif 'iis' in server_header:
                    hardware_info['server_headers'].append(f"IIS Server: {server_header}")
                
                # Response time analysis for load indication
                start_time = time.time()
                test_response = self.safe_request(f"http://{target}")
                end_time = time.time()
                if test_response:
                    load_time = end_time - start_time
                    hardware_info['load_times'].append(load_time)
            
            # SSL certificate analysis for additional clues
            cert_info = self.ssl_certificate_analysis(target)
            hardware_info['ssl_certificate_info'] = cert_info
            
        except Exception as e:
            print(f"[ERROR] Hardware info gathering failed: {e}")
        
        return hardware_info
    
    def gather_software_info(self, target: str) -> Dict:
        """T1592.002: Gather Victim Host Information: Software - Enhanced"""
        self.log_mitre_technique('T1592.002')
        
        print(f"[+] Enhanced software detection for {target}")
        software_info = {
            'web_technologies': [],
            'cms_detection': {},
            'programming_languages': [],
            'frameworks': [],
            'security_software': [],
            'third_party_integrations': []
        }
        
        try:
            response = self.safe_request(f"http://{target}")
            if not response:
                return software_info
            
            content = response.text.lower()
            headers = response.headers
            
            # Enhanced CMS detection
            cms_signatures = {
                'WordPress': [
                    'wp-content', 'wp-includes', 'wp-json', 'wordpress',
                    '/wp-admin/', 'wp-emoji-release'
                ],
                'Drupal': [
                    'drupal.js', 'sites/all/modules', 'drupal.settings',
                    'sites/default/files'
                ],
                'Joomla': [
                    'joomla', 'option=com_', 'joomla.js', 'templates/system'
                ],
                'Magento': [
                    'magento', 'mage/cookies.js', 'skin/frontend'
                ],
                'SharePoint': [
                    'sharepoint', '_layouts/', 'spcontextwebinformation'
                ]
            }
            
            for cms, signatures in cms_signatures.items():
                matches = sum(1 for sig in signatures if sig in content)
                if matches > 0:
                    software_info['cms_detection'][cms] = {
                        'confidence': min(matches * 25, 100),
                        'signatures_found': matches
                    }
            
            # Programming language detection
            language_indicators = {
                'PHP': ['<?php', '.php', 'phpsessionid'],
                'ASP.NET': ['__viewstate', 'asp.net', 'webresource.axd'],
                'Java': ['jsessionid', '.jsp', '.do'],
                'Python': ['django', 'flask', 'wsgi'],
                'Ruby': ['ruby', 'rails', 'csrf-token'],
                'Node.js': ['node.js', 'express']
            }
            
            for lang, indicators in language_indicators.items():
                if any(indicator in content for indicator in indicators):
                    software_info['programming_languages'].append(lang)
            
            # Framework detection
            framework_signatures = {
                'Bootstrap': ['bootstrap.css', 'bootstrap.js', 'bootstrap'],
                'jQuery': ['jquery', 'jquery.js'],
                'React': ['react', 'reactdom'],
                'Angular': ['angular', 'angular.js', 'ng-app'],
                'Vue.js': ['vue.js', 'vue '],
                'Foundation': ['foundation.css', 'foundation.js']
            }
            
            for framework, signatures in framework_signatures.items():
                if any(sig in content for sig in signatures):
                    software_info['frameworks'].append(framework)
            
            # Security software detection
            security_headers = {
                'Content-Security-Policy': 'CSP Implementation',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-XSS-Protection': 'XSS Filter',
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'MIME Sniffing Protection'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    software_info['security_software'].append(f"{description}: {headers[header]}")
            
            # Third-party integration detection
            integration_patterns = {
                'Google Analytics': ['google-analytics', 'gtag', 'ga('],
                'Google Tag Manager': ['googletagmanager'],
                'Facebook Pixel': ['fbevents.js', 'facebook.com/tr'],
                'reCAPTCHA': ['recaptcha', 'google.com/recaptcha'],
                'CDN Services': ['cloudflare', 'akamai', 'maxcdn'],
                'Payment Processors': ['paypal', 'stripe', 'square']
            }
            
            for integration, patterns in integration_patterns.items():
                if any(pattern in content for pattern in patterns):
                    software_info['third_party_integrations'].append(integration)
            
        except Exception as e:
            print(f"[ERROR] Enhanced software detection failed: {e}")
        
        return software_info
    
    def gather_firmware_info(self, target: str) -> Dict:
        """T1592.003: Gather Victim Host Information: Firmware"""
        self.log_mitre_technique('T1592.003')
        
        print(f"[+] Gathering firmware information for {target}")
        firmware_info = {
            'ssl_implementation': {},
            'network_stack_fingerprint': {},
            'server_signature': {}
        }
        
        try:
            # SSL/TLS implementation analysis
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        firmware_info['ssl_implementation'] = {
                            'cipher_suite': cipher[0],
                            'protocol_version': cipher[1],
                            'key_exchange': cipher[2] if len(cipher) > 2 else 'unknown'
                        }
        
        except Exception as e:
            print(f"[INFO] SSL analysis not available: {e}")
        
        try:
            # Network stack fingerprinting through HTTP headers
            response = self.safe_request(f"http://{target}")
            if response:
                # Analyze server response patterns
                server_header = response.headers.get('Server', '')
                if server_header:
                    firmware_info['server_signature'] = {
                        'server_string': server_header,
                        'potential_os': self._infer_os_from_server(server_header)
                    }
        
        except Exception as e:
            print(f"[ERROR] Firmware analysis failed: {e}")
        
        return firmware_info
    
    def _infer_os_from_server(self, server_string: str) -> str:
        """Infer operating system from server string"""
        server_lower = server_string.lower()
        
        if 'ubuntu' in server_lower:
            return 'Ubuntu Linux'
        elif 'centos' in server_lower:
            return 'CentOS Linux'
        elif 'red hat' in server_lower or 'rhel' in server_lower:
            return 'Red Hat Enterprise Linux'
        elif 'debian' in server_lower:
            return 'Debian Linux'
        elif 'windows' in server_lower or 'win32' in server_lower:
            return 'Microsoft Windows'
        elif 'unix' in server_lower:
            return 'Unix-like'
        else:
            return 'Unknown'
    
    def gather_client_configurations(self, target: str) -> Dict:
        """T1592.004: Gather Victim Host Information: Client Configurations"""
        self.log_mitre_technique('T1592.004')
        
        print(f"[+] Analyzing client configurations for {target}")
        client_configs = {
            'cookie_settings': [],
            'javascript_requirements': [],
            'browser_compatibility': [],
            'accessibility_features': [],
            'mobile_optimization': []
        }
        
        try:
            response = self.safe_request(f"http://{target}")
            if not response:
                return client_configs
            
            content = response.text.lower()
            headers = response.headers
            
            # Cookie analysis
            set_cookie = headers.get('Set-Cookie', '')
            if set_cookie:
                if 'secure' in set_cookie.lower():
                    client_configs['cookie_settings'].append('Secure cookies enabled')
                if 'httponly' in set_cookie.lower():
                    client_configs['cookie_settings'].append('HttpOnly cookies enabled')
                if 'samesite' in set_cookie.lower():
                    client_configs['cookie_settings'].append('SameSite cookie protection')
            
            # JavaScript requirements
            if '<script' in content:
                client_configs['javascript_requirements'].append('JavaScript required')
                if 'noscript' in content:
                    client_configs['javascript_requirements'].append('Graceful degradation for no-JS')
            
            # Mobile optimization detection
            mobile_indicators = [
                'viewport', 'mobile-optimized', 'responsive',
                '@media', 'mobile-friendly'
            ]
            
            for indicator in mobile_indicators:
                if indicator in content:
                    client_configs['mobile_optimization'].append(f'Mobile indicator: {indicator}')
            
            # Accessibility features
            accessibility_indicators = [
                'aria-', 'role=', 'alt=', 'tabindex',
                'skip to content', 'screen reader'
            ]
            
            for indicator in accessibility_indicators:
                if indicator in content:
                    client_configs['accessibility_features'].append(f'Accessibility: {indicator}')
        
        except Exception as e:
            print(f"[ERROR] Client configuration analysis failed: {e}")
        
        return client_configs
    
    def advanced_vulnerability_scan(self, domain: str) -> List[str]:
        """Advanced vulnerability scanning with additional checks"""
        print(f"[+] Advanced vulnerability scanning for {domain}")
        vulnerabilities = []
        
        try:
            # Check HTTPS variants
            for protocol in ['https', 'http']:
                url = f"{protocol}://{domain}"
                response = self.safe_request(url)
                
                if response:
                    # Check for insecure redirects
                    if protocol == 'http' and response.url.startswith('https://'):
                        vulnerabilities.append("HTTP to HTTPS redirect present (good)")
                    elif protocol == 'http' and not response.url.startswith('https://'):
                        vulnerabilities.append("No HTTPS redirect - insecure")
                    
                    # Check for common admin panels
                    admin_paths = ['/admin', '/administrator', '/wp-admin', '/login', '/dashboard']
                    for path in admin_paths:
                        admin_url = f"{url}{path}"
                        admin_response = self.safe_request(admin_url)
                        if admin_response and admin_response.status_code == 200:
                            vulnerabilities.append(f"Admin panel found: {path}")
                    
                    # Check for common sensitive files
                    sensitive_files = ['/robots.txt', '/.env', '/config.php', '/wp-config.php', 
                                     '/.git/config', '/backup.sql', '/phpinfo.php']
                    for file_path in sensitive_files:
                        file_url = f"{url}{file_path}"
                        file_response = self.safe_request(file_url)
                        if file_response and file_response.status_code == 200:
                            vulnerabilities.append(f"Sensitive file exposed: {file_path}")
                    
                    # Check for server information disclosure
                    server_header = response.headers.get('Server', '')
                    if server_header and any(version in server_header for version in 
                                           ['Apache/2.2', 'Apache/2.0', 'nginx/1.0', 'IIS/6.0']):
                        vulnerabilities.append(f"Potentially outdated server: {server_header}")
                    
                    # Check for clickjacking protection
                    if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
                        vulnerabilities.append("No clickjacking protection (missing X-Frame-Options and CSP)")
                    
                    # Check for HSTS
                    if protocol == 'https' and 'Strict-Transport-Security' not in response.headers:
                        vulnerabilities.append("HSTS not implemented")
                    
                    break  # Only check one protocol that works
        
        except Exception as e:
            print(f"[ERROR] Advanced vulnerability scan failed for {domain}: {e}")
        
        return vulnerabilities
    
    def ssl_certificate_analysis(self, domain: str) -> Dict:
        """Analyze SSL certificate"""
        print(f"[+] SSL certificate analysis for {domain}")
        cert_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
        except Exception as e:
            print(f"[ERROR] SSL analysis failed for {domain}: {e}")
            
        return cert_info
    
    def social_media_osint(self) -> List[Dict]:
        """T1593.001: Search Open Websites/Domains: Social Media"""
        self.log_mitre_technique('T1593.001')
        
        print("[+] Social media OSINT")
        social_accounts = []
        
        # Common social media platforms
        platforms = {
            'linkedin': f"site:linkedin.com {self.target_domain}",
            'twitter': f"site:twitter.com {self.target_domain}",
            'facebook': f"site:facebook.com {self.target_domain}",
            'youtube': f"site:youtube.com {self.target_domain}",
            'github': f"site:github.com {self.target_domain}"
        }
        
        # This would require actual API implementation
        print("[INFO] Social media OSINT placeholder - implement with APIs")
        
        return social_accounts
    
    def email_harvesting(self) -> List[str]:
        """T1589.002: Gather Victim Identity Information: Email Addresses"""
        self.log_mitre_technique('T1589.002')
        
        print("[+] Email harvesting")
        emails = []
        
        # Search for emails in web pages
        try:
            response = self.safe_request(f"http://{self.target_domain}")
            if response:
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, response.text)
                emails.extend(found_emails)
        
        except Exception as e:
            print(f"[ERROR] Email harvesting failed: {e}")
        
        return emails
    
    def port_scan(self, target: str, ports: List[int] = None) -> Dict:
        """T1595.001: Active Scanning: Scanning IP Blocks"""
        self.log_mitre_technique('T1595.001')
        
        if ports is None:
            # Extended port list for government systems
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 8888, 9090
            ]
        
        print(f"[+] Port scanning {target}")
        open_ports = {}
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    # Banner grabbing for additional info
                    banner = self._grab_banner(target, port)
                    sock.close()
                    return port, service, banner
                
                sock.close()
            except:
                pass
            return None
        
        max_workers = self.config.getint('scanning', 'max_threads', fallback=20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(scan_port, ports)
            
        for result in results:
            if result:
                port, service, banner = result
                open_ports[port] = {
                    'service': service,
                    'banner': banner[:200] if banner else ''  # Truncate banner
                }
                print(f"[OPEN] {target}:{port} ({service})")
                if banner:
                    print(f"[BANNER] {target}:{port} - {banner[:100]}...")
        
        return open_ports
    
    def _grab_banner(self, host: str, port: int) -> str:
        """Grab service banner for additional reconnaissance"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except:
            return ''
    
    def wordlist_scanning(self, url: str) -> List[str]:
        """T1595.003: Active Scanning: Wordlist Scanning"""
        self.log_mitre_technique('T1595.003')
        
        print(f"[+] Wordlist scanning {url}")
        discovered_paths = []
        
        # Government-specific wordlist
        gov_wordlist = [
            'admin', 'administrator', 'login', 'portal', 'dashboard', 'console',
            'api', 'docs', 'documentation', 'help', 'support', 'contact',
            'about', 'services', 'departments', 'agencies', 'offices',
            'public', 'citizen', 'residents', 'business', 'employees',
            'forms', 'applications', 'permits', 'licenses', 'taxes',
            'budget', 'finance', 'procurement', 'contracts', 'bids',
            'meetings', 'agenda', 'minutes', 'calendar', 'events',
            'news', 'press', 'media', 'publications', 'reports',
            'data', 'datasets', 'statistics', 'gis', 'maps',
            'elections', 'voting', 'candidates', 'ballot',
            'emergency', 'alerts', 'notifications', 'safety',
            'privacy', 'accessibility', 'sitemap', 'search',
            'archive', 'history', 'legacy', 'old', 'backup',
            'test', 'dev', 'staging', 'beta', 'demo'
        ]
        
        def check_path(path):
            try:
                full_url = f"{url.rstrip('/')}/{path}"
                response = self.safe_request(full_url)
                
                if response and response.status_code == 200:
                    return {
                        'path': path,
                        'url': full_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('Content-Type', '')
                    }
            except:
                pass
            return None
        
        max_workers = self.config.getint('scanning', 'max_threads', fallback=10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(check_path, gov_wordlist)
        
        for result in results:
            if result:
                discovered_paths.append(result)
                print(f"[FOUND] {result['url']} ({result['status_code']})")
        
        return discovered_paths
    
    def whois_lookup(self, domain: str) -> Dict:
        """T1590.001: Gather Victim Network Information: Domain Properties"""
        self.log_mitre_technique('T1590.001')
        
        print(f"[+] WHOIS lookup for {domain}")
        whois_info = {}
        
        # Try multiple WHOIS approaches
        try:
            # First try python-whois library
            w = whois.whois(domain)
            
            # Handle different data types returned by whois
            whois_info = {
                'domain_name': self._safe_whois_field(w.domain_name),
                'registrar': self._safe_whois_field(w.registrar),
                'creation_date': self._safe_whois_date(w.creation_date),
                'expiration_date': self._safe_whois_date(w.expiration_date),
                'updated_date': self._safe_whois_date(getattr(w, 'updated_date', None)),
                'name_servers': self._safe_whois_field(w.name_servers),
                'status': self._safe_whois_field(w.status),
                'emails': self._safe_whois_field(w.emails),
                'org': self._safe_whois_field(w.org),
                'registrant_name': self._safe_whois_field(getattr(w, 'name', None)),
                'registrant_country': self._safe_whois_field(getattr(w, 'country', None)),
                'dnssec': self._safe_whois_field(getattr(w, 'dnssec', None))
            }
            
        except Exception as e:
            self.logger.warning(f"Python-whois failed for {domain}: {e}")
            
            # Fallback to system whois command
            try:
                result = subprocess.run(['whois', domain], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=30)
                if result.returncode == 0:
                    whois_info = self._parse_whois_text(result.stdout)
                else:
                    self.logger.error(f"System whois failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                self.logger.error(f"WHOIS lookup timed out for {domain}")
            except FileNotFoundError:
                self.logger.error("System whois command not found")
            except Exception as e:
                self.logger.error(f"System whois failed: {e}")
        
        return whois_info
    
    def _safe_whois_field(self, field):
        """Safely convert whois field to string or list"""
        if field is None:
            return None
        elif isinstance(field, list):
            return [str(item) for item in field if item is not None]
        else:
            return str(field)
    
    def _safe_whois_date(self, date_field):
        """Safely convert whois date field"""
        if date_field is None:
            return None
        elif isinstance(date_field, list):
            return [str(date) for date in date_field if date is not None]
        else:
            return str(date_field)
    
    def _parse_whois_text(self, whois_text: str) -> Dict:
        """Parse raw whois text output"""
        whois_info = {}
        lines = whois_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                
                if value:
                    whois_info[key] = value
        
        return whois_info
    
    def load_config(self, config_file: str = None) -> configparser.ConfigParser:
        """Load configuration from file or create default config"""
        config = configparser.ConfigParser()
        
        # Default configuration
        config['timing'] = {
            'min_delay': '1.0',
            'max_delay': '3.0',
            'timeout': '10',
            'ssl_timeout': '10'
        }
        
        config['scanning'] = {
            'max_threads': '20',
            'max_domains': '50',
            'verify_ssl': 'false',
            'follow_redirects': 'true',
            'use_browser': 'false',
            'browser_type': 'chromium',
            'headless': 'true',
            'screenshot': 'false'
        }
        
        config['proxy'] = {
            'enabled': 'false',
            'http_proxy': '',
            'https_proxy': '',
            'socks_proxy': '',
            'tor_enabled': 'false'
        }
        
        config['api_keys'] = {
            'shodan': '',
            'virustotal': '',
            'censys': ''
        }
        
        config['output'] = {
            'formats': 'json,csv',
            'include_raw_data': 'false',
            'verbose_logging': 'false'
        }
        
        # Load from file if provided
        if config_file and os.path.exists(config_file):
            try:
                config.read(config_file)
                self.logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load config file {config_file}: {e}")
        
        return config
    
    def setup_proxy(self):
        """Setup proxy configuration"""
        if self.config.getboolean('proxy', 'enabled', fallback=False):
            proxies = {}
            
            http_proxy = self.config.get('proxy', 'http_proxy', fallback='')
            https_proxy = self.config.get('proxy', 'https_proxy', fallback='')
            socks_proxy = self.config.get('proxy', 'socks_proxy', fallback='')
            
            if http_proxy:
                proxies['http'] = http_proxy
            if https_proxy:
                proxies['https'] = https_proxy
            if socks_proxy:
                proxies['http'] = socks_proxy
                proxies['https'] = socks_proxy
            
            if proxies:
                self.session.proxies.update(proxies)
                self.logger.info(f"Proxy configured: {proxies}")
            
            # Tor configuration
            if self.config.getboolean('proxy', 'tor_enabled', fallback=False):
                tor_proxies = {
                    'http': 'socks5://127.0.0.1:9050',
                    'https': 'socks5://127.0.0.1:9050'
                }
                self.session.proxies.update(tor_proxies)
                self.logger.info("Tor proxy enabled")
    
    def shodan_integration(self, ip: str) -> Dict:
        """Integrate with Shodan API for additional intelligence"""
        shodan_data = {}
        shodan_api_key = self.config.get('api_keys', 'shodan', fallback='')
        
        if not shodan_api_key:
            self.logger.info("Shodan API key not configured")
            return shodan_data
        
        try:
            import shodan
            api = shodan.Shodan(shodan_api_key)
            
            # Get host information
            host_info = api.host(ip)
            
            shodan_data = {
                'ip': host_info.get('ip_str'),
                'organization': host_info.get('org'),
                'country': host_info.get('country_name'),
                'city': host_info.get('city'),
                'isp': host_info.get('isp'),
                'asn': host_info.get('asn'),
                'ports': host_info.get('ports', []),
                'vulns': list(host_info.get('vulns', [])),
                'last_update': host_info.get('last_update'),
                'services': []
            }
            
            # Extract service information
            for service in host_info.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'protocol': service.get('transport'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'banner': service.get('data', '')[:200],  # Truncate banner
                    'timestamp': service.get('timestamp')
                }
                shodan_data['services'].append(service_info)
            
        except ImportError:
            self.logger.warning("Shodan library not installed. Install with: pip install shodan")
        except Exception as e:
            self.logger.error(f"Shodan API error for {ip}: {e}")
        
        return shodan_data
    
    def search_open_technical_databases(self) -> Dict:
        """T1596: Search Open Technical Databases"""
        print("[+] Searching open technical databases")
        database_results = {
            'dns_passive': self.search_passive_dns(),
            'whois_extended': self.extended_whois_search(),
            'certificate_databases': self.search_certificate_databases(),
            'cdn_databases': self.search_cdn_databases(),
            'scan_databases': self.search_scan_databases()
        }
        return database_results
    
    def search_passive_dns(self) -> Dict:
        """T1596.001: Search Open Technical Databases: DNS/Passive DNS"""
        self.log_mitre_technique('T1596.001')
        
        print("[+] Searching passive DNS databases")
        passive_dns_results = {
            'historical_ips': [],
            'subdomains_found': [],
            'dns_changes': []
        }
        
        try:
            # Check multiple passive DNS sources
            passive_dns_sources = [
                f"https://api.hackertarget.com/hostsearch/?q={self.target_domain}",
                f"https://api.threatminer.org/v2/domain.php?q={self.target_domain}&rt=5"
            ]
            
            for source_url in passive_dns_sources:
                try:
                    response = self.safe_request(source_url)
                    if response and response.status_code == 200:
                        # Parse response based on source
                        if 'hackertarget' in source_url:
                            lines = response.text.split('\\n')
                            for line in lines:
                                if line.strip() and ',' in line:
                                    parts = line.split(',')
                                    if len(parts) >= 2:
                                        subdomain = parts[0].strip()
                                        ip = parts[1].strip()
                                        if subdomain.endswith(self.target_domain):
                                            passive_dns_results['subdomains_found'].append(subdomain)
                                            passive_dns_results['historical_ips'].append(ip)
                        
                        elif 'threatminer' in source_url:
                            try:
                                data = response.json()
                                if data.get('status_code') == '200' and 'results' in data:
                                    for result in data['results']:
                                        if isinstance(result, dict):
                                            ip = result.get('ip', '')
                                            if ip:
                                                passive_dns_results['historical_ips'].append(ip)
                            except json.JSONDecodeError:
                                pass
                
                except Exception as e:
                    print(f"[WARNING] Passive DNS source failed: {e}")
                    continue
        
        except Exception as e:
            print(f"[ERROR] Passive DNS search failed: {e}")
        
        # Remove duplicates
        passive_dns_results['historical_ips'] = list(set(passive_dns_results['historical_ips']))
        passive_dns_results['subdomains_found'] = list(set(passive_dns_results['subdomains_found']))
        
        return passive_dns_results
    
    def extended_whois_search(self) -> Dict:
        """T1596.002: Search Open Technical Databases: WHOIS"""
        self.log_mitre_technique('T1596.002')
        
        print("[+] Extended WHOIS database search")
        extended_whois = {
            'registrar_info': {},
            'historical_records': [],
            'related_domains': []
        }
        
        try:
            # Get basic WHOIS info
            basic_whois = self.whois_lookup(self.target_domain)
            extended_whois['registrar_info'] = basic_whois
            
            # Search for related domains by registrant
            if basic_whois.get('registrant_name'):
                registrant = basic_whois['registrant_name']
                print(f"[+] Searching for domains registered to: {registrant}")
                # This would require a reverse WHOIS service in production
                extended_whois['related_domains'].append(f"Search for: {registrant}")
            
            # Search for domains with similar WHOIS data
            if basic_whois.get('org'):
                org = basic_whois['org']
                print(f"[+] Searching for domains registered to org: {org}")
                extended_whois['related_domains'].append(f"Search for org: {org}")
        
        except Exception as e:
            print(f"[ERROR] Extended WHOIS search failed: {e}")
        
        return extended_whois
    
    def search_certificate_databases(self) -> Dict:
        """T1596.003: Search Open Technical Databases: Digital Certificates"""
        self.log_mitre_technique('T1596.003')
        
        print("[+] Searching certificate databases")
        cert_results = {
            'certificate_transparency': [],
            'ssl_certificate_info': {},
            'certificate_authorities': []
        }
        
        try:
            # Enhanced certificate transparency search
            ct_sources = [
                f"https://crt.sh/?q=%.{self.target_domain}&output=json",
                f"https://crt.sh/?q={self.target_domain}&output=json"
            ]
            
            for ct_url in ct_sources:
                try:
                    response = self.safe_request(ct_url)
                    if response and response.status_code == 200:
                        certificates = response.json()
                        for cert in certificates[:50]:  # Limit to first 50
                            cert_info = {
                                'common_name': cert.get('common_name', ''),
                                'name_value': cert.get('name_value', ''),
                                'issuer_name': cert.get('issuer_name', ''),
                                'not_before': cert.get('not_before', ''),
                                'not_after': cert.get('not_after', '')
                            }
                            cert_results['certificate_transparency'].append(cert_info)
                            
                            # Extract Certificate Authority info
                            issuer = cert.get('issuer_name', '')
                            if issuer and issuer not in cert_results['certificate_authorities']:
                                cert_results['certificate_authorities'].append(issuer)
                    
                    break  # Success, no need to try other sources
                
                except Exception as e:
                    print(f"[WARNING] Certificate transparency source failed: {e}")
                    continue
        
        except Exception as e:
            print(f"[ERROR] Certificate database search failed: {e}")
        
        return cert_results
    
    def search_cdn_databases(self) -> Dict:
        """T1596.004: Search Open Technical Databases: CDNs"""
        self.log_mitre_technique('T1596.004')
        
        print("[+] Searching CDN databases")
        cdn_results = {
            'cdn_providers': [],
            'edge_locations': [],
            'cdn_configurations': []
        }
        
        try:
            # Check for CDN usage
            response = self.safe_request(f"http://{self.target_domain}")
            if response:
                # Analyze headers for CDN indicators
                cdn_headers = {
                    'CF-RAY': 'Cloudflare',
                    'X-Akamai-Transformed': 'Akamai',
                    'X-Cache': 'Generic CDN',
                    'X-CDN': 'CDN Provider',
                    'X-Served-By': 'Fastly/Varnish',
                    'X-Varnish': 'Varnish Cache'
                }
                
                for header, provider in cdn_headers.items():
                    value = response.headers.get(header, '')
                    if value:
                        cdn_results['cdn_providers'].append({
                            'provider': provider,
                            'header': header,
                            'value': value
                        })
                
                # DNS-based CDN detection
                try:
                    cname_records = dns.resolver.resolve(self.target_domain, 'CNAME')
                    for cname in cname_records:
                        cname_str = str(cname).lower()
                        if any(cdn in cname_str for cdn in ['cloudflare', 'akamai', 'fastly', 'cloudfront']):
                            cdn_results['cdn_configurations'].append(f"CNAME: {cname_str}")
                except:
                    pass
        
        except Exception as e:
            print(f"[ERROR] CDN database search failed: {e}")
        
        return cdn_results
    
    def search_scan_databases(self) -> Dict:
        """T1596.005: Search Open Technical Databases: Scan Databases"""
        self.log_mitre_technique('T1596.005')
        
        print("[+] Searching scan databases")
        scan_results = {
            'shodan_summary': {},
            'censys_summary': {},
            'vulnerability_databases': []
        }
        
        try:
            # Shodan integration (if API key available)
            shodan_api_key = self.config.get('api_keys', 'shodan', fallback='')
            if shodan_api_key:
                try:
                    import shodan
                    api = shodan.Shodan(shodan_api_key)
                    
                    # Search for the domain
                    results = api.search(f'hostname:{self.target_domain}')
                    scan_results['shodan_summary'] = {
                        'total_results': results['total'],
                        'services_found': len(results.get('matches', [])),
                        'countries': list(set(match.get('location', {}).get('country_name', '') 
                                           for match in results.get('matches', []) if match.get('location')))
                    }
                
                except ImportError:
                    print("[INFO] Shodan library not available")
                except Exception as e:
                    print(f"[WARNING] Shodan search failed: {e}")
            
            # Note: In production, you would integrate with other scan databases
            # like Censys, BinaryEdge, etc. with proper API keys
            
        except Exception as e:
            print(f"[ERROR] Scan database search failed: {e}")
        
        return scan_results
    
    def gather_organization_info(self) -> Dict:
        """T1591: Gather Victim Org Information"""
        print("[+] Gathering organization information")
        org_info = {
            'physical_locations': self.determine_physical_locations(),
            'business_relationships': self.identify_business_relationships(),
            'business_tempo': self.identify_business_tempo(),
            'organizational_roles': self.identify_roles()
        }
        return org_info
    
    def determine_physical_locations(self) -> Dict:
        """T1591.001: Gather Victim Org Information: Determine Physical Locations"""
        self.log_mitre_technique('T1591.001')
        
        print("[+] Determining physical locations")
        locations = {
            'whois_locations': [],
            'ip_geolocation': [],
            'website_content_locations': []
        }
        
        try:
            # Extract location from WHOIS data
            whois_data = self.whois_lookup(self.target_domain)
            if whois_data.get('registrant_country'):
                locations['whois_locations'].append(whois_data['registrant_country'])
            
            # IP geolocation for discovered IPs
            for domain_info in self.results.get('domains', []):
                ip = domain_info.get('ip')
                if ip:
                    try:
                        # Simple geolocation (in production, use a proper geolocation service)
                        geo_info = f"IP {ip} geolocation lookup needed"
                        locations['ip_geolocation'].append(geo_info)
                    except Exception:
                        pass
            
            # Scan website content for location indicators
            response = self.safe_request(f"http://{self.target_domain}")
            if response:
                content = response.text.lower()
                location_keywords = [
                    'washington', 'dc', 'virginia', 'maryland', 'california',
                    'new york', 'texas', 'florida', 'illinois', 'headquarters',
                    'office', 'building', 'address', 'location'
                ]
                
                for keyword in location_keywords:
                    if keyword in content:
                        locations['website_content_locations'].append(f"Keyword found: {keyword}")
        
        except Exception as e:
            print(f"[ERROR] Physical location determination failed: {e}")
        
        return locations
    
    def identify_business_relationships(self) -> Dict:
        """T1591.002: Gather Victim Org Information: Business Relationships"""
        self.log_mitre_technique('T1591.002')
        
        print("[+] Identifying business relationships")
        relationships = {
            'technology_partners': [],
            'service_providers': [],
            'linked_organizations': []
        }
        
        try:
            # Analyze website for business relationships
            response = self.safe_request(f"http://{self.target_domain}")
            if response:
                content = response.text.lower()
                
                # Look for technology partner indicators
                tech_partners = [
                    'microsoft', 'google', 'amazon', 'oracle', 'ibm',
                    'salesforce', 'adobe', 'cisco', 'vmware'
                ]
                
                for partner in tech_partners:
                    if partner in content:
                        relationships['technology_partners'].append(partner)
                
                # Look for service provider indicators
                service_indicators = [
                    'powered by', 'hosted by', 'provided by', 'partnership',
                    'collaboration', 'contractor', 'vendor'
                ]
                
                for indicator in service_indicators:
                    if indicator in content:
                        relationships['service_providers'].append(f"Indicator: {indicator}")
        
        except Exception as e:
            print(f"[ERROR] Business relationship identification failed: {e}")
        
        return relationships
    
    def identify_business_tempo(self) -> Dict:
        """T1591.003: Gather Victim Org Information: Identify Business Tempo"""
        self.log_mitre_technique('T1591.003')
        
        print("[+] Identifying business tempo")
        tempo = {
            'operating_hours': [],
            'seasonal_patterns': [],
            'maintenance_windows': []
        }
        
        try:
            # Analyze website for tempo indicators
            response = self.safe_request(f"http://{self.target_domain}")
            if response:
                content = response.text.lower()
                
                # Look for operating hours
                time_patterns = [
                    'hours:', 'open', 'closed', 'monday', 'tuesday', 'wednesday',
                    'thursday', 'friday', 'saturday', 'sunday', '24/7', '24 hours'
                ]
                
                for pattern in time_patterns:
                    if pattern in content:
                        tempo['operating_hours'].append(f"Time indicator: {pattern}")
                
                # Look for maintenance windows
                maintenance_indicators = [
                    'maintenance', 'downtime', 'scheduled', 'outage',
                    'system update', 'unavailable'
                ]
                
                for indicator in maintenance_indicators:
                    if indicator in content:
                        tempo['maintenance_windows'].append(f"Maintenance indicator: {indicator}")
        
        except Exception as e:
            print(f"[ERROR] Business tempo identification failed: {e}")
        
        return tempo
    
    def identify_roles(self) -> Dict:
        """T1591.004: Gather Victim Org Information: Identify Roles"""
        self.log_mitre_technique('T1591.004')
        
        print("[+] Identifying organizational roles")
        roles = {
            'leadership_roles': [],
            'technical_roles': [],
            'contact_roles': []
        }
        
        try:
            # Analyze website for role information
            response = self.safe_request(f"http://{self.target_domain}")
            if response:
                content = response.text.lower()
                
                # Leadership roles
                leadership_titles = [
                    'director', 'chief', 'administrator', 'commissioner',
                    'secretary', 'manager', 'supervisor', 'head'
                ]
                
                for title in leadership_titles:
                    if title in content:
                        roles['leadership_roles'].append(f"Title found: {title}")
                
                # Technical roles
                technical_titles = [
                    'it', 'information technology', 'system administrator',
                    'network', 'security', 'database', 'developer'
                ]
                
                for title in technical_titles:
                    if title in content:
                        roles['technical_roles'].append(f"Technical role: {title}")
                
                # Contact roles
                contact_indicators = [
                    'contact', 'support', 'help desk', 'customer service',
                    'public information', 'media', 'press'
                ]
                
                for indicator in contact_indicators:
                    if indicator in content:
                        roles['contact_roles'].append(f"Contact role: {indicator}")
        
        except Exception as e:
            print(f"[ERROR] Role identification failed: {e}")
        
        return roles
    
    def search_code_repositories(self) -> Dict:
        """T1593.003: Search Open Websites/Domains: Code Repositories"""
        self.log_mitre_technique('T1593.003')
        
        print("[+] Searching code repositories")
        repo_results = {
            'github_repositories': [],
            'potential_leaks': [],
            'technology_insights': []
        }
        
        try:
            # GitHub search patterns (Note: Requires API in production)
            github_search_terms = [
                self.target_domain,
                self.target_domain.replace('.gov', ''),
                f'"{self.target_domain}"'
            ]
            
            # This is a placeholder - in production, use GitHub API
            print(f"[INFO] GitHub search terms generated: {github_search_terms}")
            repo_results['github_repositories'].append("GitHub API integration needed for full functionality")
            
            # Look for common government code indicators
            gov_tech_indicators = [
                'drupal', 'wordpress', 'jekyll', 'hugo', 'django',
                'rails', 'spring', 'angular', 'react', 'vue'
            ]
            
            for tech in gov_tech_indicators:
                repo_results['technology_insights'].append(f"Potential technology: {tech}")
        
        except Exception as e:
            print(f"[ERROR] Code repository search failed: {e}")
        
        return repo_results
    
    def search_victim_owned_websites(self) -> Dict:
        """T1594: Search Victim-Owned Websites"""
        self.log_mitre_technique('T1594')
        
        print("[+] Searching victim-owned websites")
        website_results = {
            'discovered_content': [],
            'sensitive_information': [],
            'administrative_interfaces': []
        }
        
        try:
            # Comprehensive website crawling
            paths_to_check = [
                '', '/sitemap.xml', '/robots.txt', '/admin', '/login',
                '/portal', '/dashboard', '/api', '/docs', '/help',
                '/contact', '/about', '/services', '/departments'
            ]
            
            for path in paths_to_check:
                url = f"http://{self.target_domain}{path}"
                response = self.safe_request(url)
                
                if response and response.status_code == 200:
                    content_info = {
                        'path': path,
                        'title': self._extract_title(response.text),
                        'content_length': len(response.content),
                        'content_type': response.headers.get('Content-Type', '')
                    }
                    website_results['discovered_content'].append(content_info)
                    
                    # Check for sensitive information
                    if self._contains_sensitive_info(response.text):
                        website_results['sensitive_information'].append(path)
                    
                    # Check for administrative interfaces
                    if any(keyword in response.text.lower() for keyword in 
                           ['admin', 'login', 'dashboard', 'console', 'management']):
                        website_results['administrative_interfaces'].append(path)
        
        except Exception as e:
            print(f"[ERROR] Victim-owned website search failed: {e}")
        
        return website_results
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else 'No title'
        except:
            return 'Parse error'
    
    def _contains_sensitive_info(self, content: str) -> bool:
        """Check if content contains potentially sensitive information"""
        sensitive_indicators = [
            'social security', 'ssn', 'taxpayer', 'employee id',
            'internal', 'confidential', 'restricted', 'classified',
            'password', 'username', 'api key', 'token'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in sensitive_indicators)
    
    def wayback_machine_analysis(self) -> Dict:
        """Analyze Wayback Machine for historical data with enhanced error handling"""
        wayback_data = {}
        print("[+] Analyzing Wayback Machine historical data")
        
        # Multiple Wayback Machine endpoints to try
        wayback_endpoints = [
            f"http://web.archive.org/cdx/search/cdx?url={self.target_domain}/*&output=json&limit=100",
            f"https://web.archive.org/cdx/search/cdx?url={self.target_domain}/*&output=json&limit=100",
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}/*&output=json&limit=50"
        ]
        
        for attempt, wayback_url in enumerate(wayback_endpoints, 1):
            try:
                print(f"[+] Trying Wayback endpoint {attempt}/{len(wayback_endpoints)}")
                
                # Use enhanced timeout and retry logic specifically for Wayback Machine
                response = self.safe_request(wayback_url, timeout=30, retries=2)
                
                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        
                        if len(data) > 1:  # First row is headers
                            wayback_data = {
                                'total_snapshots': len(data) - 1,
                                'first_snapshot': data[1][1] if len(data) > 1 else None,
                                'last_snapshot': data[-1][1] if len(data) > 1 else None,
                                'unique_urls': len(set(row[2] for row in data[1:] if len(row) > 2)),
                                'status_codes': list(set(row[4] for row in data[1:] if len(row) > 4)),
                                'endpoint_used': wayback_url
                            }
                            
                            # Extract interesting URLs
                            interesting_urls = []
                            sensitive_keywords = [
                                'admin', 'login', 'config', 'backup', '.env', '.git',
                                'dashboard', 'panel', 'private', 'secret', 'key',
                                'password', 'credential', 'token', 'api'
                            ]
                            
                            for row in data[1:21]:  # Limit to first 20 for analysis
                                if len(row) > 2:
                                    url = row[2]
                                    if any(keyword in url.lower() for keyword in sensitive_keywords):
                                        interesting_urls.append({
                                            'url': url,
                                            'timestamp': row[1] if len(row) > 1 else 'unknown',
                                            'status': row[4] if len(row) > 4 else 'unknown',
                                            'mimetype': row[3] if len(row) > 3 else 'unknown'
                                        })
                            
                            wayback_data['interesting_urls'] = interesting_urls
                            
                            # Calculate time span
                            if wayback_data['first_snapshot'] and wayback_data['last_snapshot']:
                                try:
                                    first_year = wayback_data['first_snapshot'][:4]
                                    last_year = wayback_data['last_snapshot'][:4]
                                    wayback_data['years_tracked'] = int(last_year) - int(first_year) + 1
                                except (ValueError, TypeError):
                                    wayback_data['years_tracked'] = 'unknown'
                            
                            print(f"[+] Wayback Machine: Found {wayback_data['total_snapshots']} snapshots")
                            break  # Success, no need to try other endpoints
                        
                        else:
                            print(f"[+] No historical data found in Wayback Machine")
                            wayback_data = {'total_snapshots': 0, 'message': 'No data found'}
                            break
                    
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Failed to parse Wayback JSON response: {e}")
                        continue  # Try next endpoint
                
                elif response:
                    self.logger.warning(f"Wayback Machine returned status {response.status_code}")
                    continue  # Try next endpoint
                else:
                    self.logger.warning(f"No response from Wayback endpoint {attempt}")
                    continue  # Try next endpoint
            
            except requests.exceptions.Timeout:
                self.logger.warning(f"Wayback Machine request timed out (endpoint {attempt})")
                continue  # Try next endpoint
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Connection error to Wayback Machine (endpoint {attempt}): {e}")
                continue  # Try next endpoint
            except Exception as e:
                self.logger.warning(f"Wayback Machine analysis failed (endpoint {attempt}): {e}")
                continue  # Try next endpoint
        
        # If all endpoints failed, set error information
        if not wayback_data:
            wayback_data = {
                'error': 'All Wayback Machine endpoints failed',
                'total_snapshots': 0,
                'endpoints_tried': len(wayback_endpoints)
            }
            self.logger.error("All Wayback Machine endpoints failed")
        
        return wayback_data
    
    async def browser_reconnaissance(self, url: str) -> Dict:
        """Advanced reconnaissance using headless browser"""
        if not PLAYWRIGHT_AVAILABLE:
            self.logger.warning("Playwright not available. Install with: pip install playwright")
            return {}
        
        browser_data = {
            'url': url,
            'method': 'playwright',
            'technologies': [],
            'forms': [],
            'links': [],
            'javascript_files': [],
            'cookies': [],
            'local_storage': {},
            'session_storage': {},
            'console_errors': [],
            'network_requests': [],
            'screenshots': []
        }
        
        try:
            async with async_playwright() as p:
                # Launch browser
                browser_type = self.config.get('scanning', 'browser_type', fallback='chromium')
                headless = self.config.getboolean('scanning', 'headless', fallback=True)
                
                if browser_type == 'firefox':
                    browser = await p.firefox.launch(headless=headless)
                elif browser_type == 'webkit':
                    browser = await p.webkit.launch(headless=headless)
                else:
                    browser = await p.chromium.launch(headless=headless)
                
                # Configure context with proxy if enabled
                context_options = {
                    'ignore_https_errors': True,
                    'user_agent': random.choice(self.user_agents)
                }
                
                if self.config.getboolean('proxy', 'enabled', fallback=False):
                    proxy_url = self.config.get('proxy', 'http_proxy', fallback='')
                    if proxy_url:
                        context_options['proxy'] = {'server': proxy_url}
                
                context = await browser.new_context(**context_options)
                page = await context.new_page()
                
                # Monitor network requests
                network_requests = []
                async def handle_request(request):
                    network_requests.append({
                        'url': request.url,
                        'method': request.method,
                        'headers': dict(request.headers),
                        'timestamp': datetime.datetime.now().isoformat()
                    })
                
                page.on('request', handle_request)
                
                # Monitor console messages
                console_messages = []
                async def handle_console(msg):
                    if msg.type in ['error', 'warning']:
                        console_messages.append({
                            'type': msg.type,
                            'text': msg.text,
                            'timestamp': datetime.datetime.now().isoformat()
                        })
                
                page.on('console', handle_console)
                
                # Navigate to page
                response = await page.goto(url, wait_until='networkidle', timeout=30000)
                
                if response:
                    browser_data['status_code'] = response.status
                    browser_data['headers'] = dict(response.headers)
                
                # Wait for page to load
                await page.wait_for_load_state('networkidle')
                
                # Extract page information
                browser_data['title'] = await page.title()
                browser_data['url_final'] = page.url
                
                # Extract forms
                forms = await page.query_selector_all('form')
                for form in forms:
                    form_data = {
                        'action': await form.get_attribute('action') or '',
                        'method': await form.get_attribute('method') or 'get',
                        'inputs': []
                    }
                    
                    inputs = await form.query_selector_all('input, textarea, select')
                    for input_elem in inputs:
                        input_data = {
                            'type': await input_elem.get_attribute('type') or 'text',
                            'name': await input_elem.get_attribute('name') or '',
                            'id': await input_elem.get_attribute('id') or '',
                            'placeholder': await input_elem.get_attribute('placeholder') or ''
                        }
                        form_data['inputs'].append(input_data)
                    
                    browser_data['forms'].append(form_data)
                
                # Extract links
                links = await page.query_selector_all('a[href]')
                for link in links[:50]:  # Limit to first 50 links
                    href = await link.get_attribute('href')
                    text = await link.inner_text()
                    if href:
                        browser_data['links'].append({
                            'href': href,
                            'text': text.strip()[:100] if text else ''
                        })
                
                # Extract JavaScript files
                scripts = await page.query_selector_all('script[src]')
                for script in scripts:
                    src = await script.get_attribute('src')
                    if src:
                        browser_data['javascript_files'].append(src)
                
                # Get cookies
                cookies = await context.cookies()
                browser_data['cookies'] = [{
                    'name': cookie['name'],
                    'domain': cookie['domain'],
                    'secure': cookie.get('secure', False),
                    'httpOnly': cookie.get('httpOnly', False)
                } for cookie in cookies]
                
                # Get local and session storage
                try:
                    local_storage = await page.evaluate('() => Object.assign({}, localStorage)')
                    browser_data['local_storage'] = local_storage or {}
                except:
                    browser_data['local_storage'] = {}
                
                try:
                    session_storage = await page.evaluate('() => Object.assign({}, sessionStorage)')
                    browser_data['session_storage'] = session_storage or {}
                except:
                    browser_data['session_storage'] = {}
                
                # Take screenshot if enabled
                if self.config.getboolean('scanning', 'screenshot', fallback=False):
                    screenshot_path = f"screenshot_{urlparse(url).netloc}_{int(time.time())}.png"
                    await page.screenshot(path=screenshot_path, full_page=True)
                    browser_data['screenshots'].append(screenshot_path)
                
                # Technology detection using browser
                await self._detect_technologies_browser(page, browser_data)
                
                # Store network requests and console messages
                browser_data['network_requests'] = network_requests[:100]  # Limit to 100 requests
                browser_data['console_errors'] = console_messages
                
                await browser.close()
                
        except Exception as e:
            self.logger.error(f"Browser reconnaissance failed for {url}: {e}")
            browser_data['error'] = str(e)
        
        return browser_data
    
    async def _detect_technologies_browser(self, page, browser_data: Dict):
        """Detect technologies using browser JavaScript execution"""
        try:
            # Check for common JavaScript frameworks/libraries
            js_checks = {
                'jQuery': 'typeof jQuery !== "undefined"',
                'React': 'typeof React !== "undefined" || document.querySelector("[data-reactroot]") !== null',
                'Angular': 'typeof angular !== "undefined" || document.querySelector("[ng-app], [data-ng-app], [ng-controller]") !== null',
                'Vue.js': 'typeof Vue !== "undefined" || document.querySelector("[data-v-], [v-]") !== null',
                'Bootstrap': 'typeof bootstrap !== "undefined" || document.querySelector(".container, .row, .col-") !== null',
                'D3.js': 'typeof d3 !== "undefined"',
                'Lodash': 'typeof _ !== "undefined" && typeof _.VERSION !== "undefined"',
                'Moment.js': 'typeof moment !== "undefined"',
                'Google Analytics': 'typeof ga !== "undefined" || typeof gtag !== "undefined"'
            }
            
            for tech, check in js_checks.items():
                try:
                    result = await page.evaluate(f'() => {check}')
                    if result:
                        browser_data['technologies'].append(f'JavaScript: {tech}')
                except:
                    pass
            
            # Check for meta tags
            meta_tags = await page.query_selector_all('meta')
            for meta in meta_tags:
                name = await meta.get_attribute('name')
                content = await meta.get_attribute('content')
                if name and content:
                    if name.lower() in ['generator', 'framework', 'platform']:
                        browser_data['technologies'].append(f'Meta: {name}={content}')
            
        except Exception as e:
            self.logger.debug(f"Technology detection failed: {e}")
    
    def selenium_reconnaissance(self, url: str) -> Dict:
        """Fallback reconnaissance using Selenium"""
        if not SELENIUM_AVAILABLE:
            self.logger.warning("Selenium not available. Install with: pip install selenium")
            return {}
        
        selenium_data = {
            'url': url,
            'method': 'selenium',
            'technologies': [],
            'forms': [],
            'links': [],
            'console_logs': []
        }
        
        driver = None
        try:
            # Setup Chrome options
            chrome_options = ChromeOptions()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument(f'--user-agent={random.choice(self.user_agents)}')
            
            if self.config.getboolean('proxy', 'enabled', fallback=False):
                proxy = self.config.get('proxy', 'http_proxy', fallback='')
                if proxy:
                    chrome_options.add_argument(f'--proxy-server={proxy}')
            
            # Try Chrome first, then Firefox as fallback
            try:
                driver = webdriver.Chrome(options=chrome_options)
            except WebDriverException:
                firefox_options = FirefoxOptions()
                firefox_options.add_argument('--headless')
                driver = webdriver.Firefox(options=firefox_options)
            
            driver.set_page_load_timeout(30)
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            selenium_data['title'] = driver.title
            selenium_data['url_final'] = driver.current_url
            
            # Extract forms
            forms = driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'get',
                    'inputs': []
                }
                
                inputs = form.find_elements(By.CSS_SELECTOR, 'input, textarea, select')
                for input_elem in inputs:
                    input_data = {
                        'type': input_elem.get_attribute('type') or 'text',
                        'name': input_elem.get_attribute('name') or '',
                        'id': input_elem.get_attribute('id') or ''
                    }
                    form_data['inputs'].append(input_data)
                
                selenium_data['forms'].append(form_data)
            
            # Extract links
            links = driver.find_elements(By.CSS_SELECTOR, 'a[href]')[:50]
            for link in links:
                href = link.get_attribute('href')
                text = link.text
                if href:
                    selenium_data['links'].append({
                        'href': href,
                        'text': text.strip()[:100] if text else ''
                    })
            
            # Get console logs
            try:
                logs = driver.get_log('browser')
                selenium_data['console_logs'] = [{
                    'level': log['level'],
                    'message': log['message'],
                    'timestamp': log['timestamp']
                } for log in logs if log['level'] in ['SEVERE', 'WARNING']]
            except:
                pass
            
        except TimeoutException:
            selenium_data['error'] = 'Page load timeout'
        except Exception as e:
            selenium_data['error'] = str(e)
        finally:
            if driver:
                driver.quit()
        
        return selenium_data
    
    def enhanced_web_reconnaissance(self, url: str) -> Dict:
        """Enhanced web reconnaissance using browser automation"""
        web_data = {}
        
        if self.config.getboolean('scanning', 'use_browser', fallback=False):
            # Try Playwright first (preferred)
            if PLAYWRIGHT_AVAILABLE:
                try:
                    web_data = asyncio.run(self.browser_reconnaissance(url))
                except Exception as e:
                    self.logger.warning(f"Playwright failed, trying Selenium: {e}")
                    web_data = self.selenium_reconnaissance(url)
            # Fallback to Selenium
            elif SELENIUM_AVAILABLE:
                web_data = self.selenium_reconnaissance(url)
            else:
                self.logger.warning("No browser automation libraries available")
                web_data = {'error': 'No browser automation available'}
        
        return web_data
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html_file = self.output_file.replace('.json', '_report.html')
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Government Domain Reconnaissance Report - {self.target_domain}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ margin: 20px 0; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 5px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .card {{ background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .vulnerability {{ background: #fff3cd; border-left-color: #ffc107; }}
        .critical {{ background: #f8d7da; border-left-color: #dc3545; }}
        .domain-list {{ list-style: none; padding: 0; }}
        .domain-item {{ background: white; margin: 5px 0; padding: 10px; border-radius: 4px; border: 1px solid #dee2e6; }}
        .tag {{ display: inline-block; background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }}
        .mitre-technique {{ background: #e7f3ff; padding: 8px; margin: 4px 0; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .timestamp {{ color: #6c757d; font-size: 12px; }}
        .status-active {{ color: #28a745; font-weight: bold; }}
        .status-error {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Government Domain Reconnaissance Report</h1>
            <p><strong>Target:</strong> {self.target_domain}</p>
            <p><strong>Generated:</strong> {self.results['timestamp']}</p>
            <p><strong>MITRE ATT&CK Techniques:</strong> {len(self.results['mitre_techniques_used'])}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="grid">
                <div class="card">
                    <h3>Domains Discovered</h3>
                    <p><strong>{len(self.results['domains'])}</strong> total domains</p>
                    <p><strong>{len(self.results['subdomains'])}</strong> subdomains</p>
                </div>
                <div class="card">
                    <h3>Vulnerabilities</h3>
                    <p><strong>{sum(len(d.get('vulnerabilities', [])) for d in self.results['domains'])}</strong> potential issues</p>
                </div>
                <div class="card">
                    <h3>Technologies</h3>
                    <p><strong>{len(set(tech for d in self.results['domains'] for tech in d.get('technologies', [])))}</strong> unique technologies</p>
                </div>
            </div>
        </div>"""
        
        # Add domains section
        if self.results['domains']:
            html_content += """
        <div class="section">
            <h2>🌐 Discovered Domains</h2>
            <ul class="domain-list">"""
            
            for domain in self.results['domains']:
                status_class = 'status-active' if domain.get('status') == 'active' else 'status-error'
                html_content += f"""
                <li class="domain-item">
                    <h4>{domain.get('domain', 'Unknown')}</h4>
                    <p><span class="{status_class}">Status: {domain.get('status', 'Unknown')}</span></p>
                    <p><strong>IP:</strong> {domain.get('ip', 'N/A')}</p>"""
                
                if domain.get('open_ports'):
                    html_content += f"<p><strong>Open Ports:</strong> {', '.join(f'{p}:{s}' for p, s in domain.get('open_ports', {}).items())}</p>"
                
                if domain.get('technologies'):
                    html_content += "<p><strong>Technologies:</strong> "
                    for tech in domain.get('technologies', []):
                        html_content += f'<span class="tag">{tech}</span>'
                    html_content += "</p>"
                
                if domain.get('vulnerabilities'):
                    html_content += "<div class='card vulnerability'><strong>Vulnerabilities:</strong><ul>"
                    for vuln in domain.get('vulnerabilities', []):
                        html_content += f"<li>{vuln}</li>"
                    html_content += "</ul></div>"
                
                html_content += "</li>"
            
            html_content += "</ul></div>"
        
        # Add MITRE techniques section
        if self.results['mitre_techniques_used']:
            html_content += """
        <div class="section">
            <h2>🎯 MITRE ATT&CK Techniques Used</h2>"""
            
            for technique in self.results['mitre_techniques_used']:
                html_content += f"""
                <div class="mitre-technique">
                    <strong>{technique['id']}</strong>: {technique['name']}
                    <div class="timestamp">Used at: {technique['timestamp']}</div>
                </div>"""
            
            html_content += "</div>"
        
        html_content += """
        <div class="section">
            <h2>⚠️ Disclaimer</h2>
            <p><em>This report is generated for authorized security testing purposes only. 
            Unauthorized scanning of government systems is illegal and unethical.</em></p>
        </div>
    </div>
</body>
</html>"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_file
    
    def generate_xml_report(self) -> str:
        """Generate XML report"""
        xml_file = self.output_file.replace('.json', '_report.xml')
        
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<reconnaissance_report>
    <target>{self.target_domain}</target>
    <timestamp>{self.results['timestamp']}</timestamp>
    <summary>
        <total_domains>{len(self.results['domains'])}</total_domains>
        <total_subdomains>{len(self.results['subdomains'])}</total_subdomains>
        <mitre_techniques_used>{len(self.results['mitre_techniques_used'])}</mitre_techniques_used>
    </summary>
    
    <domains>'''
        
        for domain in self.results['domains']:
            xml_content += f'''
        <domain>
            <name>{domain.get('domain', '')}</name>
            <ip>{domain.get('ip', '')}</ip>
            <status>{domain.get('status', '')}</status>
            <open_ports>{''.join(f'<port number="{p}" service="{s}"/>' for p, s in domain.get('open_ports', {}).items())}</open_ports>
            <technologies>{''.join(f'<technology>{tech}</technology>' for tech in domain.get('technologies', []))}</technologies>
            <vulnerabilities>{''.join(f'<vulnerability>{vuln}</vulnerability>' for vuln in domain.get('vulnerabilities', []))}</vulnerabilities>
        </domain>'''
        
        xml_content += '''
    </domains>
    
    <mitre_techniques>'''
        
        for technique in self.results['mitre_techniques_used']:
            xml_content += f'''
        <technique>
            <id>{technique['id']}</id>
            <name>{technique['name']}</name>
            <timestamp>{technique['timestamp']}</timestamp>
        </technique>'''
        
        xml_content += '''
    </mitre_techniques>
</reconnaissance_report>'''
        
        with open(xml_file, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        return xml_file
    
    def generate_report(self):
        """Generate comprehensive report in multiple formats"""
        print("[+] Generating comprehensive reports")
        
        output_formats = self.config.get('output', 'formats', fallback='json,csv').split(',')
        generated_files = []
        
        # Always generate JSON
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        generated_files.append(f"JSON: {self.output_file}")
        
        # Generate CSV if requested
        if 'csv' in output_formats:
            csv_file = self.output_file.replace('.json', '_summary.csv')
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Status', 'IP', 'Technologies', 'Open Ports', 'Vulnerabilities'])
                
                for domain_info in self.results['domains']:
                    writer.writerow([
                        domain_info.get('domain', ''),
                        domain_info.get('status', ''),
                        domain_info.get('ip', ''),
                        ', '.join(domain_info.get('technologies', [])),
                        ', '.join(f"{p}:{s}" for p, s in domain_info.get('open_ports', {}).items()),
                        ', '.join(domain_info.get('vulnerabilities', []))
                    ])
            generated_files.append(f"CSV: {csv_file}")
        
        # Generate HTML if requested
        if 'html' in output_formats:
            html_file = self.generate_html_report()
            generated_files.append(f"HTML: {html_file}")
        
        # Generate XML if requested
        if 'xml' in output_formats:
            xml_file = self.generate_xml_report()
            generated_files.append(f"XML: {xml_file}")
        
        # Generate MITRE ATT&CK mapping report
        mitre_file = self.output_file.replace('.json', '_mitre.txt')
        with open(mitre_file, 'w') as f:
            f.write("MITRE ATT&CK Techniques Used\n")
            f.write("=" * 50 + "\n\n")
            
            for technique in self.results['mitre_techniques_used']:
                f.write(f"{technique['id']}: {technique['name']}\n")
                f.write(f"Timestamp: {technique['timestamp']}\n\n")
        generated_files.append(f"MITRE: {mitre_file}")
        
        print(f"[+] Reports saved:")
        for file_info in generated_files:
            print(f"    - {file_info}")
    
    def run_full_recon(self):
        """Execute full reconnaissance workflow"""
        print(f"[+] Starting full reconnaissance on {self.target_domain}")
        print(f"[+] Output will be saved to {self.output_file}")
        
        # Domain validation
        if not self.target_domain.endswith('.gov'):
            print("[WARNING] Target is not a .gov domain!")
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                sys.exit(1)
        
        try:
            # WHOIS lookup
            whois_info = self.whois_lookup(self.target_domain)
            self.results['whois'] = whois_info
            
            # DNS enumeration
            dns_info = self.dns_enumeration(self.target_domain)
            self.results['dns_records'] = dns_info
            
            # Subdomain discovery
            subdomains = self.discover_subdomains()
            
            # Process each domain/subdomain with configurable limit
            all_domains = [self.target_domain] + subdomains
            max_domains = self.config.getint('scanning', 'max_domains', fallback=50)
            
            for domain in all_domains[:max_domains]:
                print(f"\n[+] Processing {domain}")
                
                domain_info = {
                    'domain': domain,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                try:
                    # Resolve IP
                    ip = socket.gethostbyname(domain)
                    domain_info['ip'] = ip
                    domain_info['status'] = 'active'
                    
                    # Port scanning
                    open_ports = self.port_scan(ip)
                    domain_info['open_ports'] = open_ports
                    
                    # Technology detection
                    if 80 in open_ports or 443 in open_ports:
                        protocol = 'https' if 443 in open_ports else 'http'
                        url = f"{protocol}://{domain}"
                        technologies = self.technology_detection(url)
                        domain_info['technologies'] = technologies
                        
                        # Enhanced web reconnaissance with browser automation
                        web_recon = self.enhanced_web_reconnaissance(url)
                        if web_recon:
                            domain_info['web_reconnaissance'] = web_recon
                            # Merge browser-detected technologies
                            if 'technologies' in web_recon:
                                domain_info['technologies'].extend(web_recon['technologies'])
                        
                        # Vulnerability scanning
                        vulnerabilities = self.vulnerability_scan(domain)
                        domain_info['vulnerabilities'] = vulnerabilities
                    
                    # SSL certificate analysis
                    if 443 in open_ports:
                        cert_info = self.ssl_certificate_analysis(domain)
                        domain_info['ssl_certificate'] = cert_info
                        
                        # Advanced vulnerability scanning
                        advanced_vulns = self.advanced_vulnerability_scan(domain)
                        domain_info['advanced_vulnerabilities'] = advanced_vulns
                
                except Exception as e:
                    print(f"[ERROR] Failed to process {domain}: {e}")
                    domain_info['status'] = 'error'
                    domain_info['error'] = str(e)
                
                self.results['domains'].append(domain_info)
                
                # Rate limiting
                time.sleep(random.uniform(2, 5))
            
            # Enhanced OSINT and Reconnaissance
            print("\n[+] Performing enhanced OSINT gathering...")
            
            # T1589: Gather Victim Identity Information
            emails = self.email_harvesting()
            self.results['emails'] = emails
            
            social_media = self.social_media_osint()
            self.results['social_media'] = social_media
            
            # T1596: Search Open Technical Databases
            technical_db_results = self.search_open_technical_databases()
            self.results['technical_databases'] = technical_db_results
            
            # T1591: Gather Victim Org Information
            org_info = self.gather_organization_info()
            self.results['organization_info'] = org_info
            
            # T1593.003: Search Code Repositories
            code_repos = self.search_code_repositories()
            self.results['code_repositories'] = code_repos
            
            # T1594: Search Victim-Owned Websites
            victim_websites = self.search_victim_owned_websites()
            self.results['victim_owned_websites'] = victim_websites
            
            # Wayback Machine analysis
            wayback_data = self.wayback_machine_analysis()
            self.results['wayback_machine'] = wayback_data
            
            # Enhanced host information gathering for discovered domains
            print("\n[+] Gathering enhanced host information...")
            for domain_info in self.results['domains']:
                domain = domain_info.get('domain')
                if domain and domain_info.get('status') == 'active':
                    try:
                        # T1592: Gather Victim Host Information
                        domain_info['hardware_info'] = self.gather_hardware_info(domain)
                        domain_info['enhanced_software_info'] = self.gather_software_info(domain)
                        domain_info['firmware_info'] = self.gather_firmware_info(domain)
                        domain_info['client_configurations'] = self.gather_client_configurations(domain)
                        
                        # T1590: Enhanced Network Information
                        domain_info['network_topology'] = self.network_topology_discovery(domain)
                        domain_info['security_appliances'] = self.network_security_appliances_detection(domain)
                        
                        # T1595.003: Wordlist Scanning
                        if domain_info.get('technologies'):
                            wordlist_results = self.wordlist_scanning(f"http://{domain}")
                            domain_info['wordlist_scan_results'] = wordlist_results
                    
                    except Exception as e:
                        print(f"[WARNING] Enhanced reconnaissance failed for {domain}: {e}")
                        continue
            
            # Shodan integration for discovered IPs
            if self.config.get('api_keys', 'shodan'):
                for domain in self.results['domains']:
                    if domain.get('ip') and domain.get('status') == 'active':
                        shodan_data = self.shodan_integration(domain['ip'])
                        if shodan_data:
                            domain['shodan_data'] = shodan_data
            
            # Generate reports
            self.generate_report()
            
            print(f"\n[+] Reconnaissance complete!")
            print(f"[+] Found {len(subdomains)} subdomains")
            print(f"[+] Processed {len(self.results['domains'])} domains")
            print(f"[+] Used {len(self.results['mitre_techniques_used'])} MITRE ATT&CK techniques")
            
        except KeyboardInterrupt:
            print("\n[!] Reconnaissance interrupted by user")
            self.generate_report()
        except Exception as e:
            print(f"\n[ERROR] Reconnaissance failed: {e}")
            self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='Government Domain OSINT Reconnaissance')
    parser.add_argument('domain', help='Target .gov domain')
    parser.add_argument('-o', '--output', default='gov_recon_results.json', 
                       help='Output file name')
    parser.add_argument('-c', '--config', 
                       help='Configuration file path')
    parser.add_argument('--ports', nargs='+', type=int,
                       help='Custom ports to scan')
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'xml'], 
                       action='append', help='Output formats (can be used multiple times)')
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy (format: http://proxy:port)')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy (requires Tor running on 9050)')
    parser.add_argument('--threads', type=int, help='Number of scanning threads')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('--max-domains', type=int, help='Maximum domains to process')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--browser', action='store_true', help='Enable browser automation for enhanced reconnaissance')
    parser.add_argument('--browser-type', choices=['chromium', 'firefox', 'webkit'], 
                       default='chromium', help='Browser type for automation')
    parser.add_argument('--screenshot', action='store_true', help='Take screenshots of discovered pages')
    parser.add_argument('--headless', action='store_true', default=True, help='Run browser in headless mode')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("=" * 60)
    print("Government Domain OSINT Reconnaissance Script")
    print("Enhanced with MITRE ATT&CK Framework")
    print("=" * 60)
    print("\nDISCLAIMER: Use only on authorized targets!")
    print("Unauthorized scanning of government systems is illegal.")
    print("=" * 60)
    
    # Confirmation prompt
    print(f"\nTarget: {args.domain}")
    response = input("Proceed with reconnaissance? (y/N): ")
    if response.lower() != 'y':
        sys.exit(0)
    
    # Initialize reconnaissance with configuration
    recon = GovRecon(args.domain, args.output, args.config)
    
    # Override config with command line arguments
    if args.format:
        recon.config.set('output', 'formats', ','.join(args.format))
    if args.proxy:
        recon.config.set('proxy', 'enabled', 'true')
        if args.proxy.startswith('http://'):
            recon.config.set('proxy', 'http_proxy', args.proxy)
        else:
            recon.config.set('proxy', 'https_proxy', args.proxy)
    if args.tor:
        recon.config.set('proxy', 'tor_enabled', 'true')
    if args.threads:
        recon.config.set('scanning', 'max_threads', str(args.threads))
    if args.timeout:
        recon.config.set('timing', 'timeout', str(args.timeout))
    if args.max_domains:
        recon.config.set('scanning', 'max_domains', str(args.max_domains))
    if args.browser:
        recon.config.set('scanning', 'use_browser', 'true')
    if args.browser_type:
        recon.config.set('scanning', 'browser_type', args.browser_type)
    if args.screenshot:
        recon.config.set('scanning', 'screenshot', 'true')
    if not args.headless:
        recon.config.set('scanning', 'headless', 'false')
    
    # Re-setup proxy after config changes
    recon.setup_proxy()
    
    # Run reconnaissance
    recon.run_full_recon()

if __name__ == "__main__":
    main()