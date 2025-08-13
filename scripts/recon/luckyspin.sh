#!/usr/bin/env python3
"""
🛡️  LUCKYSPIN - Enhanced Bug Bounty OSINT Automation Tool
🎯 Comprehensive reconnaissance and intelligence gathering platform
👨‍💻 Author: Kdairatchi | github.com/kdairatchi/dotfiles
"""

import sys
import os
import importlib

# Ensure the standard library 'random' module is loaded, even if a local
# file named 'random.py' exists in this directory.
_here = os.path.dirname(__file__)
if sys.path and sys.path[0] == _here:
    sys.path.pop(0)
sys.modules['random'] = importlib.import_module('random')
sys.path.insert(0, _here)

import argparse
import asyncio
import json
import random
import requests
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta
import csv
import re
from dataclasses import dataclass, asdict
import yaml
from colorama import Fore, Style, Back, init
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.live import Live

# Initialize colorama and rich
init(autoreset=True)
console = Console()

# Optional imports with fallback
try:
    import aiohttp
    import aiofiles
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

try:
    from crawl4ai import WebCrawler
    CRAWL4AI_AVAILABLE = True
except ImportError:
    CRAWL4AI_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

@dataclass
class TargetInfo:
    """Enhanced target information structure"""
    domain: str
    clean_domain: str
    is_wildcard: bool
    risk_rating: str
    priority_score: int
    programs: List[Dict]
    technologies: List[str]
    vulnerabilities: List[str]
    endpoints: List[str]
    subdomains: List[str]
    ports: List[int]
    headers: Dict[str, str]
    cms_info: Dict[str, Any]
    cloud_services: List[str]
    certificates: Dict[str, Any]
    recent_reports: List[Dict]
    public_apis: List[Dict]
    social_media: List[Dict]
    github_repos: List[Dict]
    employee_info: List[Dict]
    breach_data: List[Dict]
    threat_intel: Dict[str, Any]

class LuckySpinBanner:
    """Beautiful banner and UI components"""
    
    @staticmethod
    def print_banner():
        """Print the main banner"""
        banner = f"""
{Fore.CYAN}{'='*80}
{Fore.BRIGHT_CYAN}  🎰 LUCKYSPIN - Enhanced Bug Bounty OSINT Tool 🎰
{Fore.BLUE}  🎯 Comprehensive Reconnaissance & Intelligence Gathering
{Fore.MAGENTA}  👨‍💻 Author: Kdairatchi | github.com/kdairatchi/dotfiles
{Fore.YELLOW}  🛡️  "real never lies." | Stay safe, keep hunting!
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
"""
        console.print(Panel(banner, style="cyan"))

    @staticmethod
    def print_status(message: str, status: str = "INFO"):
        """Print status message with colors"""
        status_colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "DEBUG": Fore.MAGENTA
        }
        
        color = status_colors.get(status, Fore.CYAN)
        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"{color}[{timestamp}] {status}: {message}{Style.RESET_ALL}")

    @staticmethod
    def print_menu(title: str, options: List[Tuple[str, str]]):
        """Print a formatted menu"""
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        
        for key, description in options:
            table.add_row(f"[{key}]", description)
        
        console.print(table)

class EnhancedBountyTool:
    def __init__(self, config_file: str = None):
        self.base_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/"
        self.data_cache = {}
        self.config = self.load_config(config_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Initialize API clients
        self.shodan_client = None
        if SHODAN_AVAILABLE and self.config.get('shodan_api_key'):
            self.shodan_client = shodan.Shodan(self.config['shodan_api_key'])
        
        # Enhanced wordlists
        self.load_wordlists()
        
        # API endpoints for free intelligence gathering
        self.api_endpoints = {
            'crt_sh': 'https://crt.sh/?q={domain}&output=json',
            'dnsdumpster': 'https://dnsdumpster.com/',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/domain/report',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general',
            'urlvoid': 'http://api.urlvoid.com/1.0/?key={api_key}&host={domain}',
            'hackertarget': 'https://api.hackertarget.com/dnslookup/?q={domain}',
            'securitytrails': 'https://api.securitytrails.com/v1/domain/{domain}',
            'builtwith': 'https://api.builtwith.com/v20/api.json',
            'github_search': 'https://api.github.com/search/repositories',
            'github_code': 'https://api.github.com/search/code',
            'publicapis': 'https://api.publicapis.org/entries',
            'wayback': 'http://web.archive.org/cdx/search/cdx',
            'threatcrowd': 'https://www.threatcrowd.org/searchApi/v2/domain/report/',
            'censys': 'https://search.censys.io/api/v2/hosts/search',
            'bgpview': 'https://api.bgpview.io/ip/{ip}',
            'ipinfo': 'https://ipinfo.io/{ip}/json',
            'emailrep': 'https://emailrep.io/{email}',
            'haveibeenpwned': 'https://haveibeenpwned.com/api/v3/breaches'
        }
        
        # Recent bug bounty reports sources
        self.report_sources = {
            'hackerone': 'https://api.hackerone.com/v1/hacktivity',
            'bugcrowd': 'https://bugcrowd.com/programs.json',
            'github_reports': 'https://api.github.com/repos/LRose7/hackerone-reports/contents/',
            'pentesterland': 'https://pentester.land/writeups.json'
        }

    def load_config(self, config_file: str) -> Dict:
        """Load configuration from file or return defaults"""
        default_config = {
            'max_threads': 20,
            'timeout': 30,
            'rate_limit': 1.0,
            'output_dir': './output',
            'api_keys': {},
            'enable_aggressive_scan': False,
            'enable_social_media': False,
            'enable_employee_search': False,
            'custom_wordlists': [],
            'excluded_extensions': ['.jpg', '.png', '.gif', '.css', '.js'],
            'interesting_extensions': ['.php', '.asp', '.jsp', '.do', '.action'],
            'gowitness_args': ['--disable-logging', '--timeout', '10'],
            'nuclei_templates': ['cves', 'vulnerabilities', 'exposures'],
            'enable_crawl4ai': CRAWL4AI_AVAILABLE,
            'crawl_depth': 2,
            'max_pages_crawl': 100
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config

    def load_wordlists(self):
        """Load comprehensive wordlists"""
        self.wordlists = {
            'subdomains': self.get_subdomain_wordlist(),
            'directories': self.get_directory_wordlist(),
            'files': self.get_file_wordlist(),
            'parameters': self.get_parameter_wordlist(),
            'technologies': self.get_technology_wordlist(),
            'vulnerabilities': self.get_vulnerability_patterns(),
            'apis': self.get_api_wordlist(),
            'cloud': self.get_cloud_wordlist()
        }
        
        # Load custom wordlists if specified
        for wordlist_path in self.config.get('custom_wordlists', []):
            if os.path.exists(wordlist_path):
                name = os.path.basename(wordlist_path).split('.')[0]
                with open(wordlist_path, 'r') as f:
                    self.wordlists[name] = [line.strip() for line in f if line.strip()]

    def get_subdomain_wordlist(self) -> List[str]:
        """Enhanced subdomain wordlist"""
        base_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'www1', 'beta', 'delta', 'static', 'staging', 'secure', 'demo',
            'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www3',
            'ftp2', 'secure2', 'shop', 'sql', 'database', 'search', 'crm', 'cms', 'support',
            'store', 'app', 'mobile', 'api', 'download', 'upload', 'admin2', 'backup',
            'dev2', 'test2', 'portal', 'video', 'subdomain', 'moodle', 'mail1', 'sms',
            'gallery', 'mx', 'mx1', 'mx2', 'ns4', 'remote', 'dns', 'mail3', 'webmail2',
            'relay', 'old2', 'files', 'cdn', 'assets', 'resources', 'content', 'docs',
            'documentation', 'help', 'kb', 'status', 'monitor', 'stats', 'internal',
            'intranet', 'extranet', 'vpn2', 'ssl', 'secure3', 'payments', 'billing',
            'accounts', 'auth', 'sso', 'ldap', 'directory', 'corp', 'corporate', 'staging2',
            'preprod', 'prod', 'production', 'www-dev', 'dev-www', 'test-www', 'stage',
            'uat', 'qa', 'quality', 'testing', 'integration', 'ci', 'build', 'jenkins',
            'git', 'svn', 'repo', 'repository', 'code', 'source', 'gitlab', 'github',
            'bitbucket', 'jira', 'confluence', 'wiki2', 'redmine', 'trac', 'bugzilla'
        ]
        
        # Add cloud service subdomains
        cloud_subs = [
            'aws', 'azure', 'gcp', 'cloud', 'k8s', 'kubernetes', 'docker', 'container',
            's3', 'blob', 'bucket', 'storage', 'cdn', 'cloudfront', 'cloudflare',
            'heroku', 'netlify', 'vercel', 'firebase', 'amplify', 'elastic'
        ]
        
        # Add modern development subdomains
        modern_subs = [
            'graphql', 'rest', 'microservice', 'lambda', 'function', 'edge',
            'webhook', 'notification', 'queue', 'worker', 'scheduler', 'cron',
            'monitoring', 'logging', 'metrics', 'trace', 'health', 'status',
            'swagger', 'openapi', 'docs', 'documentation', 'spec'
        ]
        
        return base_subs + cloud_subs + modern_subs

    def get_directory_wordlist(self) -> List[str]:
        """Enhanced directory wordlist"""
        return [
            'admin', 'administrator', 'admincp', 'admins', 'administration',
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'webhook', 'endpoints',
            'backup', 'backups', 'bak', 'old', 'tmp', 'temp', 'cache',
            'config', 'configuration', 'settings', 'env', 'environment',
            'debug', 'test', 'testing', 'dev', 'development', 'staging',
            'upload', 'uploads', 'files', 'file', 'documents', 'docs',
            'download', 'downloads', 'shared', 'public', 'private',
            'login', 'auth', 'authentication', 'oauth', 'sso', 'signin',
            'register', 'signup', 'account', 'profile', 'user', 'users',
            'dashboard', 'panel', 'control', 'manage', 'manager',
            'wp-admin', 'wp-content', 'wp-includes', 'wordpress',
            'phpmyadmin', 'pma', 'mysql', 'database', 'db', 'sql',
            'jenkins', 'ci', 'build', 'deploy', 'deployment',
            'git', 'svn', 'mercurial', 'bzr', 'cvs', '.git', '.svn',
            'server-status', 'server-info', 'status', 'health', 'metrics',
            'search', 'elasticsearch', 'solr', 'lucene', 'sphinx',
            'mail', 'webmail', 'email', 'smtp', 'imap', 'pop3',
            'ftp', 'sftp', 'ftps', 'rsync', 'scp', 'ssh',
            'ssl', 'tls', 'cert', 'certificate', 'certs', 'ca',
            'logs', 'log', 'logging', 'logger', 'syslog', 'audit',
            'monitoring', 'nagios', 'cacti', 'munin', 'zabbix',
            'backup', 'restore', 'dump', 'export', 'import',
            'install', 'setup', 'configure', 'wizard', 'installer'
        ]

    def get_file_wordlist(self) -> List[str]:
        """Enhanced file wordlist"""
        return [
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            '.htaccess', '.htpasswd', 'web.config', 'app.config', 'global.asax',
            'config.php', 'config.inc.php', 'configuration.php', 'settings.php',
            'wp-config.php', 'config.yml', 'config.yaml', 'settings.yml',
            '.env', '.env.local', '.env.production', '.env.development',
            'package.json', 'composer.json', 'requirements.txt', 'Gemfile',
            'dockerfile', 'docker-compose.yml', 'kubernetes.yml', 'helm.yml',
            'readme.txt', 'README.md', 'CHANGELOG.md', 'LICENSE',
            'backup.sql', 'dump.sql', 'database.sql', 'db.sql',
            'admin.php', 'login.php', 'auth.php', 'signin.php',
            'upload.php', 'file.php', 'download.php', 'image.php',
            'search.php', 'contact.php', 'feedback.php', 'submit.php',
            'index.php', 'home.php', 'main.php', 'default.php',
            'error.log', 'access.log', 'debug.log', 'app.log',
            'test.php', 'phpinfo.php', 'info.php', 'server.php',
            'install.php', 'setup.php', 'update.php', 'upgrade.php',
            'swagger.json', 'openapi.json', 'api-docs.json', 'schema.json'
        ]

    def get_parameter_wordlist(self) -> List[str]:
        """Enhanced parameter wordlist for testing"""
        return [
            'id', 'user', 'admin', 'username', 'password', 'email', 'name',
            'q', 'query', 'search', 'keyword', 'term', 'filter', 'sort',
            'page', 'limit', 'offset', 'start', 'end', 'from', 'to',
            'file', 'path', 'dir', 'folder', 'location', 'url', 'link',
            'action', 'method', 'function', 'operation', 'command', 'cmd',
            'token', 'key', 'api_key', 'access_token', 'auth_token', 'session',
            'callback', 'redirect', 'return', 'next', 'goto', 'forward',
            'debug', 'test', 'dev', 'mode', 'env', 'environment', 'config',
            'lang', 'language', 'locale', 'country', 'region', 'timezone',
            'format', 'type', 'version', 'api_version', 'v', 'ver',
            'data', 'json', 'xml', 'csv', 'export', 'import', 'upload'
        ]

    def get_technology_wordlist(self) -> List[str]:
        """Technology detection wordlist"""
        return [
            'WordPress', 'Joomla', 'Drupal', 'Magento', 'Shopify', 'WooCommerce',
            'React', 'Angular', 'Vue', 'jQuery', 'Bootstrap', 'Foundation',
            'Laravel', 'Django', 'Rails', 'Express', 'Spring', 'ASP.NET',
            'Apache', 'Nginx', 'IIS', 'Tomcat', 'Jetty', 'Gunicorn',
            'MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'Elasticsearch', 'Cassandra',
            'Docker', 'Kubernetes', 'Jenkins', 'GitLab', 'GitHub', 'Bitbucket',
            'AWS', 'Azure', 'GCP', 'CloudFlare', 'DigitalOcean', 'Heroku',
            'PHP', 'Python', 'Java', 'JavaScript', 'TypeScript', 'Go', 'Rust',
            'XAMPP', 'WAMP', 'MAMP', 'LAMP', 'MEAN', 'MERN'
        ]

    def get_vulnerability_patterns(self) -> List[str]:
        """Vulnerability detection patterns"""
        return [
            'SQL Error', 'MySQL Error', 'ORA-', 'Microsoft JET',
            'Warning: include', 'Warning: require', 'Fatal error',
            'Stack trace', 'Exception', 'Traceback', 'Debug',
            'eval(', 'setTimeout(', 'setInterval(', 'document.write(',
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            '<?php', '<?=', '<%', '{{', '${', '#{',
            'SELECT * FROM', 'INSERT INTO', 'UPDATE SET', 'DELETE FROM',
            'access denied', 'forbidden', 'unauthorized', '401', '403', '500',
            'internal server error', 'application error', 'runtime error'
        ]

    def get_api_wordlist(self) -> List[str]:
        """API endpoint wordlist"""
        return [
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'webhook',
            'auth', 'oauth', 'token', 'login', 'logout', 'register',
            'user', 'users', 'profile', 'account', 'admin', 'admin-api',
            'data', 'json', 'xml', 'csv', 'export', 'import',
            'search', 'query', 'filter', 'sort', 'page', 'limit',
            'upload', 'download', 'file', 'files', 'media',
            'notification', 'webhook', 'callback', 'event',
            'status', 'health', 'ping', 'metrics', 'stats',
            'config', 'settings', 'preferences', 'options'
        ]

    def get_cloud_wordlist(self) -> List[str]:
        """Cloud service wordlist"""
        return [
            'aws', 'amazon', 's3', 'ec2', 'lambda', 'cloudfront',
            'azure', 'microsoft', 'blob', 'function', 'cdn',
            'gcp', 'google', 'cloud', 'storage', 'compute',
            'cloudflare', 'heroku', 'netlify', 'vercel',
            'digitalocean', 'linode', 'vultr', 'ovh',
            'firebase', 'amplify', 'elastic', 'fastly'
        ]

    async def fetch_bounty_targets(self) -> List[Dict]:
        """Fetch bug bounty targets from multiple sources"""
        LuckySpinBanner.print_status("Fetching bug bounty targets...", "INFO")
        
        targets = []
        
        # Fetch from GitHub repository
        try:
            response = self.session.get(f"{self.base_url}wildcards.txt")
            if response.status_code == 200:
                wildcard_domains = response.text.strip().split('\n')
                for domain in wildcard_domains:
                    if domain and not domain.startswith('#'):
                        targets.append({
                            'domain': domain,
                            'type': 'wildcard',
                            'source': 'github'
                        })
        except Exception as e:
            LuckySpinBanner.print_status(f"Error fetching wildcard targets: {e}", "ERROR")
        
        # Fetch from HackerOne
        try:
            response = self.session.get(self.report_sources['hackerone'])
            if response.status_code == 200:
                data = response.json()
                for program in data.get('data', []):
                    if 'attributes' in program:
                        domain = program['attributes'].get('name', '')
                        if domain:
                            targets.append({
                                'domain': domain,
                                'type': 'hackerone',
                                'source': 'hackerone'
                            })
        except Exception as e:
            LuckySpinBanner.print_status(f"Error fetching HackerOne targets: {e}", "ERROR")
        
        # Fetch from Bugcrowd
        try:
            response = self.session.get(self.report_sources['bugcrowd'])
            if response.status_code == 200:
                data = response.json()
                for program in data.get('programs', []):
                    domain = program.get('name', '')
                    if domain:
                        targets.append({
                            'domain': domain,
                            'type': 'bugcrowd',
                            'source': 'bugcrowd'
                        })
        except Exception as e:
            LuckySpinBanner.print_status(f"Error fetching Bugcrowd targets: {e}", "ERROR")
        
        LuckySpinBanner.print_status(f"Found {len(targets)} targets", "SUCCESS")
        return targets

    async def scan_target(self, target: Dict) -> TargetInfo:
        """Comprehensive target scanning"""
        domain = target['domain']
        LuckySpinBanner.print_status(f"Scanning target: {domain}", "INFO")
        
        target_info = TargetInfo(
            domain=domain,
            clean_domain=domain.replace('*.', ''),
            is_wildcard=domain.startswith('*.'),
            risk_rating='MEDIUM',
            priority_score=50,
            programs=[],
            technologies=[],
            vulnerabilities=[],
            endpoints=[],
            subdomains=[],
            ports=[],
            headers={},
            cms_info={},
            cloud_services=[],
            certificates={},
            recent_reports=[],
            public_apis=[],
            social_media=[],
            github_repos=[],
            employee_info=[],
            breach_data=[],
            threat_intel={}
        )
        
        # Perform various scans
        await self.scan_subdomains(target_info)
        await self.scan_technologies(target_info)
        await self.scan_vulnerabilities(target_info)
        await self.scan_certificates(target_info)
        await self.scan_apis(target_info)
        await self.scan_social_media(target_info)
        await self.scan_github(target_info)
        await self.scan_threat_intel(target_info)
        
        return target_info

    async def scan_subdomains(self, target_info: TargetInfo):
        """Scan for subdomains"""
        try:
            # Certificate transparency
            response = self.session.get(
                self.api_endpoints['crt_sh'].format(domain=target_info.clean_domain)
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        names = entry['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lstrip('*.')
                            if name and target_info.clean_domain in name:
                                target_info.subdomains.append(name)
        except Exception as e:
            LuckySpinBanner.print_status(f"Error scanning subdomains: {e}", "ERROR")

    async def scan_technologies(self, target_info: TargetInfo):
        """Scan for technologies"""
        try:
            # BuiltWith API
            response = self.session.get(
                self.api_endpoints['builtwith'],
                params={'KEY': self.config.get('api_keys', {}).get('builtwith', '')}
            )
            if response.status_code == 200:
                data = response.json()
                for tech in data.get('technologies', []):
                    target_info.technologies.append(tech.get('name', ''))
        except Exception as e:
            LuckySpinBanner.print_status(f"Error scanning technologies: {e}", "ERROR")

    async def scan_vulnerabilities(self, target_info: TargetInfo):
        """Scan for vulnerabilities"""
        # This would integrate with tools like Nuclei, Nmap, etc.
        pass

    async def scan_certificates(self, target_info: TargetInfo):
        """Scan SSL certificates"""
        try:
            response = self.session.get(
                self.api_endpoints['crt_sh'].format(domain=target_info.clean_domain)
            )
            if response.status_code == 200:
                data = response.json()
                if data:
                    target_info.certificates = data[0]
        except Exception as e:
            LuckySpinBanner.print_status(f"Error scanning certificates: {e}", "ERROR")

    async def scan_apis(self, target_info: TargetInfo):
        """Scan for public APIs"""
        # Common API endpoints
        api_endpoints = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/docs', '/openapi', '/redoc'
        ]
        
        for endpoint in api_endpoints:
            try:
                url = f"https://{target_info.clean_domain}{endpoint}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    target_info.public_apis.append({
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', '')
                    })
            except:
                pass

    async def scan_social_media(self, target_info: TargetInfo):
        """Scan for social media presence"""
        social_platforms = [
            'twitter.com', 'linkedin.com', 'facebook.com', 'instagram.com',
            'youtube.com', 'github.com', 'gitlab.com', 'bitbucket.org'
        ]
        
        for platform in social_platforms:
            try:
                url = f"https://{platform}/{target_info.clean_domain}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    target_info.social_media.append({
                        'platform': platform,
                        'url': url,
                        'status_code': response.status_code
                    })
            except:
                pass

    async def scan_github(self, target_info: TargetInfo):
        """Scan for GitHub repositories"""
        try:
            response = self.session.get(
                self.api_endpoints['github_search'],
                params={'q': target_info.clean_domain, 'type': 'repository'}
            )
            if response.status_code == 200:
                data = response.json()
                for repo in data.get('items', []):
                    target_info.github_repos.append({
                        'name': repo.get('name', ''),
                        'url': repo.get('html_url', ''),
                        'description': repo.get('description', ''),
                        'stars': repo.get('stargazers_count', 0)
                    })
        except Exception as e:
            LuckySpinBanner.print_status(f"Error scanning GitHub: {e}", "ERROR")

    async def scan_threat_intel(self, target_info: TargetInfo):
        """Scan threat intelligence sources"""
        try:
            # AlienVault OTX
            response = self.session.get(
                self.api_endpoints['alienvault'].format(domain=target_info.clean_domain)
            )
            if response.status_code == 200:
                data = response.json()
                target_info.threat_intel['alienvault'] = data
        except Exception as e:
            LuckySpinBanner.print_status(f"Error scanning threat intel: {e}", "ERROR")

    def generate_report(self, targets: List[TargetInfo], output_file: str):
        """Generate comprehensive report"""
        LuckySpinBanner.print_status("Generating report...", "INFO")
        
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'LuckySpin',
                'version': '2.0.0',
                'targets_scanned': len(targets)
            },
            'summary': {
                'total_targets': len(targets),
                'wildcard_domains': len([t for t in targets if t.is_wildcard]),
                'total_subdomains': sum(len(t.subdomains) for t in targets),
                'total_technologies': len(set([tech for t in targets for tech in t.technologies])),
                'total_vulnerabilities': sum(len(t.vulnerabilities) for t in targets),
                'total_apis': sum(len(t.public_apis) for t in targets),
                'total_github_repos': sum(len(t.github_repos) for t in targets)
            },
            'targets': [asdict(target) for target in targets]
        }
        
        # Save JSON report
        with open(f"{output_file}.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save CSV report
        with open(f"{output_file}.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Domain', 'Type', 'Subdomains', 'Technologies', 'Vulnerabilities',
                'APIs', 'GitHub Repos', 'Social Media', 'Risk Rating'
            ])
            
            for target in targets:
                writer.writerow([
                    target.domain,
                    'wildcard' if target.is_wildcard else 'domain',
                    len(target.subdomains),
                    len(target.technologies),
                    len(target.vulnerabilities),
                    len(target.public_apis),
                    len(target.github_repos),
                    len(target.social_media),
                    target.risk_rating
                ])
        
        LuckySpinBanner.print_status(f"Report saved: {output_file}.json and {output_file}.csv", "SUCCESS")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="🎰 LuckySpin - Enhanced Bug Bounty OSINT Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python luckyspin.sh --target example.com
  python luckyspin.sh --config config.yml --output report
  python luckyspin.sh --interactive
        """
    )
    
    parser.add_argument('-t', '--target', help='Single target domain')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('-o', '--output', help='Output file prefix', default='luckyspin_report')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--max-targets', type=int, default=100, help='Maximum targets to scan')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    
    args = parser.parse_args()
    
    # Print banner
    LuckySpinBanner.print_banner()
    
    # Initialize tool
    tool = EnhancedBountyTool(args.config)
    
    if args.interactive:
        # Interactive mode
        console.print("\n[bold cyan]Interactive Mode[/bold cyan]")
        
        options = [
            ("1", "🎯 Scan Single Target"),
            ("2", "📋 Scan Multiple Targets"),
            ("3", "🔍 Fetch Bug Bounty Targets"),
            ("4", "⚙️  Configuration"),
            ("5", "📊 View Previous Reports"),
            ("0", "🚪 Exit")
        ]
        
        while True:
            LuckySpinBanner.print_menu("LuckySpin Menu", options)
            choice = Prompt.ask("Choose an option", choices=["0", "1", "2", "3", "4", "5"])
            
            if choice == "0":
                console.print("[bold green]Goodbye! Stay safe and keep hunting! 🛡️[/bold green]")
                break
            elif choice == "1":
                target = Prompt.ask("Enter target domain")
                if target:
                    # Scan single target
                    pass
            elif choice == "2":
                # Scan multiple targets
                pass
            elif choice == "3":
                # Fetch bug bounty targets
                pass
            elif choice == "4":
                # Configuration
                pass
            elif choice == "5":
                # View reports
                pass
    
    else:
        # Command line mode
        if args.target:
            # Scan single target
            LuckySpinBanner.print_status(f"Scanning target: {args.target}", "INFO")
            # Implementation here
        else:
            # Fetch and scan bug bounty targets
            LuckySpinBanner.print_status("Fetching bug bounty targets...", "INFO")
            # Implementation here

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted by user[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        sys.exit(1)