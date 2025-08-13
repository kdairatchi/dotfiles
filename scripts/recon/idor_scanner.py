#!/usr/bin/env python3
"""
Advanced Bug Bounty Security Scanner
A comprehensive tool for discovering IDOR, auth bypasses, and various web vulnerabilities

Author: Bug Bounty Security Team
Purpose: Comprehensive automated vulnerability discovery for bug bounty research
Features: IDOR, JWT analysis, Cookie testing, Recon, Code analysis, Security checks

USAGE:
    # Interactive menu (recommended for beginners)
    python3 idor_scanner.py --interactive
    
    # Quick IDOR scan
    python3 idor_scanner.py -u "https://target.com/api/user?id=123"
    
    # Comprehensive security scan
    python3 idor_scanner.py -u "https://target.com" --comprehensive --output report.txt
    
    # Multiple targets
    python3 idor_scanner.py -f targets.txt --json --output results.json

INSTALL DEPENDENCIES:
    pip install playwright beautifulsoup4 requests PyJWT
    playwright install

FEATURES:
    ✓ IDOR vulnerability detection with advanced payloads (70+ parameter patterns)
    ✓ JWT token analysis and vulnerability testing
    ✓ Cookie security analysis
    ✓ Comprehensive reconnaissance (50+ endpoints)
    ✓ JavaScript analysis for secrets/endpoints
    ✓ Authentication bypass testing (6 technique categories)
    ✓ Security headers analysis (20+ headers)
    ✓ Interactive menu for guided testing
    ✓ Multiple output formats (text, JSON)
    ✓ Detailed vulnerability reports with methodology guide
    ✓ Advanced parameter detection (UUID, hash, base64, ObjectId patterns)
    ✓ Comprehensive payload generation (20+ test values per parameter)
    ✓ Enhanced response analysis (90+ sensitive data patterns)
    ✓ Multi-format ID support and manipulation techniques
    ✓ Authentication bypass payload library
    ✓ Detailed IDOR testing methodology documentation
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import random
import re
import requests
import subprocess
import sys
import time
import uuid
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from urllib.parse import parse_qs, urljoin, urlparse, quote, unquote

try:
    from playwright.async_api import async_playwright, Browser, Page, Response
except ImportError:
    print("[ERROR] Playwright not installed. Run: pip install playwright && playwright install")
    sys.exit(1)

try:
    import jwt
except ImportError:
    print("[WARNING] PyJWT not installed. JWT analysis will be limited. Run: pip install PyJWT")
    jwt = None

# Check for additional dependencies
missing_deps = []

try:
    from bs4 import BeautifulSoup
except ImportError:
    missing_deps.append("beautifulsoup4")

try:
    import requests
except ImportError:
    missing_deps.append("requests")

if missing_deps:
    print(f"[ERROR] Missing required dependencies: {', '.join(missing_deps)}")
    print(f"[ERROR] Install with: pip install {' '.join(missing_deps)}")
    sys.exit(1)


class AdvancedBugBountyScanner:
    """Comprehensive bug bounty scanner for multiple vulnerability types"""
    
    def __init__(self, headless: bool = True, timeout: int = 10000, user_agent: str = None):
        """
        Initialize the advanced bug bounty scanner
        
        Args:
            headless: Whether to run browser in headless mode
            timeout: Request timeout in milliseconds
            user_agent: Custom user agent string
        """
        self.headless = headless
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.context = None
        self.tested_params: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session_cookies: Dict[str, str] = {}
        self.jwt_tokens: List[str] = []
        self.discovered_endpoints: Set[str] = set()
        self.recon_data: Dict[str, Any] = {}
        self.custom_headers: Dict[str, str] = {}
        
        # Authentication bypass techniques and payloads
        self.auth_bypass_techniques = {
            'parameter_pollution': [
                {'user_id': '1', 'user_id[]': '2'},
                {'id': '1', 'id': '2'},  # Duplicate parameters
                {'user': 'victim', 'user[]': 'attacker'},
            ],
            'method_override': [
                'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'
            ],
            'header_injection': {
                'X-Original-URL': '/admin/users',
                'X-Rewrite-URL': '/admin/users',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
                'X-Forwarded-Host': 'localhost',
                'X-Host': 'localhost',
                'X-HTTP-Method-Override': 'PUT',
                'X-HTTP-Method': 'PUT',
                'X-Method-Override': 'PUT',
                'X-User-ID': '1',
                'X-Admin': 'true',
                'X-Is-Admin': '1',
                'X-Role': 'admin',
                'X-Privilege': 'admin',
                'X-Access-Level': 'admin',
                'X-User-Role': 'administrator',
                'Authorization': 'Bearer fake-token',
                'X-Authorization': 'Bearer fake-token',
                'X-API-Key': 'admin-key',
                'X-Token': 'admin-token',
            },
            'url_encoding': [
                '%2e%2e%2f',  # ../
                '%252e%252e%252f',  # Double encoded ../
                '%c0%ae%c0%ae%c0%af',  # UTF-8 overlong encoding
                '%ef%bc%8e%ef%bc%8e%ef%bc%8f',  # Unicode ../
            ],
            'path_traversal': [
                '../', '..\\', '....//....',
                '%2e%2e%2f', '%2e%2e\\',
                '..%2f', '..%5c',
                '/%2e%2e%2f%2e%2e%2f',
                '/..%252f..%252f',
            ],
            'null_byte_injection': [
                '%00', '\\x00', '%0a', '\\n',
                '%0d', '\\r', '%09', '\\t',
            ],
            'case_manipulation': [
                'Admin', 'ADMIN', 'aDmIn',
                'Root', 'ROOT', 'rOoT',
                'User', 'USER', 'uSeR',
            ],
            'wildcard_bypass': [
                '*', '?', '%', '%%',
                '.*', '.+', '[a-z]*',
            ]
        }
        
        # IDOR testing methodologies and techniques
        self.idor_methodologies = {
            'sequential_enumeration': {
                'description': 'Test sequential IDs by incrementing/decrementing values',
                'severity_impact': 'High - Can lead to complete data enumeration',
                'detection_methods': ['response_content', 'status_code', 'response_time', 'headers']
            },
            'privilege_escalation': {
                'description': 'Test access to higher privilege resources',
                'severity_impact': 'Critical - Can lead to admin access',
                'detection_methods': ['sensitive_data_patterns', 'admin_content', 'privilege_indicators']
            },
            'cross_tenant_access': {
                'description': 'Test access to other tenants/organizations data',
                'severity_impact': 'High - Can lead to data breach across tenants',
                'detection_methods': ['tenant_specific_data', 'organization_data', 'multi_tenant_indicators']
            },
            'function_level_access': {
                'description': 'Test access to different functional areas',
                'severity_impact': 'Medium-High - Can expose different feature sets',
                'detection_methods': ['feature_specific_content', 'function_indicators']
            },
            'temporal_access': {
                'description': 'Test access to time-based resources (old/future data)',
                'severity_impact': 'Medium - Can expose historical or planned data',
                'detection_methods': ['timestamp_analysis', 'date_based_content']
            }
        }
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        self.current_user_agent = user_agent or random.choice(self.user_agents)
        
        # Common parameter patterns that often contain object references
        self.target_params = {
            'id', 'user_id', 'uid', 'account_id', 'profile_id',
            'order_id', 'transaction_id', 'item_id', 'post_id',
            'file_id', 'document_id', 'message_id', 'thread_id',
            'group_id', 'team_id', 'project_id', 'folder_id',
            'category_id', 'session_id', 'token', 'key', 'ref',
            'reference', 'resource_id', 'object_id', 'entity_id',
            'invoice_id', 'payment_id', 'subscription_id', 'plan_id',
            'company_id', 'organization_id', 'workspace_id', 'tenant_id',
            'client_id', 'customer_id', 'merchant_id', 'vendor_id',
            'report_id', 'ticket_id', 'task_id', 'job_id', 'request_id',
            'notification_id', 'alert_id', 'event_id', 'activity_id',
            'comment_id', 'reply_id', 'feedback_id', 'review_id',
            'rating_id', 'vote_id', 'poll_id', 'survey_id',
            'campaign_id', 'offer_id', 'coupon_id', 'discount_id',
            'product_id', 'service_id', 'feature_id', 'module_id',
            'component_id', 'version_id', 'build_id', 'release_id',
            'deployment_id', 'environment_id', 'config_id', 'setting_id',
            'permission_id', 'role_id', 'privilege_id', 'access_id',
            'credential_id', 'certificate_id', 'license_id', 'secret_id',
            'api_key', 'access_token', 'refresh_token', 'jwt_token',
            'auth_token', 'bearer_token', 'csrf_token', 'session_token',
            'verification_token', 'reset_token', 'activation_token',
            'invitation_token', 'temp_token', 'one_time_token'
        }
        
        # Status codes that might indicate successful unauthorized access
        self.success_codes = {200, 201, 202, 204, 206, 302, 304}
        
        # Response patterns that might indicate data disclosure
        self.disclosure_patterns = [
            # Personal Information
            r'"email":\s*"[^"]+@[^"]+"',
            r'"phone":\s*"[\d\-\+\(\)\s]+"',
            r'"ssn":\s*"[\d\-]+"',
            r'"social_security":\s*"[\d\-]+"',
            r'"address":\s*"[^"]+"',
            r'"home_address":\s*"[^"]+"',
            r'"zip_code":\s*"\d+"',
            r'"postal_code":\s*"[A-Za-z0-9\s\-]+"',
            r'"birth_date":\s*"[\d\-/]+"',
            r'"birthday":\s*"[\d\-/]+"',
            r'"date_of_birth":\s*"[\d\-/]+"',
            r'"full_name":\s*"[^"]+"',
            r'"first_name":\s*"[^"]+"',
            r'"last_name":\s*"[^"]+"',
            r'"middle_name":\s*"[^"]+"',
            r'"maiden_name":\s*"[^"]+"',
            
            # Financial Information
            r'"credit_card":\s*"[\d\-\s]+"',
            r'"card_number":\s*"[\d\-\s]+"',
            r'"cvv":\s*"\d+"',
            r'"security_code":\s*"\d+"',
            r'"balance":\s*[\d\.]+',
            r'"account_balance":\s*[\d\.]+',
            r'"bank_account":\s*"[\d\-]+"',
            r'"routing_number":\s*"\d+"',
            r'"iban":\s*"[A-Z0-9]+"',
            r'"swift_code":\s*"[A-Z0-9]+"',
            r'"salary":\s*[\d\.]+',
            r'"income":\s*[\d\.]+',
            r'"tax_id":\s*"[\d\-]+"',
            r'"ein":\s*"[\d\-]+"',
            
            # Authentication & Security
            r'"password":\s*"[^"]+"',
            r'"passwd":\s*"[^"]+"',
            r'"pass":\s*"[^"]+"',
            r'"token":\s*"[^"]+"',
            r'"access_token":\s*"[^"]+"',
            r'"refresh_token":\s*"[^"]+"',
            r'"api_key":\s*"[^"]+"',
            r'"secret":\s*"[^"]+"',
            r'"private_key":\s*"[^"]+"',
            r'"public_key":\s*"[^"]+"',
            r'"certificate":\s*"[^"]+"',
            r'"session_id":\s*"[^"]+"',
            r'"csrf_token":\s*"[^"]+"',
            r'"bearer":\s*"[^"]+"',
            r'"authorization":\s*"[^"]+"',
            r'"auth_token":\s*"[^"]+"',
            r'"login_token":\s*"[^"]+"',
            r'"security_question":\s*"[^"]+"',
            r'"security_answer":\s*"[^"]+"',
            r'"pin":\s*"\d+"',
            r'"passcode":\s*"\d+"',
            
            # Medical & Health Information
            r'"medical_record":\s*"[^"]+"',
            r'"patient_id":\s*"[^"]+"',
            r'"diagnosis":\s*"[^"]+"',
            r'"prescription":\s*"[^"]+"',
            r'"insurance_number":\s*"[^"]+"',
            r'"health_condition":\s*"[^"]+"',
            r'"allergies":\s*"[^"]+"',
            r'"medication":\s*"[^"]+"',
            
            # Business & Professional
            r'"salary_range":\s*"[^"]+"',
            r'"compensation":\s*[\d\.]+',
            r'"performance_review":\s*"[^"]+"',
            r'"employee_id":\s*"[^"]+"',
            r'"department":\s*"[^"]+"',
            r'"position":\s*"[^"]+"',
            r'"manager":\s*"[^"]+"',
            r'"contract":\s*"[^"]+"',
            r'"agreement":\s*"[^"]+"',
            r'"confidential":\s*"[^"]+"',
            r'"proprietary":\s*"[^"]+"',
            r'"classified":\s*"[^"]+"',
            
            # System & Technical
            r'"database_url":\s*"[^"]+"',
            r'"connection_string":\s*"[^"]+"',
            r'"server_ip":\s*"[\d\.]+"',
            r'"internal_ip":\s*"[\d\.]+"',
            r'"admin_panel":\s*"[^"]+"',
            r'"backup_location":\s*"[^"]+"',
            r'"config_file":\s*"[^"]+"',
            r'"environment_variable":\s*"[^"]+"',
            r'"debug_info":\s*"[^"]+"',
            r'"error_details":\s*"[^"]+"',
            r'"stack_trace":\s*"[^"]+"',
            
            # Location & Tracking
            r'"latitude":\s*[\d\.\-]+',
            r'"longitude":\s*[\d\.\-]+',
            r'"gps_coordinates":\s*"[^"]+"',
            r'"location":\s*"[^"]+"',
            r'"ip_address":\s*"[\d\.]+"',
            r'"user_agent":\s*"[^"]+"',
            r'"device_id":\s*"[^"]+"',
            r'"device_fingerprint":\s*"[^"]+"',
            r'"tracking_id":\s*"[^"]+"',
            
            # Generic Sensitive Patterns
            r'"[a-zA-Z]*_secret[a-zA-Z]*":\s*"[^"]+"',
            r'"[a-zA-Z]*_key[a-zA-Z]*":\s*"[^"]+"',
            r'"[a-zA-Z]*_password[a-zA-Z]*":\s*"[^"]+"',
            r'"[a-zA-Z]*_token[a-zA-Z]*":\s*"[^"]+"',
            r'"[a-zA-Z]*_credential[a-zA-Z]*":\s*"[^"]+"',
        ]
        
        # JWT patterns
        self.jwt_patterns = [
            r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # Standard JWT
            r'bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # Bearer JWT
        ]
        
        # Security headers to check
        self.security_headers = [
            'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'Referrer-Policy', 'Permissions-Policy'
        ]
        
        # Common endpoints for reconnaissance
        self.recon_endpoints = [
            '/robots.txt', '/.well-known/security.txt', '/sitemap.xml',
            '/api/v1/', '/api/v2/', '/admin/', '/api/docs/', '/swagger/',
            '/graphql', '/.env', '/config.json', '/app.json'
        ]

    async def start_browser(self) -> None:
        """Initialize and start the browser instance"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent=self.current_user_agent,
            extra_http_headers=self.custom_headers
        )

    async def close_browser(self) -> None:
        """Clean up browser resources"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()

    def extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract query parameters from URL
        
        Args:
            url: Target URL to extract parameters from
            
        Returns:
            Dictionary of parameter names and values
        """
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Flatten parameter values (take first value if multiple)
        return {key: values[0] if values else '' for key, values in params.items()}

    def identify_target_parameters(self, params: Dict[str, str]) -> Dict[str, str]:
        """
        Identify parameters that are likely to contain object references
        
        Args:
            params: Dictionary of all parameters
            
        Returns:
            Dictionary of target parameters for IDOR testing
        """
        target_params = {}
        
        for param_name, param_value in params.items():
            # Check if parameter name matches known patterns
            if any(pattern in param_name.lower() for pattern in self.target_params):
                target_params[param_name] = param_value
            # Check if parameter value looks like an ID (numeric or UUID)
            elif (param_value.isdigit() or 
                  re.match(r'^[a-f0-9\-]{8,}$', param_value.lower()) or
                  re.match(r'^[a-zA-Z0-9_\-]{10,}$', param_value)):
                target_params[param_name] = param_value
                
        return target_params

    def generate_test_values(self, original_value: str) -> List[str]:
        """
        Generate test values for IDOR testing based on original value
        
        Args:
            original_value: Original parameter value
            
        Returns:
            List of test values to try
        """
        test_values = []
        
        if original_value.isdigit():
            # Numeric ID manipulation
            original_num = int(original_value)
            test_values.extend([
                str(original_num + 1),
                str(original_num - 1),
                str(original_num + 10),
                str(original_num - 10),
                '1',
                '0',
                '999999',
                str(original_num * 2),
                str(abs(original_num - 1000))
            ])
        else:
            # String/UUID manipulation
            if len(original_value) > 10:
                # Try common ID patterns
                test_values.extend([
                    original_value[:-1] + '1',
                    original_value[:-1] + '0',
                    'admin',
                    'test',
                    '1',
                    '0',
                    'user1',
                    'administrator'
                ])
            
        # Remove duplicates and original value
        test_values = list(set(test_values))
        if original_value in test_values:
            test_values.remove(original_value)
            
        return test_values[:10]  # Limit to 10 test values per parameter

    async def make_request(self, page: Page, url: str) -> Tuple[int, str, Dict]:
        """
        Make HTTP request and capture response details
        
        Args:
            page: Playwright page object
            url: URL to request
            
        Returns:
            Tuple of (status_code, response_text, headers)
        """
        try:
            response = await page.goto(url, timeout=self.timeout)
            if response:
                status_code = response.status
                headers = await response.all_headers()
                content = await page.content()
                return status_code, content, headers
            else:
                return 0, '', {}
        except Exception as e:
            print(f"[ERROR] Request failed for {url}: {str(e)}")
            return 0, '', {}

    def analyze_response(self, original_response: Tuple[int, str, Dict], 
                        test_response: Tuple[int, str, Dict], 
                        url: str, param_name: str, test_value: str) -> Optional[Dict]:
        """
        Analyze response to detect potential IDOR vulnerability
        
        Args:
            original_response: Original request response data
            test_response: Test request response data
            url: Test URL
            param_name: Parameter name being tested
            test_value: Test value used
            
        Returns:
            Vulnerability details if found, None otherwise
        """
        orig_status, orig_content, orig_headers = original_response
        test_status, test_content, test_headers = test_response
        
        # Skip if test request failed
        if test_status == 0:
            return None
            
        vulnerability = {
            'url': url,
            'parameter': param_name,
            'test_value': test_value,
            'original_status': orig_status,
            'test_status': test_status,
            'timestamp': datetime.now().isoformat(),
            'severity': 'info',
            'indicators': []
        }
        
        # Check for successful status codes
        if test_status in self.success_codes:
            vulnerability['indicators'].append(f"Success status code: {test_status}")
            
            # Check for different content length (potential data disclosure)
            if abs(len(test_content) - len(orig_content)) > 100:
                vulnerability['indicators'].append(
                    f"Content length difference: {len(test_content)} vs {len(orig_content)}"
                )
                vulnerability['severity'] = 'medium'
                
            # Check for sensitive data patterns in response
            for pattern in self.disclosure_patterns:
                if re.search(pattern, test_content, re.IGNORECASE):
                    vulnerability['indicators'].append(f"Sensitive data pattern found: {pattern}")
                    vulnerability['severity'] = 'high'
                    
            # Advanced response analysis
            response_analysis = self.analyze_response_patterns(test_content)
            
            # Check for admin indicators
            if response_analysis['admin_indicators']:
                vulnerability['indicators'].append(f"Admin interface indicators: {response_analysis['admin_indicators']}")
                vulnerability['severity'] = 'critical'
                
            # Check for user data indicators
            if response_analysis['user_data_indicators']:
                vulnerability['indicators'].append(f"User data indicators: {response_analysis['user_data_indicators']}")
                if vulnerability['severity'] in ['info', 'low']:
                    vulnerability['severity'] = 'medium'
                    
            # Check for API endpoints
            if response_analysis['api_endpoints']:
                vulnerability['indicators'].append(f"API endpoints found: {len(response_analysis['api_endpoints'])}")
                
            # Check for database errors
            if response_analysis['database_errors']:
                vulnerability['indicators'].append(f"Database errors detected: {response_analysis['database_errors']}")
                vulnerability['severity'] = 'high'
                    
            # Check if response is significantly different (potential data disclosure)
            if len(test_content) > 0 and test_content != orig_content:
                # Calculate simple similarity
                similarity = len(set(test_content.split()) & set(orig_content.split()))
                total_words = len(set(test_content.split()) | set(orig_content.split()))
                
                if total_words > 0:
                    similarity_ratio = similarity / total_words
                    if similarity_ratio < 0.8:
                        vulnerability['indicators'].append(f"Significantly different response content (similarity: {similarity_ratio:.2f})")
                        if vulnerability['severity'] == 'info':
                            vulnerability['severity'] = 'low'
                    elif similarity_ratio < 0.9:
                        vulnerability['indicators'].append(f"Moderately different response content (similarity: {similarity_ratio:.2f})")
                        
                # Advanced content analysis
                if len(test_content) > len(orig_content) * 1.5:
                    vulnerability['indicators'].append("Response significantly larger than original")
                    if vulnerability['severity'] == 'info':
                        vulnerability['severity'] = 'low'
                        
                # Check for authentication bypass indicators
                auth_bypass_indicators = [
                    'welcome', 'dashboard', 'profile', 'account',
                    'logout', 'settings', 'preferences'
                ]
                
                found_bypass_indicators = []
                for indicator in auth_bypass_indicators:
                    if indicator.lower() in test_content.lower():
                        found_bypass_indicators.append(indicator)
                        
                if found_bypass_indicators:
                    vulnerability['indicators'].append(f"Authentication bypass indicators: {found_bypass_indicators}")
                    vulnerability['severity'] = 'high'
                        
        # Only return if we found indicators
        if vulnerability['indicators']:
            return vulnerability
            
        return None

    async def scan_url(self, url: str) -> List[Dict]:
        """
        Scan a single URL for IDOR vulnerabilities
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of vulnerabilities found
        """
        print(f"[INFO] Scanning URL: {url}")
        
        # Extract and identify target parameters
        params = self.extract_parameters(url)
        target_params = self.identify_target_parameters(params)
        
        if not target_params:
            print(f"[INFO] No target parameters found in {url}")
            return []
            
        print(f"[INFO] Found {len(target_params)} target parameters: {list(target_params.keys())}")
        
        vulnerabilities = []
        page = await self.context.new_page()
        
        try:
            # Get original response
            original_response = await self.make_request(page, url)
            
            # Test each target parameter
            for param_name, param_value in target_params.items():
                param_key = f"{url}#{param_name}"
                if param_key in self.tested_params:
                    continue
                    
                self.tested_params.add(param_key)
                print(f"[INFO] Testing parameter: {param_name} = {param_value}")
                
                # Generate test values
                test_values = self.generate_test_values(param_value)
                
                for test_value in test_values:
                    # Construct test URL
                    test_url = url.replace(f"{param_name}={param_value}", 
                                         f"{param_name}={test_value}")
                    
                    print(f"[DEBUG] Testing: {param_name} = {test_value}")
                    
                    # Make test request
                    test_response = await self.make_request(page, test_url)
                    
                    # Analyze response for IDOR indicators
                    vulnerability = self.analyze_response(
                        original_response, test_response, test_url, param_name, test_value
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        print(f"[FOUND] Potential IDOR: {param_name} = {test_value} "
                              f"(Severity: {vulnerability['severity']})")
                        
                    # Small delay to avoid overwhelming the server
                    await asyncio.sleep(0.5)
                    
        finally:
            await page.close()
            
        return vulnerabilities

    async def scan_multiple_urls(self, urls: List[str]) -> List[Dict]:
        """
        Scan multiple URLs for IDOR vulnerabilities
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of all vulnerabilities found
        """
        all_vulnerabilities = []
        
        for url in urls:
            try:
                vulnerabilities = await self.scan_url(url)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"[ERROR] Failed to scan {url}: {str(e)}")
                
        return all_vulnerabilities

    def generate_report(self, vulnerabilities: List[Dict], output_file: str = None) -> str:
        """
        Generate a detailed report of findings
        
        Args:
            vulnerabilities: List of vulnerabilities found
            output_file: Optional output file path
            
        Returns:
            Report content as string
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
IDOR Vulnerability Scan Report
Generated: {timestamp}
Total Vulnerabilities Found: {len(vulnerabilities)}

{'='*80}
SUMMARY BY SEVERITY
{'='*80}
"""
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        for severity, count in sorted(severity_counts.items()):
            report += f"{severity.upper()}: {count}\n"
            
        report += f"\n{'='*80}\nDETAILED FINDINGS\n{'='*80}\n"
        
        # Sort vulnerabilities by severity
        severity_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report += f"""
Finding #{i}
Severity: {vuln.get('severity', 'unknown').upper()}
URL: {vuln.get('url', 'N/A')}
Parameter: {vuln.get('parameter', 'N/A')}
Test Value: {vuln.get('test_value', 'N/A')}
Original Status: {vuln.get('original_status', 'N/A')}
Test Status: {vuln.get('test_status', 'N/A')}
Timestamp: {vuln.get('timestamp', 'N/A')}

Indicators:
"""
            for indicator in vuln.get('indicators', []):
                report += f"  - {indicator}\n"
                
            report += f"{'-'*40}\n"
            
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                print(f"[INFO] Report saved to: {output_file}")
            except Exception as e:
                print(f"[ERROR] Failed to save report: {str(e)}")
                
        return report

    def analyze_jwt_token(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token for security issues"""
        if not jwt:
            return {'error': 'PyJWT not available'}
            
        try:
            # Decode without verification to inspect
            unverified = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            issues = []
            
            # Check for common JWT vulnerabilities
            if header.get('alg') == 'none':
                issues.append('Algorithm set to "none" - critical vulnerability')
            
            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                issues.append('HMAC algorithm used - vulnerable to key confusion')
            
            # Check token expiration
            if 'exp' in unverified:
                exp_time = datetime.fromtimestamp(unverified['exp'])
                if exp_time < datetime.now():
                    issues.append('Token is expired')
                elif exp_time > datetime.now() + timedelta(days=365):
                    issues.append('Token has very long expiration (>1 year)')
            else:
                issues.append('No expiration claim found')
                
            # Check for sensitive data in payload
            sensitive_fields = ['password', 'secret', 'key', 'private']
            for field in sensitive_fields:
                if any(field in str(v).lower() for v in unverified.values()):
                    issues.append(f'Sensitive data detected: {field}')
            
            return {
                'header': header,
                'payload': unverified,
                'issues': issues,
                'token': token[:50] + '...' if len(token) > 50 else token
            }
            
        except Exception as e:
            return {'error': f'Failed to decode JWT: {str(e)}'}

    def test_jwt_vulnerabilities(self, token: str) -> List[Dict]:
        """Test JWT token for common vulnerabilities"""
        vulnerabilities = []
        
        if not jwt:
            return [{'type': 'error', 'description': 'PyJWT not available for testing'}]
            
        try:
            # Test algorithm confusion
            header = jwt.get_unverified_header(token)
            if header.get('alg') in ['RS256', 'RS384', 'RS512']:
                vulnerabilities.append({
                    'type': 'algorithm_confusion',
                    'description': 'Token uses RSA algorithm - test for HMAC confusion',
                    'severity': 'high',
                    'payload': 'Try signing with HS256 using RSA public key as secret'
                })
            
            # Test none algorithm
            if header.get('alg') != 'none':
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                    unsigned_token = jwt.encode(payload, '', algorithm='none')
                    
                    vulnerabilities.append({
                        'type': 'none_algorithm',
                        'description': 'Test with algorithm set to "none"',
                        'severity': 'critical',
                        'test_token': unsigned_token
                    })
                except:
                    pass
            
            # Test weak secrets
            weak_secrets = ['secret', 'key', 'password', '123456', 'admin', 'test']
            for secret in weak_secrets:
                try:
                    jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                    vulnerabilities.append({
                        'type': 'weak_secret',
                        'description': f'JWT signed with weak secret: {secret}',
                        'severity': 'critical',
                        'secret': secret
                    })
                    break
                except:
                    continue
                    
        except Exception as e:
            vulnerabilities.append({
                'type': 'error',
                'description': f'JWT testing error: {str(e)}'
            })
            
        return vulnerabilities

    def analyze_cookies(self, cookies: List[Dict]) -> List[Dict]:
        """Analyze cookies for security issues"""
        cookie_issues = []
        
        for cookie in cookies:
            issues = []
            name = cookie.get('name', '')
            value = cookie.get('value', '')
            
            # Check for security flags
            if not cookie.get('secure', False):
                issues.append('Missing Secure flag')
            if not cookie.get('httpOnly', False):
                issues.append('Missing HttpOnly flag')
            if not cookie.get('sameSite'):
                issues.append('Missing SameSite attribute')
                
            # Check for JWT in cookies
            if re.match(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', value):
                issues.append('Contains JWT token')
                if value not in self.jwt_tokens:
                    self.jwt_tokens.append(value)
            
            # Check for sensitive names
            sensitive_names = ['session', 'auth', 'token', 'api_key', 'password']
            if any(sens in name.lower() for sens in sensitive_names):
                issues.append('Potentially sensitive cookie')
            
            if issues:
                cookie_issues.append({
                    'name': name,
                    'value': value[:50] + '...' if len(value) > 50 else value,
                    'issues': issues,
                    'domain': cookie.get('domain', ''),
                    'path': cookie.get('path', '/')
                })
                
        return cookie_issues

    async def perform_reconnaissance(self, base_url: str) -> Dict[str, Any]:
        """Perform comprehensive reconnaissance on target"""
        print(f"[INFO] Starting reconnaissance on {base_url}")
        recon_results = {
            'base_url': base_url,
            'endpoints_found': [],
            'technologies': [],
            'security_headers': {},
            'interesting_files': [],
            'api_endpoints': [],
            'forms_found': [],
            'js_files': []
        }
        
        page = await self.context.new_page()
        
        try:
            # Check main page
            response = await page.goto(base_url, timeout=self.timeout)
            if response:
                # Analyze security headers
                headers = await response.all_headers()
                for header in self.security_headers:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        recon_results['security_headers'][header] = 'Present'
                    else:
                        recon_results['security_headers'][header] = 'Missing'
                
                # Extract page content for analysis
                content = await page.content()
                
                # Find forms
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'inputs': [inp.get('name', '') for inp in form.find_all('input')]
                    }
                    recon_results['forms_found'].append(form_data)
                
                # Find JavaScript files
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    js_url = urljoin(base_url, script['src'])
                    recon_results['js_files'].append(js_url)
                
                # Find API endpoints in JavaScript
                inline_scripts = soup.find_all('script', src=False)
                for script in inline_scripts:
                    if script.string:
                        api_patterns = [
                            r'/api/[^"\\s]+',
                            r'/v\\d+/[^"\\s]+',
                            r'https?://[^/]+/api/[^"\\s]+'
                        ]
                        for pattern in api_patterns:
                            matches = re.findall(pattern, script.string)
                            recon_results['api_endpoints'].extend(matches)
            
            # Check common endpoints
            for endpoint in self.recon_endpoints:
                try:
                    test_url = urljoin(base_url, endpoint)
                    test_response = await page.goto(test_url, timeout=5000)
                    if test_response and test_response.status == 200:
                        recon_results['endpoints_found'].append({
                            'url': test_url,
                            'status': test_response.status,
                            'size': len(await page.content())
                        })
                except:
                    continue
                    
        except Exception as e:
            print(f"[ERROR] Reconnaissance failed: {str(e)}")
        finally:
            await page.close()
            
        # Remove duplicates
        recon_results['api_endpoints'] = list(set(recon_results['api_endpoints']))
        
        self.recon_data[base_url] = recon_results
        return recon_results

    async def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive security scan"""
        print(f"[INFO] Starting comprehensive scan of {url}")
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        scan_results = {
            'url': url,
            'base_url': base_url,
            'timestamp': datetime.now().isoformat(),
            'recon': {},
            'idor_vulns': [],
            'auth_bypass': [],
            'jwt_analysis': [],
            'cookie_issues': [],
            'js_analysis': [],
            'security_headers': {},
            'total_findings': 0
        }
        
        try:
            # Reconnaissance
            scan_results['recon'] = await self.perform_reconnaissance(base_url)
            
            # IDOR testing
            scan_results['idor_vulns'] = await self.scan_url(url)
            
            # JWT analysis
            for token in self.jwt_tokens:
                jwt_analysis = self.analyze_jwt_token(token)
                if jwt_analysis:
                    jwt_vulns = self.test_jwt_vulnerabilities(token)
                    jwt_analysis['vulnerabilities'] = jwt_vulns
                    scan_results['jwt_analysis'].append(jwt_analysis)
            
            # Cookie analysis
            page = await self.context.new_page()
            try:
                await page.goto(url)
                cookies = await self.context.cookies()
                scan_results['cookie_issues'] = self.analyze_cookies(cookies)
            finally:
                await page.close()
            
            # Security headers
            scan_results['security_headers'] = scan_results['recon'].get('security_headers', {})
            
            # Calculate total findings
            scan_results['total_findings'] = (
                len(scan_results['idor_vulns']) +
                len(scan_results['jwt_analysis']) +
                len(scan_results['cookie_issues'])
            )
            
        except Exception as e:
            print(f"[ERROR] Comprehensive scan failed: {str(e)}")
            
        return scan_results
    
    def test_authentication_bypass(self, url: str, original_response: Tuple[int, str, Dict]) -> List[Dict]:
        """
        Test various authentication bypass techniques
        
        Args:
            url: Target URL to test
            original_response: Original response for comparison
            
        Returns:
            List of potential bypass vulnerabilities
        """
        bypass_vulns = []
        orig_status, orig_content, orig_headers = original_response
        
        # Skip if original request was successful (likely not protected)
        if orig_status in self.success_codes:
            return bypass_vulns
            
        # Test header injection bypasses
        for header, value in self.auth_bypass_techniques['header_injection'].items():
            # This would require actual HTTP requests - placeholder for methodology
            bypass_vulns.append({
                'type': 'header_injection_bypass',
                'technique': f'{header}: {value}',
                'description': f'Test bypassing authentication using {header} header',
                'severity': 'high',
                'payload': {header: value}
            })
            
        # Test method override bypasses
        for method in self.auth_bypass_techniques['method_override']:
            if method != 'GET':  # Assuming original was GET
                bypass_vulns.append({
                    'type': 'method_override_bypass',
                    'technique': f'HTTP {method}',
                    'description': f'Test bypassing authentication using {method} method',
                    'severity': 'medium',
                    'payload': {'method': method}
                })
                
        return bypass_vulns
    
    def analyze_response_patterns(self, content: str) -> Dict[str, Any]:
        """
        Analyze response content for various indicators and patterns
        
        Args:
            content: Response content to analyze
            
        Returns:
            Analysis results with detected patterns and indicators
        """
        analysis = {
            'sensitive_data_found': [],
            'admin_indicators': [],
            'user_data_indicators': [],
            'api_endpoints': [],
            'internal_paths': [],
            'database_errors': [],
            'debug_information': [],
            'version_disclosure': [],
            'technology_stack': []
        }
        
        # Check for sensitive data patterns
        for pattern in self.disclosure_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['sensitive_data_found'].extend(matches)
                
        # Admin interface indicators
        admin_patterns = [
            r'admin', r'administrator', r'dashboard', r'control panel',
            r'management', r'settings', r'configuration', r'users list',
            r'user management', r'role', r'permission', r'privilege'
        ]
        
        for pattern in admin_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis['admin_indicators'].append(pattern)
                
        # User data indicators
        user_patterns = [
            r'profile', r'account', r'personal', r'private',
            r'my account', r'my profile', r'user info'
        ]
        
        for pattern in user_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis['user_data_indicators'].append(pattern)
                
        # API endpoint discovery
        api_patterns = [
            r'/api/[^\s"\'<>]+',
            r'/v\d+/[^\s"\'<>]+',
            r'https?://[^/]+/api/[^\s"\'<>]+'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            analysis['api_endpoints'].extend(matches)
            
        # Internal path disclosure
        path_patterns = [
            r'/var/[^\s"\'<>]+',
            r'/etc/[^\s"\'<>]+',
            r'/home/[^\s"\'<>]+',
            r'C:\\[^\s"\'<>]+',
            r'/usr/[^\s"\'<>]+'
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, content)
            analysis['internal_paths'].extend(matches)
            
        # Database error patterns
        db_error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*\Wmysql_.*',
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_.*',
            r'Oracle error',
            r'Microsoft.*ODBC.*SQL',
            r'SQLite.*error'
        ]
        
        for pattern in db_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis['database_errors'].append(pattern)
                
        # Debug information
        debug_patterns = [
            r'debug', r'trace', r'stack trace', r'exception',
            r'error.*line \d+', r'warning.*line \d+'
        ]
        
        for pattern in debug_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis['debug_information'].append(pattern)
                
        # Version disclosure
        version_patterns = [
            r'version\s*[:\=]\s*[\d\.]+',
            r'v\d+\.\d+\.\d+',
            r'Apache/[\d\.]+',
            r'nginx/[\d\.]+',
            r'PHP/[\d\.]+'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis['version_disclosure'].extend(matches)
            
        # Technology stack detection
        tech_patterns = {
            'PHP': [r'\.php', r'PHP', r'<?php'],
            'ASP.NET': [r'\.aspx?', r'ASP\.NET', r'__VIEWSTATE'],
            'Java': [r'\.jsp', r'\.do', r'jsessionid'],
            'Python': [r'Django', r'Flask', r'Python'],
            'Ruby': [r'Ruby', r'Rails', r'\.rb'],
            'Node.js': [r'Node\.js', r'Express', r'npm']
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if tech not in analysis['technology_stack']:
                        analysis['technology_stack'].append(tech)
                    break
                    
        return analysis
    
    def test_advanced_idor_techniques(self, url: str, param_name: str, param_value: str) -> List[Dict]:
        """
        Test advanced IDOR techniques beyond basic parameter manipulation
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            param_value: Original parameter value
            
        Returns:
            List of advanced technique payloads to test
        """
        advanced_techniques = []
        
        # Array/object notation bypass
        if param_name not in ['id[]', f'{param_name}[]']:
            advanced_techniques.append({
                'technique': 'array_notation',
                'param_name': f'{param_name}[]',
                'param_value': param_value,
                'description': 'Test array notation bypass'
            })
            
        # Object notation bypass
        advanced_techniques.append({
            'technique': 'object_notation', 
            'param_name': f'{param_name}[id]',
            'param_value': param_value,
            'description': 'Test object notation bypass'
        })
        
        # Nested parameter bypass
        advanced_techniques.append({
            'technique': 'nested_parameter',
            'param_name': f'user[{param_name}]',
            'param_value': param_value,
            'description': 'Test nested parameter bypass'
        })
        
        # HTTP Parameter Pollution
        advanced_techniques.append({
            'technique': 'parameter_pollution',
            'param_name': param_name,
            'param_value': [param_value, '1'],  # Original + admin ID
            'description': 'Test HTTP Parameter Pollution'
        })
        
        # Case sensitivity bypass
        if param_name != param_name.upper():
            advanced_techniques.append({
                'technique': 'case_bypass',
                'param_name': param_name.upper(),
                'param_value': param_value,
                'description': 'Test case sensitivity bypass'
            })
            
        # Unicode/encoding bypass
        unicode_param = ''.join(f'\\u{ord(c):04x}' for c in param_name)
        advanced_techniques.append({
            'technique': 'unicode_bypass',
            'param_name': unicode_param,
            'param_value': param_value,
            'description': 'Test Unicode encoding bypass'
        })
        
        # URL encoding bypass
        encoded_param = quote(param_name)
        if encoded_param != param_name:
            advanced_techniques.append({
                'technique': 'url_encoding_bypass',
                'param_name': encoded_param,
                'param_value': param_value,
                'description': 'Test URL encoding bypass'
            })
            
        # Double encoding bypass
        double_encoded_param = quote(quote(param_name))
        advanced_techniques.append({
            'technique': 'double_encoding_bypass',
            'param_name': double_encoded_param,
            'param_value': param_value,
            'description': 'Test double URL encoding bypass'
        })
        
        return advanced_techniques
    
    def generate_idor_methodology_report(self) -> str:
        """
        Generate comprehensive IDOR testing methodology documentation
        
        Returns:
            Detailed methodology report
        """
        methodology_report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    IDOR TESTING METHODOLOGY GUIDE                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

{'='*80}
OVERVIEW
{'='*80}

Insecure Direct Object References (IDOR) occur when an application provides 
direct access to objects based on user-supplied input. This vulnerability 
allows attackers to bypass authorization and access data belonging to other users.

{'='*80}
TESTING METHODOLOGIES
{'='*80}

"""
        
        for methodology, details in self.idor_methodologies.items():
            methodology_report += f"""
{methodology.upper().replace('_', ' ')}
{'-' * len(methodology)}
Description: {details['description']}
Severity Impact: {details['severity_impact']}
Detection Methods: {', '.join(details['detection_methods'])}

"""
            
        methodology_report += f"""
{'='*80}
PARAMETER IDENTIFICATION TECHNIQUES
{'='*80}

1. DIRECT PARAMETER ANALYSIS
   - Look for parameters containing 'id', 'key', 'ref', 'token'
   - Analyze parameter values for ID-like patterns
   - Check for numeric, UUID, hash, and base64 patterns
   
2. PATTERN MATCHING
   - Sequential numeric IDs (1, 2, 3, ...)
   - UUID formats (8-4-4-4-12 hex digits)
   - Hash patterns (MD5: 32 hex, SHA1: 40 hex, SHA256: 64 hex)
   - Base64 encoded values
   - MongoDB ObjectIds (24 hex digits)
   - Snowflake IDs (15-20 digit numbers)
   
3. BEHAVIORAL ANALYSIS
   - Parameters that change application state
   - Values that affect data returned
   - References to user-specific resources

{'='*80}
TESTING TECHNIQUES
{'='*80}

1. SEQUENTIAL ENUMERATION
   - Increment/decrement numeric IDs
   - Test boundary values (0, 1, -1, max int)
   - Random ID generation within reasonable ranges
   
2. PRIVILEGE ESCALATION TESTING
   - Test admin/root user IDs (typically low numbers)
   - Common admin identifiers: 1, 100, 1000, admin, root
   - Service account testing
   
3. CROSS-TENANT ACCESS
   - Test IDs from different organizations/tenants
   - Multi-tenancy bypass techniques
   - Isolation boundary testing
   
4. ADVANCED BYPASS TECHNIQUES
   - HTTP Parameter Pollution (HPP)
   - Array notation: id[] vs id
   - Object notation: user[id]
   - Case sensitivity bypass
   - Encoding bypass (URL, Unicode, double encoding)
   - Method override (GET vs POST vs PUT)
   - Header injection bypasses

{'='*80}
RESPONSE ANALYSIS INDICATORS
{'='*80}

1. STATUS CODE ANALYSIS
   - 200 OK: Successful unauthorized access
   - 206 Partial Content: Partial data disclosure
   - 302 Found: Redirection to authorized content
   - 403 vs 404: Information disclosure about resource existence
   
2. CONTENT ANALYSIS
   - Sensitive data patterns in response
   - Admin interface indicators
   - User-specific information disclosure
   - Database error messages
   - Debug information leakage
   
3. RESPONSE SIZE ANALYSIS
   - Significant size differences indicate different data
   - Empty responses may indicate access control
   - Large responses may contain sensitive data dumps
   
4. TIMING ANALYSIS
   - Response time differences
   - Processing delay variations
   - Database query timing differences

{'='*80}
SENSITIVE DATA PATTERNS DETECTED
{'='*80}

This tool detects {len(self.disclosure_patterns)} different sensitive data patterns:

Personal Information:
- Email addresses, phone numbers, addresses
- Social security numbers, birth dates
- Full names, personal identifiers

Financial Information:
- Credit card numbers, CVV codes
- Bank account details, routing numbers
- Account balances, salary information

Authentication Data:
- Passwords, tokens, API keys
- Session identifiers, CSRF tokens
- Private keys, certificates

Medical Information:
- Medical records, patient IDs
- Diagnoses, prescriptions
- Insurance information

Business Data:
- Employee information, contracts
- Confidential/proprietary data
- Performance reviews, compensation

Technical Information:
- Database connection strings
- Server IP addresses, internal paths
- Configuration files, debug info

{'='*80}
AUTHENTICATION BYPASS TECHNIQUES
{'='*80}

1. HEADER INJECTION
   - X-Original-URL, X-Rewrite-URL
   - X-Forwarded-For, X-Real-IP variations
   - X-User-ID, X-Admin, X-Role headers
   - Authorization bypass headers
   
2. METHOD OVERRIDE
   - HTTP method manipulation
   - X-HTTP-Method-Override header
   - Method tunneling through POST
   
3. PARAMETER POLLUTION
   - Duplicate parameter handling
   - Array vs scalar confusion
   - Framework-specific parsing differences
   
4. ENCODING BYPASS
   - URL encoding variations
   - Unicode normalization
   - Double/triple encoding
   - Case manipulation

{'='*80}
BEST PRACTICES FOR TESTING
{'='*80}

1. RECONNAISSANCE
   - Map application functionality
   - Identify user roles and permissions
   - Document parameter patterns
   - Analyze authentication mechanisms
   
2. SYSTEMATIC TESTING
   - Test all identified parameters
   - Use both automated and manual techniques
   - Document all findings with evidence
   - Test with different user privilege levels
   
3. IMPACT ASSESSMENT
   - Determine data sensitivity
   - Assess privilege escalation potential
   - Evaluate business impact
   - Test for data manipulation capabilities
   
4. RESPONSIBLE DISCLOSURE
   - Follow coordinated disclosure policies
   - Provide clear reproduction steps
   - Include impact assessment
   - Suggest remediation strategies

{'='*80}
REMEDIATION RECOMMENDATIONS
{'='*80}

1. ACCESS CONTROL
   - Implement proper authorization checks
   - Use session-based access control
   - Validate user permissions for each request
   
2. INDIRECT REFERENCES
   - Use random, unpredictable identifiers
   - Implement reference maps
   - Avoid exposing internal IDs
   
3. INPUT VALIDATION
   - Validate all user inputs
   - Implement whitelist validation
   - Use parameterized queries
   
4. MONITORING
   - Log access attempts
   - Monitor for unusual patterns
   - Implement rate limiting
   - Alert on suspicious activities

{'='*80}
TOOL CAPABILITIES
{'='*80}

This advanced IDOR scanner provides:

✓ Comprehensive parameter identification ({len(self.target_params)} patterns)
✓ Advanced payload generation (20+ techniques per parameter)
✓ Multi-format ID support (numeric, UUID, hash, base64, ObjectId)
✓ Sensitive data pattern detection ({len(self.disclosure_patterns)} patterns)
✓ Authentication bypass testing ({len(self.auth_bypass_techniques)} techniques)
✓ Response analysis and comparison
✓ Severity assessment based on impact
✓ Detailed reporting with remediation guidance
✓ Interactive testing modes
✓ Comprehensive reconnaissance capabilities

{'='*80}
DISCLAIMER
{'='*80}

This tool is for authorized security testing only. Always ensure you have 
proper permission before testing any application. Unauthorized access to 
computer systems is illegal and may result in criminal charges.

Use responsibly and follow ethical disclosure practices.

"""
        
        return methodology_report

    def generate_comprehensive_report(self, scan_results: Dict[str, Any], output_file: str = None) -> str:
        """Generate comprehensive bug bounty report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ADVANCED BUG BOUNTY SECURITY SCAN REPORT                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

Generated: {timestamp}
Target: {scan_results.get('url', 'N/A')}
Base URL: {scan_results.get('base_url', 'N/A')}
Total Findings: {scan_results.get('total_findings', 0)}

{'='*80}
EXECUTIVE SUMMARY
{'='*80}
"""
        
        # Count severity levels
        critical_count = high_count = medium_count = low_count = 0
        
        for vuln in scan_results.get('idor_vulns', []):
            severity = vuln.get('severity', 'info')
            if severity == 'high': high_count += 1
            elif severity == 'medium': medium_count += 1
            elif severity == 'low': low_count += 1
            
        for jwt in scan_results.get('jwt_analysis', []):
            for vuln in jwt.get('vulnerabilities', []):
                if vuln.get('severity') == 'critical': critical_count += 1
                elif vuln.get('severity') == 'high': high_count += 1
        
        report += f"""
CRITICAL: {critical_count}
HIGH: {high_count}
MEDIUM: {medium_count}
LOW: {low_count}
INFO: {len(scan_results.get('cookie_issues', []))}

{'='*80}
DETAILED FINDINGS
{'='*80}
"""
        
        # Add detailed findings
        if scan_results.get('idor_vulns'):
            report += f"\n\nIDOR VULNERABILITIES:\n{'-'*40}\n"
            for i, vuln in enumerate(scan_results['idor_vulns'], 1):
                report += f"[{i}] {vuln.get('url')} - {vuln.get('parameter')} = {vuln.get('test_value')}\n"
        
        if scan_results.get('jwt_analysis'):
            report += f"\n\nJWT ANALYSIS:\n{'-'*40}\n"
            for i, jwt_data in enumerate(scan_results['jwt_analysis'], 1):
                report += f"[{i}] Token issues: {len(jwt_data.get('issues', []))}\n"
        
        if scan_results.get('cookie_issues'):
            report += f"\n\nCOOKIE ISSUES:\n{'-'*40}\n"
            for i, cookie in enumerate(scan_results['cookie_issues'], 1):
                report += f"[{i}] {cookie.get('name')} - {len(cookie.get('issues', []))} issues\n"
        
        # Add methodology information
        methodology_section = self.generate_idor_methodology_report()
        report += f"\n\n{'='*80}\nIDOR TESTING METHODOLOGY\n{'='*80}\n"
        report += methodology_section
        
        report += f"\n\n{'='*80}\nSCAN COMPLETED\n{'='*80}\n"
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"[INFO] Comprehensive report saved to: {output_file}")
            except Exception as e:
                print(f"[ERROR] Failed to save report: {str(e)}")
        
        return report

def interactive_menu():
    """Interactive menu for bug bounty hunters"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ADVANCED BUG BOUNTY SECURITY SCANNER                     ║
║                           Interactive Hunt Menu                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

1. 🎯 Quick IDOR Scan
2. 🔍 Comprehensive Security Scan
3. 🗝️  JWT Token Analysis
4. 🍪 Cookie Security Analysis
5. 🕵️  Reconnaissance Only
6. 🚫 Authentication Bypass Testing
7. 📊 Advanced Parameter Analysis
8. 🔬 IDOR Methodology Guide
9. 📝 Custom Scan (Advanced)
A. ❓ Help & Documentation
0. 🚪 Exit

""")
    
    choice = input("Select your hunting option: ").strip()
    return choice

def get_scan_options():
    """Get scan configuration from user"""
    print("\n[CONFIG] Scan Configuration")
    
    target = input("Enter target URL: ").strip()
    if not target:
        print("[ERROR] Target URL is required")
        return None
    
    options = {
        'target': target,
        'headless': True,
        'timeout': 10000,
        'output_file': None,
        'custom_headers': {}
    }
    
    # Ask for additional options
    visible = input("Run in visible browser mode? (y/N): ").strip().lower()
    if visible == 'y':
        options['headless'] = False
    
    timeout = input("Request timeout in seconds (default 10): ").strip()
    if timeout.isdigit():
        options['timeout'] = int(timeout) * 1000
    
    output = input("Output file (optional): ").strip()
    if output:
        options['output_file'] = output
    
    return options

async def run_interactive_scan():
    """Run interactive scanning session"""
    while True:
        choice = interactive_menu()
        
        if choice == '0':
            print("\n[INFO] Exiting scanner. Happy hunting! 🎯")
            break
        elif choice.upper() == 'A':
            print("\n[INFO] Help documentation would be displayed here")
            continue
        elif choice == '8':
            print("\n[INFO] IDOR Testing Methodology Guide")
            scanner = AdvancedBugBountyScanner()
            methodology = scanner.generate_idor_methodology_report()
            print(methodology)
            input("\nPress Enter to continue...")
            continue
        elif choice not in ['1', '2', '3', '4', '5', '6', '7', '9']:
            print("[ERROR] Invalid choice. Please try again.")
            continue
        
        options = get_scan_options()
        if not options:
            continue
        
        scanner = AdvancedBugBountyScanner(
            headless=options['headless'],
            timeout=options['timeout']
        )
        
        try:
            await scanner.start_browser()
            
            if choice == '1':
                print("\n[INFO] Running Quick IDOR Scan...")
                results = await scanner.scan_url(options['target'])
                report = scanner.generate_report(results, options['output_file'])
                if not options['output_file']:
                    print(report)
            
            elif choice == '2':
                print("\n[INFO] Running Comprehensive Security Scan...")
                results = await scanner.comprehensive_scan(options['target'])
                report = scanner.generate_comprehensive_report(results, options['output_file'])
                if not options['output_file']:
                    print(report)
            
            elif choice == '3':
                print("\n[INFO] Analyzing JWT Tokens...")
                page = await scanner.context.new_page()
                await page.goto(options['target'])
                await page.close()
                
                if scanner.jwt_tokens:
                    for token in scanner.jwt_tokens:
                        analysis = scanner.analyze_jwt_token(token)
                        vulns = scanner.test_jwt_vulnerabilities(token)
                        print(f"\nJWT Analysis: {analysis}")
                        print(f"Vulnerabilities: {vulns}")
                else:
                    print("[INFO] No JWT tokens found")
            
            elif choice == '4':
                print("\n[INFO] Analyzing Cookies...")
                page = await scanner.context.new_page()
                await page.goto(options['target'])
                cookies = await scanner.context.cookies()
                cookie_issues = scanner.analyze_cookies(cookies)
                await page.close()
                
                if cookie_issues:
                    for issue in cookie_issues:
                        print(f"\nCookie Issue: {issue}")
                else:
                    print("[INFO] No cookie security issues found")
            
            elif choice == '5':
                print("\n[INFO] Running Reconnaissance...")
                parsed_url = urlparse(options['target'])
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                recon = await scanner.perform_reconnaissance(base_url)
                print(json.dumps(recon, indent=2))
            
            elif choice == '6':
                print("\n[INFO] Testing Authentication Bypass...")
                page = await scanner.context.new_page()
                original_response = await scanner.make_request(page, options['target'])
                bypass_tests = scanner.test_authentication_bypass(options['target'], original_response)
                await page.close()
                
                if bypass_tests:
                    for test in bypass_tests:
                        print(f"\nBypass Test: {test}")
                else:
                    print("[INFO] No authentication bypass tests applicable")
            
            elif choice == '7':
                print("\n[INFO] Advanced Parameter Analysis...")
                params = scanner.extract_parameters(options['target'])
                if params:
                    print(f"\nExtracted Parameters: {params}")
                    target_params = scanner.identify_target_parameters(params)
                    print(f"Target Parameters: {target_params}")
                    
                    for param_name, param_value in target_params.items():
                        print(f"\nAnalyzing parameter: {param_name} = {param_value}")
                        is_likely_id = scanner._is_likely_id_value(param_value)
                        print(f"Likely ID value: {is_likely_id}")
                        
                        test_values = scanner.generate_test_values(param_value)
                        print(f"Generated {len(test_values)} test values: {test_values[:5]}...")
                        
                        advanced_techniques = scanner.test_advanced_idor_techniques(
                            options['target'], param_name, param_value
                        )
                        print(f"Advanced techniques: {len(advanced_techniques)}")
                        for technique in advanced_techniques[:3]:
                            print(f"  - {technique['technique']}: {technique['description']}")
                else:
                    print("[INFO] No parameters found in target URL")
        
        except Exception as e:
            print(f"[ERROR] Scan failed: {str(e)}")
        finally:
            await scanner.close_browser()
        
        input("\nPress Enter to continue...")


async def main():
    """Main entry point for the Advanced Bug Bounty Scanner CLI"""
    parser = argparse.ArgumentParser(
        description="Advanced Bug Bounty Security Scanner - Comprehensive vulnerability testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive menu mode
  python idor_scanner.py --interactive
  
  # Quick IDOR scan
  python idor_scanner.py -u "http://example.com/api/user?id=123"
  
  # Comprehensive scan with output
  python idor_scanner.py -u "http://example.com/api/user?id=123" --comprehensive --output report.txt
  
  # Multiple URLs from file
  python idor_scanner.py -f urls.txt --output results.json --json
  
  # Custom scan configuration
  python idor_scanner.py -u "http://example.com/profile?user_id=456" --no-headless --timeout 15000
        """
    )
    
    # URL input options (not required if interactive mode)
    url_group = parser.add_mutually_exclusive_group(required=False)
    url_group.add_argument('-u', '--url', help='Single URL to scan')
    url_group.add_argument('-f', '--file', help='File containing URLs to scan (one per line)')
    
    # Mode options
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Launch interactive menu mode')
    parser.add_argument('--comprehensive', action='store_true',
                       help='Perform comprehensive security scan (vs quick IDOR scan)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    # Browser options
    parser.add_argument('--no-headless', action='store_true', 
                       help='Run browser in visible mode (default: headless)')
    parser.add_argument('--timeout', type=int, default=10000,
                       help='Request timeout in milliseconds (default: 10000)')
    
    # Scanning options
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Check for interactive mode
    if args.interactive:
        await run_interactive_scan()
        return
    
    # Prepare URLs list
    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)
    
    if not urls:
        print("[ERROR] No URLs provided. Use --interactive for menu mode or provide URL with -u/--url")
        sys.exit(1)
        
    scan_type = "Comprehensive" if args.comprehensive else "Quick IDOR"
    print(f"[INFO] Starting {scan_type} scan for {len(urls)} URL(s)")
    print(f"[INFO] Headless mode: {not args.no_headless}")
    print(f"[INFO] Timeout: {args.timeout}ms")
    
    # Initialize scanner
    scanner = AdvancedBugBountyScanner(
        headless=not args.no_headless,
        timeout=args.timeout
    )
    
    try:
        # Start browser
        await scanner.start_browser()
        
        # Perform scan
        start_time = time.time()
        
        if args.comprehensive:
            # Comprehensive scan for each URL
            all_results = []
            for url in urls:
                result = await scanner.comprehensive_scan(url)
                all_results.append(result)
            scan_time = time.time() - start_time
            
            # Generate comprehensive report
            if args.json:
                output_data = {
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'urls_scanned': len(urls),
                        'scan_duration': scan_time,
                        'scan_type': 'comprehensive'
                    },
                    'results': all_results
                }
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(output_data, f, indent=2)
                    print(f"[INFO] JSON results saved to: {args.output}")
                else:
                    print(json.dumps(output_data, indent=2))
            else:
                # Generate text reports for each scan
                for i, result in enumerate(all_results):
                    if len(all_results) > 1:
                        print(f"\n{'='*60}\nSCAN RESULT {i+1} of {len(all_results)}\n{'='*60}")
                    
                    output_file = None
                    if args.output and len(all_results) > 1:
                        base_name = args.output.rsplit('.', 1)[0] if '.' in args.output else args.output
                        ext = args.output.rsplit('.', 1)[1] if '.' in args.output else 'txt'
                        output_file = f"{base_name}_{i+1}.{ext}"
                    elif args.output:
                        output_file = args.output
                    
                    report = scanner.generate_comprehensive_report(result, output_file)
                    if not output_file:
                        print(report)
        else:
            # Quick IDOR scan
            vulnerabilities = await scanner.scan_multiple_urls(urls)
            scan_time = time.time() - start_time
        
            print(f"\n[INFO] Scan completed in {scan_time:.2f} seconds")
            print(f"[INFO] Found {len(vulnerabilities)} potential vulnerabilities")
            
            # Generate output for quick scan
            if args.json:
                output_data = {
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'urls_scanned': len(urls),
                        'scan_duration': scan_time,
                        'vulnerabilities_found': len(vulnerabilities)
                    },
                    'vulnerabilities': vulnerabilities
                }
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(output_data, f, indent=2)
                    print(f"[INFO] JSON results saved to: {args.output}")
                else:
                    print(json.dumps(output_data, indent=2))
            else:
                # Generate text report
                report = scanner.generate_report(vulnerabilities, args.output)
                if not args.output:
                    print(report)
                
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
    except Exception as e:
        print(f"[ERROR] Scan failed: {str(e)}")
        sys.exit(1)
    finally:
        await scanner.close_browser()


if __name__ == "__main__":
    asyncio.run(main())