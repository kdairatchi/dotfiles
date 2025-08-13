import asyncio
import json
from urllib.parse import urlparse, urljoin
import time
import aiohttp
import argparse
from pathlib import Path
import sys
import re
import logging
from datetime import datetime
import random
import ssl
import warnings
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Optional imports with better error handling
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    print("⚠️  Warning: playwright not installed. Install with: pip install playwright && playwright install")
    print("    Google dorking will be disabled.")
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None

try:
    from crawl4ai import AsyncWebCrawler
    CRAWL4AI_AVAILABLE = True
except ImportError:
    print("⚠️  Warning: crawl4ai not installed. Install with: pip install -U crawl4ai")
    print("    Deep scanning features will be disabled.")
    CRAWL4AI_AVAILABLE = False
    AsyncWebCrawler = None

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    print("⚠️  Warning: requests not installed. Install with: pip install requests")
    REQUESTS_AVAILABLE = False
    requests = None

class SwaggerDorkScanner:
    def __init__(self, target_domain=None, output_dir="swagger_results", verbose=True):
        self.verbose = verbose
        self.setup_logging()
        if self.verbose:
            print(f"🚀 Initializing SwaggerDorkScanner at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            if target_domain:
                print(f"🎯 Target domain: {target_domain}")
            else:
                print("🌐 Global scan mode (no specific domain)")
        self.swagger_paths = [
            "/api", "/api/", "api", "api/", "/api/api-docs", "/api/apidocs", "api/api-docs", "api/apidocs",
            "/api/api-docs/swagger.json", "/api/apidocs/swagger.json", "api/api-docs/swagger.json", "api/apidocs/swagger.json",
            "/api/api-docs/swagger.yaml", "/api/apidocs/swagger.yaml", "api/api-docs/swagger.yaml", "api/apidocs/swagger.yaml",
            "/api/doc", "api/doc", "/api/doc.json", "api/doc.json", "/api-docs/", "/api/docs/", "/api_docs", "api-docs",
            "api-docs/", "api/docs", "api/docs/", "api_docs", "/api-docs/swagger.json", "api-docs/swagger.json",
            "/api-docs/swagger.yaml", "api-docs/swagger.yaml", "api/documentation", "api/documentation/", "/api/help",
            "api/help", "/api/index.html", "api/index.html", "api/openapi.json", "api/openapi.yaml", "/api-reference",
            "api-reference", "/api/spec", "api/spec", "/api/spec/swagger.json", "api/spec/swagger.json",
            "/api/spec/swagger.yaml", "api/spec/swagger.yaml", "/api/__swagger__/", "/api/_swagger__/", "/api/swagger",
            "api/__swagger__/", "api/_swagger__/", "api/swagger", "api/swagger/", "/api/swagger_doc.json",
            "api/swagger_doc.json", "/api/swagger/index.html", "api/swagger/index.html", "/api/swagger.json",
            "api/swagger.json", "/api/swagger-resources", "api/swagger-resources", "/api/swagger-resources/restservices/v2/api-docs",
            "api/swagger-resources/restservices/v2/api-docs", "/api/swagger/static/index.html", "api/swagger/static/index.html",
            "/api/swagger/swagger-ui.html", "api/swagger/swagger-ui.html", "api/swagger-ui", "api/swagger-ui/", "/api/swagger-ui/"
        ]
        
        # Enhanced comprehensive dorks for global swagger discovery
        self.dorks = [
            # High-priority patterns (most likely to find live APIs)
            'intitle:"Swagger UI" -site:github.com -site:swagger.io -site:petstore',
            'inurl:"/swagger-ui.html" -site:github.com -site:swagger.io',
            'inurl:"/swagger-ui/" -site:github.com -site:swagger.io',
            'inurl:"/redoc" -site:github.com "API"',
            'inurl:"/docs" "FastAPI" -site:github.com',
            'inurl:"/api-docs" -site:swagger.io -site:github.com',
            'inurl:"/v2/api-docs" "swagger" -site:github.com',
            'inurl:"/v3/api-docs" "openapi" -site:github.com',
            'inurl:"/actuator/swagger-ui" -site:github.com',
            
            # Specific file types with high confidence
            'filetype:json "swagger" "paths" -site:github.com',
            'filetype:yaml "openapi" "info" -site:github.com',
            'filetype:yml "swagger" "definitions" -site:github.com',
            'inurl:"/swagger.json" -site:github.com',
            'inurl:"/swagger.yaml" -site:github.com',
            'inurl:"/openapi.json" -site:github.com',
            'inurl:"/openapi.yaml" -site:github.com',
            
            # Development/staging environments (high value targets)
            'inurl:"/swagger" (site:dev.* OR site:test.* OR site:staging.* OR site:beta.*)',
            'inurl:"/api-docs" (site:dev.* OR site:test.* OR site:staging.* OR site:beta.*)',
            'inurl:"/docs" (site:dev.* OR site:test.* OR site:staging.* OR site:beta.*)',
            
            # Cloud platforms (common hosting)
            'inurl:"/api" site:*.herokuapp.com "swagger"',
            'inurl:"/api" site:*.vercel.app "docs"',
            'inurl:"/api" site:*.netlify.app "swagger"',
            'inurl:"/api" site:*.azurewebsites.net "api-docs"',
            'inurl:"/api" site:*.amazonaws.com "swagger"',
            'inurl:"/swagger" site:*.firebaseapp.com',
            'inurl:"/docs" site:*.railway.app',
            'inurl:"/api-docs" site:*.render.com',
            
            # Framework-specific patterns
            'inurl:"/swagger/ui" "Spring Boot" -site:github.com',
            'inurl:"/swagger-resources" "Spring" -site:github.com',
            'inurl:"/swagger/v1/swagger.json" ".NET" -site:github.com',
            'inurl:"/api/documentation" "Laravel" -site:github.com',
            'inurl:"/docs/api" "Scribe" -site:github.com',
            'inurl:"/api/schema" "Django" -site:github.com',
            'inurl:"/graphql" OR inurl:"/graphiql" -site:github.com',
            
            # Popular API gateway patterns
            'inurl:"/api/swagger" "Kong" OR "Zuul" OR "Gateway"',
            'inurl:"/swagger" "microservice" -site:github.com',
            'inurl:"/api/v1" "swagger" -site:github.com',
            'inurl:"/api/v2" "openapi" -site:github.com',
            
            # CMS and platform APIs
            'inurl:"/wp-json/wp/v2" "WordPress" -site:github.com',
            'inurl:"/jsonapi" "Drupal" -site:github.com',
            'inurl:"/rest/V1" "Magento" -site:github.com',
            'inurl:"/api" "Shopify" "REST" -site:github.com',
            
            # Error exposure patterns (often reveal internal APIs)
            '"swagger-ui" ("500" OR "error" OR "exception") -site:github.com',
            '"api-docs" ("unauthorized" OR "forbidden") -site:github.com',
            '"openapi" "internal server error" -site:github.com',
            
            # Authentication bypass indicators
            'inurl:"/swagger" "no authentication" OR "public api"',
            'inurl:"/api-docs" "anonymous" OR "guest"',
            '"swagger" "cors" "enabled" -site:github.com',
            
            # Mobile and IoT APIs
            'inurl:"/api/mobile" OR inurl:"/mobile/api" "swagger"',
            'inurl:"/api/app" "documentation" -site:github.com',
            'inurl:"/api/iot" OR inurl:"/iot/api" "docs"',
            
            # Admin and internal APIs (high value)
            'inurl:"/admin/api" "swagger" -site:github.com',
            'inurl:"/internal/api" "docs" -site:github.com',
            'inurl:"/management/api" "swagger" -site:github.com',
            'inurl:"/debug/api" "documentation" -site:github.com',
            
            # Version-specific patterns
            'inurl:"/v1/swagger" OR inurl:"/v2/swagger" OR inurl:"/v3/swagger"',
            'inurl:"/api/v1/docs" OR inurl:"/api/v2/docs"',
            
            # Localized APIs
            'inurl:"/api" ("en/" OR "fr/" OR "de/" OR "es/" OR "it/" OR "zh/")',
            
            # Real-time and WebSocket APIs
            'inurl:"/api" ("websocket" OR "ws" OR "realtime" OR "streaming")',
            
            # Health and monitoring endpoints
            'inurl:"/health" "swagger" OR "api" -site:github.com',
            'inurl:"/status" "api" "json" -site:github.com',
            'inurl:"/metrics" "swagger" OR "api" -site:github.com',
            'inurl:"/actuator" "swagger" OR "api-docs"',
            
            # Additional high-value patterns
            'intitle:"API Documentation" -site:github.com -site:swagger.io',
            'intitle:"REST API" -site:github.com -site:postman.com',
            'intitle:"Developer API" -site:github.com',
            'intitle:"API Reference" -site:github.com',
            'intitle:"ReDoc" -site:github.com',
            'intitle:"API Explorer" -site:github.com',
            
            # Security-focused patterns
            '"api_key" "swagger" "documentation" -site:github.com',
            '"authorization" "bearer" "swagger" -site:github.com',
            '"token" "api" "swagger" "auth" -site:github.com'
        ]
        
        self.target_domain = target_domain
        self.results = []
        # Rotating user agents for better stealth
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0"
        ]
        self.user_agent = random.choice(self.user_agents)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        if self.verbose:
            print(f"📁 Output directory: {self.output_dir.absolute()}")
    
    def setup_logging(self):
        """Setup comprehensive logging with rotation"""
        try:
            from logging.handlers import RotatingFileHandler
            
            log_format = '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            
            # Create log file with rotation
            log_file = self.output_dir / 'swagger_scan.log'
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=3
            )
            file_handler.setFormatter(logging.Formatter(log_format))
            
            handlers = [file_handler]
            
            if self.verbose:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
                handlers.append(console_handler)
            
            logging.basicConfig(
                level=logging.INFO if self.verbose else logging.WARNING,
                format=log_format,
                handlers=handlers,
                force=True  # Override any existing configuration
            )
            
            self.logger = logging.getLogger(__name__)
            
        except Exception as e:
            print(f"Warning: Failed to setup logging: {e}")
            self.logger = logging.getLogger(__name__)
        
    def log_progress(self, message, level="info"):
        """Log progress with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        if self.verbose:
            if level == "error":
                print(f"❌ [{timestamp}] {message}")
            elif level == "warning":
                print(f"⚠️  [{timestamp}] {message}")
            elif level == "success":
                print(f"✅ [{timestamp}] {message}")
            else:
                print(f"ℹ️  [{timestamp}] {message}")
        
        # Also log to file
        if level == "error":
            self.logger.error(message)
        elif level == "warning":
            self.logger.warning(message)
        else:
            self.logger.info(message)
        
    async def check_swagger_endpoint(self, base_url, path):
        """Check if a specific swagger endpoint exists with enhanced error handling"""
        full_url = urljoin(base_url, path.lstrip('/'))
        
        # Rotate user agent for each request
        current_user_agent = random.choice(self.user_agents)
        
        try:
            # Enhanced timeout and connection settings
            timeout = aiohttp.ClientTimeout(
                total=30,
                connect=10,
                sock_read=20
            )
            
            # SSL context that's more permissive
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(
                limit=10,
                ssl=ssl_context,
                enable_cleanup_closed=True
            )
            
            headers = {
                'User-Agent': current_user_agent,
                'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=headers
            ) as session:
                async with session.get(
                    full_url,
                    allow_redirects=True,
                    max_redirects=3
                ) as response:
                    
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '').lower()
                        
                        # Read content with size limit to prevent memory issues
                        content_size = int(response.headers.get('content-length', 0))
                        if content_size > 5 * 1024 * 1024:  # 5MB limit
                            self.log_progress(f"Content too large ({content_size} bytes): {full_url}", "warning")
                            return None
                        
                        try:
                            content = await response.text()
                        except UnicodeDecodeError:
                            # Try different encoding
                            content = await response.read()
                            content = content.decode('utf-8', errors='ignore')
                        
                        # Enhanced swagger detection
                        swagger_indicators = self._detect_swagger_content(content, content_type)
                        
                        if swagger_indicators:
                            result = {
                                'url': full_url,
                                'status': response.status,
                                'content_type': content_type,
                                'size': len(content),
                                'swagger_indicators': swagger_indicators,
                                'server': response.headers.get('server', 'Unknown'),
                                'last_modified': response.headers.get('last-modified'),
                                'validated': True
                            }
                            self.log_progress(f"Found valid endpoint: {full_url}", "success")
                            return result
                            
                    elif response.status in [401, 403]:
                        # Still log restricted endpoints as they might be valid APIs
                        result = {
                            'url': full_url,
                            'status': response.status,
                            'content_type': response.headers.get('content-type', ''),
                            'access_restricted': True,
                            'server': response.headers.get('server', 'Unknown')
                        }
                        self.log_progress(f"Access restricted ({response.status}): {full_url}", "warning")
                        return result
                        
                    elif response.status in [301, 302, 307, 308]:
                        redirect_url = response.headers.get('location')
                        if redirect_url:
                            self.log_progress(f"Redirect ({response.status}) to: {redirect_url}")
                            # Follow redirect manually to check if it's a swagger endpoint
                            return await self.check_swagger_endpoint(redirect_url, '')
                            
                    elif response.status == 404:
                        pass  # Expected for many endpoints
                    else:
                        self.log_progress(f"Unexpected status {response.status}: {full_url}", "warning")
                        
        except asyncio.TimeoutError:
            self.log_progress(f"Timeout accessing: {full_url}", "warning")
        except aiohttp.ClientError as e:
            self.log_progress(f"HTTP client error for {full_url}: {str(e)}", "warning")
        except ssl.SSLError as e:
            self.log_progress(f"SSL error for {full_url}: {str(e)}", "warning")
        except Exception as e:
            self.log_progress(f"Unexpected error checking {full_url}: {str(e)}", "error")
        
        return None
    
    def _detect_swagger_content(self, content, content_type):
        """Enhanced swagger content detection"""
        indicators = []
        content_lower = content.lower()
        
        # JSON API specification indicators
        if 'json' in content_type:
            try:
                import json
                json_data = json.loads(content)
                
                if 'swagger' in json_data:
                    indicators.append(f"swagger_version:{json_data['swagger']}")
                if 'openapi' in json_data:
                    indicators.append(f"openapi_version:{json_data['openapi']}")
                if 'paths' in json_data:
                    indicators.append(f"paths_count:{len(json_data['paths'])}")
                if 'info' in json_data and 'title' in json_data['info']:
                    indicators.append(f"api_title:{json_data['info']['title'][:50]}")
                    
            except (json.JSONDecodeError, TypeError):
                pass
        
        # HTML UI indicators
        if 'html' in content_type:
            html_indicators = [
                ('swagger ui', 'swagger_ui'),
                ('swagger-ui', 'swagger_ui'),
                ('redoc', 'redoc_ui'),
                ('api documentation', 'api_docs'),
                ('openapi', 'openapi_ui'),
                ('graphiql', 'graphql_ui'),
                ('api explorer', 'api_explorer')
            ]
            
            for pattern, indicator in html_indicators:
                if pattern in content_lower:
                    indicators.append(indicator)
        
        # YAML indicators
        if any(ext in content_type for ext in ['yaml', 'yml']) or content.strip().startswith(('openapi:', 'swagger:')):
            indicators.append('yaml_spec')
        
        # Text-based indicators
        text_patterns = [
            ('"swagger":', 'swagger_field'),
            ('"openapi":', 'openapi_field'),
            ('"paths":', 'paths_field'),
            ('"definitions":', 'definitions_field'),
            ('"components":', 'components_field'),
            ('"basePath":', 'basepath_field'),
            ('"schemes":', 'schemes_field')
        ]
        
        for pattern, indicator in text_patterns:
            if pattern in content_lower:
                indicators.append(indicator)
        
        return indicators

    async def scan_target_domain(self, domain):
        """Scan a specific domain for swagger endpoints"""
        self.log_progress(f"Starting direct scan of {domain} for Swagger/API endpoints")
        found_endpoints = []
        
        protocols = ['https://', 'http://']
        total_paths = len(self.swagger_paths) * len(protocols)
        current_check = 0
        
        for protocol in protocols:
            base_url = f"{protocol}{domain}"
            self.log_progress(f"Testing {protocol} protocol on {domain}")
            
            for path in self.swagger_paths:
                current_check += 1
                if self.verbose and current_check % 10 == 0:
                    progress = (current_check / total_paths) * 100
                    self.log_progress(f"Progress: {current_check}/{total_paths} ({progress:.1f}%)")
                
                result = await self.check_swagger_endpoint(base_url, path)
                if result:
                    found_endpoints.append(result)
                    self.log_progress(f"Found valid endpoint: {result['url']}", "success")
                
                # Small delay to avoid overwhelming the server
                await asyncio.sleep(0.1)
        
        self.log_progress(f"Direct scan complete. Found {len(found_endpoints)} endpoints")
        return found_endpoints

    def get_prioritized_dorks(self, max_dorks=20):
        """Get prioritized dorks based on whether domain is specified"""
        if self.target_domain:
            # For domain-specific scans, use more focused dorks
            priority_dorks = [
                'inurl:"/swagger-ui.html"',
                'inurl:"/swagger.json"',
                'inurl:"/api-docs"',
                'inurl:"/openapi.json"',
                'inurl:"/v2/api-docs"',
                'inurl:"/v3/api-docs"',
                'intitle:"Swagger UI"',
                'inurl:"/redoc"'
            ]
        else:
            # For global scans, prioritize high-yield dorks
            priority_dorks = [
                'intitle:"Swagger UI" -site:github.com -site:swagger.io',
                'inurl:"/swagger-ui.html" -site:github.com',
                'inurl:"/api-docs" -site:swagger.io -site:github.com',
                'inurl:"/swagger" (site:dev.* OR site:test.* OR site:staging.*)',
                'inurl:"/actuator/swagger-ui"',
                'inurl:"/docs" "FastAPI"',
                'inurl:"/v2/api-docs" "swagger"',
                'filetype:json "swagger" "paths"',
                'inurl:"/api" site:*.herokuapp.com',
                'inurl:"/api" site:*.vercel.app',
                '"swagger-ui" "unauthorized" OR "forbidden"',
                'inurl:"/openapi.json" "FastAPI"',
                'inurl:"/swagger" "ASP.NET"',
                'inurl:"/api/documentation" "Laravel"',
                'inurl:"/graphql" OR inurl:"/graphiql"'
            ]
        
        # Add remaining dorks up to max_dorks limit
        remaining_dorks = [d for d in self.dorks if d not in priority_dorks]
        selected_dorks = priority_dorks + remaining_dorks
        return selected_dorks[:max_dorks]

    async def search_with_playwright(self, dork):
        """Search using Google dorks with Playwright with enhanced anti-detection"""
        if not PLAYWRIGHT_AVAILABLE:
            self.log_progress(f"Skipping dork '{dork}' - Playwright not available", "warning")
            return
            
        search_query = dork
        if self.target_domain:
            search_query = f"{dork} site:{self.target_domain}"
        
        self.log_progress(f"Executing Google dork: {dork}")
        if self.target_domain:
            self.log_progress(f"Full query: {search_query}")
            
        async with async_playwright() as p:
            # Enhanced browser args for better stealth
            browser_args = [
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--disable-web-security',
                '--disable-features=VizDisplayCompositor',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
                '--disable-ipc-flooding-protection',
                '--disable-default-apps',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-sync',
                '--disable-translate',
                '--hide-scrollbars',
                '--mute-audio',
                '--no-default-browser-check',
                '--no-first-run',
                '--disable-gpu',
                '--disable-software-rasterizer',
                '--remote-debugging-port=0',
                f'--user-agent={self.user_agent}'
            ]
            
            browser = await p.chromium.launch(
                headless=True,
                args=browser_args
            )
            
            # Enhanced context with more realistic settings
            context = await browser.new_context(
                user_agent=self.user_agent,
                viewport={'width': 1366, 'height': 768},  # More common resolution
                locale='en-US',
                timezone_id='America/New_York',
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'Cache-Control': 'max-age=0'
                }
            )
            
            # Add stealth patches
            await context.add_init_script("""
                // Remove webdriver property
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                
                // Mock plugins
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
                
                // Mock languages
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
                
                // Mock permissions
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
            """)
            page = await context.new_page()
            
            try:
                # Random delay to avoid rate limiting
                delay = random.uniform(5, 12)
                self.log_progress(f"Waiting {delay:.1f}s before search to avoid rate limiting")
                await asyncio.sleep(delay)
                
                # Navigate to Google first to establish session
                self.log_progress(f"Establishing Google session...")
                await page.goto("https://www.google.com", timeout=60000)
                await asyncio.sleep(random.uniform(2, 4))
                
                # Navigate to search with encoded query
                import urllib.parse
                encoded_query = urllib.parse.quote_plus(search_query)
                search_url = f"https://www.google.com/search?q={encoded_query}&num=20&start=0"
                
                self.log_progress(f"Navigating to Google search...")
                await page.goto(search_url, timeout=90000)
                
                # Wait for page to fully load
                await asyncio.sleep(random.uniform(3, 6))
                
                # Enhanced selector waiting with multiple fallbacks
                selectors_to_try = ["#search", "#rso", ".g", "[data-ved]", ".tF2Cxc", ".yuRUbf"]
                selector_found = None
                
                # Check for blocking first
                page_title = await page.title()
                page_url = page.url
                page_content = await page.content()
                
                self.log_progress(f"Current page title: {page_title}")
                
                # Enhanced blocking detection
                blocking_indicators = [
                    "captcha", "unusual traffic", "automated queries", "robot", "bot",
                    "verify you're human", "suspicious activity", "too many requests"
                ]
                
                if any(indicator in page_title.lower() for indicator in blocking_indicators) or \
                   any(indicator in page_content.lower() for indicator in blocking_indicators):
                    self.log_progress("Anti-bot protection detected - implementing evasion", "warning")
                    
                    # Try alternative search engines or direct endpoint search
                    self.log_progress("Switching to alternative discovery methods", "warning")
                    return await self._fallback_search_methods(search_query)
                
                # Try selectors with different timeouts
                for i, selector in enumerate(selectors_to_try):
                    try:
                        timeout = 15000 - (i * 2000)  # Decreasing timeout
                        self.log_progress(f"Waiting for selector: {selector} (timeout: {timeout}ms)")
                        await page.wait_for_selector(selector, timeout=timeout)
                        selector_found = selector
                        self.log_progress(f"Found selector: {selector}", "success")
                        break
                    except Exception as e:
                        self.log_progress(f"Selector {selector} not found: {str(e)[:100]}", "warning")
                        continue
                
                if not selector_found:
                    self.log_progress("No search result selectors found - trying direct extraction", "warning")
                    return await self._extract_results_without_selectors(page)
                
                self.log_progress("Extracting search results...")
                results = await page.evaluate('''() => {
                    const items = [];
                    
                    // Enhanced selectors for different Google layouts
                    const resultSelectors = ['.g', '[data-ved]', '.tF2Cxc', '.yuRUbf', '.dURPMd'];
                    let resultElements = [];
                    
                    for (const selector of resultSelectors) {
                        const elements = document.querySelectorAll(selector);
                        if (elements.length > 0) {
                            resultElements = elements;
                            console.log(`Using selector: ${selector}, found ${elements.length} elements`);
                            break;
                        }
                    }
                    
                    if (resultElements.length === 0) {
                        // Fallback: try to find any clickable links with API-related text
                        const allLinks = document.querySelectorAll('a[href]');
                        for (const link of allLinks) {
                            const linkText = link.textContent.toLowerCase();
                            const href = link.href;
                            if (href && !href.includes('google.com') && 
                                (linkText.includes('swagger') || linkText.includes('api') || 
                                 linkText.includes('docs') || linkText.includes('openapi'))) {
                                items.push({
                                    title: link.textContent.trim() || 'API Documentation',
                                    url: href,
                                    description: 'Found via fallback link extraction'
                                });
                            }
                        }
                        return items;
                    }
                    
                    resultElements.forEach((result, index) => {
                        try {
                            // Enhanced title selectors
                            const titleSelectors = ['h3', '.LC20lb', '.DKV0Md', '.yuRUbf h3', '.tF2Cxc h3'];
                            let title = null;
                            for (const selector of titleSelectors) {
                                const titleEl = result.querySelector(selector);
                                if (titleEl && titleEl.innerText.trim()) {
                                    title = titleEl.innerText.trim();
                                    break;
                                }
                            }
                            
                            // Enhanced URL selectors
                            const urlSelectors = ['a[href]:not([href*="google.com"])', '[href]:not([href*="google.com"])'];
                            let url = null;
                            for (const selector of urlSelectors) {
                                const urlEl = result.querySelector(selector);
                                if (urlEl && urlEl.href && 
                                    !urlEl.href.includes('google.com') && 
                                    !urlEl.href.includes('webcache') &&
                                    !urlEl.href.includes('translate.google')) {
                                    url = urlEl.href;
                                    break;
                                }
                            }
                            
                            // Enhanced description selectors
                            const descSelectors = ['.VwiC3b', '.s3v9rd', '.IsZvec', '.yXK7lf', '.hgKElc'];
                            let description = '';
                            for (const selector of descSelectors) {
                                const descEl = result.querySelector(selector);
                                if (descEl && descEl.innerText.trim()) {
                                    description = descEl.innerText.trim();
                                    break;
                                }
                            }
                            
                            if (title && url) {
                                items.push({title, url, description});
                                console.log(`Extracted result ${index + 1}: ${title.substring(0, 50)}`);
                            }
                        } catch (e) {
                            console.error(`Error processing result ${index}:`, e);
                        }
                    });
                    
                    console.log(`Total extracted items: ${items.length}`);
                    return items;
                }''')
                
                self.log_progress(f"Extracted {len(results)} search results")
                
                # Enhanced filtering with better confidence scoring
                valid_results = 0
                excluded_domains = [
                    'github.com', 'swagger.io', 'postman.com', 'stackoverflow.com',
                    'npmjs.com', 'pypi.org', 'mvnrepository.com', 'packagist.org',
                    'cocoapods.org', 'pub.dev', 'crates.io', 'godoc.org',
                    'docs.microsoft.com', 'developer.mozilla.org'
                ]
                
                api_indicators = [
                    'swagger', 'api-docs', 'openapi', 'redoc', 'api', 'docs',
                    'graphql', 'rest', 'json', 'yaml', 'documentation'
                ]
                
                for i, result in enumerate(results):
                    try:
                        parsed_url = urlparse(result['url'])
                        
                        # Skip excluded domains
                        if any(excluded in parsed_url.netloc.lower() for excluded in excluded_domains):
                            continue
                            
                        # Check for API indicators in URL or content
                        has_api_indicator = (
                            any(indicator in parsed_url.path.lower() for indicator in api_indicators) or
                            any(indicator in parsed_url.query.lower() for indicator in api_indicators) or
                            any(indicator in result['title'].lower() for indicator in api_indicators) or
                            any(indicator in result['description'].lower() for indicator in api_indicators)
                        )
                        
                        if parsed_url.netloc and has_api_indicator:
                            confidence = self._calculate_confidence(result, parsed_url)
                            
                            # Only include results with reasonable confidence
                            if confidence >= 2:
                                new_result = {
                                    'dork': dork,
                                    'title': result['title'][:200],  # Truncate long titles
                                    'url': result['url'],
                                    'description': result['description'][:300],  # Truncate long descriptions
                                    'domain': parsed_url.netloc,
                                    'source': 'google_dork',
                                    'confidence': confidence
                                }
                                
                                # Check for duplicates
                                if not any(existing['url'] == new_result['url'] for existing in self.results):
                                    self.results.append(new_result)
                                    valid_results += 1
                                    
                                    if self.verbose:
                                        self.log_progress(f"Added result {valid_results}: {result['url']} (confidence: {confidence})")
                    except Exception as e:
                        self.log_progress(f"Error processing result {i}: {str(e)}", "warning")
                
                self.log_progress(f"Added {valid_results} valid results from this dork", "success")
                
            except Exception as e:
                self.log_progress(f"Error searching dork {dork}: {str(e)}", "error")
                # Take screenshot for debugging if possible
                try:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    screenshot_path = self.output_dir / f"error_screenshot_{timestamp}.png"
                    await page.screenshot(path=str(screenshot_path), full_page=True)
                    self.log_progress(f"Error screenshot saved: {screenshot_path}")
                except:
                    pass
            finally:
                try:
                    await context.close()
                    await browser.close()
                    self.log_progress("Browser closed successfully")
                except:
                    self.log_progress("Error closing browser", "warning")
    
    async def _fallback_search_methods(self, search_query):
        """Fallback search methods when Google blocks requests"""
        self.log_progress("Implementing fallback search strategies", "warning")
        
        # Extract domain from search query if present
        if "site:" in search_query:
            try:
                domain = search_query.split("site:")[1].split()[0]
                self.log_progress(f"Attempting direct domain scan: {domain}")
                return await self.scan_target_domain(domain)
            except:
                pass
        
        return []
    
    async def _extract_results_without_selectors(self, page):
        """Extract results when normal selectors fail"""
        self.log_progress("Attempting direct link extraction", "warning")
        
        try:
            # Get all links and filter for API-related content
            links = await page.evaluate('''
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    return links.map(link => ({
                        url: link.href,
                        text: link.textContent,
                        title: link.title || link.textContent
                    })).filter(link => 
                        link.url && 
                        !link.url.includes('google.com') &&
                        !link.url.includes('webcache') &&
                        (link.text.toLowerCase().includes('api') ||
                         link.text.toLowerCase().includes('swagger') ||
                         link.text.toLowerCase().includes('docs') ||
                         link.url.includes('swagger') ||
                         link.url.includes('api-docs') ||
                         link.url.includes('openapi'))
                    );
                }
            ''')
            
            for link in links[:10]:  # Limit to first 10
                parsed_url = urlparse(link['url'])
                confidence = 3  # Medium confidence for fallback results
                
                result = {
                    'title': link['title'][:200],
                    'url': link['url'],
                    'description': 'Found via fallback extraction',
                    'domain': parsed_url.netloc,
                    'source': 'google_dork_fallback',
                    'confidence': confidence
                }
                
                self.results.append(result)
                self.log_progress(f"Fallback result: {link['url']}")
                
        except Exception as e:
            self.log_progress(f"Fallback extraction failed: {str(e)}", "error")
    
    def _calculate_confidence(self, result, parsed_url):
        """Enhanced confidence scoring for better result quality"""
        score = 0
        
        # High confidence URL path indicators (exact matches)
        high_confidence_paths = {
            'swagger-ui.html': 5,
            'swagger-ui/': 5,
            'api-docs': 4,
            'openapi.json': 5,
            'openapi.yaml': 5,
            'swagger.json': 5,
            'swagger.yaml': 5,
            'redoc': 4,
            'graphql': 3,
            'graphiql': 4
        }
        
        # Medium confidence path indicators
        medium_confidence_paths = {
            'swagger': 2,
            'api/docs': 3,
            'api/v1': 2,
            'api/v2': 2,
            'api/v3': 2,
            'docs': 1,
            'documentation': 2
        }
        
        # Check URL path
        url_path = parsed_url.path.lower()
        for path, points in high_confidence_paths.items():
            if path in url_path:
                score += points
                
        for path, points in medium_confidence_paths.items():
            if path in url_path:
                score += points
        
        # Title indicators with weighted scoring
        title_lower = result['title'].lower()
        title_indicators = {
            'swagger ui': 4,
            'api documentation': 3,
            'openapi': 3,
            'redoc': 3,
            'api reference': 2,
            'developer api': 2,
            'rest api': 2,
            'graphql': 2
        }
        
        for indicator, points in title_indicators.items():
            if indicator in title_lower:
                score += points
        
        # Description indicators
        desc_lower = result['description'].lower()
        if any(term in desc_lower for term in ['swagger', 'openapi', 'api documentation', 'rest api']):
            score += 1
        
        # Domain quality indicators
        domain_lower = parsed_url.netloc.lower()
        
        # Development/staging environments (higher chance of exposed APIs)
        if any(env in domain_lower for env in ['dev', 'test', 'staging', 'beta', 'demo']):
            score += 2
            
        # Cloud platforms (common for APIs)
        if any(platform in domain_lower for platform in [
            'herokuapp.com', 'vercel.app', 'netlify.app', 'azurewebsites.net',
            'amazonaws.com', 'firebaseapp.com', 'railway.app', 'render.com'
        ]):
            score += 1
            
        # File extension bonuses
        if parsed_url.path.endswith(('.json', '.yaml', '.yml')):
            score += 2
            
        # Query parameter indicators
        if any(param in parsed_url.query.lower() for param in ['swagger', 'openapi', 'docs']):
            score += 1
            
        return min(score, 10)  # Cap at 10
    
    async def scan_with_crawl4ai(self, url):
        """Enhanced scanning with Crawl4AI using the updated API"""
        if not CRAWL4AI_AVAILABLE:
            print(f"  Skipping Crawl4AI scan for {url} - library not available")
            return None
            
        try:
            async with AsyncWebCrawler(
                headless=True,
                user_agent=self.user_agent,
                viewport_size={"width": 1920, "height": 1080}
            ) as crawler:
                result = await crawler.arun(
                    url=url,
                    wait_for=3000,
                    timeout=30000,
                    bypass_cache=True
                )
                
                if result.success:
                    content = result.markdown if result.markdown else result.html
                    
                    # Extract swagger/API indicators
                    swagger_patterns = [
                        r'"swagger":\s*"[\d\.]+"',
                        r'"openapi":\s*"[\d\.]+"',
                        r'"paths":\s*\{',
                        r'"definitions":\s*\{',
                        r'"components":\s*\{',
                        r'swagger\s*ui',
                        r'api\s*documentation',
                        r'redoc',
                        r'"info":\s*\{.*?"title"'
                    ]
                    
                    swagger_indicators = []
                    content_lower = content.lower()
                    
                    for pattern in swagger_patterns:
                        if re.search(pattern, content_lower, re.IGNORECASE):
                            swagger_indicators.append(pattern)
                    
                    # Extract links to other API endpoints
                    link_patterns = [
                        r'href="([^"]*(?:swagger|api|openapi)[^"]*)"',
                        r'href="([^"]*\.json)"',
                        r'href="([^"]*\.yaml)"',
                        r'src="([^"]*(?:swagger|api)[^"]*)"'
                    ]
                    
                    found_links = []
                    for pattern in link_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if match.startswith('/'):
                                full_link = urljoin(url, match)
                            elif match.startswith('http'):
                                full_link = match
                            else:
                                full_link = urljoin(url, match)
                            found_links.append(full_link)
                    
                    if swagger_indicators or any(kw in content_lower for kw in ['swagger', 'openapi', 'api documentation', 'redoc']):
                        return {
                            'url': url,
                            'title': result.metadata.get('title', 'N/A') if result.metadata else 'N/A',
                            'content': content[:1500] + "..." if len(content) > 1500 else content,
                            'swagger_indicators': swagger_indicators,
                            'found_links': list(set(found_links))[:10],  # Limit and deduplicate
                            'content_length': len(content),
                            'source': 'crawl4ai'
                        }
                return None
        except Exception as e:
            print(f"Error scanning {url} with Crawl4AI: {str(e)}")
            return None
    
    async def validate_swagger_endpoint(self, url):
        """Enhanced validation of Swagger/API endpoints with better error handling"""
        self.log_progress(f"Validating endpoint: {url}")
        
        try:
            # Enhanced timeout and connection settings
            timeout = aiohttp.ClientTimeout(
                total=30,
                connect=10,
                sock_read=20
            )
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(
                limit=10,
                ssl=ssl_context,
                enable_cleanup_closed=True
            )
            
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none'
            }
            
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            ) as session:
                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=5
                ) as response:
                    
                    content_type = response.headers.get('content-type', '').lower()
                    server = response.headers.get('server', 'Unknown')
                    
                    if response.status == 200:
                        # Check content size
                        content_length = int(response.headers.get('content-length', 0))
                        if content_length > 10 * 1024 * 1024:  # 10MB limit
                            self.log_progress(f"Content too large for validation: {url}", "warning")
                            return None
                        
                        try:
                            content = await response.text()
                        except (UnicodeDecodeError, aiohttp.ClientPayloadError):
                            try:
                                content_bytes = await response.read()
                                content = content_bytes.decode('utf-8', errors='ignore')
                            except Exception:
                                self.log_progress(f"Failed to decode content for: {url}", "warning")
                                return None
                        
                        # Enhanced content analysis
                        validation_result = self._analyze_api_content(url, content, content_type, server)
                        if validation_result:
                            validation_result['status_code'] = response.status
                            validation_result['validated'] = True
                            return validation_result
                            
                    elif response.status in [401, 403]:
                        # Document restricted endpoints
                        return {
                            'url': url,
                            'type': 'restricted_api',
                            'status_code': response.status,
                            'server': server,
                            'content_type': content_type,
                            'validated': True,
                            'access_restricted': True
                        }
                        
                    elif response.status in [301, 302, 307, 308]:
                        redirect_url = response.headers.get('location')
                        if redirect_url and redirect_url != url:
                            self.log_progress(f"Following redirect from {url} to {redirect_url}")
                            return await self.validate_swagger_endpoint(redirect_url)
                            
                    else:
                        self.log_progress(f"Validation failed with status {response.status}: {url}", "warning")
                        
        except asyncio.TimeoutError:
            self.log_progress(f"Timeout validating endpoint: {url}", "warning")
        except aiohttp.ClientError as e:
            self.log_progress(f"HTTP client error validating {url}: {str(e)}", "warning")
        except ssl.SSLError as e:
            self.log_progress(f"SSL error validating {url}: {str(e)}", "warning")
        except Exception as e:
            self.log_progress(f"Unexpected error validating {url}: {str(e)}", "error")
            
        return None
    
    def _analyze_api_content(self, url, content, content_type, server):
        """Comprehensive analysis of API content"""
        content_lower = content.lower()
        
        # JSON API specification analysis
        if 'json' in content_type:
            try:
                json_data = json.loads(content)
                
                # OpenAPI/Swagger JSON detection
                if any(key in json_data for key in ['swagger', 'openapi']):
                    version = json_data.get('swagger') or json_data.get('openapi', 'Unknown')
                    info = json_data.get('info', {})
                    title = info.get('title', 'Unknown API')
                    description = info.get('description', '')
                    paths = json_data.get('paths', {})
                    
                    return {
                        'url': url,
                        'type': 'openapi_spec',
                        'format': 'json',
                        'version': version,
                        'title': title,
                        'description': description[:200],
                        'endpoints': len(paths),
                        'server': server,
                        'api_methods': self._extract_api_methods(paths),
                        'security_schemes': list(json_data.get('securityDefinitions', {}).keys()) or 
                                          [comp.get('securitySchemes', {}).keys() for comp in [json_data.get('components', {})]]
                    }
                
                # GraphQL schema detection
                elif any(key in json_data for key in ['data', '__schema', 'query', 'mutation']):
                    return {
                        'url': url,
                        'type': 'graphql_schema',
                        'format': 'json',
                        'title': 'GraphQL API',
                        'server': server
                    }
                    
            except (json.JSONDecodeError, TypeError) as e:
                self.log_progress(f"JSON parsing error for {url}: {str(e)}", "warning")
        
        # YAML API specification analysis
        elif any(ext in content_type for ext in ['yaml', 'yml']) or content.strip().startswith(('openapi:', 'swagger:')):
            try:
                # Simple YAML detection without importing yaml library
                if any(pattern in content_lower for pattern in ['openapi:', 'swagger:', 'paths:', 'info:']):
                    title_match = re.search(r"title:\s*[\"\']?([^\n\r]+)", content, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else 'Unknown API'
                    
                    version_match = re.search(r"(?:openapi|swagger):\s*[\"\']?([^\n\r]+)", content, re.IGNORECASE)
                    version = version_match.group(1).strip() if version_match else 'Unknown'
                    
                    return {
                        'url': url,
                        'type': 'openapi_spec',
                        'format': 'yaml',
                        'version': version,
                        'title': title,
                        'server': server
                    }
            except Exception as e:
                self.log_progress(f"YAML analysis error for {url}: {str(e)}", "warning")
        
        # HTML UI analysis
        elif 'html' in content_type:
            ui_indicators = {
                'swagger ui': 'swagger_ui',
                'swagger-ui': 'swagger_ui',
                'redoc': 'redoc',
                'api documentation': 'api_docs',
                'graphiql': 'graphiql',
                'api explorer': 'api_explorer',
                'postman': 'postman_docs'
            }
            
            for indicator, ui_type in ui_indicators.items():
                if indicator in content_lower:
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else 'API Documentation'
                    
                    # Extract API info from HTML
                    api_info = self._extract_html_api_info(content)
                    
                    return {
                        'url': url,
                        'type': ui_type,
                        'format': 'html',
                        'title': title,
                        'server': server,
                        **api_info
                    }
        
        return None
    
    def _extract_api_methods(self, paths):
        """Extract HTTP methods from OpenAPI paths"""
        methods = set()
        for path_info in paths.values():
            if isinstance(path_info, dict):
                methods.update(path_info.keys())
        return list(methods)
    
    def _extract_html_api_info(self, content):
        """Extract additional API information from HTML content"""
        info = {}
        
        # Try to find API base URL with simpler patterns
        if 'baseUrl' in content:
            base_match = re.search(r'baseUrl[^:]*:[^"\']*["\']([^"\'\\n]+)', content, re.IGNORECASE)
            if base_match:
                info['spec_url'] = base_match.group(1)
        
        if 'basePath' in content and 'spec_url' not in info:
            path_match = re.search(r'basePath[^:]*:[^"\']*["\']([^"\'\\n]+)', content, re.IGNORECASE)
            if path_match:
                info['spec_url'] = path_match.group(1)
        
        # Try to find version
        if 'version' in content:
            version_match = re.search(r'version[^:]*:[^"\']*["\']([^"\'\\n]+)', content, re.IGNORECASE)
            if version_match:
                info['api_version'] = version_match.group(1)
        
        return info

    async def run(self, mode="all", max_dorks=10, max_scans=5):
        """Enhanced run method with multiple modes"""
        start_time = datetime.now()
        self.log_progress("Starting Enhanced Swagger/API Dork Scanner...", "success")
        self.log_progress(f"Scan mode: {mode}")
        self.log_progress(f"Max dorks: {max_dorks}, Max scans: {max_scans}")
        all_results = []
        
        if mode in ["all", "direct"] and self.target_domain:
            self.log_progress(f"[Phase 1/4] Direct Scan - Checking {self.target_domain} for common Swagger paths")
            direct_results = await self.scan_target_domain(self.target_domain)
            all_results.extend([{**r, 'source': 'direct_scan'} for r in direct_results])
            self.log_progress(f"Direct scan completed: {len(direct_results)} endpoints found", "success")
        
        if mode in ["all", "dork"]:
            if not PLAYWRIGHT_AVAILABLE:
                self.log_progress("Skipping Google dork phase - Playwright not available", "warning")
            else:
                selected_dorks = self.get_prioritized_dorks(max_dorks)
                self.log_progress(f"[Phase 2/4] Google Dork - Running {len(selected_dorks)} prioritized Google dorks")
                if not self.target_domain:
                    self.log_progress("Using enhanced global discovery dorks (no domain specified)")
                
                successful_dorks = 0
                failed_dorks = 0
                
                for i, dork in enumerate(selected_dorks):
                    self.log_progress(f"Processing dork {i+1}/{len(selected_dorks)}: {dork}")
                    
                    try:
                        results_before = len(self.results)
                        await self.search_with_playwright(dork)
                        results_after = len(self.results)
                        
                        if results_after > results_before:
                            successful_dorks += 1
                            self.log_progress(f"Dork successful: {results_after - results_before} new results", "success")
                        else:
                            self.log_progress(f"Dork yielded no new results")
                    
                    except Exception as e:
                        failed_dorks += 1
                        self.log_progress(f"Dork failed: {str(e)}", "error")
                        
                        # If too many failures, consider stopping
                        if failed_dorks >= 3 and successful_dorks == 0:
                            self.log_progress("Too many consecutive failures, stopping dork search", "error")
                            break
                    
                    # Enhanced rate limiting with adaptive delays
                    if i < len(selected_dorks) - 1:
                        base_delay = 10 if not self.target_domain else 5
                        random_delay = random.uniform(1, 5)
                        failure_penalty = min(failed_dorks * 3, 15)  # Cap penalty at 15s
                        success_bonus = max(0, successful_dorks - 2) * 0.5  # Slight reduction for successful dorks
                        total_delay = base_delay + random_delay + failure_penalty - success_bonus + (i % 5)
                        
                        # Add jitter to make timing less predictable
                        jitter = random.uniform(-1, 1)
                        total_delay = max(3, total_delay + jitter)  # Minimum 3 seconds
                        
                        self.log_progress(f"Waiting {total_delay:.1f}s before next dork (S:{successful_dorks}/F:{failed_dorks})...")
                        await asyncio.sleep(total_delay)
                
                self.log_progress(f"Google dork phase completed: {len(self.results)} total results found (success: {successful_dorks}, failed: {failed_dorks})", "success")
        
        if mode in ["all", "crawl"] and self.results:
            scan_count = min(max_scans, len(self.results))
            self.log_progress(f"[Phase 3/4] Deep Scan - Analyzing {scan_count} discovered URLs with Crawl4AI")
            
            for i, result in enumerate(self.results[:max_scans]):
                self.log_progress(f"Analyzing {i+1}/{scan_count}: {result['url']}")
                scan_result = await self.scan_with_crawl4ai(result['url'])
                if scan_result:
                    all_results.append(scan_result)
                    self.log_progress(f"Deep scan successful for: {result['url']}", "success")
                else:
                    self.log_progress(f"Deep scan yielded no results for: {result['url']}", "warning")
                    
                # Delay between crawl operations
                if i < scan_count - 1:
                    await asyncio.sleep(2)
            
            self.log_progress(f"Deep scan phase completed", "success")
        
        # Validate discovered endpoints
        if mode in ["all", "validate"] and (self.results or all_results):
            self.log_progress(f"[Phase 4/4] Validation - Validating discovered endpoints")
            validation_targets = []
            
            # Collect URLs for validation
            for result in self.results + all_results:
                if 'url' in result:
                    validation_targets.append(result['url'])
                if 'found_links' in result:
                    validation_targets.extend(result['found_links'])
            
            validation_targets = list(set(validation_targets))[:20]  # Limit validation
            self.log_progress(f"Validating {len(validation_targets)} unique endpoints")
            
            validated_count = 0
            for i, url in enumerate(validation_targets):
                self.log_progress(f"Validating {i+1}/{len(validation_targets)}: {url}")
                validation_result = await self.validate_swagger_endpoint(url)
                if validation_result:
                    all_results.append(validation_result)
                    validated_count += 1
                    self.log_progress(f"Validation successful: {url}", "success")
                else:
                    self.log_progress(f"Validation failed: {url}", "warning")
                    
                # Small delay between validations
                if i < len(validation_targets) - 1:
                    await asyncio.sleep(1)
            
            self.log_progress(f"Validation phase completed: {validated_count}/{len(validation_targets)} endpoints validated", "success")
        
        # Combine and deduplicate results with enhanced filtering
        combined_results = self.results + all_results
        unique_results = self.deduplicate_results(combined_results)
        
        # Apply additional quality filters
        filtered_results = self._apply_quality_filters(unique_results)
        
        self.log_progress(f"Quality filtering: {len(unique_results)} -> {len(filtered_results)} results")
        
        # Calculate scan duration
        end_time = datetime.now()
        scan_duration = end_time - start_time
        
        self.log_progress(f"Scan completed in {scan_duration}", "success")
        self.log_progress(f"Total unique results: {len(unique_results)}")
        
        # Save results
        self.save_results(filtered_results, scan_duration)
        self.generate_report(filtered_results, scan_duration)
        
        return filtered_results
    
    def deduplicate_results(self, results):
        """Enhanced deduplication with URL normalization and confidence merging"""
        url_map = {}
        
        for result in results:
            url = result.get('url', '')
            if not url:
                continue
                
            # Normalize URL for better deduplication
            normalized_url = self._normalize_url(url)
            
            if normalized_url in url_map:
                # Merge with existing result, keeping higher confidence
                existing = url_map[normalized_url]
                if result.get('confidence', 0) > existing.get('confidence', 0):
                    # Update with higher confidence result but preserve some data
                    existing['confidence'] = result.get('confidence', 0)
                    if 'validated' in result and result['validated']:
                        existing.update(result)
                # Merge sources
                existing_sources = existing.get('sources', [existing.get('source')])
                new_source = result.get('source')
                if new_source and new_source not in existing_sources:
                    existing['sources'] = existing_sources + [new_source]
            else:
                url_map[normalized_url] = result.copy()
                url_map[normalized_url]['sources'] = [result.get('source')]
        
        unique_results = list(url_map.values())
        
        # Enhanced sorting with multiple criteria
        source_priority = {
            'direct_scan': 0, 'crawl4ai': 1, 'google_dork': 2, 
            'google_dork_fallback': 3, 'unknown': 999
        }
        
        unique_results.sort(key=lambda x: (
            -int(x.get('validated', False)),  # Validated results first
            -x.get('confidence', 0),  # Higher confidence
            source_priority.get(x.get('source', 'unknown'), 999),  # Better sources
            -len(x.get('swagger_indicators', [])),  # More indicators
            x.get('url', '')  # Alphabetical
        ))
        
        return unique_results
    
    def _normalize_url(self, url):
        """Normalize URL for better deduplication"""
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            
            # Remove common query parameters that don't affect the API
            # and normalize the path
            path = parsed.path.rstrip('/')
            if not path:
                path = '/'
                
            # Remove fragment and most query parameters
            normalized = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path,
                '',  # params
                '',  # query - removed for deduplication
                ''   # fragment
            ))
            return normalized
        except:
            return url.lower()
    
    def _apply_quality_filters(self, results):
        """Apply quality filters to remove low-value results"""
        filtered = []
        
        for result in results:
            # Skip very low confidence results unless validated
            if result.get('confidence', 0) < 2 and not result.get('validated', False):
                continue
                
            # Skip results with suspicious patterns
            url = result.get('url', '')
            if any(suspicious in url.lower() for suspicious in [
                'example.com', 'localhost', '127.0.0.1', 'test.test',
                'placeholder', 'dummy', 'fake'
            ]):
                continue
                
            # Require reasonable domain name
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                if not domain or len(domain) < 3:
                    continue
            except:
                continue
                
            filtered.append(result)
        
        return filtered
    
    def save_results(self, results, scan_duration=None):
        """Save results to JSON file"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        domain_suffix = f"_{self.target_domain}" if self.target_domain else ""
        filename = self.output_dir / f"swagger_results_{timestamp}{domain_suffix}.json"
        
        # Add metadata to results
        output_data = {
            'scan_metadata': {
                'timestamp': timestamp,
                'target_domain': self.target_domain,
                'total_results': len(results),
                'scan_duration': str(scan_duration) if scan_duration else None,
                'scanner_version': '2.0_enhanced'
            },
            'results': results
        }
        
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        self.log_progress(f"Results saved to {filename}", "success")
        return filename
    
    def generate_report(self, results, scan_duration=None):
        """Generate a human-readable report"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        domain_suffix = f"_{self.target_domain}" if self.target_domain else ""
        report_file = self.output_dir / f"swagger_report_{timestamp}{domain_suffix}.txt"
        
        with open(report_file, 'w') as f:
            f.write("=== ENHANCED SWAGGER/API DISCOVERY REPORT ===\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Domain: {self.target_domain or 'All domains (global scan)'}\n")
            f.write(f"Total Results: {len(results)}\n")
            if scan_duration:
                f.write(f"Scan Duration: {scan_duration}\n")
            f.write(f"Scanner Version: 2.0 Enhanced\n\n")
            
            # Group by source
            sources = {}
            for result in results:
                source = result.get('source', 'unknown')
                if source not in sources:
                    sources[source] = []
                sources[source].append(result)
            
            for source, source_results in sources.items():
                f.write(f"\n=== {source.upper()} RESULTS ({len(source_results)}) ===\n")
                for i, result in enumerate(source_results, 1):
                    confidence = result.get('confidence', 0)
                    confidence_indicator = "🔥" if confidence >= 7 else "⭐" if confidence >= 4 else "💡"
                    
                    f.write(f"\n{i}. {confidence_indicator} {result.get('url', 'N/A')}\n")
                    if 'confidence' in result:
                        f.write(f"   Confidence: {confidence}/10\n")
                    if 'status' in result:
                        f.write(f"   Status: {result['status']}\n")
                    if 'type' in result:
                        f.write(f"   Type: {result['type']}\n")
                    if 'version' in result:
                        f.write(f"   Version: {result['version']}\n")
                    if 'endpoints' in result:
                        f.write(f"   Endpoints: {result['endpoints']}\n")
                    if 'swagger_indicators' in result:
                        f.write(f"   Indicators: {', '.join(result['swagger_indicators'])}\n")
                    if 'title' in result:
                        f.write(f"   Title: {result['title']}\n")
                    if 'domain' in result:
                        f.write(f"   Domain: {result['domain']}\n")
                    if 'dork' in result:
                        f.write(f"   Found via: {result['dork']}\n")
                    if 'found_links' in result and result['found_links']:
                        f.write(f"   Related Links: {len(result['found_links'])} found\n")
                    if 'validated' in result and result['validated']:
                        f.write(f"   ✓ VALIDATED SWAGGER/API ENDPOINT\n")
            
            # Add summary statistics
            f.write(f"\n=== SUMMARY STATISTICS ===\n")
            high_confidence = len([r for r in results if r.get('confidence', 0) >= 7])
            medium_confidence = len([r for r in results if 4 <= r.get('confidence', 0) < 7])
            low_confidence = len([r for r in results if r.get('confidence', 0) < 4])
            
            f.write(f"High Confidence (7-10): {high_confidence}\n")
            f.write(f"Medium Confidence (4-6): {medium_confidence}\n")
            f.write(f"Low Confidence (0-3): {low_confidence}\n")
            
            # Domain distribution
            domains = {}
            for result in results:
                domain = result.get('domain', 'unknown')
                domains[domain] = domains.get(domain, 0) + 1
            
            f.write(f"\nTop Domains:\n")
            for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"  {domain}: {count} endpoints\n")
        
        self.log_progress(f"Report saved to {report_file}", "success")
        return report_file

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║              Enhanced SwaggerDorker v2.0                     ║
║          Advanced Swagger/API Discovery Tool                 ║
║                                                              ║
║  Features:                                                   ║
║  • Enhanced Google Dorking with 100+ patterns               ║
║  • Direct endpoint scanning                                  ║
║  • Deep content analysis with Crawl4AI                      ║
║  • Comprehensive validation                                  ║
║  • Verbose logging and progress tracking                     ║
║  • Improved timeout handling                                 ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Enhanced Swagger/API Discovery Tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com                    # Scan specific domain
  %(prog)s -d example.com -m direct         # Direct scan only
  %(prog)s -m dork --max-dorks 20           # Global dork scan
  %(prog)s -d example.com -q                # Quiet mode
  %(prog)s -d example.com --max-scans 10    # More deep scans
        """
    )
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-m', '--mode', choices=['all', 'direct', 'dork', 'crawl', 'validate'], 
                       default='all', help='Scan mode (default: all)')
    parser.add_argument('--max-dorks', type=int, default=10, help='Maximum Google dorks to use (default: 10)')
    parser.add_argument('--max-scans', type=int, default=5, help='Maximum URLs to deep scan (default: 5)')
    parser.add_argument('-o', '--output', default='swagger_results', help='Output directory (default: swagger_results)')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='Enable verbose output (default: True)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Disable verbose output')
    
    args = parser.parse_args()
    
    # Handle verbose/quiet flags
    verbose = args.verbose and not args.quiet
    
    if not args.domain and args.mode in ['direct', 'all']:
        if verbose:
            print("⚠️  Warning: Direct scan requires a target domain (-d)")
        if args.mode == 'direct':
            print("❌ Error: Direct scan mode requires a target domain")
            sys.exit(1)
    
    if not args.domain and verbose:
        print("🌐 Running global scan with enhanced dorks for maximum discovery")
        print("   Targeting development environments, cloud platforms, and exposed APIs")
        print("   This may take several minutes due to rate limiting...")
    
    async def run_scanner():
        scanner = SwaggerDorkScanner(target_domain=args.domain, output_dir=args.output, verbose=verbose)
        results = await scanner.run(mode=args.mode, max_dorks=args.max_dorks, max_scans=args.max_scans)
        
        if verbose:
            scanner.log_progress(f"Scan Complete! Found {len(results)} unique Swagger/API endpoints", "success")
        else:
            print(f"Found {len(results)} endpoints")
        
        if results:
            if verbose:
                print("\n📋 Top Results Summary:")
                for result in results[:10]:  # Show first 10
                    url = result.get('url', 'N/A')
                    source = result.get('source', 'unknown')
                    confidence = result.get('confidence', 0)
                    confidence_emoji = "🔥" if confidence >= 7 else "⭐" if confidence >= 4 else "💡"
                    print(f"  {confidence_emoji} {url} ({source})")
                
                if len(results) > 10:
                    print(f"  ... and {len(results) - 10} more (see full report)")
            else:
                # Quiet mode - just show URLs
                for result in results:
                    print(result.get('url', 'N/A'))
        else:
            if verbose:
                scanner.log_progress("No Swagger/API endpoints found", "warning")
            else:
                print("No endpoints found")
    
    asyncio.run(run_scanner())

if __name__ == "__main__":
    main()