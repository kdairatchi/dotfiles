#!/usr/bin/env python3

import asyncio
import sys
import json
import yaml
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import urlparse

# Import our enhanced scanners
from enhanced_domsink_scanner import DOMSinkScanner, ScanResult
from playwright_dom_poc_framework import PlaywrightDOMPOCFramework, POCResult

class ComprehensiveDOMScanner:
    """
    Comprehensive DOM XSS Scanner combining multiple detection techniques:
    1. Enhanced DOM sink detection
    2. Playwright-based PoC framework
    3. Advanced payload testing
    4. Comprehensive reporting
    """
    
    def __init__(self, config_file: str = "domsink_config.yaml"):
        self.config = self.load_config(config_file)
        self.setup_logging()
        
        # Initialize scanners
        self.sink_scanner = None
        self.poc_framework = None
        self.results = {
            'scan_results': [],
            'poc_results': [],
            'summary': {},
            'recommendations': []
        }
    
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[-] Config file {config_file} not found, using defaults")
            return self.get_default_config()
        except yaml.YAMLError as e:
            print(f"[-] Error parsing config file: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'scanner': {
                'timeout': 30000,
                'headless': True,
                'test_payloads': True,
                'enable_poc_framework': True,
                'take_screenshots': True
            },
            'risk_scoring': {
                'critical_threshold': 90,
                'high_risk_threshold': 80,
                'medium_risk_threshold': 50,
                'poc_generation_threshold': 75
            },
            'output': {
                'generate_nuclei_templates': True,
                'detailed_reporting': True,
                'export_formats': ['json']
            }
        }
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('scanner', {}).get('log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('comprehensive_dom_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def initialize_scanners(self):
        """Initialize all scanning components"""
        scanner_config = self.config.get('scanner', {})
        
        # Initialize DOM sink scanner
        self.sink_scanner = DOMSinkScanner(
            headless=scanner_config.get('headless', True),
            timeout=scanner_config.get('timeout', 30000),
            use_interactsh=self.config.get('interactsh', {}).get('enabled', False),
            telegram_token=self.config.get('notifications', {}).get('telegram', {}).get('bot_token'),
            discord_webhook=self.config.get('notifications', {}).get('discord', {}).get('webhook_url'),
            max_crawl_depth=scanner_config.get('max_crawl_depth', 3),
            enable_crawling=scanner_config.get('enable_crawling', False)
        )
        
        # Initialize PoC framework if enabled
        if scanner_config.get('enable_poc_framework', True):
            self.poc_framework = PlaywrightDOMPOCFramework(
                headless=scanner_config.get('headless', True),
                timeout=scanner_config.get('timeout', 30000),
                take_screenshots=scanner_config.get('take_screenshots', True)
            )
    
    async def scan_urls(self, urls: List[str]) -> Dict:
        """Perform comprehensive scanning on URLs"""
        if not urls:
            self.logger.error("No URLs provided for scanning")
            raise ValueError("URLs list cannot be empty")
        
        # Validate URLs
        valid_urls = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    valid_urls.append(url)
                else:
                    self.logger.warning(f"Invalid URL format: {url}")
            except Exception as e:
                self.logger.warning(f"Error parsing URL {url}: {e}")
        
        if not valid_urls:
            self.logger.error("No valid URLs found")
            raise ValueError("No valid URLs provided")
        
        self.logger.info(f"Starting comprehensive DOM scan on {len(valid_urls)} valid URLs")
        
        try:
            # Phase 1: DOM Sink Detection
            print(f"[*] Phase 1: DOM Sink Detection")
            scan_results = await self.sink_scanner.scan_urls(
                valid_urls, 
                test_payloads=self.config.get('scanner', {}).get('test_payloads', True)
            )
        except Exception as e:
            self.logger.error(f"Error in Phase 1 - DOM Sink Detection: {e}")
            scan_results = []
        
        self.results['scan_results'] = scan_results
        
        # Phase 2: PoC Generation and Testing (for high-risk findings)
        poc_results = []
        if self.poc_framework and scan_results:
            try:
                print(f"[*] Phase 2: PoC Generation and Testing")
                
                # Filter high-risk results for PoC testing
                high_risk_results = [
                    r for r in scan_results 
                    if r.risk_score >= self.config.get('risk_scoring', {}).get('poc_generation_threshold', 75)
                ]
                
                if high_risk_results:
                    print(f"[*] Testing PoCs for {len(high_risk_results)} high-risk findings")
                    
                    for result in high_risk_results:
                        try:
                            if result.sinks:
                                url_poc_results = await self.poc_framework.comprehensive_poc_test(
                                    result.url, result.sinks
                                )
                                poc_results.extend(url_poc_results)
                        except Exception as e:
                            self.logger.error(f"Error testing PoC for {result.url}: {e}")
                            continue
                else:
                    self.logger.info("No high-risk findings found for PoC testing")
            except Exception as e:
                self.logger.error(f"Error in Phase 2 - PoC Generation: {e}")
                poc_results = []
        
        self.results['poc_results'] = poc_results
        
        # Phase 3: Analysis and Reporting
        print(f"[*] Phase 3: Analysis and Reporting")
        self.generate_comprehensive_analysis()
        
        return self.results
    
    def generate_comprehensive_analysis(self):
        """Generate comprehensive analysis of all results"""
        scan_results = self.results['scan_results']
        poc_results = self.results['poc_results']
        
        # Calculate statistics
        total_urls = len(set(r.url for r in scan_results))
        total_findings = len(scan_results)
        successful_pocs = len([r for r in poc_results if r.execution_confirmed]) if poc_results else 0
        
        # Risk distribution
        risk_distribution = {
            'critical': len([r for r in scan_results if r.risk_score >= 90]),
            'high': len([r for r in scan_results if 80 <= r.risk_score < 90]),
            'medium': len([r for r in scan_results if 50 <= r.risk_score < 80]),
            'low': len([r for r in scan_results if r.risk_score < 50])
        }
        
        # Sink analysis
        all_sinks = []
        for result in scan_results:
            all_sinks.extend(result.sinks)
        
        sink_frequency = {}
        for sink in all_sinks:
            sink_frequency[sink] = sink_frequency.get(sink, 0) + 1
        
        # WAF analysis
        waf_detections = {}
        for result in scan_results:
            if result.waf_detected:
                waf_detections[result.waf_detected] = waf_detections.get(result.waf_detected, 0) + 1
        
        self.results['summary'] = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_urls_scanned': total_urls,
            'total_findings': total_findings,
            'successful_pocs': successful_pocs,
            'risk_distribution': risk_distribution,
            'most_common_sinks': dict(sorted(sink_frequency.items(), key=lambda x: x[1], reverse=True)[:10]),
            'waf_detections': waf_detections,
            'average_risk_score': round(sum(r.risk_score for r in scan_results) / len(scan_results), 2) if scan_results else 0,
            'mutation_observations': len([r for r in scan_results if r.mutation_observed]),
            'interactsh_callbacks': len([r for r in scan_results if r.interactsh_triggered])
        }
        
        # Generate recommendations
        self.generate_recommendations()
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        scan_results = self.results['scan_results']
        poc_results = self.results['poc_results']
        
        recommendations = []
        
        # Critical findings
        critical_findings = [r for r in scan_results if r.risk_score >= 90]
        if critical_findings:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'Immediate Action Required',
                'description': f'{len(critical_findings)} critical DOM XSS vulnerabilities found',
                'urls': [r.url for r in critical_findings],
                'action': 'Patch these vulnerabilities immediately and verify fixes'
            })
        
        # Successful PoCs
        successful_pocs = [r for r in poc_results if r.execution_confirmed] if poc_results else []
        if successful_pocs:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Confirmed Exploitable Vulnerabilities',
                'description': f'{len(successful_pocs)} PoCs successfully executed',
                'urls': list(set(r.url for r in successful_pocs)),
                'action': 'These have confirmed exploitation - prioritize for immediate remediation'
            })
        
        # Common sinks
        sink_frequency = self.results['summary'].get('most_common_sinks', {})
        if sink_frequency:
            try:
                top_sink = max(sink_frequency.items(), key=lambda x: x[1])
                recommendations.append({
                    'priority': 'MEDIUM',
                    'title': f'Most Common Sink: {top_sink[0]}',
                    'description': f'Found in {top_sink[1]} locations',
                    'action': f'Review all instances of {top_sink[0]} for proper input validation and output encoding'
                })
            except Exception as e:
                self.logger.warning(f"Error determining most common sink: {e}")
        
        # WAF bypass
        waf_detections = self.results['summary'].get('waf_detections', {})
        if waf_detections:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'WAF Detected but Vulnerabilities Found',
                'description': f'WAFs detected: {", ".join(waf_detections.keys())}',
                'action': 'Review WAF rules - they may not be blocking all XSS vectors'
            })

        # General recommendations
        if scan_results:
            recommendations.append({
                'priority': 'LOW',
                'title': 'General Security Improvements',
                'description': 'Implement comprehensive XSS prevention',
                'action': 'Use Content Security Policy, input validation, output encoding, and DOM sanitization'
            })

        self.results['recommendations'] = recommendations
    
    def save_results(self, output_file: str = "comprehensive_dom_results.json"):
        """Save comprehensive results to file"""
        from dataclasses import asdict
        
        serializable_results = {
            'scan_results': [
                {
                    'url': r.url,
                    'sinks': r.sinks,
                    'risk_score': r.risk_score,
                    'execution_context': r.execution_context,
                    'mutation_observed': r.mutation_observed,
                    'waf_detected': r.waf_detected,
                    'interactsh_triggered': r.interactsh_triggered,
                    'timestamp': r.timestamp,
                    'crawl_depth': r.crawl_depth,
                    'ai_analysis': r.ai_analysis
                } for r in self.results['scan_results']
            ],
            'poc_results': [
                {
                    'url': r.url,
                    'sink': r.sink,
                    'payload': r.payload,
                    'execution_confirmed': r.execution_confirmed,
                    'execution_method': r.execution_method,
                    'response_time': r.response_time,
                    'screenshot_path': r.screenshot_path,
                    'timestamp': r.timestamp
                } for r in self.results['poc_results']
            ] if self.results['poc_results'] else [],
            'summary': self.results['summary'],
            'recommendations': self.results['recommendations']
        }

        # Save main results
        with open(output_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)

        # Generate additional formats if configured
        export_formats = self.config.get('output', {}).get('export_formats', ['json'])

        if 'yaml' in export_formats:
            yaml_file = output_file.replace('.json', '.yaml')
            with open(yaml_file, 'w') as f:
                yaml.dump(serializable_results, f, default_flow_style=False)

        if 'csv' in export_formats:
            self.export_csv_summary(output_file.replace('.json', '_summary.csv'))

        # Generate HTML report if configured
        if self.config.get('output', {}).get('generate_html_report', False):
            self.generate_html_report(output_file.replace('.json', '_report.html'))

        self.logger.info(f"Results saved to {output_file}")
    
    def export_csv_summary(self, csv_file: str):
        """Export summary data to CSV"""
        import csv
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Risk Score', 'Sinks Found', 'WAF Detected', 'PoC Confirmed'])
            
            for result in self.results['scan_results']:
                poc_confirmed = any(
                    poc.url == result.url and poc.execution_confirmed 
                    for poc in (self.results['poc_results'] or [])
                )
                writer.writerow([
                    result.url,
                    result.risk_score,
                    ', '.join(result.sinks),
                    result.waf_detected or 'None',
                    'Yes' if poc_confirmed else 'No'
                ])
    
    def generate_html_report(self, html_file: str):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Comprehensive DOM XSS Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .critical {{ color: red; font-weight: bold; }}
                .high {{ color: orange; font-weight: bold; }}
                .medium {{ color: #ff6600; }}
                .low {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .summary-box {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #007cba; }}
            </style>
        </head>
        <body>
            <h1>Comprehensive DOM XSS Scan Report</h1>
            <div class="summary-box">
                <h2>Executive Summary</h2>
                <p><strong>Scan Date:</strong> {self.results['summary']['scan_timestamp']}</p>
                <p><strong>URLs Scanned:</strong> {self.results['summary']['total_urls_scanned']}</p>
                <p><strong>Total Findings:</strong> {self.results['summary']['total_findings']}</p>
                <p><strong>Successful PoCs:</strong> {self.results['summary']['successful_pocs']}</p>
                <p><strong>Average Risk Score:</strong> {self.results['summary']['average_risk_score']}/100</p>
            </div>
            
            <h2>Risk Distribution</h2>
            <table>
                <tr><th>Risk Level</th><th>Count</th></tr>
                <tr><td class="critical">Critical (90+)</td><td>{self.results['summary']['risk_distribution']['critical']}</td></tr>
                <tr><td class="high">High (80-89)</td><td>{self.results['summary']['risk_distribution']['high']}</td></tr>
                <tr><td class="medium">Medium (50-79)</td><td>{self.results['summary']['risk_distribution']['medium']}</td></tr>
                <tr><td class="low">Low (<50)</td><td>{self.results['summary']['risk_distribution']['low']}</td></tr>
            </table>
            
            <h2>Recommendations</h2>
            <ul>
        """
        
        for rec in self.results['recommendations']:
            priority_class = rec['priority'].lower()
            html_content += f'<li class="{priority_class}"><strong>{rec["title"]}</strong>: {rec["description"]} - {rec["action"]}</li>'
        
        html_content += """
            </ul>
            
            <h2>Detailed Findings</h2>
            <table>
                <tr><th>URL</th><th>Risk Score</th><th>Sinks</th><th>WAF</th><th>PoC Confirmed</th></tr>
        """
        
        for result in self.results['scan_results']:
            risk_class = 'critical' if result.risk_score >= 90 else 'high' if result.risk_score >= 80 else 'medium' if result.risk_score >= 50 else 'low'
            poc_confirmed = any(
                poc.url == result.url and poc.execution_confirmed 
                for poc in (self.results['poc_results'] or [])
            )
            html_content += f"""
                <tr>
                    <td>{result.url}</td>
                    <td class="{risk_class}">{result.risk_score}</td>
                    <td>{', '.join(result.sinks)}</td>
                    <td>{result.waf_detected or 'None'}</td>
                    <td>{'✓' if poc_confirmed else '✗'}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
    
    def print_summary(self):
        """Print scan summary to console"""
        summary = self.results['summary']
        
        print(f"\n{'='*60}")
        print(f"COMPREHENSIVE DOM XSS SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Scan completed: {summary['scan_timestamp']}")
        print(f"URLs scanned: {summary['total_urls_scanned']}")
        print(f"Total findings: {summary['total_findings']}")
        print(f"Successful PoCs: {summary['successful_pocs']}")
        print(f"Average risk score: {summary['average_risk_score']}/100")
        
        print(f"\nRisk Distribution:")
        print(f"  Critical (90+): {summary['risk_distribution']['critical']}")
        print(f"  High (80-89): {summary['risk_distribution']['high']}")
        print(f"  Medium (50-79): {summary['risk_distribution']['medium']}")
        print(f"  Low (<50): {summary['risk_distribution']['low']}")
        
        if summary['most_common_sinks']:
            print(f"\nMost Common Sinks:")
            for sink, count in list(summary['most_common_sinks'].items())[:5]:
                print(f"  {sink}: {count}")
        
        if summary['waf_detections']:
            print(f"\nWAF Detections:")
            for waf, count in summary['waf_detections'].items():
                print(f"  {waf}: {count}")
        
        print(f"\nRecommendations:")
        for rec in self.results['recommendations'][:3]:  # Show top 3
            print(f"  [{rec['priority']}] {rec['title']}")

async def main():
    parser = argparse.ArgumentParser(description="Comprehensive DOM XSS Scanner")
    parser.add_argument("urls", help="File containing URLs to scan (one per line)")
    parser.add_argument("-c", "--config", default="domsink_config.yaml",
                       help="Configuration file (default: domsink_config.yaml)")
    parser.add_argument("-o", "--output", default="comprehensive_dom_results.json",
                       help="Output file for results")
    parser.add_argument("--disable-poc", action="store_true",
                       help="Disable PoC framework")
    parser.add_argument("--visible", action="store_true",
                       help="Run browsers in visible mode")
    
    args = parser.parse_args()
    
    # Read URLs
    try:
        with open(args.urls, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[-] Error: File '{args.urls}' not found")
        sys.exit(1)
    
    if not urls:
        print("[-] No valid URLs found in input file")
        sys.exit(1)
    
    # Initialize scanner
    scanner = ComprehensiveDOMScanner(args.config)
    
    # Override config with command line args
    if args.disable_poc:
        scanner.config['scanner']['enable_poc_framework'] = False
    if args.visible:
        scanner.config['scanner']['headless'] = False
    
    # Initialize and run scan
    await scanner.initialize_scanners()
    await scanner.scan_urls(urls)
    
    # Save results and print summary
    scanner.save_results(args.output)
    scanner.print_summary()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Fatal error: {str(e)}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)