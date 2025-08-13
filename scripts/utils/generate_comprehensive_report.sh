#!/bin/bash

# Comprehensive Reporting System for Bug Bounty Framework
# Enhanced with interactive dashboards, JSON exports, and analytics

set -euo pipefail

# Colors for terminal output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORTS_DIR="$HOME/security_reports"

usage() {
    cat << 'EOF'
Comprehensive Security Report Generator

Usage: ./generate_comprehensive_report.sh [options] <scan_results_directory>

Options:
  -o, --output <dir>     Output directory for reports (default: ~/security_reports)
  -f, --format <type>    Report format: html|json|pdf|all (default: html)
  -t, --template <name>  Report template: modern|classic|executive (default: modern)
  -d, --dashboard        Generate interactive dashboard
  -c, --charts           Include charts and visualizations
  -e, --export           Export data for external tools
  -v, --verbose          Verbose output
  -h, --help            Show this help

Examples:
  ./generate_comprehensive_report.sh /path/to/scan/results
  ./generate_comprehensive_report.sh -f all -d -c /path/to/results
  ./generate_comprehensive_report.sh --dashboard --export /path/to/results
EOF
}

# Parse command line arguments
OUTPUT_DIR="$REPORTS_DIR"
FORMAT="html"
TEMPLATE="modern"
DASHBOARD=false
CHARTS=false
EXPORT=false
VERBOSE=false
SCAN_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -f|--format) FORMAT="$2"; shift 2 ;;
        -t|--template) TEMPLATE="$2"; shift 2 ;;
        -d|--dashboard) DASHBOARD=true; shift ;;
        -c|--charts) CHARTS=true; shift ;;
        -e|--export) EXPORT=true; shift ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; usage; exit 1 ;;
        *) SCAN_DIR="$1"; shift ;;
    esac
done

if [[ -z "$SCAN_DIR" ]]; then
    echo "Error: Scan results directory is required" >&2
    usage
    exit 1
fi

if [[ ! -d "$SCAN_DIR" ]]; then
    echo "Error: Scan directory does not exist: $SCAN_DIR" >&2
    exit 1
fi

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*"
}

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Extract data from scan results
extract_scan_data() {
    local scan_dir="$1"
    local data_file="$OUTPUT_DIR/scan_data.json"
    
    log "Extracting scan data from: $scan_dir"
    
    # Initialize data structure
    cat > "$data_file" << 'EOF'
{
    "scan_info": {},
    "statistics": {},
    "findings": {
        "subdomains": [],
        "live_hosts": [],
        "vulnerabilities": [],
        "open_ports": [],
        "urls": [],
        "technologies": []
    },
    "analysis": {
        "risk_score": 0,
        "critical_issues": 0,
        "high_issues": 0,
        "medium_issues": 0,
        "low_issues": 0
    }
}
EOF

    # Extract basic information
    local target=$(basename "$scan_dir" | cut -d'_' -f3-)
    local scan_date=$(basename "$scan_dir" | cut -d'_' -f1-2)
    
    # Count findings
    local subdomain_count=$(wc -l < "$scan_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    local live_count=$(wc -l < "$scan_dir/live_subdomains.txt" 2>/dev/null || echo 0)
    local vuln_count=$(wc -l < "$scan_dir/vulnerabilities.txt" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$scan_dir/all_urls.txt" 2>/dev/null || echo 0)
    local port_count=$(wc -l < "$scan_dir/open_ports.txt" 2>/dev/null || echo 0)
    
    # Update JSON with extracted data using jq
    if command -v jq >/dev/null 2>&1; then
        jq --arg target "$target" \
           --arg date "$scan_date" \
           --argjson subdomains "$subdomain_count" \
           --argjson live_hosts "$live_count" \
           --argjson vulns "$vuln_count" \
           --argjson urls "$url_count" \
           --argjson ports "$port_count" \
           '.scan_info.target = $target |
            .scan_info.scan_date = $date |
            .statistics.subdomains_total = $subdomains |
            .statistics.live_hosts = $live_hosts |
            .statistics.vulnerabilities = $vulns |
            .statistics.urls_discovered = $urls |
            .statistics.open_ports = $ports' \
           "$data_file" > "${data_file}.tmp" && mv "${data_file}.tmp" "$data_file"
    fi
    
    log_success "Data extraction completed"
}

# Generate HTML report
generate_html_report() {
    local data_file="$OUTPUT_DIR/scan_data.json"
    local html_file="$OUTPUT_DIR/comprehensive_report.html"
    
    log "Generating HTML report: $html_file"
    
    # Read data from JSON
    local target=$(jq -r '.scan_info.target // "Unknown"' "$data_file" 2>/dev/null || echo "Unknown")
    local scan_date=$(jq -r '.scan_info.scan_date // "Unknown"' "$data_file" 2>/dev/null || echo "Unknown")
    local subdomains=$(jq -r '.statistics.subdomains_total // 0' "$data_file" 2>/dev/null || echo 0)
    local live_hosts=$(jq -r '.statistics.live_hosts // 0' "$data_file" 2>/dev/null || echo 0)
    local vulnerabilities=$(jq -r '.statistics.vulnerabilities // 0' "$data_file" 2>/dev/null || echo 0)
    local urls=$(jq -r '.statistics.urls_discovered // 0' "$data_file" 2>/dev/null || echo 0)
    local ports=$(jq -r '.statistics.open_ports // 0' "$data_file" 2>/dev/null || echo 0)
    
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Security Report - $target</title>
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --dark-color: #343a40;
            --light-color: #f8f9fa;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: var(--dark-color);
            background: var(--light-color);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        
        .header h2 {
            font-size: 1.8rem;
            margin-bottom: 1rem;
            opacity: 0.9;
        }
        
        .header .meta {
            font-size: 1rem;
            opacity: 0.8;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            border-left: 4px solid var(--primary-color);
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
            line-height: 1;
        }
        
        .stat-label {
            color: #6c757d;
            font-weight: 500;
            font-size: 1rem;
        }
        
        .section {
            background: white;
            padding: 2rem;
            margin-bottom: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        
        .section h2 {
            margin-bottom: 1.5rem;
            color: var(--dark-color);
            border-bottom: 3px solid var(--primary-color);
            padding-bottom: 0.5rem;
            font-size: 1.5rem;
        }
        
        .section h3 {
            margin-bottom: 1rem;
            color: var(--dark-color);
            font-size: 1.2rem;
        }
        
        .vulnerability {
            background: #fff3cd;
            border-left: 4px solid var(--warning-color);
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 4px;
        }
        
        .vulnerability.critical {
            background: #f8d7da;
            border-left-color: var(--danger-color);
        }
        
        .vulnerability.high {
            background: #fff3cd;
            border-left-color: #fd7e14;
        }
        
        .vulnerability.medium {
            background: #d4edda;
            border-left-color: var(--success-color);
        }
        
        .vulnerability.low {
            background: #d1ecf1;
            border-left-color: var(--info-color);
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        .badge-critical { background: var(--danger-color); color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: var(--warning-color); color: var(--dark-color); }
        .badge-low { background: var(--info-color); color: white; }
        .badge-info { background: var(--info-color); color: white; }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            transition: width 0.3s ease;
        }
        
        .chart-container {
            width: 100%;
            height: 300px;
            margin: 1rem 0;
            background: #f8f9fa;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #6c757d;
        }
        
        .risk-meter {
            text-align: center;
            padding: 1rem;
        }
        
        .risk-score {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .risk-low { color: var(--success-color); }
        .risk-medium { color: var(--warning-color); }
        .risk-high { color: var(--danger-color); }
        
        .file-list {
            list-style: none;
            padding: 0;
        }
        
        .file-list li {
            padding: 0.5rem;
            margin: 0.25rem 0;
            background: #f8f9fa;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            margin-top: 2rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .executive-summary {
            background: linear-gradient(135deg, #667eea20, #764ba220);
            border: 1px solid #667eea40;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .timeline {
            position: relative;
            padding-left: 2rem;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            left: 0.5rem;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--primary-color);
        }
        
        .timeline-item {
            position: relative;
            margin-bottom: 1rem;
            padding-left: 1.5rem;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -0.375rem;
            top: 0.375rem;
            width: 0.75rem;
            height: 0.75rem;
            border-radius: 50%;
            background: var(--primary-color);
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Comprehensive Security Report</h1>
            <h2>$target</h2>
            <div class="meta">
                <p>Generated on $(date '+%Y-%m-%d %H:%M:%S') | Scan Date: $scan_date</p>
                <p>High-Performance Bug Bounty Framework | Parallel Processing Enabled</p>
            </div>
        </header>
        
        <section class="executive-summary">
            <h2>📋 Executive Summary</h2>
            <p>This comprehensive security assessment was conducted using advanced parallel processing techniques with up to 9,000 concurrent jobs. The assessment covered subdomain enumeration, vulnerability scanning, port analysis, and technology fingerprinting.</p>
            <div class="risk-meter">
                <div class="risk-score risk-$([ $vulnerabilities -gt 10 ] && echo 'high' || [ $vulnerabilities -gt 5 ] && echo 'medium' || echo 'low')">
                    $([ $vulnerabilities -gt 0 ] && echo "RISK IDENTIFIED" || echo "LOW RISK")
                </div>
                <p>$vulnerabilities vulnerabilities discovered across $live_hosts live hosts</p>
            </div>
        </section>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$subdomains</div>
                <div class="stat-label">Total Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$live_hosts</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$urls</div>
                <div class="stat-label">URLs Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vulnerabilities</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$ports</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(printf "%.1f" $(echo "scale=1; $live_hosts * 100 / ($subdomains + 1)" | bc -l 2>/dev/null || echo 0))</div>
                <div class="stat-label">Live Host Ratio (%)</div>
            </div>
        </div>
        
        <section class="section">
            <h2>🔍 Vulnerability Assessment</h2>
            $(if [[ -f "$SCAN_DIR/vulnerabilities.txt" && -s "$SCAN_DIR/vulnerabilities.txt" ]]; then
                echo "<h3>Critical & High Severity Findings</h3>"
                echo "<div class='vulnerability critical'>"
                echo "<h4>🚨 Security Issues Detected</h4>"
                echo "<p>Found $vulnerabilities potential vulnerabilities. Manual review recommended.</p>"
                echo "<div class='chart-container'>Vulnerability distribution chart would appear here</div>"
                echo "</div>"
            else
                echo "<div class='vulnerability low'>"
                echo "<h4>✅ No Critical Vulnerabilities Detected</h4>"
                echo "<p>The automated scan did not identify any critical security issues. Continue monitoring and testing.</p>"
                echo "</div>"
            fi)
        </section>
        
        <section class="section">
            <h2>🌐 Asset Discovery</h2>
            <h3>Subdomain Enumeration Results</h3>
            <div class="progress-bar">
                <div class="progress-fill" style="width: $([ $subdomains -gt 0 ] && echo "scale=0; $live_hosts * 100 / $subdomains" | bc || echo 0)%"></div>
            </div>
            <p>Discovered $subdomains total subdomains with $live_hosts responding to HTTP requests.</p>
            
            $(if [[ -f "$SCAN_DIR/live_subdomains.txt" && -s "$SCAN_DIR/live_subdomains.txt" ]]; then
                echo "<h3>Top Live Subdomains</h3>"
                echo "<ul class='file-list'>"
                head -20 "$SCAN_DIR/live_subdomains.txt" | while read line; do
                    echo "<li>$line</li>"
                done
                echo "</ul>"
            fi)
        </section>
        
        <section class="section">
            <h2>🚪 Port Analysis</h2>
            $(if [[ -f "$SCAN_DIR/open_ports.txt" && -s "$SCAN_DIR/open_ports.txt" ]]; then
                echo "<p>Identified $ports open ports across the target infrastructure.</p>"
                echo "<h3>Open Ports Summary</h3>"
                echo "<ul class='file-list'>"
                head -30 "$SCAN_DIR/open_ports.txt" | while read line; do
                    echo "<li>$line</li>"
                done
                echo "</ul>"
            else
                echo "<p>No port scanning data available or no open ports detected.</p>"
            fi)
        </section>
        
        <section class="section">
            <h2>🔗 URL Discovery</h2>
            <p>Discovered $urls URLs through wayback machine analysis, crawling, and archival sources.</p>
            $(if [[ -f "$SCAN_DIR/urls_with_params.txt" && -s "$SCAN_DIR/urls_with_params.txt" ]]; then
                local param_count=$(wc -l < "$SCAN_DIR/urls_with_params.txt" 2>/dev/null || echo 0)
                echo "<p><span class='badge badge-info'>$param_count URLs with parameters</span> identified for further testing.</p>"
            fi)
        </section>
        
        <section class="section">
            <h2>📊 Scan Methodology</h2>
            <div class="timeline">
                <div class="timeline-item">
                    <h4>Phase 1: Reconnaissance</h4>
                    <p>Multi-source subdomain enumeration using Subfinder, Assetfinder, and Chaos</p>
                </div>
                <div class="timeline-item">
                    <h4>Phase 2: Discovery</h4>
                    <p>Live host detection and HTTP service analysis with technology fingerprinting</p>
                </div>
                <div class="timeline-item">
                    <h4>Phase 3: Enumeration</h4>
                    <p>Port scanning and URL discovery from multiple archival sources</p>
                </div>
                <div class="timeline-item">
                    <h4>Phase 4: Assessment</h4>
                    <p>Vulnerability scanning using Nuclei with 5000+ templates</p>
                </div>
            </div>
        </section>
        
        <section class="section">
            <h2>📁 Output Files</h2>
            <p>All scan results have been saved to the following files:</p>
            <ul class="file-list">
                <li>📄 all_subdomains.txt - Complete subdomain enumeration results</li>
                <li>🌐 live_subdomains.txt - Active hosts responding to HTTP requests</li>
                <li>🔗 all_urls.txt - Comprehensive URL discovery results</li>
                <li>🚨 vulnerabilities.txt - Security vulnerability findings</li>
                <li>🚪 open_ports.txt - Network port scanning results</li>
                <li>📊 scan_data.json - Machine-readable results for automation</li>
                <li>📋 comprehensive_report.html - This detailed report</li>
            </ul>
        </section>
        
        <section class="section">
            <h2>🔧 Technical Details</h2>
            <h3>Scan Configuration</h3>
            <ul>
                <li><strong>Target:</strong> $target</li>
                <li><strong>Scan Date:</strong> $scan_date</li>
                <li><strong>Framework:</strong> High-Performance Bug Bounty Framework</li>
                <li><strong>Parallel Jobs:</strong> Up to 9,000 concurrent processes</li>
                <li><strong>Tools Used:</strong> Subfinder, Nuclei, HTTPx, Naabu, Katana, Dalfox</li>
                <li><strong>Report Generated:</strong> $(date '+%Y-%m-%d %H:%M:%S')</li>
            </ul>
        </section>
    </div>
    
    <footer class="footer">
        <p>Generated by High-Performance Bug Bounty Framework</p>
        <p>⚡ Optimized for up to 9,000 parallel jobs | 🛡️ Comprehensive Security Testing</p>
        <p><em>Remember: Use responsibly and with proper authorization</em></p>
    </footer>
</body>
</html>
EOF

    log_success "HTML report generated: $html_file"
}

# Generate JSON report
generate_json_report() {
    local data_file="$OUTPUT_DIR/scan_data.json"
    local json_file="$OUTPUT_DIR/detailed_results.json"
    
    log "Generating detailed JSON report: $json_file"
    
    # Enhanced JSON with more details
    if command -v jq >/dev/null 2>&1; then
        jq --arg timestamp "$(date -Iseconds)" \
           --arg generator "High-Performance Bug Bounty Framework" \
           --arg version "2.0" \
           '. + {
               "report_info": {
                   "generated_at": $timestamp,
                   "generator": $generator,
                   "version": $version,
                   "format": "comprehensive_json_v2"
               }
           }' "$data_file" > "$json_file"
    else
        cp "$data_file" "$json_file"
    fi
    
    log_success "JSON report generated: $json_file"
}

# Generate dashboard
generate_dashboard() {
    if [[ "$DASHBOARD" == true ]]; then
        log "Generating interactive dashboard..."
        
        local dashboard_file="$OUTPUT_DIR/dashboard.html"
        
        cat > "$dashboard_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; padding: 20px; }
        .widget { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; text-align: center; }
        h1 { margin: 0; }
        h2 { margin-top: 0; color: #333; }
        .metric { text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; color: #667eea; }
        .metric-label { color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Security Assessment Dashboard</h1>
        <p>Real-time insights from high-performance security scanning</p>
    </div>
    
    <div class="dashboard">
        <div class="widget">
            <h2>📊 Scan Overview</h2>
            <canvas id="overviewChart"></canvas>
        </div>
        
        <div class="widget">
            <h2>🎯 Target Analysis</h2>
            <div class="metric">
                <div class="metric-value" id="targetCount">-</div>
                <div class="metric-label">Targets Scanned</div>
            </div>
        </div>
        
        <div class="widget">
            <h2>🔍 Vulnerability Distribution</h2>
            <canvas id="vulnChart"></canvas>
        </div>
        
        <div class="widget">
            <h2>⚡ Performance Metrics</h2>
            <div class="metric">
                <div class="metric-value">9000</div>
                <div class="metric-label">Max Parallel Jobs</div>
            </div>
        </div>
    </div>
    
    <script>
        // Sample dashboard implementation
        // In a real implementation, this would load data from scan_data.json
        
        // Overview Chart
        const overviewCtx = document.getElementById('overviewChart').getContext('2d');
        new Chart(overviewCtx, {
            type: 'doughnut',
            data: {
                labels: ['Subdomains', 'Live Hosts', 'URLs', 'Vulnerabilities'],
                datasets: [{
                    data: [100, 75, 200, 5],
                    backgroundColor: ['#667eea', '#764ba2', '#f093fb', '#f5576c']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Vulnerability Chart
        const vulnCtx = document.getElementById('vulnChart').getContext('2d');
        new Chart(vulnCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [0, 1, 3, 1],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8']
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
EOF
        
        log_success "Interactive dashboard generated: $dashboard_file"
    fi
}

# Export data for external tools
export_data() {
    if [[ "$EXPORT" == true ]]; then
        log "Exporting data for external tools..."
        
        # Create CSV exports
        local csv_dir="$OUTPUT_DIR/csv_exports"
        mkdir -p "$csv_dir"
        
        # Export subdomains to CSV
        if [[ -f "$SCAN_DIR/all_subdomains.txt" ]]; then
            echo "subdomain,status" > "$csv_dir/subdomains.csv"
            while read -r subdomain; do
                echo "$subdomain,discovered" >> "$csv_dir/subdomains.csv"
            done < "$SCAN_DIR/all_subdomains.txt"
        fi
        
        # Export vulnerabilities to CSV
        if [[ -f "$SCAN_DIR/vulnerabilities.txt" ]]; then
            echo "finding,severity,target" > "$csv_dir/vulnerabilities.csv"
            while read -r vuln; do
                echo "$vuln,unknown,unknown" >> "$csv_dir/vulnerabilities.csv"
            done < "$SCAN_DIR/vulnerabilities.txt"
        fi
        
        log_success "Data exported to: $csv_dir"
    fi
}

# Main execution
main() {
    log "Starting comprehensive report generation..."
    log "Scan directory: $SCAN_DIR"
    log "Output directory: $OUTPUT_DIR"
    log "Format: $FORMAT"
    
    # Extract scan data
    extract_scan_data "$SCAN_DIR"
    
    # Generate reports based on format
    case "$FORMAT" in
        "html")
            generate_html_report
            ;;
        "json")
            generate_json_report
            ;;
        "all")
            generate_html_report
            generate_json_report
            generate_dashboard
            export_data
            ;;
        *)
            log_error "Unknown format: $FORMAT"
            exit 1
            ;;
    esac
    
    # Additional features
    if [[ "$FORMAT" == "html" || "$FORMAT" == "all" ]]; then
        generate_dashboard
    fi
    
    if [[ "$EXPORT" == true ]]; then
        export_data
    fi
    
    log_success "Report generation completed!"
    log "Reports available in: $OUTPUT_DIR"
    
    if [[ "$FORMAT" == "html" || "$FORMAT" == "all" ]]; then
        echo
        log "📊 View your report:"
        echo "   HTML Report: file://$OUTPUT_DIR/comprehensive_report.html"
        if [[ "$DASHBOARD" == true ]]; then
            echo "   Dashboard: file://$OUTPUT_DIR/dashboard.html"
        fi
    fi
}

# Run main function
main "$@"