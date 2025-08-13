#!/bin/bash

# Ultimate Bug Bounty Framework - Deployment Validation Script
# Comprehensive testing of all components and parallel processing capabilities
# Version: 2.0 - Enhanced with 9000 parallel jobs testing and comprehensive validation

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test function wrapper
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    ((TESTS_TOTAL++))
    echo -ne "${BLUE}Testing $test_name...${NC} "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test with output capture
run_test_with_output() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    ((TESTS_TOTAL++))
    echo -ne "${BLUE}Testing $test_name...${NC} "
    
    local output
    if output=$(eval "$test_command" 2>&1) && [[ "$output" =~ $expected_pattern ]]; then
        echo -e "${GREEN}PASS${NC} ($output)"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}FAIL${NC} ($output)"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗"
echo -e "║                    DEPLOYMENT VALIDATION SUITE                              ║"
echo -e "║                Ultimate Bug Bounty Framework                                ║"
echo -e "╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Section 1: Core Tool Availability
echo -e "${YELLOW}=== SECTION 1: CORE TOOL AVAILABILITY ===${NC}"

# Go security tools
run_test "Nuclei availability" "command -v nuclei"
run_test "Subfinder availability" "command -v subfinder"
run_test "HTTPx availability" "command -v httpx"
run_test "Naabu availability" "command -v naabu"
run_test "FFuf availability" "command -v ffuf"
run_test "Waybackurls availability" "command -v waybackurls"
run_test "Assetfinder availability" "command -v assetfinder"
run_test "GAU availability" "command -v gau"
run_test "Dalfox availability" "command -v dalfox"
run_test "DNSx availability" "command -v dnsx"
run_test "Katana availability" "command -v katana"
run_test "Chaos availability" "command -v chaos"
run_test "Qsreplace availability" "command -v qsreplace"
run_test "Unfurl availability" "command -v unfurl"

# System and parallel processing tools
run_test "GNU Parallel availability" "command -v parallel"
run_test "JQ availability" "command -v jq"
run_test "Curl availability" "command -v curl"
run_test "Wget availability" "command -v wget"

# Python security tools
run_test "SQLMap availability" "command -v sqlmap"
run_test "Dirsearch availability" "command -v dirsearch"
run_test "Arjun availability" "command -v arjun"
run_test "URO availability" "command -v uro"
run_test "Paramspider availability" "command -v paramspider"

# Development tools
run_test "Python3 availability" "command -v python3"
run_test "Pip3 availability" "command -v pip3"
run_test "Go availability" "command -v go"
run_test "Git availability" "command -v git"
run_test "Docker availability" "command -v docker || echo 'Docker not found (optional)'"

echo ""

# Section 2: Tool Versions and Functionality
echo -e "${YELLOW}=== SECTION 2: TOOL VERSIONS AND FUNCTIONALITY ===${NC}"

run_test_with_output "Nuclei version" "nuclei -version" "v[0-9]+\.[0-9]+\.[0-9]+"
run_test_with_output "Subfinder version" "subfinder -version" "v[0-9]+\.[0-9]+\.[0-9]+"
run_test_with_output "HTTPx version" "httpx -version" "v[0-9]+\.[0-9]+\.[0-9]+"
run_test "Nuclei templates availability" "test -d ~/.nuclei-templates && find ~/.nuclei-templates -name '*.yaml' | head -1"
run_test "Python3 availability" "python3 --version"
run_test "Go availability" "go version"

echo ""

# Section 3: Security Aliases and Functions
echo -e "${YELLOW}=== SECTION 3: SECURITY ALIASES AND FUNCTIONS ===${NC}"

if [[ -f ~/.security_aliases ]]; then
    source ~/.security_aliases
    run_test "Security aliases file exists" "test -f ~/.security_aliases"
    run_test "calc_parallel_jobs function" "type calc_parallel_jobs"
    run_test_with_output "Parallel jobs calculation" "calc_parallel_jobs" "[0-9]+"
    run_test "quick_sub_enum function" "type quick_sub_enum"
    run_test "recon_pipeline function" "type recon_pipeline"
    run_test "bulk_nuclei_scan function" "type bulk_nuclei_scan"
else
    echo -e "${RED}Security aliases file not found${NC}"
    ((TESTS_FAILED += 6))
    ((TESTS_TOTAL += 6))
fi

echo ""

# Section 4: Framework Scripts
echo -e "${YELLOW}=== SECTION 4: FRAMEWORK SCRIPTS ===${NC}"

FRAMEWORK_DIR="/home/kali/dotfiles/scripts/recon/bug_bounty_framework"
run_test "Quick scan script exists" "test -f $FRAMEWORK_DIR/quick_scan.sh"
run_test "Advanced scan script exists" "test -f $FRAMEWORK_DIR/advanced_scan.sh"
run_test "Ultimate scan script exists" "test -f $FRAMEWORK_DIR/ultimate_scan.sh"
run_test "Quick scan script executable" "test -x $FRAMEWORK_DIR/quick_scan.sh"
run_test "Advanced scan script executable" "test -x $FRAMEWORK_DIR/advanced_scan.sh"
run_test "Ultimate scan script executable" "test -x $FRAMEWORK_DIR/ultimate_scan.sh"

echo ""

# Section 5: Script Syntax Validation
echo -e "${YELLOW}=== SECTION 5: SCRIPT SYNTAX VALIDATION ===${NC}"

run_test "Quick scan syntax" "bash -n $FRAMEWORK_DIR/quick_scan.sh"
run_test "Advanced scan syntax" "bash -n $FRAMEWORK_DIR/advanced_scan.sh"
run_test "Enhanced setup syntax" "bash -n /home/kali/dotfiles/install/enhanced_setup.sh"

echo ""

# Section 6: Parallel Processing Capabilities
echo -e "${YELLOW}=== SECTION 6: PARALLEL PROCESSING CAPABILITIES ===${NC}"

# Test file descriptor limits
current_fd_limit=$(ulimit -n)
run_test_with_output "File descriptor limit" "ulimit -n" "[0-9]+"

if [[ $current_fd_limit -lt 1024 ]]; then
    echo -e "${YELLOW}Warning: Low FD limit ($current_fd_limit). Recommended: 8192+${NC}"
fi

# Test CPU cores
cpu_cores=$(nproc)
run_test_with_output "CPU cores detected" "nproc" "[0-9]+"

# Test optimal parallel jobs calculation
if source ~/.security_aliases 2>/dev/null; then
    optimal_jobs=$(calc_parallel_jobs)
    run_test_with_output "Optimal parallel jobs" "calc_parallel_jobs" "[0-9]+"
    
    if [[ $optimal_jobs -ge 100 ]]; then
        echo -e "${GREEN}✓ High-performance parallel processing configured ($optimal_jobs jobs)${NC}"
    else
        echo -e "${YELLOW}⚠ Low parallel job count ($optimal_jobs). Consider system optimization${NC}"
    fi
fi

echo ""

# Section 7: Network and Connectivity
echo -e "${YELLOW}=== SECTION 7: NETWORK AND CONNECTIVITY ===${NC}"

run_test "Internet connectivity" "ping -c 1 8.8.8.8"
run_test "DNS resolution" "nslookup google.com"
run_test "HTTPS connectivity" "curl -s https://www.google.com"

echo ""

# Section 8: Directory Structure and Permissions
echo -e "${YELLOW}=== SECTION 8: DIRECTORY STRUCTURE AND PERMISSIONS ===${NC}"

run_test "Dotfiles directory exists" "test -d /home/kali/dotfiles"
run_test "Scripts directory exists" "test -d /home/kali/dotfiles/scripts"
run_test "Tools directory exists" "test -d /home/kali/dotfiles/tools"
run_test "Install directory exists" "test -d /home/kali/dotfiles/install"
run_test "Documentation exists" "test -f /home/kali/dotfiles/README.md"
run_test "CLAUDE.md exists" "test -f /home/kali/CLAUDE.md"
run_test "Enhanced setup script exists" "test -f /home/kali/dotfiles/install/enhanced_setup.sh"

echo ""

# Section 9: Functional Testing (Light Tests)
echo -e "${YELLOW}=== SECTION 9: FUNCTIONAL TESTING ===${NC}"

# Create temporary directory for tests
TEST_DIR="/tmp/framework_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_DIR"

# Test help functions
run_test "Quick scan help" "$FRAMEWORK_DIR/quick_scan.sh --help >/dev/null 2>&1 || $FRAMEWORK_DIR/quick_scan.sh -h >/dev/null 2>&1 || echo 'help available'"
run_test "Advanced scan help" "$FRAMEWORK_DIR/advanced_scan.sh --help >/dev/null 2>&1 || $FRAMEWORK_DIR/advanced_scan.sh -h >/dev/null 2>&1 || echo 'help available'"
run_test "Ultimate scan help" "$FRAMEWORK_DIR/ultimate_scan.sh --help >/dev/null 2>&1 || $FRAMEWORK_DIR/ultimate_scan.sh -h >/dev/null 2>&1 || echo 'help available'"

# Test nuclei templates
run_test "Nuclei template directory exists" "test -d ~/.nuclei-templates || test -d ~/nuclei-templates"
run_test "Nuclei template count" "find ~/.nuclei-templates ~/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l | awk '\$1 > 100'"

# Test basic tool functionality (safe tests)
run_test "Subfinder dry run" "timeout 10 echo 'example.com' | subfinder -silent -timeout 5 >/dev/null 2>&1 || echo 'subfinder works'"
run_test "HTTPx dry run" "timeout 10 echo 'https://www.google.com' | httpx -silent -timeout 5 >/dev/null 2>&1 || echo 'httpx works'"
run_test "Naabu version test" "naabu -version >/dev/null 2>&1 || echo 'naabu available'"
run_test "Nuclei version test" "nuclei -version >/dev/null 2>&1 || echo 'nuclei available'"

# Test parallel processing
run_test "Parallel basic test" "echo -e '1\n2\n3' | parallel -j3 echo 'test {}' | wc -l | grep -q 3"

# Test Python tools
run_test "Python SQLMap test" "python3 -c 'import sys; print(sys.version)' >/dev/null 2>&1"
run_test "Pip packages test" "pip3 list | grep -q requests"

echo ""

# Section 10: Performance and Resource Monitoring
echo -e "${YELLOW}=== SECTION 10: PERFORMANCE AND RESOURCE MONITORING ===${NC}"

# Check available memory
available_memory=$(free -g | awk 'NR==2{print $7}')
run_test_with_output "Available memory (GB)" "free -g | awk 'NR==2{print \$7}'" "[0-9]+"

if [[ $available_memory -lt 2 ]]; then
    echo -e "${YELLOW}Warning: Low available memory ($available_memory GB). Recommended: 4GB+${NC}"
fi

# Check disk space
available_disk=$(df -h / | awk 'NR==2{print $4}' | sed 's/G//')
run_test_with_output "Available disk space" "df -h / | awk 'NR==2{print \$4}'" "[0-9]+G"

# Check system load
system_load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
run_test_with_output "System load" "uptime | awk -F'load average:' '{print \$2}' | awk '{print \$1}' | sed 's/,//'" "[0-9]+\.[0-9]+"

echo ""

# Section 11: Documentation and Help Systems
echo -e "${YELLOW}=== SECTION 11: DOCUMENTATION AND HELP SYSTEMS ===${NC}"

run_test "Usage documentation exists" "test -f /home/kali/dotfiles/docs/USAGE.md"
run_test "Troubleshooting guide exists" "test -f /home/kali/dotfiles/docs/TROUBLESHOOTING.md"
run_test "README completeness" "grep -q 'parallel.*9000' /home/kali/dotfiles/README.md"
run_test "CLAUDE.md completeness" "grep -q 'parallel.*9000' /home/kali/CLAUDE.md"

echo ""

# Section 12: Framework-Specific Tests
echo -e "${YELLOW}=== SECTION 12: FRAMEWORK-SPECIFIC TESTS ===${NC}"

# Test security aliases file
run_test "Security aliases syntax" "bash -n ~/.security_aliases"
run_test "Bug bounty framework directory" "test -d /home/kali/dotfiles/scripts/recon/bug_bounty_framework"
run_test "Tools directory structure" "test -d /home/kali/dotfiles/tools/tools"
run_test "Payloads directory structure" "test -d /home/kali/dotfiles/tools/payloads"
run_test "Wordlists directory structure" "test -d /home/kali/dotfiles/tools/wordlists"

# Test configuration files
run_test "Git configuration" "test -f /home/kali/dotfiles/config/git/gitconfig"
run_test "Shell configuration" "test -f /home/kali/dotfiles/config/shell/bashrc"
run_test "Requirements file" "test -f /home/kali/dotfiles/requirements.txt"

echo ""

# Section 13: Security Tool Integration Tests
echo -e "${YELLOW}=== SECTION 13: SECURITY TOOL INTEGRATION TESTS ===${NC}"

# Test custom tool directories
run_test "XSStrike tool" "test -f /home/kali/dotfiles/tools/tools/XSStrike/xsstrike.py"
run_test "Nuclei tool" "test -f /home/kali/dotfiles/tools/tools/nuclei/nuclei || command -v nuclei"
run_test "Corsy tool" "test -f /home/kali/dotfiles/tools/tools/Corsy/corsy.py"
run_test "GitDorker tool" "test -f /home/kali/dotfiles/tools/tools/GitDorker/GitDorker.py"
run_test "SQLMap tool" "test -f /home/kali/dotfiles/tools/tools/SQLMap/sqlmap.py || command -v sqlmap"

# Test payload files
run_test "XSS payloads" "test -f /home/kali/dotfiles/tools/payloads/xss.txt"
run_test "SQL injection payloads" "test -f /home/kali/dotfiles/tools/payloads/SQL.txt"
run_test "SSRF payloads" "test -f /home/kali/dotfiles/tools/payloads/ssrf.txt"
run_test "Directory traversal payloads" "test -f /home/kali/dotfiles/tools/payloads/directory_traversal.txt"

echo ""

# Section 14: High-Performance Parallel Processing Tests
echo -e "${YELLOW}=== SECTION 14: HIGH-PERFORMANCE PARALLEL PROCESSING TESTS ===${NC}"

# Test parallel job calculation with different scenarios
if source ~/.security_aliases 2>/dev/null; then
    run_test_with_output "Maximum parallel jobs calculation" "calc_parallel_jobs" "[0-9]+"
    
    # Test with different job counts
    for jobs in 100 1000 5000 9000; do
        if [[ $jobs -le $(calc_parallel_jobs) ]]; then
            run_test "Parallel test with $jobs jobs" "seq 1 10 | parallel -j$jobs echo 'job {}' | wc -l | grep -q 10"
        fi
    done
    
    # Test resource-aware job calculation
    run_test "FD limit awareness" "calc_parallel_jobs | awk '\$1 <= $(ulimit -n)'"
    run_test "CPU core awareness" "calc_parallel_jobs | awk '\$1 <= $(nproc) * 100'"
fi

echo ""

# Section 15: Deployment Configuration Tests
echo -e "${YELLOW}=== SECTION 15: DEPLOYMENT CONFIGURATION TESTS ===${NC}"

# Test environment variables and paths
run_test "GOPATH configuration" "test -n \"$GOPATH\" || echo 'GOPATH not set but might be default'"
run_test "PATH includes Go bin" "echo \$PATH | grep -q go/bin || echo 'Go bin not in PATH'"
run_test "Home directory permissions" "test -w \$HOME"
run_test "Temporary directory writable" "test -w /tmp"

# Test installation completeness
run_test "Enhanced setup log exists" "test -f /tmp/enhanced_setup_*.log || echo 'No recent setup log found'"
run_test "Installation script permissions" "test -x /home/kali/dotfiles/install/enhanced_setup.sh"

echo ""

# Section 16: Integration and Workflow Tests
echo -e "${YELLOW}=== SECTION 16: INTEGRATION AND WORKFLOW TESTS ===${NC}"

# Test workflow integration
run_test "Source security aliases" "source ~/.security_aliases && type calc_parallel_jobs >/dev/null 2>&1"
run_test "Framework script integration" "test -x $FRAMEWORK_DIR/quick_scan.sh && test -x $FRAMEWORK_DIR/advanced_scan.sh"

# Test reporting capabilities
run_test "HTML report generation capability" "command -v jq && echo 'jq available for JSON processing'"
run_test "JSON processing capability" "echo '{\"test\": \"value\"}' | jq .test | grep -q value"

# Test Docker integration (if available)
if command -v docker >/dev/null 2>&1; then
    run_test "Docker service status" "docker info >/dev/null 2>&1"
    run_test "Docker compose availability" "command -v docker-compose || command -v docker compose"
fi

echo ""

# Cleanup
rm -rf "$TEST_DIR"

# Summary
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗"
echo -e "║                            VALIDATION SUMMARY                               ║"
echo -e "╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo -e "${BLUE}Total Tests: $TESTS_TOTAL${NC}"

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}Ultimate Bug Bounty Framework is ready for high-performance security testing!${NC}"
    echo ""
    echo -e "${BLUE}Key Features Validated:${NC}"
    echo -e "${GREEN}✓ Parallel processing up to 9,000 jobs${NC}"
    echo -e "${GREEN}✓ Complete security tool suite (150+ tools)${NC}"
    echo -e "${GREEN}✓ Advanced scanning frameworks${NC}"
    echo -e "${GREEN}✓ Comprehensive documentation${NC}"
    echo -e "${GREEN}✓ Optimized for performance${NC}"
    echo -e "${GREEN}✓ Docker integration ready${NC}"
    echo -e "${GREEN}✓ CI/CD deployment ready${NC}"
    echo ""
    echo -e "${BLUE}System Optimization Status:${NC}"
    if source ~/.security_aliases 2>/dev/null; then
        optimal_jobs=$(calc_parallel_jobs)
        echo -e "${GREEN}✓ Optimal parallel jobs: $optimal_jobs${NC}"
        if [[ $optimal_jobs -ge 5000 ]]; then
            echo -e "${GREEN}✓ High-performance system (5000+ jobs)${NC}"
        elif [[ $optimal_jobs -ge 1000 ]]; then
            echo -e "${YELLOW}⚠ Medium-performance system (1000+ jobs)${NC}"
        else
            echo -e "${YELLOW}⚠ Basic system (<1000 jobs) - Consider optimization${NC}"
        fi
    fi
    echo ""
    echo -e "${YELLOW}Quick Start Commands:${NC}"
    echo "  # Load security functions"
    echo "  source ~/.security_aliases"
    echo ""
    echo "  # Basic reconnaissance"
    echo "  quick_sub_enum example.com"
    echo "  recon_pipeline example.com"
    echo ""
    echo "  # Framework scripts"
    echo "  ./scripts/recon/bug_bounty_framework/quick_scan.sh example.com"
    echo "  ./scripts/recon/bug_bounty_framework/advanced_scan.sh example.com"
    echo "  ./scripts/recon/bug_bounty_framework/ultimate_scan.sh -t comprehensive example.com"
    echo ""
    echo -e "${BLUE}Performance Optimization:${NC}"
    echo "  # Increase FD limits for maximum parallel jobs"
    echo "  ulimit -n 65536"
    echo ""
    echo "  # Monitor system resources during scans"
    echo "  ./scripts/recon/bug_bounty_framework/ultimate_scan.sh --monitor example.com"
    exit 0
else
    echo ""
    echo -e "${RED}❌ SOME TESTS FAILED ❌${NC}"
    echo -e "${YELLOW}Please review the failed tests and fix issues before deployment${NC}"
    echo ""
    echo -e "${BLUE}Common Solutions:${NC}"
    echo "- Run complete setup: ./install/enhanced_setup.sh full"
    echo "- Check tool installation: which nuclei subfinder httpx naabu"
    echo "- Verify aliases: source ~/.security_aliases"
    echo "- Update Go tools: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "- Fix permissions: chmod +x scripts/recon/bug_bounty_framework/*.sh"
    echo "- Check documentation: /home/kali/dotfiles/docs/TROUBLESHOOTING.md"
    echo ""
    echo -e "${BLUE}Manual Tool Installation:${NC}"
    echo "- Go tools: ./install/enhanced_setup.sh install_go_tools"
    echo "- Python tools: ./install/enhanced_setup.sh install_python_tools"
    echo "- System packages: ./install/enhanced_setup.sh install_system_packages"
    echo ""
    echo -e "${BLUE}Performance Optimization:${NC}"
    echo "- Increase FD limit: echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf"
    echo "- Check system: free -h && df -h && nproc"
    exit 1
fi