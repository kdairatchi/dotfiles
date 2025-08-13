#!/usr/bin/env bash
# test_alienvault.sh - Smoke tests for alienvault.sh
# Part of Security Research Tools

set -euo pipefail

# Test configuration
readonly TEST_SCRIPT="../alienvault.sh"
readonly TEST_DOMAIN="example.com"
readonly TEST_OUTPUT_DIR="/tmp/alienvault_test_$$"

# Colors for test output
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ============================================================================
# TEST FRAMEWORK
# ============================================================================

setup() {
    mkdir -p "${TEST_OUTPUT_DIR}"
    echo "Setting up tests in ${TEST_OUTPUT_DIR}"
}

teardown() {
    rm -rf "${TEST_OUTPUT_DIR}"
    echo "Cleaned up test directory"
}

assert_command_exists() {
    local cmd="${1}"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo -e "${RED}SKIP${NC}: ${cmd} not found"
        return 1
    fi
    return 0
}

run_test() {
    local test_name="${1}"
    local test_command="${2}"
    local expected_exit_code="${3:-0}"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))\n    
    echo -n "Testing ${test_name}... "
    
    local exit_code=0\n    if eval "${test_command}" >/dev/null 2>&1; then\n        exit_code=0\n    else\n        exit_code=$?\n    fi\n    \n    if [[ ${exit_code} -eq ${expected_exit_code} ]]; then\n        echo -e "${GREEN}PASS${NC}"\n        TESTS_PASSED=$((TESTS_PASSED + 1))\n        return 0\n    else\n        echo -e "${RED}FAIL${NC} (exit code: ${exit_code}, expected: ${expected_exit_code})"\n        TESTS_FAILED=$((TESTS_FAILED + 1))\n        return 1\n    fi\n}\n\nrun_test_with_output() {\n    local test_name="${1}"\n    local test_command="${2}"\n    local expected_pattern="${3}"\n    \n    TESTS_TOTAL=$((TESTS_TOTAL + 1))\n    \n    echo -n "Testing ${test_name}... "\n    \n    local output\n    local exit_code=0\n    if output=$(eval "${test_command}" 2>&1); then\n        exit_code=0\n    else\n        exit_code=$?\n    fi\n    \n    if [[ ${exit_code} -eq 0 ]] && echo "${output}" | grep -q "${expected_pattern}"; then\n        echo -e "${GREEN}PASS${NC}"\n        TESTS_PASSED=$((TESTS_PASSED + 1))\n        return 0\n    else\n        echo -e "${RED}FAIL${NC}"\n        echo "Output: ${output}"\n        TESTS_FAILED=$((TESTS_FAILED + 1))\n        return 1\n    fi\n}\n\n# ============================================================================\n# SPECIFIC TESTS\n# ============================================================================\n\ntest_help() {\n    run_test_with_output "help flag" \\\n        "bash ${TEST_SCRIPT} --help" \\\n        "Usage:"\n}\n\ntest_version() {\n    run_test_with_output "version flag" \\\n        "bash ${TEST_SCRIPT} --version" \\\n        "alienvault 2.0.0"\n}\n\ntest_no_arguments() {\n    run_test "no arguments (should fail)" \\\n        "bash ${TEST_SCRIPT}" \\\n        2\n}\n\ntest_invalid_domain() {\n    run_test "invalid domain" \\\n        "bash ${TEST_SCRIPT} -d 'invalid..domain'" \\\n        2\n}\n\ntest_invalid_limit() {\n    run_test "invalid limit" \\\n        "bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --limit 0" \\\n        2\n}\n\ntest_invalid_format() {\n    run_test "invalid format" \\\n        "bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --format xml" \\\n        2\n}\n\ntest_missing_dependencies() {\n    # Test with PATH that doesn't include jq\n    run_test "missing jq dependency" \\\n        "PATH=/bin:/usr/bin bash ${TEST_SCRIPT} -d ${TEST_DOMAIN}" \\\n        1\n}\n\ntest_quiet_mode() {\n    run_test_with_output "quiet mode" \\\n        "timeout 10s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --quiet --timeout 5 --pages 1" \\\n        ""\n}\n\ntest_verbose_mode() {\n    run_test_with_output "verbose mode" \\\n        "timeout 10s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --verbose --timeout 5 --pages 1" \\\n        "DEBUG"\n}\n\ntest_json_output() {\n    local output_file="${TEST_OUTPUT_DIR}/test_json.json"\n    run_test "JSON output format" \\\n        "timeout 10s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --format json --timeout 5 --pages 1 -o ${output_file}" \\\n        0\n    \n    # Verify JSON is valid\n    if [[ -f "${output_file}" ]]; then\n        run_test "JSON format validation" \\\n            "jq empty ${output_file}" \\\n            0\n    fi\n}\n\ntest_csv_output() {\n    local output_file="${TEST_OUTPUT_DIR}/test_csv.csv"\n    run_test "CSV output format" \\\n        "timeout 10s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --format csv --timeout 5 --pages 1 -o ${output_file}" \\\n        0\n    \n    # Verify CSV has header\n    if [[ -f "${output_file}" ]]; then\n        run_test_with_output "CSV header validation" \\\n            "head -1 ${output_file}" \\\n            "url,domain,timestamp"\n    fi\n}\n\ntest_report_generation() {\n    local report_dir="${TEST_OUTPUT_DIR}/reports"\n    run_test "report generation" \\\n        "timeout 10s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --report ${report_dir} --timeout 5 --pages 1" \\\n        0\n    \n    # Check if report files were created\n    run_test "report files exist" \\\n        "test -d ${report_dir} && find ${report_dir} -name '*.txt' | head -1" \\\n        0\n}\n\ntest_rate_limiting() {\n    run_test "rate limiting (delay)" \\\n        "timeout 15s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --delay 2 --timeout 5 --pages 2 --quiet" \\\n        0\n}\n\ntest_timeout_handling() {\n    run_test "timeout handling" \\\n        "timeout 5s bash ${TEST_SCRIPT} -d ${TEST_DOMAIN} --timeout 1 --pages 1 --quiet" \\\n        0\n}\n\n# ============================================================================\n# MAIN TEST RUNNER\n# ============================================================================\n\nmain() {\n    echo "Starting alienvault.sh smoke tests..."\n    echo "======================================"\n    \n    # Check if script exists\n    if [[ ! -f "${TEST_SCRIPT}" ]]; then\n        echo -e "${RED}ERROR${NC}: Test script not found: ${TEST_SCRIPT}"\n        exit 1\n    fi\n    \n    # Check dependencies\n    if ! assert_command_exists "bash"; then\n        echo -e "${RED}ERROR${NC}: bash not found"\n        exit 1\n    fi\n    \n    if ! assert_command_exists "jq"; then\n        echo -e "${YELLOW}WARNING${NC}: jq not found, skipping dependency tests"\n    fi\n    \n    # Setup\n    setup\n    \n    # Run tests\n    test_help\n    test_version\n    test_no_arguments\n    test_invalid_domain\n    test_invalid_limit\n    test_invalid_format\n    \n    if assert_command_exists "jq"; then\n        test_missing_dependencies\n        test_quiet_mode\n        test_verbose_mode\n        test_json_output\n        test_csv_output\n        test_report_generation\n        test_rate_limiting\n        test_timeout_handling\n    fi\n    \n    # Cleanup\n    teardown\n    \n    # Summary\n    echo "======================================"\n    echo "Test Results:"\n    echo -e "  ${GREEN}Passed${NC}: ${TESTS_PASSED}"\n    echo -e "  ${RED}Failed${NC}: ${TESTS_FAILED}"\n    echo -e "  Total:  ${TESTS_TOTAL}"\n    \n    if [[ ${TESTS_FAILED} -eq 0 ]]; then\n        echo -e "\\n${GREEN}All tests passed!${NC}"\n        exit 0\n    else\n        echo -e "\\n${RED}Some tests failed!${NC}"\n        exit 1\n    fi\n}\n\n# Run tests if script is executed directly\nif [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then\n    main "$@"\nfi
