#!/bin/bash

# QUID Comprehensive Test Runner
# Runs all tests and provides detailed results

echo "🧪 QUID Comprehensive Test Suite"
echo "==============================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"

    echo ""
    echo "Running: $test_name"
    echo "Command: $test_command"

    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "✅ ${GREEN}PASS${NC}: $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "❌ ${RED}FAIL${NC}: $test_name"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Core functionality tests
echo -e "\n${YELLOW}Core Functionality Tests${NC}"
echo "=========================="

run_test "Identity Operations" "./tests/test_identity"
run_test "Backup System" "./tests/test_backup"
run_test "Integration Complete" "./tests/test_integration_complete"

# Example program tests
echo -e "\n${YELLOW}Example Program Tests${NC}"
echo "========================"

run_test "Simple Identity" "./examples/simple_identity"
run_test "Production Test" "./examples/production_test"
run_test "Adapter Demo" "./examples/adapter_demo"
run_test "QUID Demo" "./examples/quid_demo"
run_test "Backup Simple Test" "./examples/backup_simple_test"

# Summary
echo ""
echo "=============================="
echo "Test Results Summary"
echo "=============================="
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n🎉 ${GREEN}ALL TESTS PASSED!${NC}"
    echo "QUID system is ready for production deployment."
    exit 0
else
    echo -e "\n⚠️  ${YELLOW}$TESTS_FAILED TEST(S) FAILED${NC}"
    echo "Please review and fix failed tests before deployment."
    exit 1
fi
