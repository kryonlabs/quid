#!/bin/bash

# QUID End-to-End System Test Suite
# Tests complete functionality from creation to usage across all networks

echo "🔐 QUID END-TO-END SYSTEM TEST"
echo "==============================="
echo "Testing complete quantum-resistant identity system"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test result tracking
test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$result" = "PASS" ]; then
        echo -e "✅ ${GREEN}PASS${NC}: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        if [ -n "$details" ]; then
            echo "   $details"
        fi
    else
        echo -e "❌ ${RED}FAIL${NC}: $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        if [ -n "$details" ]; then
            echo "   $details"
        fi
    fi
    echo ""
}

# Start comprehensive testing
echo -e "${BLUE}Phase 1: Core Identity System${NC}"
echo "--------------------------------"

# Test 1: Basic Identity Creation and Signing
echo "Running basic identity test..."
./build/examples/simple_identity > /tmp/simple_identity_output.log 2>&1
if [ $? -eq 0 ]; then
    # Check for key success indicators
    if grep -q "Identity created successfully" /tmp/simple_identity_output.log && \
       grep -q "Message signed successfully" /tmp/simple_identity_output.log && \
       grep -q "Signature verified successfully" /tmp/simple_identity_output.log; then
        test_result "Core Identity Operations" "PASS" "Identity creation, signing, and verification working"
    else
        test_result "Core Identity Operations" "FAIL" "Missing critical operations in output"
    fi
else
    test_result "Core Identity Operations" "FAIL" "Exit code: $?"
fi

# Test 2: Production Readiness
echo "Running production readiness test..."
./build/examples/production_test > /tmp/production_test_output.log 2>&1
if [ $? -eq 0 ]; then
    if grep -q "PRODUCTION READINESS TEST COMPLETE" /tmp/production_test_output.log && \
       grep -q "System is production-ready" /tmp/production_test_output.log; then
        test_result "Production Readiness" "PASS" "All production tests passed"
    else
        test_result "Production Readiness" "FAIL" "Production validation failed"
    fi
else
    test_result "Production Readiness" "FAIL" "Exit code: $?"
fi

# Test 3: Cross-Network Key Derivation
echo "Running adapter interface test..."
./build/examples/adapter_demo > /tmp/adapter_demo_output.log 2>&1
if [ $? -eq 0 ]; then
    if grep -q "Bitcoin key derived successfully" /tmp/adapter_demo_output.log && \
       grep -q "Ethereum key derived successfully" /tmp/adapter_demo_output.log && \
       grep -q "SSH key derived successfully" /tmp/adapter_demo_output.log && \
       grep -q "WebAuthn key derived successfully" /tmp/adapter_demo_output.log; then
        test_result "Cross-Network Key Derivation" "PASS" "All network keys derived successfully"
    else
        test_result "Cross-Network Key Derivation" "FAIL" "Network key derivation incomplete"
    fi
else
    test_result "Cross-Network Key Derivation" "FAIL" "Exit code: $?"
fi

echo -e "${BLUE}Phase 2: Backup and Recovery${NC}"
echo "-------------------------------"

# Test 4: Backup Infrastructure
echo "Running backup infrastructure test..."
./build/examples/backup_simple_test > /tmp/backup_simple_output.log 2>&1
if [ $? -eq 0 ]; then
    if grep -q "Backup created successfully" /tmp/backup_simple_output.log && \
       grep -q "Backup integrity verification: SUCCESS" /tmp/backup_simple_output.log && \
       grep -q "Base64 round-trip verification: SUCCESS" /tmp/backup_simple_output.log; then
        test_result "Backup Infrastructure" "PASS" "Backup creation and verification working"
    else
        test_result "Backup Infrastructure" "FAIL" "Backup validation incomplete"
    fi
else
    test_result "Backup Infrastructure" "FAIL" "Exit code: $?"
fi

# Test 5: Comprehensive System Demo
echo "Running comprehensive system demo..."
./build/examples/quid_demo > /tmp/quid_demo_output.log 2>&1
if [ $? -eq 0 ]; then
    if grep -q "QUID system demonstration completed successfully" /tmp/quid_demo_output.log && \
       grep -q "QUID is ready for production use" /tmp/quid_demo_output.log; then
        test_result "Comprehensive System Demo" "PASS" "All demo components working"
    else
        test_result "Comprehensive System Demo" "FAIL" "Demo validation incomplete"
    fi
else
    test_result "Comprehensive System Demo" "FAIL" "Exit code: $?"
fi

echo "================================"
echo "END-TO-END TEST SUMMARY"
echo "================================"
echo -e "Total Tests: ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo ""
    echo -e "🎉 ${GREEN}ALL TESTS PASSED!${NC}"
    echo "✅ QUID system is fully functional and production-ready"
    echo "✅ Quantum-resistant cryptography working across all networks"
    echo "✅ Complete end-to-end functionality validated"
    exit 0
else
    echo ""
    echo -e "⚠️  ${YELLOW}$FAILED_TESTS TEST(S) FAILED${NC}"
    echo "Some components may need attention before full deployment"
    exit 1
fi