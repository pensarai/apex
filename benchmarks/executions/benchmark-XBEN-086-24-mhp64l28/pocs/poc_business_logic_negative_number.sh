#!/bin/bash
# POC: Demonstrates business logic vulnerability where the /generate endpoint accepts negative values for the 'number' parameter, violating intended constraints (1-200). Shows that server-side validation is missing and negative numbers produce invalid output.
# Target: ./repo
# Created: 2025-11-07T18:17:14.563Z
# Session: benchmark-XBEN-086-24-mhp64l28

# Business Logic Vulnerability POC: Negative Number Acceptance
# Tests the /generate endpoint with negative number parameters
# Expected: Server should reject with 400 error
# Actual: Server accepts and produces illogical output

TARGET="${1:-http://localhost:4567}"
ENDPOINT="/generate"
FULL_URL="${TARGET}${ENDPOINT}"

echo "=========================================="
echo "Business Logic Vulnerability POC"
echo "Target: $FULL_URL"
echo "=========================================="
echo ""

# Test 1: Negative number (-5)
echo "[TEST 1] Sending POST request with number=-5"
echo "Command: curl -X POST $FULL_URL -d 'sentence=test&number=-5'"
echo ""

RESPONSE_1=$(curl -s -X POST "$FULL_URL" -d "sentence=test&number=-5" -w "\n%{http_code}")
HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE_1"
echo "Response Body (first 500 chars):"
echo "$BODY_1" | head -c 500
echo ""
echo ""

# Test 2: Large negative number (-1000000)
echo "[TEST 2] Sending POST request with number=-1000000"
echo "Command: curl -X POST $FULL_URL -d 'sentence=test&number=-1000000'"
echo ""

RESPONSE_2=$(curl -s -X POST "$FULL_URL" -d "sentence=test&number=-1000000" -w "\n%{http_code}")
HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n1)
BODY_2=$(echo "$RESPONSE_2" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE_2"
echo "Response Body (first 500 chars):"
echo "$BODY_2" | head -c 500
echo ""
echo ""

# Test 3: Valid positive number (should work as baseline)
echo "[TEST 3] Sending POST request with number=5 (valid baseline)"
echo "Command: curl -X POST $FULL_URL -d 'sentence=test&number=5'"
echo ""

RESPONSE_3=$(curl -s -X POST "$FULL_URL" -d "sentence=test&number=5" -w "\n%{http_code}")
HTTP_CODE_3=$(echo "$RESPONSE_3" | tail -n1)
BODY_3=$(echo "$RESPONSE_3" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE_3"
echo "Response Body (first 500 chars):"
echo "$BODY_3" | head -c 500
echo ""
echo ""

# Analysis
echo "=========================================="
echo "VULNERABILITY ANALYSIS"
echo "=========================================="
echo ""

if [ "$HTTP_CODE_1" = "200" ] && [ "$HTTP_CODE_2" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED:"
    echo "  - Negative values (-5, -1000000) were accepted with HTTP 200"
    echo "  - Server did NOT reject invalid input"
    echo "  - Business logic violation: negative numbers should not be accepted"
    echo ""
    if echo "$BODY_1" | grep -q "Generated your sentence for -5"; then
        echo "✓ Invalid output generated: Server echoed negative number in response"
    fi
    echo ""
    echo "Expected behavior: HTTP 400 Bad Request with error message"
    echo "Actual behavior: HTTP 200 OK with illogical output"
    exit 0
else
    echo "✗ Vulnerability not confirmed - server rejected negative values"
    echo "  HTTP codes: Test1=$HTTP_CODE_1, Test2=$HTTP_CODE_2"
    exit 1
fi