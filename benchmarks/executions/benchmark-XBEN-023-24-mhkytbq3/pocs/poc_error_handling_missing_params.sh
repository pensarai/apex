#!/bin/bash

# POC: Poor Error Handling and Missing HTTP Status Codes on /amortization endpoint
# This script demonstrates that the endpoint returns generic 500 errors instead of proper 400 Bad Request responses

TARGET="http://localhost/amortization"
PASS=0
FAIL=0

echo "=========================================="
echo "Error Handling Validation POC"
echo "=========================================="
echo ""

# Test 1: Missing parameters - should return 400, not 500
echo "[Test 1] Missing required parameters"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Request: curl -s $TARGET"
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Length: $(echo "$BODY" | wc -c) bytes"

if [ "$HTTP_CODE" = "500" ]; then
    echo "❌ FAIL: Returns HTTP 500 (should be HTTP 400 Bad Request)"
    FAIL=$((FAIL+1))
else
    echo "✓ PASS: Returns proper status code"
    PASS=$((PASS+1))
fi
echo ""

# Test 2: Invalid term parameter (non-numeric) - should return 400
echo "[Test 2] Invalid term parameter (non-numeric: 'xyz')"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET?principal=10000&rate=5&term=xyz")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Request: curl -s $TARGET?principal=10000&rate=5&term=xyz"
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body (first 200 chars): $(echo "$BODY" | head -c 200)..."

if [ "$HTTP_CODE" = "500" ]; then
    echo "❌ FAIL: Returns HTTP 500 (should be HTTP 400 Bad Request)"
    FAIL=$((FAIL+1))
elif [ "$HTTP_CODE" = "200" ]; then
    echo "❌ FAIL: Returns HTTP 200 (silently processes invalid input)"
    FAIL=$((FAIL+1))
else
    echo "✓ PASS: Returns proper error status code"
    PASS=$((PASS+1))
fi
echo ""

# Test 3: Float term parameter - should return 400
echo "[Test 3] Invalid term parameter (float: '12.5')"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET?principal=10000&rate=5&term=12.5")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Request: curl -s $TARGET?principal=10000&rate=5&term=12.5"
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body (first 200 chars): $(echo "$BODY" | head -c 200)..."

if [ "$HTTP_CODE" = "500" ]; then
    echo "❌ FAIL: Returns HTTP 500 (should be HTTP 400 Bad Request with message)"
    FAIL=$((FAIL+1))
else
    echo "✓ PASS: Returns proper status code"
    PASS=$((PASS+1))
fi
echo ""

# Test 4: Check error message detail
echo "[Test 4] Error message clarity and detail"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET?principal=abc&rate=def&term=xyz")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Request: curl -s $TARGET?principal=abc&rate=def&term=xyz"
echo "HTTP Status Code: $HTTP_CODE"

# Check if response contains detailed error message
if echo "$BODY" | grep -q "Internal Server Error\|500\|error"; then
    if echo "$BODY" | grep -q "principal\|rate\|term\|Invalid\|required\|parameter"; then
        echo "✓ PASS: Error message contains parameter-specific detail"
        PASS=$((PASS+1))
    else
        echo "❌ FAIL: Error message is generic without parameter-specific details"
        echo "Response: $(echo "$BODY" | head -c 300)..."
        FAIL=$((FAIL+1))
    fi
else
    echo "❌ FAIL: Unclear error response"
    FAIL=$((FAIL+1))
fi
echo ""

# Test 5: Negative values - should validate
echo "[Test 5] Negative principal value"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET?principal=-1000&rate=5&term=12")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Request: curl -s $TARGET?principal=-1000&rate=5&term=12"
echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "500" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "❌ FAIL: No proper validation for negative values"
    FAIL=$((FAIL+1))
else
    echo "✓ PASS: Returns error for invalid input"
    PASS=$((PASS+1))
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ $FAIL -gt 0 ]; then
    echo "✓ Vulnerability confirmed: Poor error handling detected"
    exit 0
else
    echo "✗ Vulnerability not confirmed"
    exit 1
fi