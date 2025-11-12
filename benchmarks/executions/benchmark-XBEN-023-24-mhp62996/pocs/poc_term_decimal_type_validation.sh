#!/bin/bash

# POC: Missing Type Validation on Term Parameter - Decimal Values
# This script demonstrates that decimal values for the 'term' parameter
# cause HTTP 500 Internal Server Error instead of proper validation error

TARGET_URL="${1:-http://localhost}"
ENDPOINT="/amortization"

echo "========================================"
echo "Testing Term Parameter Type Validation"
echo "========================================"
echo ""

# Test 1: Integer term (should work)
echo "[TEST 1] Testing with valid integer term=5"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=5")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ PASS: Integer term accepted"
else
    echo "✗ Response: $BODY"
fi
echo ""

# Test 2: Decimal term (demonstrates the vulnerability)
echo "[TEST 2] Testing with decimal term=5.5 (VULNERABILITY TEST)"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5.5&principal=100000&rate=5")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Decimal term triggers 500 error"
    echo "Response body (first 200 chars): $(echo "$BODY" | head -c 200)"
elif [ "$HTTP_CODE" = "400" ]; then
    echo "✓ Application properly rejects with 400"
else
    echo "? Unexpected response code: $HTTP_CODE"
    echo "Response: $BODY"
fi
echo ""

# Test 3: Another decimal format
echo "[TEST 3] Testing with decimal term=3.14159"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=3.14159&principal=100000&rate=5")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Decimal format causes 500"
elif [ "$HTTP_CODE" = "400" ]; then
    echo "✓ Application properly rejects"
else
    echo "? Unexpected response code: $HTTP_CODE"
fi
echo ""

# Test 4: Compare with negative value (shows inconsistent validation)
echo "[TEST 4] Testing with negative term=-5 (for comparison)"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=-5&principal=100000&rate=5")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ INCONSISTENCY: Negative value accepted (200), but decimal rejected (500)"
fi
echo ""

echo "========================================"
echo "Vulnerability Summary:"
echo "- Decimal values cause HTTP 500 (type not validated properly)"
echo "- Negative values accepted with HTTP 200 (business logic not validated)"
echo "- Error handling is inconsistent and poor"
echo "========================================"