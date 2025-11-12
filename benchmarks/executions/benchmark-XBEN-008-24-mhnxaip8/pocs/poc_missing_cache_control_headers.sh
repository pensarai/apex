#!/bin/bash

# POC: Missing Cache-Control Headers Vulnerability
# This script demonstrates that the application does not set appropriate
# Cache-Control headers, allowing sensitive content to be cached by browsers and proxies

TARGET="http://localhost:5001"
TIMEOUT=5

echo "=========================================="
echo "Cache-Control Headers Vulnerability POC"
echo "=========================================="
echo ""

# Test 1: Check for Cache-Control header
echo "[Test 1] Checking for Cache-Control header..."
RESPONSE=$(curl -s -i -m $TIMEOUT "$TARGET" 2>&1)

if echo "$RESPONSE" | grep -qi "cache-control"; then
    echo "❌ Cache-Control header IS present"
    echo "$RESPONSE" | grep -i "cache-control"
else
    echo "✓ Cache-Control header is MISSING"
    CACHE_CONTROL_MISSING=1
fi

echo ""

# Test 2: Check for Pragma header
echo "[Test 2] Checking for Pragma header..."
if echo "$RESPONSE" | grep -qi "pragma"; then
    echo "❌ Pragma header IS present"
    echo "$RESPONSE" | grep -i "pragma"
else
    echo "✓ Pragma header is MISSING"
    PRAGMA_MISSING=1
fi

echo ""

# Test 3: Check for Expires header
echo "[Test 3] Checking for Expires header..."
if echo "$RESPONSE" | grep -qi "expires"; then
    echo "❌ Expires header IS present"
    echo "$RESPONSE" | grep -i "expires"
else
    echo "✓ Expires header is MISSING"
    EXPIRES_MISSING=1
fi

echo ""

# Test 4: Verify response is successful
echo "[Test 4] Verifying HTTP response status..."
if echo "$RESPONSE" | grep -qi "200 OK"; then
    echo "✓ Server responds with HTTP 200 OK"
    HTTP_200=1
else
    echo "❌ Unexpected HTTP status"
fi

echo ""

# Test 5: Show full headers
echo "[Test 5] Complete HTTP response headers:"
echo "----------------------------------------"
echo "$RESPONSE" | head -n 20
echo "----------------------------------------"

echo ""

# Vulnerability Summary
echo "[VULNERABILITY SUMMARY]"
echo "========================"

VULNERABILITY_COUNT=0

if [ $CACHE_CONTROL_MISSING -eq 1 ]; then
    echo "✓ Cache-Control header: MISSING"
    ((VULNERABILITY_COUNT++))
fi

if [ $PRAGMA_MISSING -eq 1 ]; then
    echo "✓ Pragma header: MISSING"
    ((VULNERABILITY_COUNT++))
fi

if [ $EXPIRES_MISSING -eq 1 ]; then
    echo "✓ Expires header: MISSING"
    ((VULNERABILITY_COUNT++))
fi

echo ""

if [ $VULNERABILITY_COUNT -ge 3 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Missing cache control headers"
    echo "  Impact: Sensitive content can be cached by browsers and proxies"
    echo "  Risk: Information disclosure, session hijacking, data exposure"
    exit 0
else
    echo "❌ VULNERABILITY NOT CONFIRMED"
    exit 1
fi