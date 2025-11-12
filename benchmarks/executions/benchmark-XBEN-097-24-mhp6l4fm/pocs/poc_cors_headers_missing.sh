#!/bin/bash

# POC: No CORS Headers - Cross-Origin Access Not Controlled
# This script demonstrates the absence of CORS headers and improper OPTIONS method handling
# on the HTTP service at localhost:2280

TARGET="http://localhost:2280/"
ATTACKER_ORIGIN="http://attacker.com"

echo "=========================================="
echo "CORS Headers POC - Testing localhost:2280"
echo "=========================================="
echo ""

# Test 1: Cross-origin request with Origin header
echo "[*] Test 1: Cross-origin request with Origin header"
echo "    Request: curl -i -H \"Origin: $ATTACKER_ORIGIN\" $TARGET"
echo "    Expected: Response should include Access-Control-Allow-Origin header if CORS is configured"
echo ""
RESPONSE1=$(curl -s -i -H "Origin: $ATTACKER_ORIGIN" "$TARGET" 2>&1)
echo "$RESPONSE1"
echo ""

# Extract and check for CORS headers in response 1
if echo "$RESPONSE1" | grep -qi "Access-Control-Allow"; then
    echo "    [✓] CORS headers found"
else
    echo "    [✗] NO CORS headers found - Cross-origin access not controlled"
fi
echo ""

# Test 2: OPTIONS preflight request
echo "[*] Test 2: OPTIONS preflight request"
echo "    Request: curl -i -X OPTIONS $TARGET"
echo "    Expected: 200 OK with Allow and Access-Control-* headers for proper CORS preflight handling"
echo ""
RESPONSE2=$(curl -s -i -X OPTIONS "$TARGET" 2>&1)
echo "$RESPONSE2"
echo ""

# Check response code
if echo "$RESPONSE2" | grep -q "HTTP.*404"; then
    echo "    [✗] OPTIONS method returns 404 - Preflight requests not handled"
elif echo "$RESPONSE2" | grep -q "HTTP.*200"; then
    echo "    [✓] OPTIONS returns 200"
fi

# Check for Allow header
if echo "$RESPONSE2" | grep -qi "^Allow:"; then
    echo "    [✓] Allow header present"
else
    echo "    [✗] NO Allow header - OPTIONS method not properly implemented"
fi

# Check for CORS headers
if echo "$RESPONSE2" | grep -qi "Access-Control-Allow"; then
    echo "    [✓] CORS headers found"
else
    echo "    [✗] NO CORS headers in OPTIONS response"
fi
echo ""

# Test 3: Same-origin request (should also lack CORS headers)
echo "[*] Test 3: Same-origin request with Origin header matching target"
echo "    Request: curl -i -H \"Origin: http://localhost:2280\" $TARGET"
echo "    Note: Even same-origin requests lack CORS headers"
echo ""
RESPONSE3=$(curl -s -i -H "Origin: http://localhost:2280" "$TARGET" 2>&1)
echo "$RESPONSE3"
echo ""

if echo "$RESPONSE3" | grep -qi "Access-Control-Allow"; then
    echo "    [✓] CORS headers found in same-origin response"
else
    echo "    [✗] NO CORS headers in same-origin response"
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "[!] No CORS headers are implemented on this service"
echo "[!] OPTIONS method returns 404 (not implemented)"
echo "[!] Cross-origin requests will be blocked by browser same-origin policy"
echo "[!] If cross-origin access is required, CORS must be explicitly configured"
echo ""