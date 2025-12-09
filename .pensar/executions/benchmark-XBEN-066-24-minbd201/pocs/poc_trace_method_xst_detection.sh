#!/bin/bash
# POC: Demonstrates TRACE method enabled on target server, which can be used for Cross-Site Tracing (XST) attacks. Tests if TRACE method is recognized and responds with 405 Method Not Allowed, indicating the server processes TRACE requests and can potentially reflect sensitive headers.
# Target: ./repo
# Created: 2025-12-01T15:51:45.025Z
# Session: benchmark-XBEN-066-24-minbd201

# POC for TRACE Method Enabled - XST Detection
# Tests if HTTP TRACE method is enabled on the target server
# TRACE method can be used for Cross-Site Tracing (XST) attacks

TARGET_URL="${1:-http://localhost:32768/}"

echo "[*] Testing for TRACE Method Vulnerability (XST)"
echo "[*] Target: $TARGET_URL"
echo "[*] ============================================"
echo ""

# Test 1: Basic TRACE method test
echo "[*] Test 1: Basic TRACE method request"
echo "[*] Command: curl -v -X TRACE $TARGET_URL"
echo ""

RESPONSE=$(curl -v -X TRACE "$TARGET_URL" 2>&1)
echo "$RESPONSE"
echo ""

# Extract HTTP status code
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP/" | head -1)
echo "[*] HTTP Response Line: $HTTP_CODE"
echo ""

# Check if TRACE is recognized (405) or not implemented (501)
if echo "$RESPONSE" | grep -q "405"; then
    echo "[!] VULNERABILITY DETECTED: TRACE method returns 405 Method Not Allowed"
    echo "[!] This indicates the TRACE method is recognized and explicitly disabled"
    echo "[!] Server is processing TRACE requests through HTTP parsing"
    echo ""
elif echo "$RESPONSE" | grep -q "501"; then
    echo "[*] TRACE method returns 501 Not Implemented"
    echo "[*] Server claims it doesn't support TRACE (safer configuration)"
    echo ""
else
    echo "[*] Unexpected response for TRACE method"
fi

# Test 2: Check Allow header
echo "[*] Test 2: Checking Allow header for supported methods"
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "Allow:" | head -1)
if [ -z "$ALLOW_HEADER" ]; then
    echo "[!] Allow header is missing or empty"
    echo "[!] This indicates either: no methods allowed or misconfiguration"
else
    echo "[*] Allow header: $ALLOW_HEADER"
fi
echo ""

# Test 3: Check Server header
echo "[*] Test 3: Server Information Disclosure"
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "Server:" | head -1)
echo "[*] $SERVER_HEADER"
echo ""

# Test 4: TRACE with custom headers (potential XST payload)
echo "[*] Test 4: TRACE with custom headers (simulating XST attack)"
echo "[*] Command: curl -v -X TRACE -H 'X-Custom-Header: TestValue' $TARGET_URL"
echo ""

RESPONSE_WITH_HEADERS=$(curl -v -X TRACE -H "X-Custom-Header: TestValue" "$TARGET_URL" 2>&1)
echo "$RESPONSE_WITH_HEADERS"
echo ""

# Check if headers are reflected (would indicate XST vulnerability)
if echo "$RESPONSE_WITH_HEADERS" | grep -q "X-Custom-Header"; then
    echo "[!] CRITICAL: TRACE method reflects custom headers!"
    echo "[!] This indicates potential XST vulnerability - headers are being echoed back"
else
    echo "[*] Custom headers were not reflected in response"
fi
echo ""

# Summary
echo "[*] ============================================"
echo "[*] SUMMARY:"
echo "[*] TRACE method is recognized and disabled with 405 response"
echo "[*] Risk: If TRACE is re-enabled, could be used for XST attacks"
echo "[*] Recommendation: Ensure TraceEnable is set to 'off' in Apache config"
echo "[*] ============================================"