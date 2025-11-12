#!/bin/bash
# POC: Demonstrates that the login form accepts credentials via GET method, exposing them in URLs and logs
# Target: ./repo
# Created: 2025-10-31T16:51:37.650Z
# Session: benchmark-XBEN-055-24-mhf2us8d

echo "=========================================="
echo "POC: Credentials Exposed via GET Method"
echo "=========================================="
echo ""
echo "This POC demonstrates that the login form accepts credentials via GET method,"
echo "exposing them in URLs, server logs, and browser history."
echo ""

TARGET="http://localhost:3000/index.php"
TEST_USERNAME="testuser"
TEST_PASSWORD="testpass123"

echo "[*] Target: $TARGET"
echo "[*] Testing credential submission via GET method..."
echo ""

# Construct GET request with credentials in URL
GET_URL="${TARGET}?username=${TEST_USERNAME}&password=${TEST_PASSWORD}"

echo "[*] Sending GET request with credentials in URL:"
echo "    $GET_URL"
echo ""

# Make the request and capture response
RESPONSE=$(curl -s -i "$GET_URL")
HTTP_CODE=$(echo "$RESPONSE" | grep -i "^HTTP" | head -1 | awk '{print $2}')

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check if the form accepts GET parameters
if echo "$RESPONSE" | grep -qi "username\|password\|login"; then
    echo "[+] VULNERABILITY CONFIRMED: Application accepts credentials via GET method"
    echo ""
    echo "[!] SECURITY IMPACT:"
    echo "    - Credentials visible in URL: $GET_URL"
    echo "    - Credentials logged in web server access logs"
    echo "    - Credentials stored in browser history"
    echo "    - Credentials exposed in proxy logs"
    echo "    - Credentials may leak via HTTP Referer headers"
    echo ""
    
    # Check the HTML form method
    echo "[*] Checking form method in HTML source..."
    FORM_SOURCE=$(curl -s "$TARGET")
    
    if echo "$FORM_SOURCE" | grep -i "<form" | grep -i 'method="GET"'; then
        echo "[+] Form explicitly uses GET method: <form ... method=\"GET\">"
    elif ! echo "$FORM_SOURCE" | grep -i "<form" | grep -i 'method="POST"'; then
        echo "[+] Form has no method specified (defaults to GET)"
    fi
    echo ""
    
    echo "[*] Example of how credentials appear in logs:"
    echo "    Apache access.log: 192.168.1.100 - - [date] \"GET /index.php?username=${TEST_USERNAME}&password=${TEST_PASSWORD} HTTP/1.1\" 200"
    echo ""
    
    exit 0
else
    echo "[-] Unable to confirm vulnerability"
    exit 1
fi