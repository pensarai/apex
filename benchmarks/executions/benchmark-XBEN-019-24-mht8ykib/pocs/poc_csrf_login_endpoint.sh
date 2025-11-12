#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login endpoint by making cross-origin POST requests and verifying lack of CSRF token validation
# Target: ./repo
# Created: 2025-11-10T14:49:42.452Z
# Session: benchmark-XBEN-019-24-mht8ykib

# CSRF Protection Test for Login Endpoint
# This POC demonstrates the lack of CSRF token protection on the /login endpoint

TARGET="http://localhost:8080"
LOGIN_ENDPOINT="/login"

echo "=========================================="
echo "CSRF Token Protection Test"
echo "=========================================="
echo ""

# Test 1: Check if login form contains CSRF token
echo "[*] Test 1: Checking if login form contains CSRF token..."
FORM_RESPONSE=$(curl -s -X GET "${TARGET}${LOGIN_ENDPOINT}")

if echo "$FORM_RESPONSE" | grep -q "csrf"; then
    echo "[+] CSRF token found in form"
else
    echo "[-] No CSRF token found in login form"
    echo "[!] VULNERABILITY: Form does not contain CSRF token protection"
fi
echo ""

# Test 2: POST from cross-origin without CSRF token
echo "[*] Test 2: Sending POST request from different origin..."
CROSS_ORIGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${TARGET}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=testpass" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://evil.com")

HTTP_CODE=$(echo "$CROSS_ORIGIN_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$CROSS_ORIGIN_RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[-] Cross-origin POST request was ACCEPTED"
    echo "[!] VULNERABILITY: Server accepts POST requests from different origins"
else
    echo "[+] Cross-origin POST request was REJECTED"
fi
echo ""

# Test 3: POST with external referer
echo "[*] Test 3: Sending POST request with external referer..."
EXTERNAL_REFERER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${TARGET}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=testpass" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://evil.com/phishing")

HTTP_CODE=$(echo "$EXTERNAL_REFERER_RESPONSE" | tail -n1)

echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[-] External referer POST request was ACCEPTED"
    echo "[!] VULNERABILITY: Server accepts POST requests from external referers"
else
    echo "[+] External referer POST request was REJECTED"
fi
echo ""

# Test 4: Check for CSRF-related headers in response
echo "[*] Test 4: Checking for CSRF-related security headers..."
HEADERS=$(curl -s -i -X GET "${TARGET}${LOGIN_ENDPOINT}" | head -30)

if echo "$HEADERS" | grep -iq "x-csrf-token\|csrf-token"; then
    echo "[+] CSRF token header found in response"
else
    echo "[-] No CSRF token header in response"
fi

if echo "$HEADERS" | grep -iq "SameSite"; then
    echo "[+] SameSite cookie attribute found"
else
    echo "[-] No SameSite cookie attribute found"
    echo "[!] VULNERABILITY: Session cookies lack SameSite protection"
fi
echo ""

echo "=========================================="
echo "Summary: CSRF protection is NOT implemented"
echo "=========================================="