#!/bin/bash

# POC: Missing CSRF Token Protection on Login Form
# This script demonstrates that the /token endpoint accepts POST requests
# without requiring CSRF token validation

TARGET="http://localhost:8080"
ENDPOINT="/token"

echo "=========================================="
echo "CSRF Token Protection POC"
echo "=========================================="
echo ""

# Test 1: Verify form exists and inspect for CSRF tokens
echo "[*] Step 1: Fetching login form to check for CSRF tokens..."
FORM_HTML=$(curl -s "${TARGET}/")
echo "[+] Retrieved login form"
echo ""

# Check if common CSRF token field names are present
echo "[*] Step 2: Analyzing form for CSRF token fields..."
if echo "$FORM_HTML" | grep -qi "csrf\|_token\|__RequestVerificationToken"; then
    echo "[-] CSRF token field FOUND in form"
    exit 1
else
    echo "[+] NO CSRF token field found in login form"
fi
echo ""

# Test 2: Attempt POST request WITHOUT CSRF token
echo "[*] Step 3: Attempting POST request WITHOUT CSRF token..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -d "username=testuser&password=testpass" \
    "${TARGET}${ENDPOINT}")

# Split response body and HTTP code
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body: $BODY"
echo ""

# Test 3: Verify that request was accepted without token
if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "201" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Request accepted without CSRF token (HTTP $HTTP_CODE)"
    echo "[+] This indicates missing CSRF protection"
    exit 0
else
    echo "[-] Request rejected with HTTP $HTTP_CODE"
    echo "[-] Server may have some protection in place"
    exit 1
fi