#!/bin/bash

# POC: Apache Server Version Disclosure in 404 Error Page
# Description: Demonstrates that accessing non-existent resources reveals Apache version
# in the HTML 404 error page footer

TARGET_URL="${1:-http://localhost}"

echo "[*] Apache Version Disclosure in 404 Error Page POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Request a non-existent resource to trigger 404 error page
echo "[*] Sending request to non-existent resource: /nonexistent_page_$(date +%s).php"
RESPONSE=$(curl -s -i "$TARGET_URL/nonexistent_page_$(date +%s).php")

echo "[*] Response received:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Extract and check for Apache version in the response body
if echo "$RESPONSE" | grep -q "Apache/"; then
    echo "[+] VULNERABLE: Apache version disclosed in 404 error page!"
    echo ""
    echo "[+] Version information found:"
    echo "$RESPONSE" | grep -oP 'Apache/[^ <]+.*(?=</address>)' || echo "$RESPONSE" | grep -oP 'Apache.*' | head -1
    echo ""
    echo "[+] Full HTML footer:"
    echo "$RESPONSE" | grep -oP '<address>.*?</address>'
    exit 0
else
    echo "[-] Apache version not found in 404 response"
    exit 1
fi