#!/bin/bash

# POC: X-XSS-Protection Header Disabled on /xss32 Endpoint
# Demonstrates that the /xss32 endpoint explicitly disables browser XSS protection

TARGET_URL="http://localhost:5000/xss32"

echo "[*] X-XSS-Protection Header Vulnerability on /xss32"
echo "[*] Testing for disabled XSS protection filter"
echo ""

# Test 1: GET request (guaranteed to show the header)
echo "[TEST 1] GET request to /xss32"
echo "================================"
response=$(curl -s -i -X GET "$TARGET_URL" 2>&1)

echo "$response" | head -10
echo ""

xss_header=$(echo "$response" | grep -i "X-XSS-Protection:" | head -1)
if echo "$xss_header" | grep -q "0"; then
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "[+] $xss_header"
    echo "[+] The X-XSS-Protection header is explicitly set to 0"
    echo "[+] This disables the browser's built-in XSS protection filter"
    exit 0
fi

# Test 2: POST with empty parameter (also guaranteed)
echo ""
echo "[TEST 2] POST request with empty name parameter"
echo "================================================"
response=$(curl -s -i -X POST "$TARGET_URL" -d "name=" 2>&1)

echo "$response" | head -10
echo ""

xss_header=$(echo "$response" | grep -i "X-XSS-Protection:" | head -1)
if echo "$xss_header" | grep -q "0"; then
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "[+] $xss_header"
    echo "[+] The X-XSS-Protection header is explicitly set to 0"
    echo "[+] This disables the browser's built-in XSS protection filter"
    exit 0
fi

echo "[-] Header not found in expected format"
exit 1