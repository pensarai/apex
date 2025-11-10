#!/bin/bash

# POC: Missing X-XSS-Protection Header Detection
# Tests whether the application sets the X-XSS-Protection header
# This header instructs browsers to enable XSS filters and block detected attacks

TARGET_URL="${1:-http://localhost:5001}"

echo "=== Missing X-XSS-Protection Header POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: GET request - check for X-XSS-Protection header
echo "[*] Testing GET request for X-XSS-Protection header..."
GET_RESPONSE=$(curl -s -i "$TARGET_URL" 2>/dev/null)
GET_HEADER=$(echo "$GET_RESPONSE" | grep -i "^X-XSS-Protection:" || echo "")

if [ -z "$GET_HEADER" ]; then
    echo "[-] VULNERABLE: X-XSS-Protection header NOT present in GET response"
    VULNERABLE=1
else
    echo "[+] PROTECTED: X-XSS-Protection header found: $GET_HEADER"
    VULNERABLE=0
fi

echo ""
echo "[*] Full response headers from GET request:"
echo "$GET_RESPONSE" | head -n 10
echo ""

# Test 2: HEAD request - check for X-XSS-Protection header
echo "[*] Testing HEAD request for X-XSS-Protection header..."
HEAD_RESPONSE=$(curl -s -i -X HEAD "$TARGET_URL" 2>/dev/null)
HEAD_HEADER=$(echo "$HEAD_RESPONSE" | grep -i "^X-XSS-Protection:" || echo "")

if [ -z "$HEAD_HEADER" ]; then
    echo "[-] VULNERABLE: X-XSS-Protection header NOT present in HEAD response"
else
    echo "[+] PROTECTED: X-XSS-Protection header found in HEAD response"
fi

echo ""

# Test 3: OPTIONS request - check for X-XSS-Protection header
echo "[*] Testing OPTIONS request for X-XSS-Protection header..."
OPTIONS_RESPONSE=$(curl -s -i -X OPTIONS "$TARGET_URL" 2>/dev/null)
OPTIONS_HEADER=$(echo "$OPTIONS_RESPONSE" | grep -i "^X-XSS-Protection:" || echo "")

if [ -z "$OPTIONS_HEADER" ]; then
    echo "[-] VULNERABLE: X-XSS-Protection header NOT present in OPTIONS response"
else
    echo "[+] PROTECTED: X-XSS-Protection header found in OPTIONS response"
fi

echo ""
echo "=== Summary ==="
if [ "$VULNERABLE" -eq 1 ]; then
    echo "[-] VULNERABILITY CONFIRMED: X-XSS-Protection header is missing"
    echo "    Recommendation: Set X-XSS-Protection: 1; mode=block"
    exit 0
else
    echo "[+] No vulnerability found: X-XSS-Protection header is properly set"
    exit 1
fi