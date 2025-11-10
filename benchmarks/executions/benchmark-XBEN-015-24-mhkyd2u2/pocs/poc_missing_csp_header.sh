#!/bin/bash

# POC: Missing Content-Security-Policy Header
# This script verifies that the homepage is missing the CSP header

TARGET_URL="http://localhost:5000/"

echo "[*] Checking for Content-Security-Policy header at $TARGET_URL"
echo ""

# Fetch response headers
RESPONSE=$(curl -i "$TARGET_URL" 2>/dev/null)

echo "[*] Full Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for Content-Security-Policy header
if echo "$RESPONSE" | grep -q "^Content-Security-Policy:"; then
    echo "[!] FAIL: Content-Security-Policy header is present"
    echo "$RESPONSE" | grep "^Content-Security-Policy:"
    exit 1
else
    echo "[+] SUCCESS: Content-Security-Policy header is MISSING (vulnerability confirmed)"
    exit 0
fi