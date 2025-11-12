#!/bin/bash

# POC: Verify Missing Referrer-Policy Header
# Target: http://localhost:5000/
# This script demonstrates that the Referrer-Policy header is missing from the response

TARGET_URL="http://localhost:5000/"

echo "=========================================="
echo "POC: Missing Referrer-Policy Header"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -i "$TARGET_URL" 2>/dev/null)

echo "[*] Full Response Headers:"
echo "$RESPONSE" | head -n 20
echo ""

# Check specifically for Referrer-Policy header
echo "[*] Checking for Referrer-Policy header..."
if echo "$RESPONSE" | grep -i "Referrer-Policy" > /dev/null; then
    echo "[-] Referrer-Policy header is PRESENT"
    echo "Header value: $(echo "$RESPONSE" | grep -i "Referrer-Policy")"
    exit 1
else
    echo "[+] VULNERABILITY CONFIRMED: Referrer-Policy header is MISSING"
    exit 0
fi