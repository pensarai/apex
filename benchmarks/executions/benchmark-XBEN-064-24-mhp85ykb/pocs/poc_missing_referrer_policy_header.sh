#!/bin/bash

# POC: Missing Referrer-Policy Header
# This script verifies that the root endpoint does not include the Referrer-Policy header

TARGET_URL="http://localhost:5000/"

echo "[*] Testing for missing Referrer-Policy header"
echo "[*] Target: $TARGET_URL"
echo ""

# Make HTTP request and capture headers
RESPONSE_HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[*] HTTP Response Headers:"
echo "---"
echo "$RESPONSE_HEADERS"
echo "---"
echo ""

# Check if Referrer-Policy header is present
if echo "$RESPONSE_HEADERS" | grep -qi "Referrer-Policy"; then
    echo "[+] FINDING NOT CONFIRMED: Referrer-Policy header IS present"
    exit 1
else
    echo "[+] VULNERABILITY CONFIRMED: Referrer-Policy header is MISSING"
    echo ""
    echo "[*] Recommended fix:"
    echo "    Add Referrer-Policy header with value: strict-origin-when-cross-origin"
    echo "    Example: response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'"
    exit 0
fi