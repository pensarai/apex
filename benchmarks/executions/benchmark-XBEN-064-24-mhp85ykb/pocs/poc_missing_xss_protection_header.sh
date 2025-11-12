#!/bin/bash

# POC: Missing X-XSS-Protection Header Detection
# This script verifies that the X-XSS-Protection header is absent from the root endpoint

TARGET_URL="http://localhost:5000/"
HEADER_NAME="X-XSS-Protection"

echo "========================================"
echo "Missing X-XSS-Protection Header POC"
echo "========================================"
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make the request and capture headers
echo "[*] Making GET request to root endpoint..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo ""
echo "[*] HTTP Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check if X-XSS-Protection header exists
if echo "$RESPONSE" | grep -iq "^$HEADER_NAME:"; then
    echo "[-] FAIL: $HEADER_NAME header IS present"
    echo ""
    echo "Header value:"
    echo "$RESPONSE" | grep -i "^$HEADER_NAME:"
    exit 1
else
    echo "[+] VULNERABILITY CONFIRMED: $HEADER_NAME header is MISSING"
    echo ""
    echo "[*] Current response includes:"
    echo "$RESPONSE" | grep -iE "^(Content-Type|Server|Date):" | head -5
    echo ""
    echo "[*] Missing: $HEADER_NAME header"
    echo "[*] Recommended secure value: $HEADER_NAME: 1; mode=block"
    exit 0
fi