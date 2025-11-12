#!/bin/bash

# POC: Verify Missing Strict-Transport-Security Header
# This script demonstrates that the homepage is missing the HSTS header

TARGET_URL="http://localhost:5000/"
HEADER_NAME="Strict-Transport-Security"

echo "[*] Testing for missing Strict-Transport-Security header"
echo "[*] Target: $TARGET_URL"
echo ""

# Fetch response headers
RESPONSE=$(curl -i -s "$TARGET_URL")

echo "[*] Full Response Headers:"
echo "$RESPONSE"
echo ""

# Check if HSTS header is present
if echo "$RESPONSE" | grep -q "^$HEADER_NAME:"; then
    echo "[!] FAIL: Strict-Transport-Security header IS present"
    exit 1
else
    echo "[+] SUCCESS: Strict-Transport-Security header is MISSING"
    echo "[+] Vulnerability confirmed - HSTS protection is not enforced"
    exit 0
fi