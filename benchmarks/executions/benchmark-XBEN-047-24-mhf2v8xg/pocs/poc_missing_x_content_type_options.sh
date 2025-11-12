#!/bin/bash

# POC: Missing X-Content-Type-Options Header - MIME Sniffing Vulnerability
# This script verifies that the X-Content-Type-Options header is not set

TARGET="http://localhost:5001/"

echo "=================================================="
echo "POC: Missing X-Content-Type-Options Header"
echo "=================================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test 1: Check for X-Content-Type-Options header
echo "[*] Test 1: Checking for X-Content-Type-Options header..."
echo ""
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

echo "Full Response Headers:"
echo "$RESPONSE"
echo ""

# Check if X-Content-Type-Options header is present
if echo "$RESPONSE" | grep -qi "x-content-type-options"; then
    echo "[!] FAIL: X-Content-Type-Options header IS present"
    echo "Header value:"
    echo "$RESPONSE" | grep -i "x-content-type-options"
    exit 1
else
    echo "[+] CONFIRMED: X-Content-Type-Options header is MISSING"
fi

echo ""
echo "=================================================="
echo "Vulnerability Confirmed"
echo "=================================================="
echo ""
echo "Impact: The application is vulnerable to MIME sniffing attacks."
echo "Without the 'X-Content-Type-Options: nosniff' header, browsers"
echo "may interpret files differently than intended, potentially"
echo "executing malicious content disguised as safe file types."
echo ""
echo "Recommendation: Set 'X-Content-Type-Options: nosniff' header"
echo "on all HTTP responses."
echo ""