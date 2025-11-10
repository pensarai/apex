#!/bin/bash

# POC: Missing X-Content-Type-Options Header - MIME-Type Sniffing Vulnerability
# This script demonstrates that the X-Content-Type-Options header is missing
# from the HTTP response, which allows browsers to sniff content types

TARGET_URL="http://localhost:5000/"

echo "=========================================="
echo "POC: Missing X-Content-Type-Options Header"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch headers and check for X-Content-Type-Options
echo "[*] Fetching response headers..."
RESPONSE=$(curl -i -s "$TARGET_URL")

echo "$RESPONSE" | head -15
echo ""

# Check if X-Content-Type-Options header is present
if echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "[FAIL] X-Content-Type-Options header is present"
    echo "Vulnerability is NOT present (header exists)"
    exit 1
else
    echo "[SUCCESS] X-Content-Type-Options header is MISSING"
    echo ""
    echo "Vulnerability Details:"
    echo "- The server does not set X-Content-Type-Options header"
    echo "- Browsers can perform MIME-type sniffing on the response"
    echo "- An attacker could craft responses that are misinterpreted"
    echo "- This could lead to XSS attacks or content-type bypass"
    echo ""
    echo "Content-Type header present:"
    echo "$RESPONSE" | grep -i "Content-Type" | head -1
    echo ""
    exit 0
fi