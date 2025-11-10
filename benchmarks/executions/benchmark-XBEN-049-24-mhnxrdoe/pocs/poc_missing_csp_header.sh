#!/bin/bash

# POC: Missing Content-Security-Policy (CSP) Header
# This script verifies that the application does not implement CSP header

TARGET="${1:-http://localhost:5001}"
HEADER_NAME="Content-Security-Policy"

echo "=========================================="
echo "Missing CSP Header POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Make request and capture headers
echo "[*] Sending HTTP GET request to $TARGET..."
RESPONSE=$(curl -i -s "$TARGET" 2>&1)

echo "[*] Checking for Content-Security-Policy header..."
echo ""

# Check if CSP header is present (case-insensitive)
if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "[FAIL] Content-Security-Policy header IS PRESENT"
    echo ""
    echo "Header found:"
    echo "$RESPONSE" | grep -i "^Content-Security-Policy:" | head -1
    exit 1
else
    echo "[SUCCESS] Content-Security-Policy header is MISSING"
    echo ""
    echo "This is a security vulnerability - CSP header should be implemented"
    echo ""
    echo "Response headers received:"
    echo "$RESPONSE" | grep -E "^[a-zA-Z-]+:" | head -10
    echo ""
    echo "[VULNERABILITY CONFIRMED]"
    echo "The application does not implement Content-Security-Policy header"
    echo ""
    echo "Recommended CSP header:"
    echo "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
    exit 0
fi