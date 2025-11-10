#!/bin/bash

# POC: Missing X-XSS-Protection Header
# This script demonstrates that the application does not set the X-XSS-Protection header

TARGET="http://localhost:8000/"

echo "[*] Testing for missing X-XSS-Protection header"
echo "[*] Target: $TARGET"
echo ""

# Perform HTTP request and capture all headers
echo "[*] Sending HTTP request and analyzing response headers..."
RESPONSE_HEADERS=$(curl -s -i "$TARGET" 2>/dev/null)

echo "[*] Full Response Headers:"
echo "---"
echo "$RESPONSE_HEADERS" | head -20
echo "---"
echo ""

# Check for X-XSS-Protection header
if echo "$RESPONSE_HEADERS" | grep -iq "X-XSS-Protection"; then
    echo "[✓] X-XSS-Protection header IS present"
    echo "$RESPONSE_HEADERS" | grep -i "X-XSS-Protection"
    exit 0
else
    echo "[✗] X-XSS-Protection header is MISSING"
    echo ""
    echo "[!] Vulnerability confirmed: The application does not set the X-XSS-Protection header"
    echo "[!] This leaves users with older browsers vulnerable to reflected XSS attacks"
    echo ""
    echo "[*] Expected header format: X-XSS-Protection: 1; mode=block"
    exit 0
fi