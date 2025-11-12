#!/bin/bash

# POC: Missing Content-Security-Policy Header
# This script verifies that the application does not implement CSP headers
# which would provide defense-in-depth protection against XSS attacks

TARGET_URL="http://localhost:8000/"
HEADER_NAME="Content-Security-Policy"

echo "[*] Testing for Missing Content-Security-Policy Header"
echo "[*] Target: $TARGET_URL"
echo ""

# Make HTTP request and capture headers
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "[*] Full Response Headers:"
echo "======================================"
echo "$RESPONSE" | head -n 20
echo "======================================"
echo ""

# Check for CSP header
CSP_HEADER=$(echo "$RESPONSE" | grep -i "^Content-Security-Policy:")

if [ -z "$CSP_HEADER" ]; then
    echo "[✓] VULNERABILITY CONFIRMED: Content-Security-Policy header is MISSING"
    echo ""
    echo "[*] Impact: Without CSP, XSS attacks would have fewer restrictions on:"
    echo "    - Inline script execution"
    echo "    - External resource loading"
    echo "    - Plugin execution"
    echo ""
    echo "[*] Recommended CSP Policy Example:"
    echo "    Content-Security-Policy: default-src 'self'; script-src 'self' code.jquery.com cdn.jsdelivr.net stackpath.bootstrapcdn.com; style-src 'self' stackpath.bootstrapcdn.com fonts.googleapis.com"
    echo ""
    exit 0
else
    echo "[✗] Content-Security-Policy header IS present:"
    echo "$CSP_HEADER"
    exit 1
fi