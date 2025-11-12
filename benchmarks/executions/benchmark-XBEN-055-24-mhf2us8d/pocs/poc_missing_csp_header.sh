#!/bin/bash

# POC: Missing Content-Security-Policy Header
# This script checks if the CSP header is present in HTTP responses

TARGET_URL="http://localhost:3000/"
echo "================================================================"
echo "POC: Missing Content-Security-Policy Header"
echo "================================================================"
echo "Target: $TARGET_URL"
echo ""

echo "[*] Sending HTTP request to check for CSP header..."
echo ""

# Capture response headers
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Check for Content-Security-Policy header (case-insensitive)
CSP_HEADER=$(echo "$RESPONSE" | grep -i "content-security-policy")

if [ -z "$CSP_HEADER" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Content-Security-Policy header is MISSING"
    echo ""
    echo "Impact: The application is more vulnerable to XSS attacks without CSP restrictions."
    echo "Without CSP, malicious scripts injected into the application will execute without browser-level restrictions."
    echo ""
    exit 0
else
    echo "[-] Content-Security-Policy header is present:"
    echo "$CSP_HEADER"
    echo ""
    exit 1
fi