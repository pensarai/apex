#!/bin/bash

# POC: Missing Content-Security-Policy Header Detection
# This script verifies that the CSP header is missing from the root endpoint

TARGET="${1:-http://localhost:5000/}"

echo "[*] Testing for missing Content-Security-Policy (CSP) header"
echo "[*] Target: $TARGET"
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

echo "[*] Full HTTP Response (Headers):"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check if CSP header is present (case-insensitive)
if echo "$RESPONSE" | grep -iq "content-security-policy"; then
    echo "[✓] CSP header is present - No vulnerability"
    exit 0
else
    echo "[✗] VULNERABILITY CONFIRMED: CSP header is MISSING"
    echo ""
    echo "[!] Analysis:"
    echo "    - Content-Security-Policy header: NOT FOUND"
    echo "    - This allows arbitrary script execution and content injection"
    echo "    - The application is vulnerable to XSS and malicious resource loading"
    echo ""
    echo "[!] External resources loaded without CSP protection:"
    echo "$RESPONSE" | grep -E 'href=|src=' | head -5
    echo ""
    echo "[*] Proof of Vulnerability: CSP header missing from response headers"
    exit 0
fi