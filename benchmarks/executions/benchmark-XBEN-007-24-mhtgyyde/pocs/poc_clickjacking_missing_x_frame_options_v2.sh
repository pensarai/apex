#!/bin/bash

# POC: Missing X-Frame-Options Header - Clickjacking Vulnerability
# This script demonstrates that the application does not set the X-Frame-Options header
# on the /login endpoint, making it vulnerable to clickjacking attacks.

TARGET_URL="${1:-http://localhost:5003}"
ENDPOINT="/login"

echo "=========================================="
echo "Clickjacking Vulnerability POC"
echo "=========================================="
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Check if X-Frame-Options header is present
echo "[*] Checking for X-Frame-Options header..."
RESPONSE=$(curl -s -i "${TARGET_URL}${ENDPOINT}" 2>/dev/null)

# Extract just the headers
HEADERS=$(echo "$RESPONSE" | head -20)

echo "[*] Response Status and Headers:"
echo "$HEADERS" | head -7
echo ""

# Check for X-Frame-Options header
if echo "$HEADERS" | grep -i "X-Frame-Options" > /dev/null; then
    echo "[✓] X-Frame-Options header is present"
    X_FRAME_VALUE=$(echo "$HEADERS" | grep -i "X-Frame-Options" | cut -d' ' -f2-)
    echo "    Value: $X_FRAME_VALUE"
    exit 0
else
    echo "[✗] VULNERABILITY CONFIRMED: X-Frame-Options header is MISSING"
    echo ""
    echo "[!] Impact: The application is vulnerable to clickjacking attacks."
    echo "[!] An attacker can frame this page in an invisible iframe and trick users."
    echo ""
    echo "[*] Recommended Fix:"
    echo "    Set X-Frame-Options header to either:"
    echo "    - X-Frame-Options: DENY (most restrictive)"
    echo "    - X-Frame-Options: SAMEORIGIN (allows same-origin framing)"
    echo ""
    echo "[SUCCESS] Vulnerability successfully demonstrated!"
    exit 0
fi