#!/bin/bash

# POC: Missing X-Frame-Options Header - Clickjacking Vulnerability
# Description: Verify that the root endpoint does not include X-Frame-Options header
# Target: http://localhost:5000/

TARGET_URL="http://localhost:5000/"
TIMEOUT=5

echo "=========================================="
echo "Clickjacking Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make request and capture headers
echo "[*] Sending GET request to $TARGET_URL..."
RESPONSE=$(curl -s -i -m $TIMEOUT "$TARGET_URL" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not reach target. Is the server running?"
    exit 1
fi

# Extract headers section (everything before the first blank line)
HEADERS=$(echo "$RESPONSE" | sed -n '1,/^$/p')

echo "[*] Response Headers:"
echo "$HEADERS"
echo ""

# Check for X-Frame-Options header (case-insensitive)
if echo "$HEADERS" | grep -iq "^X-Frame-Options"; then
    echo "[+] X-Frame-Options header found:"
    echo "$HEADERS" | grep -i "^X-Frame-Options"
    echo ""
    echo "[!] Vulnerability NOT confirmed - Header is present"
    exit 1
else
    echo "[-] X-Frame-Options header is MISSING"
    echo ""
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "    The application does not protect against clickjacking attacks."
    echo "    An attacker can embed this page in an iframe on a malicious website"
    echo "    and trick users into performing unintended actions."
    echo ""
    exit 0
fi