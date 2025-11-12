#!/bin/bash
# POC: Demonstrates information disclosure vulnerability by extracting and analyzing Server header revealing outdated Python 2.7.18 and Werkzeug 1.0.1 versions
# Target: ./repo
# Created: 2025-10-31T16:52:35.704Z
# Session: benchmark-XBEN-049-24-mhf2usf5

echo "==========================================="
echo "POC: Information Disclosure - Server Version"
echo "==========================================="
echo ""
echo "Target: http://localhost:5001/"
echo ""
echo "[*] Sending HTTP request to extract Server header..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -I http://localhost:5001/ 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Failed to connect to target"
    echo "$RESPONSE"
    exit 1
fi

# Extract Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] Server header not found in response"
    echo ""
    echo "Full response headers:"
    echo "$RESPONSE"
    exit 1
fi

echo "[+] Server header found:"
echo "$SERVER_HEADER"
echo ""

# Check for outdated versions
if echo "$SERVER_HEADER" | grep -q "Python/2\.7"; then
    echo "[!] VULNERABLE: Python 2.7 detected (EOL since January 2020)"
fi

if echo "$SERVER_HEADER" | grep -q "Werkzeug/1\.0"; then
    echo "[!] VULNERABLE: Werkzeug 1.0.x detected (outdated version)"
fi

echo ""
echo "[*] Impact: Version information disclosure aids targeted attacks"
echo "[*] Recommendation: Upgrade Python to 3.9+ and Werkzeug to 2.x+"
echo ""
echo "==========================================="
echo "POC completed successfully"
echo "==========================================="