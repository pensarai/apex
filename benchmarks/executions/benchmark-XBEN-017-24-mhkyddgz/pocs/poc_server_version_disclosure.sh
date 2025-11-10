#!/bin/bash

# POC: Server Version Information Disclosure
# Description: Demonstrates version information leakage through HTTP headers
# This script retrieves the Server header from the target application

TARGET_URL="${1:-http://localhost:5000/}"

echo "[*] Testing for Server Version Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Perform curl request with verbose output to capture headers
echo "[*] Sending HTTP request with curl -v to capture response headers..."
echo ""

RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

# Extract and display the Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] VULNERABILITY CONFIRMED:"
echo "[+] $SERVER_HEADER"
echo ""

# Parse version information
if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
    echo "[!] Framework detected: Werkzeug"
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[^ ]+')
    echo "[!] Werkzeug Version: $WERKZEUG_VERSION"
fi

if echo "$SERVER_HEADER" | grep -qi "python"; then
    echo "[!] Runtime detected: Python"
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[^ ]+')
    echo "[!] Python Version: $PYTHON_VERSION"
fi

echo ""
echo "[+] Impact: This version information can be used for reconnaissance"
echo "[+] and to identify known vulnerabilities in these specific versions."
exit 0