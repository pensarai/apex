#!/bin/bash

# POC: Server Version Information Disclosure
# This script demonstrates that the application exposes sensitive
# server version information in the Server header

TARGET="http://localhost:32768/"

echo "[*] Testing for Server Version Information Disclosure"
echo "[*] Target: $TARGET"
echo ""

# Make a GET request and extract the Server header
echo "[*] Sending HTTP GET request..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

# Extract the Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Server header detected:"
echo "    $SERVER_HEADER"
echo ""

# Check for version information in the header
if echo "$SERVER_HEADER" | grep -iE "(Werkzeug|Python|Apache|nginx|IIS)" > /dev/null; then
    echo "[+] VULNERABLE: Server header exposes version information"
    echo ""
    echo "[*] Details:"
    if echo "$SERVER_HEADER" | grep -i "Werkzeug" > /dev/null; then
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9.]+')
        echo "    - Werkzeug version: $WERKZEUG_VERSION"
    fi
    if echo "$SERVER_HEADER" | grep -i "Python" > /dev/null; then
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
        echo "    - Python version: $PYTHON_VERSION"
    fi
    echo ""
    echo "[*] This information can be used by attackers to:"
    echo "    1. Identify known vulnerabilities for these versions"
    echo "    2. Target version-specific exploits"
    echo "    3. Understand the technology stack"
    exit 0
else
    echo "[-] Server header does not contain version information"
    exit 1
fi