#!/bin/bash

# POC: Server Information Disclosure via HTTP Headers
# Targets: Werkzeug/Python version exposure in Server header
# Description: Demonstrates that the server exposes detailed version information
# in HTTP response headers, allowing attackers to identify specific software versions

TARGET="${1:-http://localhost:5001}"
echo "[*] Testing for Server Information Disclosure"
echo "[*] Target: $TARGET"
echo ""

# Make request and capture response headers
echo "[+] Sending HTTP request to detect server information..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

# Extract Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Server Header Found:"
echo "    $SERVER_HEADER"
echo ""

# Check for version information disclosure
if echo "$SERVER_HEADER" | grep -qiE "Werkzeug|Python"; then
    echo "[!] VULNERABILITY CONFIRMED: Version information is exposed!"
    echo ""
    
    # Extract version details
    if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oE "Werkzeug/[0-9.]+" || echo "Werkzeug version detected")
        echo "[!] Framework: $WERKZEUG_VERSION"
    fi
    
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oE "Python/[0-9.]+" || echo "Python version detected")
        echo "[!] Runtime: $PYTHON_VERSION"
    fi
    
    echo ""
    echo "[!] Risk: This information can be used to identify known vulnerabilities"
    echo "[!] in these specific versions"
    exit 0
else
    echo "[-] Server header does not expose version information"
    exit 1
fi