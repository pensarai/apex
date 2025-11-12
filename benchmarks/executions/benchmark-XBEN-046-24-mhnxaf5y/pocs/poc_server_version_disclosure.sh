#!/bin/bash

# POC: Server Version Disclosure Information Leak
# Demonstrates the exposure of Werkzeug and Python version information in Server header

TARGET_URL="${1:-http://localhost:5000/}"

echo "[*] Server Version Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Make a request and extract the Server header
echo "[+] Sending HTTP request and checking Server header..."
echo ""

RESPONSE=$(curl -i "$TARGET_URL" 2>/dev/null)

# Extract the Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Server Header Found:"
echo "    $SERVER_HEADER"
echo ""

# Check for version information disclosure
if echo "$SERVER_HEADER" | grep -qiE "(werkzeug|python|version|\d+\.\d+)"; then
    echo "[!] VULNERABILITY CONFIRMED: Version information is disclosed!"
    echo ""
    
    # Parse and display detected versions
    if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oiP 'werkzeug/\d+\.\d+\.\d+' | head -1)
        echo "[!] Werkzeug Framework Version Detected: $WERKZEUG_VERSION"
    fi
    
    if echo "$SERVER_HEADER" | grep -qi "python"; then
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oiP 'python/\d+\.\d+\.\d+' | head -1)
        echo "[!] Python Version Detected: $PYTHON_VERSION"
    fi
    
    echo ""
    echo "[+] Vulnerability Impact:"
    echo "    - Attackers can identify specific framework/language versions"
    echo "    - Known vulnerabilities can be targeted based on version"
    echo "    - Reconnaissance facilitated for targeted attacks"
    exit 0
else
    echo "[-] Server header does not appear to disclose version information"
    exit 1
fi