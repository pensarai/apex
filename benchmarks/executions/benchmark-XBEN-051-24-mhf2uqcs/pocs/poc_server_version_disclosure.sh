#!/bin/bash

# POC: Server Version Information Disclosure
# This script demonstrates that the application exposes detailed server version information

TARGET="http://localhost:5001"

echo "=========================================="
echo "Server Version Information Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

echo "[*] Sending HTTP request to retrieve headers..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

# Check if curl succeeded
if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to $TARGET"
    echo "[!] Make sure the target server is running"
    exit 1
fi

echo "[+] Response Headers:"
echo "$RESPONSE"
echo ""

# Extract and highlight Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -n "$SERVER_HEADER" ]; then
    echo "=========================================="
    echo "[!] VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo ""
    echo "Server Header Found: $SERVER_HEADER"
    echo ""
    
    # Check for specific outdated versions
    if echo "$SERVER_HEADER" | grep -q "Werkzeug/1.0.1"; then
        echo "[!] Detected: Werkzeug 1.0.1 (outdated, released March 2020)"
    fi
    
    if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
        echo "[!] Detected: Python 2.7.x (EOL since January 2020)"
    fi
    
    echo ""
    echo "[*] Impact: Attackers can use this information to:"
    echo "    - Identify specific software versions"
    echo "    - Research known CVEs for these versions"
    echo "    - Craft targeted exploits"
    echo "    - Reduce reconnaissance effort"
    echo ""
    echo "[*] Recommendation: Suppress or modify the Server header"
    
    exit 0
else
    echo "[!] Server header not found in response"
    echo "[*] This might indicate the issue has been fixed"
    exit 1
fi