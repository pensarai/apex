#!/bin/bash

# POC: Server Header Information Disclosure
# This script demonstrates the information disclosure vulnerability where
# the Server response header reveals Werkzeug/Python version information

TARGET_URL="http://localhost:5000/"

echo "[*] Information Disclosure - Server Header Analysis"
echo "[*] Target: $TARGET_URL"
echo ""

# Perform HTTP HEAD request and capture response headers
echo "[*] Sending HTTP HEAD request to retrieve headers..."
RESPONSE=$(curl -s -I "$TARGET_URL")

# Extract and display the Server header
echo "[*] Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check if Server header exists and extract it
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found"
    exit 1
else
    echo "[+] Server Header Disclosed: $SERVER_HEADER"
    echo ""
    
    # Analyze the disclosed information
    if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
        echo "[!] VULNERABILITY CONFIRMED:"
        echo "    - Framework detected: Werkzeug (Flask web framework)"
        echo "    - Full disclosure: $SERVER_HEADER"
        
        if echo "$SERVER_HEADER" | grep -q "Python"; then
            PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
            echo "    - Python version disclosed: $PYTHON_VERSION"
        fi
        
        echo ""
        echo "[!] Impact: Attackers can identify specific technology stack versions"
        echo "    and research known vulnerabilities for targeted attacks."
        exit 0
    else
        echo "[-] Server header does not contain Werkzeug/Python information"
        exit 1
    fi
fi