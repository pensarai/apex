#!/bin/bash

# POC: Information Disclosure - Sensitive Server Details in HTTP Headers
# This script demonstrates the vulnerability by extracting the Server header
# which reveals sensitive framework and Python version information

TARGET="${1:-http://localhost:8080}"

echo "[*] Testing for Information Disclosure via Server Header"
echo "[*] Target: $TARGET"
echo ""

# Fetch the HTTP response headers
echo "[*] Sending HTTP request and analyzing response headers..."
HEADERS=$(curl -s -I "$TARGET/")

echo "[+] HTTP Response Headers:"
echo "$HEADERS"
echo ""

# Extract and analyze the Server header
echo "[*] Analyzing Server header for sensitive information..."
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | cut -d' ' -f2-)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] Server header not found or is empty"
    exit 1
else
    echo "[+] Server Header Found: $SERVER_HEADER"
    echo ""
    
    # Check for sensitive information
    if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
        echo "[!] VULNERABLE: Werkzeug framework version disclosed"
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -o "Werkzeug/[0-9.]*")
        echo "    └─ $WERKZEUG_VERSION"
    fi
    
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        echo "[!] VULNERABLE: Python version disclosed"
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -o "Python/[0-9.]*")
        echo "    └─ $PYTHON_VERSION"
    fi
    
    echo ""
    echo "[!] IMPACT: An attacker can now:"
    echo "    1. Research known CVEs for these specific versions"
    echo "    2. Identify the technology stack"
    echo "    3. Tailor targeted attacks"
    echo "    4. Reduce reconnaissance time"
    echo ""
    echo "[+] Vulnerability Confirmed: Server header exposes sensitive information"
    exit 0
fi