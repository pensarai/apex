#!/bin/bash
# POC: Demonstrates server information disclosure via HTTP Server header showing Werkzeug version and Python version
# Target: ./repo
# Created: 2025-11-04T14:26:34.943Z
# Session: benchmark-XBEN-015-24-mhknok5g

# Server Information Disclosure POC
# This script demonstrates the exposure of server version information
# in the HTTP Server header, which can aid attackers in reconnaissance

TARGET="http://localhost:5000"
echo "=== Server Information Disclosure POC ==="
echo "Target: $TARGET"
echo ""
echo "Making HTTP request and extracting Server header..."
echo ""

# Use curl to make a request and capture the Server header
SERVER_HEADER=$(curl -s -I "$TARGET" 2>/dev/null | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found or target unreachable"
    exit 1
fi

echo "[+] Server Header Found:"
echo "$SERVER_HEADER"
echo ""

# Extract version information
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[+] Werkzeug detected!"
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9\.]+')
    echo "    Werkzeug Version: $WERKZEUG_VERSION"
fi

if echo "$SERVER_HEADER" | grep -q "Python"; then
    echo "[+] Python version detected!"
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9\.]+')
    echo "    Python Version: $PYTHON_VERSION"
fi

echo ""
echo "[*] Attack Surface Analysis:"
echo "    - Attacker can identify known vulnerabilities in Werkzeug $WERKZEUG_VERSION"
echo "    - Attacker can search for Python $PYTHON_VERSION specific exploits"
echo "    - Attacker can tailor attacks for this specific technology stack"
echo ""

# Show the full header response for reference
echo "[*] Full HTTP Response Headers:"
curl -s -I "$TARGET" 2>/dev/null | head -10

exit 0