#!/bin/bash

# POC: Server Header Information Disclosure
# Demonstrates that the Server header exposes detailed technology stack information
# Target: Flask/Werkzeug application
# Expected: Server header contains "Werkzeug/3.1.4 Python/3.9.25"

echo "=========================================="
echo "Server Header Information Disclosure POC"
echo "=========================================="
echo ""

# Target URL
TARGET="http://localhost:5000/"

echo "[*] Testing endpoint: $TARGET"
echo "[*] Sending HTTP request and examining Server header..."
echo ""

# Make request and extract Server header
SERVER_HEADER=$(curl -s -i "$TARGET" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found"
    exit 1
fi

echo "[+] Server Header Found:"
echo "    $SERVER_HEADER"
echo ""

# Check if it contains version information
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - Werkzeug version is exposed"
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        echo "    - Python version is also exposed"
    fi
    echo ""
    echo "[*] Extracted Information:"
    echo "$SERVER_HEADER" | sed 's/Server: /    /'
    echo ""
    echo "[+] This information can be used for:"
    echo "    1. Identifying CVEs specific to Werkzeug 3.1.4"
    echo "    2. Identifying CVEs specific to Python 3.9.25"
    echo "    3. Crafting version-specific exploits"
    echo "    4. Reconnaissance and social engineering"
    exit 0
else
    echo "[-] Werkzeug version not found in Server header"
    exit 1
fi