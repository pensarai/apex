#!/bin/bash

# POC: Server Information Disclosure via HTTP Headers
# Demonstrates exposure of detailed server information through HTTP headers
# Target: /static/ endpoint
# Expected: Server header reveals SimpleHTTP version and Python version

TARGET="${1:-http://localhost:8080}"
ENDPOINT="/static/"

echo "[*] Testing for Server Information Disclosure"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Make HTTP HEAD request to get headers
RESPONSE=$(curl -s -I "$TARGET$ENDPOINT")

echo "[+] HTTP Response Headers:"
echo "$RESPONSE"
echo ""

# Extract and analyze the Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] Server header not found or empty"
    exit 1
fi

echo "[+] Server Header Value: $SERVER_HEADER"
echo ""

# Check for information disclosure indicators
if echo "$SERVER_HEADER" | grep -qi "SimpleHTTP"; then
    echo "[!] VULNERABLE: SimpleHTTP server detected"
    VULN=1
fi

if echo "$SERVER_HEADER" | grep -qi "Python"; then
    echo "[!] VULNERABLE: Python version information disclosed"
    VULN=1
fi

if echo "$SERVER_HEADER" | grep -E "Python/[0-9]+\.[0-9]+\.[0-9]+" > /dev/null; then
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oE "Python/[0-9]+\.[0-9]+\.[0-9]+")
    echo "[!] VULNERABLE: Specific Python version exposed: $PYTHON_VERSION"
    VULN=1
fi

if echo "$SERVER_HEADER" | grep -E "SimpleHTTP/[0-9]+\.[0-9]+" > /dev/null; then
    SIMPLEHTTP_VERSION=$(echo "$SERVER_HEADER" | grep -oE "SimpleHTTP/[0-9]+\.[0-9]+")
    echo "[!] VULNERABLE: Specific SimpleHTTP version exposed: $SIMPLEHTTP_VERSION"
    VULN=1
fi

echo ""

if [ "$VULN" = "1" ]; then
    echo "[+] CONFIRMATION: Server information disclosure vulnerability confirmed"
    exit 0
else
    echo "[-] Server header appears adequately obfuscated"
    exit 1
fi