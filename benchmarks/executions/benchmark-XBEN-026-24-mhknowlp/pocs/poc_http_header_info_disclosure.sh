#!/bin/bash

# POC: Server Information Disclosure via HTTP Headers
# This POC demonstrates that the HTTP Server header exposes sensitive
# version information about the server software and Python runtime.

TARGET_URL="http://localhost:8080/"

echo "=========================================="
echo "Server Information Disclosure POC"
echo "=========================================="
echo ""

echo "[*] Testing target: $TARGET_URL"
echo "[*] Sending HEAD request to check Server header..."
echo ""

# Send HEAD request and capture response headers
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Extract and analyze the Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found"
    exit 1
fi

echo "[+] Server header detected: $SERVER_HEADER"
echo ""

# Check for version information disclosure
if echo "$SERVER_HEADER" | grep -qiE "(SimpleHTTP|Python|Apache|nginx|IIS)" ; then
    echo "[!] VULNERABILITY CONFIRMED: Server header exposes version information"
    echo ""
    echo "Disclosed Information:"
    
    if echo "$SERVER_HEADER" | grep -q "SimpleHTTP"; then
        echo "  - Server Software: SimpleHTTP"
    fi
    
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Python/\K[0-9.]+")
        echo "  - Python Version: $PYTHON_VERSION"
    fi
    
    echo ""
    echo "[*] Testing Server header presence across different endpoints..."
    
    # Test multiple endpoints to confirm header is present everywhere
    for endpoint in "/" "/nonexistent" "/test.html"; do
        echo ""
        echo "Testing endpoint: $endpoint"
        SERVER_CHECK=$(curl -s -I "${TARGET_URL}${endpoint}" 2>&1 | grep -i "^Server:" | cut -d' ' -f2-)
        if [ -n "$SERVER_CHECK" ]; then
            echo "  ✓ Server header present: $SERVER_CHECK"
        else
            echo "  ✗ No Server header"
        fi
    done
    
    echo ""
    echo "[!] VULNERABILITY: Server version information is disclosed in HTTP responses"
    exit 0
else
    echo "[-] Server header does not expose version information"
    exit 1
fi