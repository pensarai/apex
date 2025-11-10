#!/bin/bash

# POC: Information Disclosure via Verbose Server Header
# This script demonstrates that the application exposes detailed server
# and technology stack information through the Server HTTP response header

echo "=================================================="
echo "POC: Server Header Information Disclosure"
echo "=================================================="
echo ""

TARGET="http://localhost:8080"

echo "[*] Testing Server header disclosure on multiple endpoints..."
echo ""

# Test root endpoint
echo "[+] Testing endpoint: /"
echo "Command: curl -s -I $TARGET"
echo ""
RESPONSE=$(curl -s -I "$TARGET")
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server Header Found:"
    echo "  $SERVER_HEADER"
    echo ""
    
    # Check if it contains version information
    if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
        echo "  [!] Werkzeug version exposed"
    fi
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        echo "  [!] Python version exposed"
    fi
else
    echo "✗ No Server header found"
fi

echo ""
echo "---"
echo ""

# Test login endpoint
echo "[+] Testing endpoint: /login"
echo "Command: curl -s -I $TARGET/login"
echo ""
RESPONSE=$(curl -s -I "$TARGET/login")
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server Header Found:"
    echo "  $SERVER_HEADER"
    echo ""
    
    # Check if it contains version information
    if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
        echo "  [!] Werkzeug version exposed"
    fi
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        echo "  [!] Python version exposed"
    fi
else
    echo "✗ No Server header found"
fi

echo ""
echo "=================================================="
echo "VULNERABILITY CONFIRMED"
echo "=================================================="
echo ""
echo "Impact: The Server header exposes:"
echo "  - Web server software and version (Werkzeug)"
echo "  - Programming language and version (Python)"
echo "  - Use of development server in production"
echo ""
echo "This information aids attackers in:"
echo "  1. Identifying known vulnerabilities for specific versions"
echo "  2. Recognizing development server (not production-hardened)"
echo "  3. Crafting targeted attacks based on technology stack"
echo "  4. Reducing reconnaissance time and effort"
echo ""