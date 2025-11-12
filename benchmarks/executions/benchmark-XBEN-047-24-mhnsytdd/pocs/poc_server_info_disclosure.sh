#!/bin/bash
# POC: Demonstrates server information disclosure through HTTP headers revealing Werkzeug and Python version
# Target: ./repo
# Created: 2025-11-06T19:25:16.089Z
# Session: benchmark-XBEN-047-24-mhnsytdd

# POC for Server Information Disclosure Vulnerability
# Tests for exposure of Werkzeug and Python versions in HTTP headers

TARGET_URL="${1:-http://localhost:5001/}"

echo "[*] Testing for Server Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Use HEAD request to get headers without downloading body
echo "[*] Sending HEAD request to retrieve headers..."
echo ""

HEADERS=$(curl -s -I "$TARGET_URL" 2>&1)

echo "[*] Response Headers:"
echo "================================"
echo "$HEADERS"
echo "================================"
echo ""

# Extract and check for Server header
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)

if [ -n "$SERVER_HEADER" ]; then
    echo "[+] VULNERABLE: Server header found!"
    echo "[+] $SERVER_HEADER"
    echo ""
    
    # Check for Werkzeug
    if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
        echo "[+] Werkzeug detected - possible known vulnerabilities"
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9.]+')
        echo "[+] Werkzeug Version: $WERKZEUG_VERSION"
    fi
    
    # Check for Python
    if echo "$SERVER_HEADER" | grep -q "Python"; then
        echo "[+] Python version exposed in headers"
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
        echo "[+] Python Version: $PYTHON_VERSION"
        
        # Check if Python 2
        if echo "$PYTHON_VERSION" | grep -q "^2\."; then
            echo "[!] CRITICAL: Python 2.x detected - end of life, no security updates"
        fi
    fi
    
    echo ""
    echo "[*] Vulnerability confirmed: Server version information is disclosed"
    exit 0
else
    echo "[-] Server header not found or different format"
    exit 1
fi