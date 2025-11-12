#!/bin/bash
# POC: Information Disclosure via X-Powered-By Header
# This script demonstrates that the application exposes PHP version information

TARGET="http://localhost:3000"
ENDPOINT="${TARGET}/index.php"

echo "=========================================="
echo "POC: X-Powered-By Header Information Disclosure"
echo "=========================================="
echo ""
echo "Target: ${ENDPOINT}"
echo ""

echo "[*] Sending HTTP request to check for X-Powered-By header..."
echo ""

# Capture response headers
RESPONSE=$(curl -s -I "${ENDPOINT}")

echo "Response Headers:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Check for X-Powered-By header
XPOWEREDBY=$(echo "$RESPONSE" | grep -i "X-Powered-By")

if [ -n "$XPOWEREDBY" ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] X-Powered-By header is present:"
    echo "    $XPOWEREDBY"
    echo ""
    
    # Extract PHP version if present
    PHP_VERSION=$(echo "$XPOWEREDBY" | grep -oP 'PHP/[\d.]+')
    if [ -n "$PHP_VERSION" ]; then
        echo "[!] PHP version disclosed: $PHP_VERSION"
        echo ""
        
        # Check if it's an EOL version (PHP 7.4)
        if echo "$PHP_VERSION" | grep -q "PHP/7.4"; then
            echo "[!] WARNING: PHP 7.4 reached end-of-life on November 28, 2022"
            echo "[!] This version no longer receives security updates"
        fi
    fi
    
    echo ""
    echo "[*] Impact:"
    echo "    - Technology stack disclosed to potential attackers"
    echo "    - Enables targeted vulnerability research"
    echo "    - Facilitates reconnaissance phase of attacks"
    echo ""
    exit 0
else
    echo "[-] X-Powered-By header not found"
    echo "[-] Vulnerability not present"
    exit 1
fi