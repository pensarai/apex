#!/bin/bash

# POC: X-Powered-By Header Information Disclosure
# This script demonstrates that the application exposes the PHP version
# through the X-Powered-By header, allowing attackers to identify the
# specific technology stack for targeted exploitation.

TARGET_URL="http://localhost:8080/search.php"
ENDPOINT_PATH="${TARGET_URL##*://}"
ENDPOINT_HOST="${ENDPOINT_PATH%%/*}"

echo "[*] Testing X-Powered-By Header Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Retrieve headers and check for X-Powered-By
echo "[+] Sending HTTP GET request and capturing response headers..."
RESPONSE_HEADERS=$(curl -s -I "$TARGET_URL")

echo "[*] Response Headers:"
echo "$RESPONSE_HEADERS"
echo ""

# Check if X-Powered-By header is present
if echo "$RESPONSE_HEADERS" | grep -qi "X-Powered-By"; then
    echo "[!] VULNERABLE: X-Powered-By header is present!"
    X_POWERED_BY=$(echo "$RESPONSE_HEADERS" | grep -i "X-Powered-By" | cut -d' ' -f2-)
    echo "[!] Disclosed Information: $X_POWERED_BY"
    
    # Extract PHP version
    if echo "$X_POWERED_BY" | grep -qi "PHP"; then
        PHP_VERSION=$(echo "$X_POWERED_BY" | grep -oP 'PHP/\K[0-9]+\.[0-9]+\.[0-9]+')
        echo "[!] PHP Version Identified: $PHP_VERSION"
        echo "[*] This version can be researched for known vulnerabilities"
    fi
else
    echo "[-] X-Powered-By header not found"
    exit 1
fi

echo ""

# Test 2: Check Server header for Apache version
echo "[+] Checking for additional technology stack disclosure (Server header)..."
SERVER_HEADER=$(echo "$RESPONSE_HEADERS" | grep -i "^Server:" | cut -d' ' -f2-)
if [ -n "$SERVER_HEADER" ]; then
    echo "[!] Server header disclosed: $SERVER_HEADER"
fi

echo ""
echo "[+] Vulnerability confirmed: Application discloses technology stack information"
echo "[+] This information helps attackers in reconnaissance and targeted exploitation"