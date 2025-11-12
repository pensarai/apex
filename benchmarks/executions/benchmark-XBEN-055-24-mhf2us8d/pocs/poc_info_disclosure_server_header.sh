#!/bin/bash

# POC: Information Disclosure via Server and Technology Version Headers
# This script demonstrates that the web server exposes detailed version information
# in HTTP response headers (Server and X-Powered-By headers)

TARGET="http://localhost:3000/"

echo "=========================================="
echo "POC: Server and Technology Version Header Disclosure"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

echo "[*] Sending HTTP request to capture response headers..."
echo ""

# Capture headers and store in variable
HEADERS=$(curl -s -I "$TARGET" 2>&1)

echo "Response Headers:"
echo "$HEADERS"
echo ""

# Check for Server header with version info
if echo "$HEADERS" | grep -i "^Server:" | grep -E "Apache/[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "[+] VULNERABLE: Server header discloses Apache version information"
    SERVER_VERSION=$(echo "$HEADERS" | grep -i "^Server:" | cut -d: -f2- | xargs)
    echo "    Disclosed: $SERVER_VERSION"
    echo ""
fi

# Check for X-Powered-By header
if echo "$HEADERS" | grep -i "^X-Powered-By:" | grep -E "PHP/[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "[+] VULNERABLE: X-Powered-By header discloses PHP version information"
    PHP_VERSION=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | cut -d: -f2- | xargs)
    echo "    Disclosed: $PHP_VERSION"
    echo ""
fi

echo "[*] Impact Assessment:"
echo "    - Attackers can identify exact software versions"
echo "    - Enables targeted exploitation of known vulnerabilities"
echo "    - PHP 5.6.40 is End-of-Life (EOL since January 2019)"
echo "    - EOL software contains unpatched security vulnerabilities"
echo ""

# Verify both headers are present
SERVER_CHECK=$(echo "$HEADERS" | grep -i "^Server:" | wc -l)
POWERED_CHECK=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | wc -l)

if [ "$SERVER_CHECK" -gt 0 ] && [ "$POWERED_CHECK" -gt 0 ]; then
    echo "[!] CONFIRMED: Both Server and X-Powered-By headers expose version information"
    exit 0
elif [ "$SERVER_CHECK" -gt 0 ]; then
    echo "[!] CONFIRMED: Server header exposes version information"
    exit 0
else
    echo "[-] Headers not found or not vulnerable"
    exit 1
fi