#!/bin/bash

# POC: Server Information Disclosure in HTTP Headers
# This script demonstrates how attackers can retrieve sensitive server version information
# from HTTP response headers.

TARGET_URL="${1:-http://localhost:5000/}"
HEADER_NAME="Server"

echo "[*] Testing for Server Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Make HTTP request and capture response headers
echo "[*] Sending HTTP request and analyzing Server header..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

# Extract Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Found Server header:"
echo "    $SERVER_HEADER"
echo ""

# Check for version information disclosure
if echo "$SERVER_HEADER" | grep -qiE "werkzeug|python|flask|django|apache|nginx|iis"; then
    echo "[!] VULNERABILITY CONFIRMED: Server information disclosure detected"
    echo ""
    echo "[+] Disclosed Information:"
    echo "    - Framework/Server: $(echo "$SERVER_HEADER" | grep -oiE '(Werkzeug|Flask|Django|Apache|Nginx|IIS)[^/]*' || echo 'Unknown')"
    echo "    - Python Version: $(echo "$SERVER_HEADER" | grep -oiE 'Python/[0-9]+\.[0-9]+\.[0-9]+' || echo 'Not disclosed')"
    echo ""
    echo "[*] This information can be used to identify known vulnerabilities in specific versions"
    exit 0
else
    echo "[-] Server header does not disclose sensitive version information"
    exit 1
fi