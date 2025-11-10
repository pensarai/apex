#!/bin/bash
# POC: Demonstrates Server version information disclosure by extracting the Server header from HTTP responses
# Target: ./repo
# Created: 2025-11-04T16:59:34.511Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# Server Version Information Disclosure POC
# This script demonstrates the exposure of sensitive server version information
# through HTTP headers

TARGET_URL="http://localhost:5000/"
ENDPOINT="http://localhost:5000/"

echo "=========================================="
echo "Server Version Information Disclosure POC"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Testing for Server header exposure..."
echo ""

# Fetch the response headers and grep for Server header
SERVER_HEADER=$(curl -s -i "$ENDPOINT" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] No Server header found in response"
    exit 1
fi

echo "[+] VULNERABLE: Server header found!"
echo "[+] Header Content: $SERVER_HEADER"
echo ""

# Extract version information
if echo "$SERVER_HEADER" | grep -qE "Werkzeug|Python"; then
    echo "[+] Version Information Exposed:"
    echo "    - Framework: $(echo "$SERVER_HEADER" | grep -o 'Werkzeug/[^ ]*')"
    echo "    - Python: $(echo "$SERVER_HEADER" | grep -o 'Python/[^ ]*')"
    echo ""
    echo "[!] This allows attackers to:"
    echo "    1. Identify specific framework and Python versions"
    echo "    2. Research known CVEs for these versions"
    echo "    3. Plan targeted attacks"
    echo ""
    exit 0
else
    echo "[!] Server header does not expose expected version information"
    exit 1
fi