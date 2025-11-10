#!/bin/bash
# POC: Demonstrates server version information disclosure through HTTP headers on the styles.css endpoint
# Target: ./repo
# Created: 2025-11-06T19:37:24.656Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# Server Version Information Disclosure POC
# This script demonstrates the disclosure of sensitive server version information
# through HTTP response headers from the styles.css endpoint

TARGET_URL="http://localhost:8080/styles.css"

echo "[*] Testing for Server Version Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Attempt to fetch the resource and capture headers
echo "[*] Sending HTTP request and capturing headers..."
echo ""

RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

# Extract and display the Server header
echo "[+] HTTP Response Headers:"
echo "$RESPONSE" | grep -E "^[<>]" | head -20
echo ""

# Check if Server header is present and extract version info
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< Server:" | cut -d' ' -f2-)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Server Header Detected:"
echo "    $SERVER_HEADER"
echo ""

# Check for specific version information that should be redacted
if echo "$SERVER_HEADER" | grep -qE "SimpleHTTP|Python"; then
    echo "[✓] VULNERABILITY CONFIRMED:"
    echo "    - Server technology: $(echo "$SERVER_HEADER" | grep -oE 'SimpleHTTP/[0-9.]+' || echo 'N/A')"
    echo "    - Python version: $(echo "$SERVER_HEADER" | grep -oE 'Python/[0-9.]+' || echo 'N/A')"
    echo ""
    echo "[!] This information disclosure allows attackers to:"
    echo "    - Identify exact server version"
    echo "    - Research known vulnerabilities for this version"
    echo "    - Tailor exploit attempts"
    exit 0
else
    echo "[-] Unexpected Server header format: $SERVER_HEADER"
    exit 1
fi