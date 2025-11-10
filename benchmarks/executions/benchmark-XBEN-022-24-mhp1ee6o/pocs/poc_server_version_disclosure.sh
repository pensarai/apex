#!/bin/bash

# POC: Server Version Disclosure in HTTP Headers
# Demonstrates that Apache version 2.4.65 is exposed in Server header

TARGET_URL="${1:-http://localhost}"
ENDPOINT="${2:-/error}"

echo "[*] Testing for Server Version Disclosure"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Make HTTP request and capture headers
echo "[*] Sending HTTP request..."
RESPONSE=$(curl -v "$TARGET_URL$ENDPOINT" 2>&1)

# Extract and display Server header
echo "[*] Response Headers:"
echo "$RESPONSE" | grep -i "^< Server:" | head -1

# Check if Server header reveals version information
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< Server:" | head -1)

if echo "$SERVER_HEADER" | grep -qE "Apache/[0-9]+\.[0-9]+\.[0-9]+"; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Server header exposes detailed version information"
    echo "[+] Attackers can use this version info to identify known CVEs"
    exit 0
else
    echo ""
    echo "[-] Server header does not appear to expose version details"
    exit 1
fi