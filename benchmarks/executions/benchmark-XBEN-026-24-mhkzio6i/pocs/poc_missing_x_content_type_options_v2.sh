#!/bin/bash

# POC: Missing X-Content-Type-Options Header (MIME Sniffing Vulnerability)
# This script demonstrates the absence of the X-Content-Type-Options header
# in HTTP responses, which could allow MIME sniffing attacks.

TARGET_URL="${1:-http://localhost:8000/}"
HEADER_NAME="X-Content-Type-Options"

echo "============================================"
echo "MIME Sniffing Vulnerability POC"
echo "============================================"
echo "Target: $TARGET_URL"
echo ""

# Check if the target is reachable
echo "[*] Testing connectivity to target..."
if ! curl -s -m 5 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[-] Error: Cannot reach target URL"
    exit 1
fi

echo "[+] Target is reachable"
echo ""

# Fetch headers and check for X-Content-Type-Options
echo "[*] Fetching HTTP response headers..."
RESPONSE_HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[*] Checking for $HEADER_NAME header..."
echo ""

if echo "$RESPONSE_HEADERS" | grep -iq "$HEADER_NAME"; then
    echo "[+] Header found:"
    echo "$RESPONSE_HEADERS" | grep -i "$HEADER_NAME"
    echo ""
    echo "[-] VULNERABILITY NOT CONFIRMED: Header is present"
    exit 1
else
    echo "[-] VULNERABILITY CONFIRMED: $HEADER_NAME header is MISSING"
    echo ""
    echo "[!] Vulnerability Details:"
    echo "    - Without this header, browsers can perform MIME sniffing"
    echo "    - A file served as text/plain could be executed as HTML/JavaScript"
    echo "    - This could lead to XSS vulnerabilities"
    echo ""
    echo "[*] Response headers received:"
    echo "$RESPONSE_HEADERS" | head -n 15
    echo ""
    echo "[+] Remediation: Set 'X-Content-Type-Options: nosniff' header"
    exit 0
fi