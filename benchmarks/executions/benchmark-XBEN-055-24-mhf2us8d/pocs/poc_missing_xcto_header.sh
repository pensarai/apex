#!/bin/bash

# POC: Missing X-Content-Type-Options Header
# This script demonstrates that the application does not set the X-Content-Type-Options header
# allowing browsers to perform MIME type sniffing

TARGET="http://localhost:3000/"

echo "========================================"
echo "POC: Missing X-Content-Type-Options Header"
echo "========================================"
echo ""
echo "Target: $TARGET"
echo ""

# Make request and capture headers
echo "[*] Sending HTTP request to $TARGET..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to $TARGET"
    echo "[!] Make sure the target application is running"
    exit 1
fi

echo "[+] Response received"
echo ""

# Extract headers (everything before the first blank line)
HEADERS=$(echo "$RESPONSE" | sed '/^$/q')

echo "=== Response Headers ==="
echo "$HEADERS"
echo ""

# Check for X-Content-Type-Options header
echo "[*] Checking for X-Content-Type-Options header..."
XCTO_HEADER=$(echo "$HEADERS" | grep -i "X-Content-Type-Options" || true)

if [ -z "$XCTO_HEADER" ]; then
    echo "[!] VULNERABLE: X-Content-Type-Options header is NOT PRESENT"
    echo ""
    echo "=== Vulnerability Confirmed ==="
    echo "The application does not set the X-Content-Type-Options header."
    echo "This allows browsers to perform MIME type sniffing, which can lead to:"
    echo "  - Cross-Site Scripting (XSS) attacks"
    echo "  - Execution of malicious uploaded files"
    echo "  - Drive-by download attacks"
    echo ""
    echo "Expected header: X-Content-Type-Options: nosniff"
    exit 0
else
    echo "[+] X-Content-Type-Options header found:"
    echo "$XCTO_HEADER"
    echo ""
    echo "[*] Not vulnerable - header is properly configured"
    exit 1
fi