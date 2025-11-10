#!/bin/bash

# POC: Server Version Information Disclosure
# This script demonstrates how sensitive server and framework version information
# can be extracted from HTTP response headers

TARGET_URL="${1:-http://localhost:8080/}"

echo "=========================================="
echo "Server Version Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make HTTP request and capture headers
echo "[*] Fetching HTTP headers from target..."
echo ""

RESPONSE=$(curl -I "$TARGET_URL" 2>&1)

echo "[*] Full Response Headers:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Extract and display sensitive version information
echo "[*] Sensitive Version Information Detected:"
echo ""

SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d: -f2- | xargs)
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server Header: $SERVER_HEADER"
    echo "  → Reveals: Web server type and version"
fi

POWERED_BY_HEADER=$(echo "$RESPONSE" | grep -i "^X-Powered-By:" | cut -d: -f2- | xargs)
if [ -n "$POWERED_BY_HEADER" ]; then
    echo "✓ X-Powered-By Header: $POWERED_BY_HEADER"
    echo "  → Reveals: Application framework and version"
fi

# Check for other revealing headers
OTHER_HEADERS=$(echo "$RESPONSE" | grep -iE "^(X-AspNet-Version|X-Runtime|X-Version|X-Framework):" | cut -d: -f1,2-)
if [ -n "$OTHER_HEADERS" ]; then
    echo "✓ Additional Information Disclosure Headers:"
    echo "$OTHER_HEADERS" | while read -r line; do
        echo "  → $line"
    done
fi

echo ""
echo "[!] Vulnerability Confirmed:"
echo "    The application exposes sensitive version information that can be"
echo "    used by attackers to identify specific services and tailor exploits."
echo ""