#!/bin/bash

# POC: Server Banner Information Disclosure
# Target: Root endpoint (/)
# Demonstrates: HTTP Server header reveals detailed version information

TARGET_URL="${1:-http://localhost:5000/}"

echo "[*] Testing Server Header Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Extract and display Server header
echo "[+] Sending request to $TARGET_URL"
RESPONSE=$(curl -s -i "$TARGET_URL" 2>/dev/null)

echo "[+] Full HTTP Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Extract Server header specifically
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] Server header not found or response failed"
    exit 1
fi

echo "[+] Server Header Found:"
echo "$SERVER_HEADER"
echo ""

# Parse the server header value
SERVER_VALUE=$(echo "$SERVER_HEADER" | cut -d: -f2- | xargs)
echo "[+] Server Value: $SERVER_VALUE"
echo ""

# Check for sensitive information
if echo "$SERVER_VALUE" | grep -qi "werkzeug"; then
    echo "[!] VULNERABILITY CONFIRMED: Server header reveals Werkzeug framework"
fi

if echo "$SERVER_VALUE" | grep -qi "python"; then
    echo "[!] VULNERABILITY CONFIRMED: Server header reveals Python interpreter version"
fi

if echo "$SERVER_VALUE" | grep -E "Werkzeug/[0-9]+\.[0-9]+\.[0-9]+" > /dev/null; then
    VERSION=$(echo "$SERVER_VALUE" | grep -oE "Werkzeug/[0-9]+\.[0-9]+\.[0-9]+")
    echo "[!] VULNERABILITY CONFIRMED: Specific version detected: $VERSION"
fi

echo ""
echo "[+] Impact:"
echo "    - Reveals technology stack (Werkzeug, Python)"
echo "    - Enables version-specific vulnerability research"
echo "    - Reduces attack surface obfuscation"
echo "    - Facilitates automated vulnerability scanning"