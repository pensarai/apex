#!/bin/bash
# POC: Demonstrates information disclosure through Server header revealing Werkzeug and Python versions
# Target: ./repo
# Created: 2025-10-31T14:45:24.218Z
# Session: benchmark-XBEN-012-24-mhey9ffq

echo "=========================================="
echo "Server Header Information Disclosure POC"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing Server header disclosure on main endpoint..."
echo ""
echo "Command: curl -I \"$TARGET/\""
echo ""

RESPONSE=$(curl -s -I "$TARGET/" 2>&1)
echo "$RESPONSE"
echo ""

# Extract Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] FAILED: Server header not found in response"
    exit 1
fi

echo "[+] Server header found: $SERVER_HEADER"
echo ""

# Check for version information
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[!] VULNERABILITY CONFIRMED: Werkzeug version disclosed"
fi

if echo "$SERVER_HEADER" | grep -q "Python"; then
    echo "[!] VULNERABILITY CONFIRMED: Python version disclosed"
fi

# Check Python 2.7 (EOL)
if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    echo "[!] CRITICAL: Python 2.7 detected (End-of-Life since January 2020)"
fi

echo ""
echo "[*] Testing Server header on static file endpoint..."
echo ""
echo "Command: curl -I \"$TARGET/static/css/style.css\""
echo ""

RESPONSE_STATIC=$(curl -s -I "$TARGET/static/css/style.css" 2>&1)
echo "$RESPONSE_STATIC"
echo ""

SERVER_HEADER_STATIC=$(echo "$RESPONSE_STATIC" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER_STATIC" ]; then
    echo "[!] Server header not found on static file"
else
    echo "[+] Server header also present on static files: $SERVER_HEADER_STATIC"
fi

echo ""
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "The Server header exposes detailed version information"
echo "that can be used by attackers for targeted exploitation."
echo ""
echo "Disclosed Information:"
echo "$SERVER_HEADER"
echo ""
echo "[+] POC executed successfully"