#!/bin/bash

# POC: HTTP Header Information Disclosure
# Demonstrates how Server header exposes Werkzeug and Python versions
# and how Allow header exposes HTTP methods

TARGET="${1:-http://localhost}"
ENDPOINT="${2:-/static/style.css}"

echo "[*] Testing Server Header Information Disclosure"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Test 1: Get Server header from static file
echo "[+] Test 1: Retrieving Server header from static file..."
RESPONSE=$(curl -s -I "$TARGET$ENDPOINT")
echo "$RESPONSE"
echo ""

# Extract and analyze Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)
if [ -n "$SERVER_HEADER" ]; then
    echo "[!] VULNERABLE: Server header disclosed: $SERVER_HEADER"
    
    # Check if version info is present
    if echo "$SERVER_HEADER" | grep -qE "Werkzeug|Python"; then
        echo "[!] CRITICAL: Version information exposed (Werkzeug/Python)"
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Werkzeug/\K[0-9.]+")
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Python/\K[0-9.]+")
        [ -n "$WERKZEUG_VERSION" ] && echo "    - Werkzeug version: $WERKZEUG_VERSION"
        [ -n "$PYTHON_VERSION" ] && echo "    - Python version: $PYTHON_VERSION"
    fi
else
    echo "[-] Server header not found (potential mitigation in place)"
fi
echo ""

# Test 2: OPTIONS method to check Allow header
echo "[+] Test 2: OPTIONS request to check Allow header..."
OPTIONS_RESPONSE=$(curl -s -I -X OPTIONS "$TARGET/")
echo "$OPTIONS_RESPONSE"
echo ""

# Extract and analyze Allow header
ALLOW_HEADER=$(echo "$OPTIONS_RESPONSE" | grep -i "^Allow:" | cut -d' ' -f2-)
if [ -n "$ALLOW_HEADER" ]; then
    echo "[!] VULNERABLE: Allow header disclosed: $ALLOW_HEADER"
    echo "[!] Exposed HTTP methods enable method enumeration attacks"
else
    echo "[-] Allow header not found (OPTIONS may be disabled)"
fi
echo ""

# Test 3: Check for version disclosure on other endpoints
echo "[+] Test 3: Checking version disclosure on main endpoint..."
MAIN_RESPONSE=$(curl -s -I "$TARGET/")
echo "$MAIN_RESPONSE" | head -n 15
echo ""

# Summary
echo "[+] Information Disclosure Summary:"
if [ -n "$SERVER_HEADER" ]; then
    echo "    [!] Server header exposes: $SERVER_HEADER"
fi
if [ -n "$ALLOW_HEADER" ]; then
    echo "    [!] Allow header exposes methods: $ALLOW_HEADER"
fi

# Check if vulnerable
if echo "$SERVER_HEADER" | grep -qE "Werkzeug|Python" || [ -n "$ALLOW_HEADER" ]; then
    echo ""
    echo "[!] Application is VULNERABLE to HTTP header-based information disclosure"
    exit 0
else
    echo ""
    echo "[-] No obvious information disclosure detected"
    exit 1
fi