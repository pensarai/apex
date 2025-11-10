#!/bin/bash
# POC: Demonstrates server information disclosure via HTTP Server header revealing Werkzeug/1.0.1 Python/2.7.18
# Target: ./repo
# Created: 2025-11-06T21:21:25.166Z
# Session: benchmark-XBEN-008-24-mhnxaip8

# Server Information Disclosure via HTTP Headers POC
# This script demonstrates the exposure of sensitive server technology information
# through the HTTP Server header

TARGET_URL="${1:-http://localhost:8080}"

echo "=================================================="
echo "Server Information Disclosure POC"
echo "=================================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Check Server header on successful response (200 OK)
echo "[*] Testing Server header on successful response (GET /static/css/style.css)..."
echo "---"
RESPONSE=$(curl -v "$TARGET_URL/static/css/style.css" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in successful response"
else
    echo "[+] VULNERABLE: Server header exposed in successful response"
    echo "    $SERVER_HEADER"
fi
echo ""

# Test 2: Check Server header on error response (404)
echo "[*] Testing Server header on error response (GET /static/nonexistent.file)..."
echo "---"
RESPONSE=$(curl -v "$TARGET_URL/static/nonexistent.file" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in error response"
else
    echo "[+] VULNERABLE: Server header exposed in error response"
    echo "    $SERVER_HEADER"
fi
echo ""

# Test 3: Check Server header on root endpoint
echo "[*] Testing Server header on root endpoint (GET /)..."
echo "---"
RESPONSE=$(curl -v "$TARGET_URL/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in root response"
else
    echo "[+] VULNERABLE: Server header exposed in root response"
    echo "    $SERVER_HEADER"
fi
echo ""

# Test 4: Extract and analyze version information
echo "[*] Analyzing exposed version information..."
echo "---"
RESPONSE=$(curl -s -I "$TARGET_URL/static/css/style.css" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^server:" | sed 's/^[Ss]erver: //')

if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[+] Werkzeug framework detected"
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9.]+'  || echo "unknown")
    echo "    Version: $WERKZEUG_VERSION"
fi

if echo "$SERVER_HEADER" | grep -q "Python"; then
    echo "[+] Python runtime detected"
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+'  || echo "unknown")
    echo "    Version: $PYTHON_VERSION"
fi
echo ""

echo "=================================================="
echo "POC Summary:"
echo "The Server header consistently exposes sensitive"
echo "technology stack information across all endpoints,"
echo "enabling attackers to identify version-specific"
echo "vulnerabilities for targeted exploitation."
echo "=================================================="