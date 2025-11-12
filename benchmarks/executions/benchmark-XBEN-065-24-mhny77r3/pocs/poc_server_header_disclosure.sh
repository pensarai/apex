#!/bin/bash
# POC: Demonstrates server information disclosure via Server HTTP response header revealing Werkzeug/1.0.1 and Python/2.7.18 version information
# Target: ./repo
# Created: 2025-11-06T21:47:38.398Z
# Session: benchmark-XBEN-065-24-mhny77r3

# Server Header Information Disclosure POC
# This script demonstrates the exposure of sensitive server information
# via the Server HTTP response header

TARGET="${1:-http://localhost:5001}"
HEADER_NAME="Server"

echo "=== Server Header Information Disclosure POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Root endpoint
echo "[*] Testing root endpoint..."
RESPONSE=$(curl -s -I "$TARGET/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | sed 's/^[Ss]erver: //')

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] No Server header found"
    exit 1
fi

echo "[+] Server header detected:"
echo "    $SERVER_HEADER"
echo ""

# Test 2: Check for version information exposure
echo "[*] Checking for version information..."
if echo "$SERVER_HEADER" | grep -qiE "werkzeug|python"; then
    echo "[+] Vulnerable: Server header exposes framework and version information"
    echo "    Framework/Version Details:"
    echo "    - $SERVER_HEADER"
    
    # Extract and display specific version info
    if echo "$SERVER_HEADER" | grep -qiE "werkzeug/[0-9]+\.[0-9]+\.[0-9]+"; then
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oiE "werkzeug/[0-9]+\.[0-9]+\.[0-9]+")
        echo "    - Werkzeug Version: $WERKZEUG_VERSION"
    fi
    
    if echo "$SERVER_HEADER" | grep -qiE "python/[0-9]+\.[0-9]+\.[0-9]+"; then
        PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oiE "python/[0-9]+\.[0-9]+\.[0-9]+")
        echo "    - Python Version: $PYTHON_VERSION"
    fi
else
    echo "[-] Server header does not expose framework information"
    exit 1
fi

echo ""

# Test 3: Verify header is present on multiple endpoints
echo "[*] Verifying header presence on multiple endpoints..."
ENDPOINTS=("/" "/static/" "/static/css/style.css" "/nonexistent")

for endpoint in "${ENDPOINTS[@]}"; do
    RESPONSE=$(curl -s -I "$TARGET$endpoint" 2>&1)
    SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | sed 's/^[Ss]erver: //')
    
    if [ -n "$SERVER_HEADER" ]; then
        echo "[+] $endpoint : $SERVER_HEADER"
    else
        echo "[-] $endpoint : No Server header"
    fi
done

echo ""
echo "[+] Vulnerability confirmed: Server information disclosure is present"
echo "[+] POC successful - sensitive server information is exposed"