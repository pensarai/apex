#!/bin/bash

# POC: Server Header Information Disclosure
# This script demonstrates how the Server header reveals detailed server information
# allowing attackers to identify specific versions for targeted exploitation

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "========================================"
echo "Server Header Information Disclosure POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Test multiple endpoints to show consistent header disclosure
ENDPOINTS=("/" "/index.html" "/styles.css" "/scripts.js" "/dev1.jpeg")

echo "[*] Testing Server header on multiple endpoints..."
echo ""

DISCLOSURE_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing: $TARGET_URL$endpoint"
    
    # Make request and extract Server header
    server_header=$(curl -s -i "$TARGET_URL$endpoint" 2>/dev/null | grep -i "^Server:" | tr -d '\r')
    
    if [ -z "$server_header" ]; then
        echo "    ❌ No Server header found"
    else
        echo "    ✓ $server_header"
        
        # Check if it reveals sensitive information
        if echo "$server_header" | grep -qiE "Python|SimpleHTTP"; then
            echo "    ⚠️  VULNERABILITY: Header reveals Python version and HTTP server type"
            DISCLOSURE_FOUND=1
        fi
    fi
    echo ""
done

echo "========================================"
echo "Analysis:"
echo "========================================"

if [ $DISCLOSURE_FOUND -eq 1 ]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo ""
    echo "The Server header discloses:"
    curl -s -i "$TARGET_URL/" 2>/dev/null | grep -i "^Server:" | while read -r line; do
        echo "  • $line" | sed 's/Server: //'
        
        # Extract and explain disclosed information
        if echo "$line" | grep -qi "SimpleHTTP"; then
            echo "    - Server Type: SimpleHTTP (Python's built-in HTTP server)"
        fi
        if echo "$line" | grep -qiE "Python/[0-9.]+"; then
            version=$(echo "$line" | grep -oiE "Python/[0-9.]+" | cut -d'/' -f2)
            echo "    - Python Version: $version"
        fi
    done
    
    echo ""
    echo "Security Impact:"
    echo "  1. Attackers can identify SimpleHTTP as the server software"
    echo "  2. Known CVEs for SimpleHTTP/0.6 can be researched and exploited"
    echo "  3. Python 3.13.3 specific vulnerabilities could be targeted"
    echo "  4. Assists in reconnaissance and attack planning"
    
    exit 0
else
    echo "✗ VULNERABILITY NOT FOUND"
    echo "Server header is either missing or does not disclose sensitive information"
    exit 1
fi