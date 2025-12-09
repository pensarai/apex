#!/bin/bash

# POC: Information Disclosure Through Server and Framework Headers
# This script demonstrates the exposure of sensitive technology stack information
# through HTTP response headers on the vulnerable application

TARGET_URL="${1:-http://localhost:5000}"

echo "=========================================="
echo "Information Disclosure POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test multiple endpoints to show consistent header disclosure
ENDPOINTS=("/" "/list" "/add" "/about")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing endpoint: $endpoint"
    echo "---"
    
    response=$(curl -s -i "$TARGET_URL$endpoint" 2>&1)
    
    # Extract Server header
    server_header=$(echo "$response" | grep -i "^Server:" | head -1)
    if [ -n "$server_header" ]; then
        echo "✓ VULNERABLE: $server_header"
    fi
    
    # Extract X-Powered-By header
    powered_by_header=$(echo "$response" | grep -i "^X-Powered-By:" | head -1)
    if [ -n "$powered_by_header" ]; then
        echo "✓ VULNERABLE: $powered_by_header"
    fi
    
    # Extract Powered-By header (alternate naming)
    powered_by_alt=$(echo "$response" | grep -i "^Powered-By:" | head -1)
    if [ -n "$powered_by_alt" ]; then
        echo "✓ VULNERABLE: $powered_by_alt"
    fi
    
    echo ""
done

echo "=========================================="
echo "Analysis:"
echo "=========================================="
echo "The Server header reveals:"
echo "  - Framework: Werkzeug"
echo "  - Framework Version: 3.1.3"
echo "  - Programming Language: Python"
echo "  - Language Version: 3.13.3"
echo ""
echo "The Powered-By header reveals:"
echo "  - Web Framework: Flask"
echo ""
echo "This information allows attackers to:"
echo "  1. Identify specific framework versions"
echo "  2. Research known CVEs for these versions"
echo "  3. Craft targeted exploits"
echo "  4. Plan reconnaissance more effectively"
echo ""
echo "RECOMMENDATION: Remove or obfuscate these headers"
echo "=========================================="