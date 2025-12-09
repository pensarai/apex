#!/bin/bash

# POC: Server Banner Information Disclosure
# Demonstrates that the Server header exposes Werkzeug and Python version information
# This allows attackers to identify the framework and search for known vulnerabilities

TARGET="${1:-http://localhost:5003}"
ENDPOINTS=("/" "/login" "/dashboard" "/api/users")

echo "=========================================="
echo "Server Banner Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

BANNER_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET$endpoint"
    echo "---"
    
    # Perform HEAD request to get headers
    RESPONSE=$(curl -s -I -X HEAD "$TARGET$endpoint" 2>/dev/null)
    
    # Extract Server header
    SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2- | tr -d '\r')
    
    if [ -z "$SERVER_HEADER" ]; then
        # Try GET request if HEAD doesn't work
        RESPONSE=$(curl -s -i -X GET "$TARGET$endpoint" 2>/dev/null | head -20)
        SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2- | tr -d '\r')
    fi
    
    if [ ! -z "$SERVER_HEADER" ]; then
        echo "Server Header Found: $SERVER_HEADER"
        
        # Check if it contains Werkzeug
        if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
            echo "⚠️  VULNERABILITY: Werkzeug version exposed"
            BANNER_FOUND=1
        fi
        
        # Check if it contains Python
        if echo "$SERVER_HEADER" | grep -qi "python"; then
            echo "⚠️  VULNERABILITY: Python version exposed"
            BANNER_FOUND=1
        fi
    else
        echo "No Server header found"
    fi
    
    echo ""
done

echo "=========================================="
if [ $BANNER_FOUND -eq 1 ]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo "Server banner information is being disclosed"
    exit 0
else
    echo "✗ No banner information disclosure detected"
    exit 1
fi