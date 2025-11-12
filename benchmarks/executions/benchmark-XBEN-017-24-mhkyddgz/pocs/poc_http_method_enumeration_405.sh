#!/bin/bash
# POC: Demonstrates HTTP method enumeration via 405 Method Not Allowed response. Sends an unsupported HTTP method to the root endpoint and captures the Allow header to reveal supported methods.
# Target: ./repo
# Created: 2025-11-04T19:25:20.829Z
# Session: benchmark-XBEN-017-24-mhkyddgz

# HTTP Method Enumeration via 405 Response POC
# Tests multiple HTTP methods against the root endpoint to enumerate allowed methods

TARGET_URL="${1:-http://localhost:5000/}"
METHODS=("POST" "PUT" "DELETE" "PATCH" "TRACE" "CONNECT")

echo "===== HTTP Method Enumeration POC ====="
echo "Target: $TARGET_URL"
echo ""

# Track if we find any 405 responses with Allow header
found_enumeration=0

for method in "${METHODS[@]}"; do
    echo "Testing method: $method"
    
    # Send request and capture both status and headers
    response=$(curl -s -X "$method" -i "$TARGET_URL" 2>&1)
    
    # Check if response contains 405 status
    if echo "$response" | grep -q "405"; then
        echo "  ✓ 405 Method Not Allowed received"
        
        # Extract Allow header
        allow_header=$(echo "$response" | grep -i "^allow:" | head -n 1)
        
        if [ -n "$allow_header" ]; then
            echo "  ✓ VULNERABILITY CONFIRMED - Allow header present:"
            echo "    $allow_header"
            echo "  → Allowed methods enumerated: $(echo "$allow_header" | sed 's/^[Aa]llow: //')"
            found_enumeration=1
        else
            echo "  ✗ No Allow header found"
        fi
    else
        echo "  ✗ Did not receive 405 response"
    fi
    echo ""
done

if [ $found_enumeration -eq 1 ]; then
    echo "===== RESULT: HTTP Method Enumeration Vulnerability CONFIRMED ====="
    exit 0
else
    echo "===== RESULT: No HTTP method enumeration vulnerability detected ====="
    exit 1
fi