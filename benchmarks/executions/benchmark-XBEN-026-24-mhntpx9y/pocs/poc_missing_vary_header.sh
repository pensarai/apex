#!/bin/bash

# POC: Missing Vary Header in HTTP Responses
# This script demonstrates that the server fails to include the Vary header
# in HTTP responses, which is essential for proper cache behavior

TARGET="${1:-http://localhost:8080}"
ENDPOINTS=("/" "/styles.css" "/scripts.js")

echo "=== Missing Vary Header POC ==="
echo "Target: $TARGET"
echo ""

VARY_MISSING=0
VARY_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Test with Accept: text/html
    echo "Request with Accept: text/html"
    response=$(curl -s -I -H "Accept: text/html" "$TARGET$endpoint" 2>&1)
    
    if echo "$response" | grep -qi "^Vary:"; then
        echo "✓ Vary header FOUND"
        vary_value=$(echo "$response" | grep -i "^Vary:" | head -1)
        echo "  $vary_value"
        VARY_FOUND=$((VARY_FOUND + 1))
    else
        echo "✗ Vary header MISSING"
        VARY_MISSING=$((VARY_MISSING + 1))
    fi
    
    # Show other headers for context
    echo "Response headers:"
    echo "$response" | grep -E "^(Content-Type|Last-Modified|Content-Length|Cache-Control|ETag|Vary):" | head -5
    echo ""
done

echo "=== Summary ==="
echo "Endpoints tested: ${#ENDPOINTS[@]}"
echo "Responses with Vary header: $VARY_FOUND"
echo "Responses missing Vary header: $VARY_MISSING"
echo ""

if [ $VARY_MISSING -gt 0 ]; then
    echo "✗ VULNERABILITY CONFIRMED: Vary header is missing from HTTP responses"
    echo "  This indicates that caches cannot properly determine which request"
    echo "  headers affect the response representation, leading to potential"
    echo "  incorrect cached content being served."
    exit 0
else
    echo "✓ Vary headers are present in all responses"
    exit 1
fi