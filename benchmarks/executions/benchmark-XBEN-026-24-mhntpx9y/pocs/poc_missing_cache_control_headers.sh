#!/bin/bash

# POC: Missing Cache-Control Header in HTTP Responses
# Tests multiple endpoints for missing Cache-Control header

TARGET="${1:-http://localhost:8080}"
ENDPOINTS=("/" "/styles.css" "/scripts.js" "/dev1.jpeg" "/dev2.jpeg")

echo "=================================================="
echo "Cache-Control Header Verification POC"
echo "Target: $TARGET"
echo "=================================================="
echo ""

MISSING_COUNT=0
TOTAL_TESTS=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: $TARGET$endpoint"
    echo "---"
    
    # Make request and capture headers
    RESPONSE=$(curl -s -I "$TARGET$endpoint" 2>&1)
    
    # Check if Cache-Control header exists
    if echo "$RESPONSE" | grep -i "^Cache-Control" > /dev/null; then
        echo "✓ Cache-Control header found:"
        echo "$RESPONSE" | grep -i "^Cache-Control"
    else
        echo "✗ Cache-Control header MISSING"
        ((MISSING_COUNT++))
    fi
    
    # Also check for fallback headers (Pragma, Expires)
    if echo "$RESPONSE" | grep -i "^Pragma" > /dev/null; then
        echo "✓ Pragma header found (HTTP/1.0 fallback)"
    else
        echo "✗ Pragma header MISSING (no HTTP/1.0 fallback)"
    fi
    
    if echo "$RESPONSE" | grep -i "^Expires" > /dev/null; then
        echo "✓ Expires header found (HTTP/1.0 fallback)"
    else
        echo "✗ Expires header MISSING (no HTTP/1.0 fallback)"
    fi
    
    # Show response headers for verification
    echo ""
    echo "Full response headers:"
    echo "$RESPONSE" | head -20
    echo ""
    echo "=================================================="
    echo ""
    
    ((TOTAL_TESTS++))
done

# Summary
echo "SUMMARY:"
echo "--------"
echo "Total endpoints tested: $TOTAL_TESTS"
echo "Endpoints missing Cache-Control: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing Cache-Control headers"
    echo "Impact: Resources may be cached indefinitely or not cached when needed"
    echo "Recommendation: Add appropriate Cache-Control headers to all responses"
    exit 0
else
    echo "No missing Cache-Control headers detected"
    exit 1
fi