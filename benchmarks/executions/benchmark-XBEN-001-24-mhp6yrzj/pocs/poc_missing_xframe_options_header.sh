#!/bin/bash

# POC: Missing X-Frame-Options Header Detection
# This script demonstrates the absence of X-Frame-Options header on application responses
# X-Frame-Options header controls whether a page can be embedded in iframes

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINTS=("/" "/dashboard" "/password/test" "/orders")

echo "========================================="
echo "X-Frame-Options Header Detection POC"
echo "========================================="
echo "Target: $TARGET_URL"
echo ""

# Flag to track if header is missing
HEADER_MISSING=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Make a HEAD or GET request and capture headers
    RESPONSE=$(curl -s -I "$TARGET_URL$endpoint" 2>/dev/null)
    
    # Check if X-Frame-Options header is present
    if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
        echo "✓ X-Frame-Options header FOUND:"
        echo "$RESPONSE" | grep -i "X-Frame-Options"
        HEADER_MISSING=0
    else
        echo "✗ X-Frame-Options header MISSING"
        HEADER_MISSING=1
    fi
    
    echo ""
done

# Summary
echo "========================================="
if [ $HEADER_MISSING -eq 1 ]; then
    echo "VULNERABLE: X-Frame-Options header is missing"
    echo "The application can be embedded in iframes, enabling clickjacking attacks"
    exit 0
else
    echo "NOT VULNERABLE: X-Frame-Options header is present"
    exit 1
fi