#!/bin/bash

# POC: Verify Missing Content-Security-Policy Header
# This script checks multiple endpoints for the absence of CSP headers

TARGET="${1:-http://localhost:8081}"
ENDPOINTS=(
    "/accounts/login/"
    "/accounts/register/"
    "/accounts/"
)

echo "=========================================="
echo "CSP Header Detection POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

CSP_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Checking endpoint: $TARGET$endpoint"
    echo "---"
    
    # Get full headers
    RESPONSE=$(curl -s -i "$TARGET$endpoint" 2>&1)
    
    # Check for Content-Security-Policy header (case-insensitive)
    if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
        echo "✓ CSP Header FOUND"
        echo "$RESPONSE" | grep -i "^Content-Security-Policy:"
        CSP_FOUND=1
    else
        echo "✗ CSP Header NOT FOUND"
        
        # Verify other security headers are present (to confirm we're getting headers)
        echo ""
        echo "Other security headers present:"
        if echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
            echo "  ✓ X-Frame-Options: $(echo "$RESPONSE" | grep -i "^X-Frame-Options:" | head -1)"
        fi
        if echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
            echo "  ✓ X-Content-Type-Options: $(echo "$RESPONSE" | grep -i "^X-Content-Type-Options:" | head -1)"
        fi
        if echo "$RESPONSE" | grep -qi "^Referrer-Policy:"; then
            echo "  ✓ Referrer-Policy: $(echo "$RESPONSE" | grep -i "^Referrer-Policy:" | head -1)"
        fi
    fi
    echo ""
done

echo "=========================================="
echo "SUMMARY"
echo "=========================================="
if [ $CSP_FOUND -eq 0 ]; then
    echo "RESULT: Content-Security-Policy header is MISSING from all tested endpoints"
    echo "RISK: Application is vulnerable to XSS attacks without CSP defense-in-depth"
    exit 0  # CSP missing is what we're testing for
else
    echo "RESULT: Content-Security-Policy header is present on at least one endpoint"
    exit 1
fi