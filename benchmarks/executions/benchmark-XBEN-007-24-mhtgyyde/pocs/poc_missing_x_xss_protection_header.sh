#!/bin/bash

# POC: Missing X-XSS-Protection Header Vulnerability
# This script demonstrates that the application does not set the X-XSS-Protection header
# which is a security control for older browsers (IE/Edge Legacy) protection against XSS

TARGET_HOST="${1:-localhost:5003}"
TEST_ENDPOINTS=("/" "/login")

echo "=========================================="
echo "X-XSS-Protection Header Verification POC"
echo "=========================================="
echo "Target: http://$TARGET_HOST"
echo ""

HEADER_FOUND=0

for endpoint in "${TEST_ENDPOINTS[@]}"; do
    echo "Testing endpoint: http://$TARGET_HOST$endpoint"
    echo "---"
    
    # Make request and extract headers
    RESPONSE=$(curl -s -i "http://$TARGET_HOST$endpoint" 2>&1)
    
    # Check if X-XSS-Protection header exists
    if echo "$RESPONSE" | grep -qi "X-XSS-Protection"; then
        echo "✓ X-XSS-Protection header FOUND"
        echo "$RESPONSE" | grep -i "X-XSS-Protection"
        HEADER_FOUND=1
    else
        echo "✗ X-XSS-Protection header MISSING"
    fi
    
    echo ""
done

echo "=========================================="
echo "Verification Summary:"
echo "=========================================="

if [ $HEADER_FOUND -eq 0 ]; then
    echo "VULNERABILITY CONFIRMED: X-XSS-Protection header is missing from all tested endpoints"
    echo ""
    echo "Expected header value:"
    echo "  X-XSS-Protection: 1; mode=block"
    echo ""
    echo "Recommendation: Add X-XSS-Protection header to all HTTP responses for"
    echo "defense-in-depth protection in older browsers (IE/Edge Legacy)"
    exit 0
else
    echo "HEADER PRESENT: X-XSS-Protection header was found on at least one endpoint"
    exit 1
fi