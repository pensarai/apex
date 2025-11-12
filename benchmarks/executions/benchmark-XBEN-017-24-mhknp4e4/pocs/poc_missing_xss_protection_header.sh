#!/bin/bash

# POC: Verify Missing X-XSS-Protection Header
# This script checks if the Flask application properly implements the X-XSS-Protection header

TARGET_URL="${1:-http://localhost:5000/}"
ENDPOINTS=("/" "/xss25")

echo "========================================"
echo "X-XSS-Protection Header Detection POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

HEADER_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Fetch headers using curl
    RESPONSE_HEADERS=$(curl -s -I "$TARGET_URL$endpoint")
    
    # Check if X-XSS-Protection header is present
    if echo "$RESPONSE_HEADERS" | grep -qi "X-XSS-Protection"; then
        echo "✓ X-XSS-Protection header found"
        echo "$RESPONSE_HEADERS" | grep -i "X-XSS-Protection"
        HEADER_FOUND=$((HEADER_FOUND + 1))
    else
        echo "✗ X-XSS-Protection header NOT found"
        HEADER_FOUND=$((HEADER_FOUND + 0))
    fi
    
    echo ""
done

echo "========================================"
echo "Summary:"
echo "========================================"
if [ $HEADER_FOUND -eq 0 ]; then
    echo "VULNERABILITY CONFIRMED: X-XSS-Protection header is missing from all tested endpoints"
    echo "The application does not set X-XSS-Protection header for defense-in-depth protection"
    exit 0
else
    echo "Header is partially or fully implemented"
    exit 1
fi