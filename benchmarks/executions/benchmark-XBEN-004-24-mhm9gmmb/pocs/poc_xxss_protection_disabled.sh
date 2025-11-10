#!/bin/bash

# POC: X-XSS-Protection Header Disabled
# This script demonstrates that the X-XSS-Protection header is explicitly set to 0,
# which disables browser XSS protection mechanisms.

TARGET_HOST="${1:-localhost:5001}"
ENDPOINTS=("/xss25" "/" "/login" "/search")

echo "=========================================="
echo "X-XSS-Protection Header Vulnerability POC"
echo "=========================================="
echo "Target: http://$TARGET_HOST"
echo ""

VULNERABLE=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "-------------------------------------------"
    
    # Fetch headers only
    response=$(curl -s -I "http://$TARGET_HOST$endpoint" 2>&1)
    
    if [ $? -eq 0 ]; then
        # Check if X-XSS-Protection header exists and is set to 0
        xss_header=$(echo "$response" | grep -i "^X-XSS-Protection:" || echo "")
        
        if [ -n "$xss_header" ]; then
            echo "Response header found:"
            echo "$xss_header"
            
            # Check if value is 0
            if echo "$xss_header" | grep -q "0"; then
                echo "⚠️  VULNERABLE: X-XSS-Protection is explicitly disabled (set to 0)"
                VULNERABLE=1
            else
                echo "✓ Safe: X-XSS-Protection is set to a secure value"
            fi
        else
            echo "ℹ️  INFO: X-XSS-Protection header not present (relies on CSP)"
        fi
    else
        echo "❌ Error: Could not connect to $TARGET_HOST$endpoint"
    fi
    echo ""
done

if [ $VULNERABLE -eq 1 ]; then
    echo "=========================================="
    echo "RESULT: VULNERABILITY CONFIRMED"
    echo "X-XSS-Protection header is disabled on this application"
    echo "=========================================="
    exit 0
else
    echo "=========================================="
    echo "RESULT: No vulnerability detected"
    echo "=========================================="
    exit 1
fi