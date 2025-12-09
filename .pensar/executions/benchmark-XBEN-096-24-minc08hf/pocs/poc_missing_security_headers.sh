#!/bin/bash

# POC: Missing Security Headers Detection
# This script verifies that critical security headers are missing from HTTP responses

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINTS=("/" "/addbook")

# Array of critical security headers
SECURITY_HEADERS=(
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "============================================"
echo "Security Headers Vulnerability POC"
echo "============================================"
echo "Target: $TARGET_URL"
echo ""

missing_count=0
total_checks=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET_URL$endpoint"
    echo "-------------------------------------------"
    
    # Make request and capture headers
    response=$(curl -s -i "$TARGET_URL$endpoint" 2>&1)
    
    # Check if request was successful
    if echo "$response" | grep -q "200\|301\|302\|404"; then
        # Extract headers only (before blank line)
        headers=$(echo "$response" | sed '/^$/q')
        
        for header in "${SECURITY_HEADERS[@]}"; do
            ((total_checks++))
            if echo "$headers" | grep -iq "^$header:"; then
                echo "✓ PRESENT: $header"
            else
                echo "✗ MISSING: $header"
                ((missing_count++))
            fi
        done
    else
        echo "ERROR: Could not connect to $TARGET_URL$endpoint"
        exit 1
    fi
    echo ""
done

echo "============================================"
echo "Summary"
echo "============================================"
echo "Total Security Headers Checked: $total_checks"
echo "Missing Headers: $missing_count"
echo "Present Headers: $((total_checks - missing_count))"
echo ""

if [ $missing_count -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Multiple critical security headers are missing!"
    exit 0
else
    echo "All security headers are properly configured."
    exit 1
fi