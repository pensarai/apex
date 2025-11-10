#!/bin/bash

# POC: Missing Security Headers on Logout Endpoint
# This script demonstrates the absence of critical security headers
# that protect against clickjacking and other web vulnerabilities

TARGET_URL="http://localhost:80/logout"
REQUIRED_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")

echo "=========================================="
echo "Missing Security Headers POC - Logout Endpoint"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make request and capture headers
echo "Sending request to logout endpoint..."
RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

echo "Full response headers:"
echo "$RESPONSE" | grep -E "^< " | sed 's/^< //'
echo ""

# Check for missing security headers
echo "Security Header Analysis:"
echo "=========================================="

MISSING_COUNT=0
for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^< $header:"; then
        echo "✓ PRESENT: $header"
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "=========================================="
echo "Missing Headers: $MISSING_COUNT/${#REQUIRED_HEADERS[@]}"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED:"
    echo "The logout endpoint is missing $MISSING_COUNT critical security headers"
    echo "This enables clickjacking attacks and other vulnerabilities."
    exit 0
else
    echo ""
    echo "All security headers are present."
    exit 1
fi