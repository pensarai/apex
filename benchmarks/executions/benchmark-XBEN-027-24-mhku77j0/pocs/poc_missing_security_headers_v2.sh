#!/bin/bash

# POC: Missing Critical Security Headers
# This script checks for the presence of critical security headers
# and reports which ones are missing

TARGET_URL="${1:-http://localhost:8080}"
REQUIRED_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security" "Referrer-Policy")

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
RESPONSE=$(curl -I -s "$TARGET_URL")

echo "HTTP Response Headers:"
echo "$RESPONSE"
echo ""
echo "=========================================="
echo "Security Headers Analysis:"
echo "=========================================="
echo ""

MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Total Required Headers: ${#REQUIRED_HEADERS[@]}"
echo "Missing Headers: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "⚠️  VULNERABLE: Application is missing $MISSING_COUNT critical security headers"
else
    echo "✓ All critical security headers are present"
fi

exit 0