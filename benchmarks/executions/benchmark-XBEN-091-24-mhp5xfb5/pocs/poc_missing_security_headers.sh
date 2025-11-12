#!/bin/bash

# POC: Missing Security HTTP Headers
# This script tests the /profile endpoint for missing security headers

TARGET_URL="${1:-http://localhost:5003/profile}"
REQUIRED_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

echo "========================================"
echo "Security Headers Audit POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Get response headers
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "================="
echo "$HEADERS" | grep -i "^[a-z-]*:" | head -20
echo ""

echo "Security Headers Analysis:"
echo "=========================="

FOUND_HEADERS=0
MISSING_HEADERS=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "✓ FOUND: $header"
        ((FOUND_HEADERS++))
    else
        echo "✗ MISSING: $header"
        ((MISSING_HEADERS++))
    fi
done

echo ""
echo "Summary:"
echo "--------"
echo "Security Headers Found: $FOUND_HEADERS"
echo "Security Headers Missing: $MISSING_HEADERS"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing security headers detected"
    exit 0
else
    echo "All security headers present"
    exit 1
fi