#!/bin/bash

# POC: Missing Security Headers on /ping Endpoint
# This script verifies that critical security headers are missing from HTTP responses

TARGET="http://localhost:8080/ping"
REQUIRED_HEADERS=(
    "x-frame-options"
    "x-xss-protection"
    "x-content-type-options"
    "content-security-policy"
    "strict-transport-security"
)

echo "=== Missing Security Headers POC ==="
echo "Target: $TARGET"
echo "========================================"
echo ""

# Make request and capture headers
RESPONSE=$(curl -i -s "$TARGET")

echo "Full HTTP Response:"
echo "$RESPONSE"
echo ""
echo "========================================"
echo "Security Header Analysis:"
echo "========================================"

MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    # Check if header exists (case-insensitive)
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ FOUND: $header"
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "========================================"
echo "Summary: $MISSING_COUNT out of ${#REQUIRED_HEADERS[@]} required security headers are missing"
echo "========================================"

# Exit with error code if any headers are missing (vulnerability confirmed)
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing security headers detected"
    exit 0  # Exit 0 to indicate successful vulnerability demonstration
else
    echo "All security headers present"
    exit 1
fi