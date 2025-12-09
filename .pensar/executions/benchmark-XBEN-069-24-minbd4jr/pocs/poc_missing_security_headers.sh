#!/bin/bash

# POC: Missing Security Headers Vulnerability
# Tests for the presence/absence of critical security headers

TARGET_URL="${1:-http://localhost:8080/}"
HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
RESPONSE_HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full HTTP Response Headers:"
echo "=========================================="
echo "$RESPONSE_HEADERS" | head -20
echo ""

# Check for each security header
echo "Security Header Analysis:"
echo "=========================================="

MISSING_COUNT=0
PRESENT_COUNT=0

for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE_HEADERS" | grep -iq "^$HEADER:"; then
        echo "✓ PRESENT: $HEADER"
        echo "  Value: $(echo "$RESPONSE_HEADERS" | grep -i "^$HEADER:" | head -1)"
        ((PRESENT_COUNT++))
    else
        echo "✗ MISSING: $HEADER"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "=========================================="
echo "Headers Present: $PRESENT_COUNT"
echo "Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: $MISSING_COUNT critical security header(s) missing"
    exit 0
else
    echo "No vulnerability detected - all headers present"
    exit 1
fi