#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates that the application is missing critical security headers

TARGET_URL="http://localhost:5001/"

echo "=== Security Headers Vulnerability POC ==="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the target
echo "Fetching HTTP response headers..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "HTTP Response:"
echo "$RESPONSE"
echo ""

# Check for critical security headers
echo "=== Security Headers Check ==="
echo ""

HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

MISSING_COUNT=0
PRESENT_COUNT=0

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ PRESENT: $header"
        ((PRESENT_COUNT++))
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Security Headers Present: $PRESENT_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"
echo ""

# Exit with status indicating vulnerability
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Application is missing $MISSING_COUNT critical security headers"
    exit 0
else
    echo "No vulnerability detected: All security headers are present"
    exit 1
fi