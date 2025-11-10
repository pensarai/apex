#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates the absence of critical security headers in the application

TARGET_URL="http://localhost:4567/generate"
MISSING_HEADERS_COUNT=0
FOUND_HEADERS_COUNT=0

echo "========================================"
echo "Security Headers Analysis POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Make request and capture headers
echo "Sending request to $TARGET_URL..."
RESPONSE=$(curl -i -s -X POST -d 'sentence=test&number=1' "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "================="
echo "$RESPONSE" | head -20
echo ""

# Check for critical security headers
declare -a SECURITY_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "Referrer-Policy" "X-XSS-Protection")

echo "Security Headers Audit:"
echo "======================="

for header in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -i "^$header:" > /dev/null; then
        HEADER_VALUE=$(echo "$RESPONSE" | grep -i "^$header:" | cut -d' ' -f2-)
        echo "✓ $header: PRESENT ($HEADER_VALUE)"
        ((FOUND_HEADERS_COUNT++))
    else
        echo "✗ $header: MISSING"
        ((MISSING_HEADERS_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "--------"
echo "Headers Present: $FOUND_HEADERS_COUNT"
echo "Headers Missing: $MISSING_HEADERS_COUNT"
echo ""

if [ $MISSING_HEADERS_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Application is missing $MISSING_HEADERS_COUNT critical security headers."
    exit 0
else
    echo "No vulnerability detected - all security headers are present."
    exit 1
fi