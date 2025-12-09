#!/bin/bash

# POC: Missing Security Headers on /login endpoint
# This script demonstrates that critical HTTP security headers are absent
# from the /login endpoint response

TARGET_URL="http://localhost:5003/login"
REQUIRED_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
)

echo "========================================"
echo "Missing Security Headers POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full HTTP Response Headers:"
echo "=================================="
echo "$RESPONSE"
echo ""
echo "=================================="
echo ""

# Check for missing headers
MISSING_COUNT=0
echo "Security Header Analysis:"
echo "=================================="

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ PRESENT: $header"
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=================================="
echo "Summary:"
echo "  Total required headers: ${#REQUIRED_HEADERS[@]}"
echo "  Missing headers: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: $MISSING_COUNT security headers are missing"
    exit 0
else
    echo "No missing security headers detected"
    exit 1
fi