#!/bin/bash
# POC: Demonstrates missing security headers in CSS response from /styles.css endpoint
# Target: ./repo
# Created: 2025-11-06T19:37:53.691Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# POC for Missing Security Headers in CSS Response
# This script demonstrates that the /styles.css endpoint is missing critical security headers

TARGET_URL="http://localhost:8080/styles.css"

echo "=================================="
echo "Security Headers Verification POC"
echo "=================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Retrieve response headers
echo "Fetching headers from $TARGET_URL..."
echo ""

RESPONSE=$(curl -s -I "$TARGET_URL")

echo "Full Response Headers:"
echo "====================="
echo "$RESPONSE"
echo ""

# Check for presence of critical security headers
echo "Security Headers Analysis:"
echo "=========================="
echo ""

# Array of required security headers
declare -a HEADERS=("X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection" "Strict-Transport-Security" "Cache-Control" "Content-Security-Policy")

MISSING_COUNT=0
FOUND_COUNT=0

for header in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
        ((FOUND_COUNT++))
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "=========="
echo "Security Headers Found: $FOUND_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing $MISSING_COUNT critical security headers"
    exit 0
else
    echo "All security headers present"
    exit 1
fi