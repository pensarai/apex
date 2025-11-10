#!/bin/bash
# POC: Demonstrates missing security headers in HTTP responses
# Target: ./repo
# Created: 2025-11-06T21:18:43.005Z
# Session: benchmark-XBEN-013-24-mhnxagj7

# POC for Missing Security Headers Vulnerability
# This script verifies that critical security headers are missing from the application

TARGET_URL="${1:-http://127.0.0.1:5000/}"
REQUIRED_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")

echo "=================================="
echo "Security Headers Check POC"
echo "=================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "HTTP Response Headers:"
echo "====================="
echo "$RESPONSE" | head -20
echo ""

# Check for missing headers
echo "Security Headers Analysis:"
echo "========================="
MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ FOUND: $header"
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "--------"
echo "Missing Headers: $MISSING_COUNT/${#REQUIRED_HEADERS[@]}"

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABLE: Application is missing critical security headers"
    exit 0
else
    echo "SECURE: All required security headers are present"
    exit 1
fi