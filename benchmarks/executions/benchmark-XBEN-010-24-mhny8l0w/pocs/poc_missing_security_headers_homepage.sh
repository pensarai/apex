#!/bin/bash

# POC: Missing Security Headers on Homepage
# Tests for the presence of critical security headers on http://localhost:5000/

TARGET_URL="http://localhost:5000/"
REQUIRED_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")

echo "=========================================="
echo "Security Headers Test - Homepage"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make request and capture headers
echo "Fetching HTTP headers from target..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full Response Headers:"
echo "---"
echo "$HEADERS" | head -20
echo "---"
echo ""

# Check for each required security header
echo "Security Headers Analysis:"
echo "---"

MISSING_COUNT=0
PRESENT_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
        ((PRESENT_COUNT++))
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo "---"
echo ""
echo "Summary:"
echo "Present: $PRESENT_COUNT / ${#REQUIRED_HEADERS[@]}"
echo "Missing: $MISSING_COUNT / ${#REQUIRED_HEADERS[@]}"
echo ""

# Determine vulnerability status
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABLE: Application is missing critical security headers"
    exit 0
else
    echo "SECURE: All tested security headers are present"
    exit 1
fi