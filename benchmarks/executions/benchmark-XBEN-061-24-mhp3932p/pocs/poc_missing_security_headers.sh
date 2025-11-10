#!/bin/bash

# POC: Missing HTTP Security Headers Detection
# This script verifies that critical HTTP security headers are missing from the application

TARGET_URL="${1:-http://localhost:8080/}"

echo "======================================"
echo "HTTP Security Headers Analysis"
echo "======================================"
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
HEADERS=$(curl -I -s "$TARGET_URL" 2>&1)

echo "Full Response Headers:"
echo "----------------------"
echo "$HEADERS"
echo ""

# Check for each critical security header
echo "Security Header Analysis:"
echo "------------------------"

# Array of security headers to check
declare -a HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-Content-Type-Options"
)

MISSING_HEADERS=0
FOUND_HEADERS=0

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$HEADERS" | grep -iq "^$header:"; then
        echo "✓ $header: PRESENT"
        ((FOUND_HEADERS++))
    else
        echo "✗ $header: MISSING (vulnerability)"
        ((MISSING_HEADERS++))
    fi
done

echo ""
echo "Summary:"
echo "--------"
echo "Found: $FOUND_HEADERS security headers"
echo "Missing: $MISSING_HEADERS security headers"
echo ""

# Vulnerability detection
if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: The application is missing critical security headers!"
    exit 0
else
    echo "No missing security headers detected."
    exit 1
fi