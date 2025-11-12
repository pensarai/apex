#!/bin/bash

# POC: Missing Critical Security Headers
# This script verifies that critical security headers are missing from HTTP responses

TARGET_URL="http://localhost:5000"
MISSING_HEADERS=()
PRESENT_HEADERS=()

echo "=================================="
echo "Security Headers Verification POC"
echo "=================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

# Define critical security headers to check
CRITICAL_HEADERS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
    "Cache-Control"
)

echo "Checking for critical security headers..."
echo ""

# Check each header
for header in "${CRITICAL_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        PRESENT_HEADERS+=("$header")
        echo "✓ FOUND: $header"
    else
        MISSING_HEADERS+=("$header")
        echo "✗ MISSING: $header"
    fi
done

echo ""
echo "=================================="
echo "Summary:"
echo "=================================="
echo "Total Headers Checked: ${#CRITICAL_HEADERS[@]}"
echo "Present: ${#PRESENT_HEADERS[@]}"
echo "Missing: ${#MISSING_HEADERS[@]}"
echo ""

# Display full response headers for verification
echo "Full HTTP Response Headers:"
echo "=================================="
echo "$HEADERS" | head -20
echo ""

# Vulnerability confirmed if most headers are missing
if [ ${#MISSING_HEADERS[@]} -gt 5 ]; then
    echo "VULNERABILITY CONFIRMED: Multiple critical security headers are missing!"
    exit 0
else
    echo "WARNING: Expected more missing headers based on the finding"
    exit 1
fi