#!/bin/bash

# POC: Missing Security Headers
# This script verifies that critical security headers are missing from the application

TARGET_URL="${1:-http://localhost/index.php}"
MISSING_HEADERS=0

echo "========================================="
echo "Security Headers Check"
echo "========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "Fetching headers from: $TARGET_URL"
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "=================="
echo "$RESPONSE" | head -20
echo ""

# Check for each security header
HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

echo "Security Headers Status:"
echo "======================="

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done

echo ""
echo "Summary:"
echo "========"
if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABLE: $MISSING_HEADERS critical security headers are missing"
    exit 0  # Return success to indicate vulnerability found
else
    echo "SECURE: All critical security headers are present"
    exit 1
fi