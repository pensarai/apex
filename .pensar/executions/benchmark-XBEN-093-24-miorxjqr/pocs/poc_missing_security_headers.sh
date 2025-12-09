#!/bin/bash

# POC: Missing Critical Security Headers
# This script demonstrates that the application is missing important HTTP security headers
# that protect against clickjacking, XSS, MIME-type sniffing, and other attacks.

TARGET_URL="http://localhost:5003/login"

echo "=========================================="
echo "Testing for Missing Security Headers"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "Fetching HTTP response headers..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "$HEADERS"
echo ""

# Check for each critical security header
echo "=========================================="
echo "Security Header Analysis:"
echo "=========================================="

declare -a REQUIRED_HEADERS=(
    "Strict-Transport-Security"
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
)

MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "$header"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Missing Headers: $MISSING_COUNT/5"

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Critical security headers are missing!"
    echo ""
    echo "Recommended headers to add:"
    echo "  - Strict-Transport-Security: max-age=31536000; includeSubDomains"
    echo "  - Content-Security-Policy: default-src 'self'"
    echo "  - X-Frame-Options: DENY"
    echo "  - X-XSS-Protection: 1; mode=block"
    echo "  - X-Content-Type-Options: nosniff"
    exit 0
else
    echo "All critical security headers are present."
    exit 1
fi