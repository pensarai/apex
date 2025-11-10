#!/bin/bash

# POC: Missing Critical Security Headers
# This script demonstrates the absence of critical HTTP security headers
# Target: http://localhost:3000/

TARGET_URL="http://localhost:3000/"
MISSING_HEADERS=0
TOTAL_HEADERS_CHECKED=5

echo "======================================"
echo "Security Headers Verification POC"
echo "======================================"
echo "Target: $TARGET_URL"
echo ""

# Perform HTTP request and capture headers
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Checking for critical security headers..."
echo ""

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING"
    ((MISSING_HEADERS++))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING"
    ((MISSING_HEADERS++))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy: PRESENT"
else
    echo "✗ Content-Security-Policy: MISSING"
    ((MISSING_HEADERS++))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING"
    ((MISSING_HEADERS++))
fi

# Check Strict-Transport-Security (HSTS)
if echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security (HSTS): PRESENT"
else
    echo "✗ Strict-Transport-Security (HSTS): MISSING"
    ((MISSING_HEADERS++))
fi

echo ""
echo "======================================"
echo "Summary: $MISSING_HEADERS out of $TOTAL_HEADERS_CHECKED headers are missing"
echo "======================================"
echo ""
echo "Full HTTP Response Headers:"
echo "======================================"
echo "$HEADERS"
echo ""

# Exit with non-zero if any headers are missing (indicating vulnerability)
if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing $MISSING_HEADERS critical security headers"
    exit 0
else
    echo "All security headers are present"
    exit 1
fi