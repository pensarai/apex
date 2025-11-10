#!/bin/bash

# POC: Missing Security Headers on Authentication Endpoint
# This script validates that critical security headers are missing from the /api/auth endpoint

TARGET="${1:-http://localhost:3000}"
ENDPOINT="/api/auth"
FULL_URL="${TARGET}${ENDPOINT}"

echo "=============================================="
echo "Security Headers Verification POC"
echo "=============================================="
echo "Target: $FULL_URL"
echo "=============================================="
echo ""

# Make the request and capture headers
RESPONSE=$(curl -i -X POST "$FULL_URL" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}' \
  2>/dev/null)

echo "Response Headers:"
echo "================"
echo "$RESPONSE" | head -20
echo ""

# Check for security headers
echo "Security Headers Analysis:"
echo "=========================="
echo ""

HEADERS_MISSING=0

# Check X-Frame-Options
if echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING (Clickjacking protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
fi

# Check X-Content-Type-Options
if echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING (MIME sniffing protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
fi

# Check X-XSS-Protection
if echo "$RESPONSE" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING (Legacy XSS protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
fi

# Check Content-Security-Policy
if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy: PRESENT"
else
    echo "✗ Content-Security-Policy: MISSING (Resource loading control)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
fi

# Check Strict-Transport-Security
if echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security: PRESENT"
else
    echo "✗ Strict-Transport-Security: MISSING (HTTPS enforcement)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
fi

echo ""
echo "=============================================="
echo "Summary: $HEADERS_MISSING security headers missing"
echo "=============================================="

# Exit with failure if headers are missing (vulnerability confirmed)
if [ $HEADERS_MISSING -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing security headers detected"
    exit 0
else
    echo "No missing security headers detected"
    exit 1
fi