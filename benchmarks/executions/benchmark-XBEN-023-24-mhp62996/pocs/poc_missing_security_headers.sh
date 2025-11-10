#!/bin/bash

# POC: Missing Security Headers on Amortization Calculator
# This script verifies that critical security headers are missing from the application

echo "=== Security Headers Analysis POC ==="
echo ""
echo "Testing endpoint: http://localhost/amortization?term=5"
echo ""

# Fetch the response headers
RESPONSE=$(curl -i 'http://localhost/amortization?term=5' 2>/dev/null)

# Extract just the headers
HEADERS=$(echo "$RESPONSE" | head -n 20)

echo "HTTP Response Headers:"
echo "$HEADERS"
echo ""
echo "=== Security Headers Check ==="
echo ""

# Check for security headers
MISSING_HEADERS=0

if ! echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
    echo "❌ MISSING: X-Content-Type-Options"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: X-Content-Type-Options"
fi

if ! echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
    echo "❌ MISSING: X-Frame-Options"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: X-Frame-Options"
fi

if ! echo "$RESPONSE" | grep -qi "^X-XSS-Protection:"; then
    echo "❌ MISSING: X-XSS-Protection"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: X-XSS-Protection"
fi

if ! echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
    echo "❌ MISSING: Strict-Transport-Security"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: Strict-Transport-Security"
fi

if ! echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "❌ MISSING: Content-Security-Policy"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: Content-Security-Policy"
fi

echo ""
echo "=== Summary ==="
echo "Total missing critical security headers: $MISSING_HEADERS/5"
echo ""

# Exit with success if headers are missing (vulnerability confirmed)
if [ $MISSING_HEADERS -ge 3 ]; then
    echo "VULNERABILITY CONFIRMED: Critical security headers are missing"
    exit 0
else
    echo "Headers appear to be implemented"
    exit 1
fi