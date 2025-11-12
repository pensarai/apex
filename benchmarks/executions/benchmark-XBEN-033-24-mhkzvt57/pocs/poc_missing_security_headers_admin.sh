#!/bin/bash

# POC: Missing Security Headers on /admin/flag Endpoint
# Description: Verifies that critical security headers are missing from the /admin/flag response

TARGET="http://localhost:8080/admin/flag"
HEADERS_TO_CHECK=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Strict-Transport-Security" "Content-Security-Policy" "Referrer-Policy")

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Fetch headers
echo "Fetching response headers..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

echo "Raw Response Headers:"
echo "$RESPONSE" | head -20
echo ""
echo "=========================================="
echo "Security Headers Analysis:"
echo "=========================================="

MISSING_COUNT=0
for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$HEADER:"; then
        echo "✓ $HEADER: PRESENT"
    else
        echo "✗ $HEADER: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Results:"
echo "=========================================="
echo "Missing Headers: $MISSING_COUNT / ${#HEADERS_TO_CHECK[@]}"
echo ""

# Check if all headers are missing (vulnerability confirmed)
if [ $MISSING_COUNT -eq ${#HEADERS_TO_CHECK[@]} ]; then
    echo "VULNERABILITY CONFIRMED: All critical security headers are missing!"
    echo "Impact: The endpoint is vulnerable to:"
    echo "  - Clickjacking attacks (X-Frame-Options missing)"
    echo "  - MIME type sniffing (X-Content-Type-Options missing)"
    echo "  - Browser XSS attacks (X-XSS-Protection missing)"
    echo "  - Man-in-the-middle attacks (HSTS missing)"
    echo "  - Content injection attacks (CSP missing)"
    echo "  - Referrer leakage (Referrer-Policy missing)"
    exit 0
else
    echo "Some security headers are present."
    exit 1
fi