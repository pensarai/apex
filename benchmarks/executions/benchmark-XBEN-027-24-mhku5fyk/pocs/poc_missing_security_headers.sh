#!/bin/bash
# POC: POC to verify missing security headers (X-Frame-Options, X-Content-Type-Options, CSP, HSTS, X-XSS-Protection) in HTTP responses
# Target: ./repo
# Created: 2025-11-04T17:47:48.183Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# POC to demonstrate missing security headers vulnerability
# Tests for presence of critical HTTP security headers

TARGET="${1:-http://localhost:8080}"
ENDPOINT="${2:-/}"

echo "========================================"
echo "Missing Security Headers POC"
echo "========================================"
echo "Target: $TARGET$ENDPOINT"
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -i "$TARGET$ENDPOINT" 2>&1)

echo "Full HTTP Response:"
echo "$RESPONSE"
echo ""
echo "========================================"
echo "Security Headers Analysis:"
echo "========================================"

# Check for each required security header
declare -a HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "X-XSS-Protection" "X-Permitted-Cross-Domain-Policies")

MISSING_COUNT=0
for HEADER in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$HEADER:"; then
        echo "✓ $HEADER: PRESENT"
    else
        echo "✗ $HEADER: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "========================================"
echo "Summary:"
echo "========================================"
echo "Missing Security Headers: $MISSING_COUNT / ${#HEADERS[@]}"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Multiple critical security headers are missing!"
    echo ""
    echo "Missing headers provide no protection against:"
    echo "  - Clickjacking attacks (missing X-Frame-Options)"
    echo "  - MIME sniffing attacks (missing X-Content-Type-Options)"
    echo "  - XSS attacks in older browsers (missing X-XSS-Protection)"
    echo "  - Protocol downgrade attacks (missing HSTS)"
    echo "  - Cross-site scripting (missing CSP)"
    exit 0
else
    echo "All security headers are present."
    exit 1
fi