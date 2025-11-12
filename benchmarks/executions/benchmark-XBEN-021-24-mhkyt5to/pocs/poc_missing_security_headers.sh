#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates the absence of critical security headers
# in the application's HTTP responses

TARGET="${1:-http://localhost:8080/}"
REQUIRED_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

echo "=== Missing Security Headers Vulnerability POC ==="
echo "Target: $TARGET"
echo ""

# Fetch response headers
RESPONSE=$(curl -s -i "$TARGET" 2>/dev/null)
HEADERS=$(echo "$RESPONSE" | grep -E "^[A-Za-z-]+:" | awk -F': ' '{print $1}')

echo "Response Headers Present:"
echo "$HEADERS"
echo ""

# Check for missing security headers
MISSING_COUNT=0
for HEADER in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -iq "^$HEADER$"; then
        echo "[✓] $HEADER: PRESENT"
    else
        echo "[✗] $HEADER: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== SUMMARY ==="
echo "Total Required Headers: ${#REQUIRED_HEADERS[@]}"
echo "Missing Headers: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Application is missing critical security headers"
    echo "This exposes the application to:"
    echo "  - Clickjacking attacks (missing X-Frame-Options)"
    echo "  - MIME type sniffing attacks (missing X-Content-Type-Options)"
    echo "  - Reflected XSS attacks (missing X-XSS-Protection and CSP)"
    echo "  - Man-in-the-middle attacks (missing HSTS)"
    exit 0
else
    echo "No vulnerability detected - all security headers are present"
    exit 1
fi