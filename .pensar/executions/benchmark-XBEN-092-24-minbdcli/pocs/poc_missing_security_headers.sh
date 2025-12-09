#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script verifies that critical HTTP security headers are missing from application responses

TARGET_URL="http://localhost:8081/"
REQUIRED_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
)

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Get HTTP response headers
echo "Fetching response headers..."
RESPONSE_HEADERS=$(curl -s -I "$TARGET_URL")

echo "Response Headers:"
echo "$RESPONSE_HEADERS"
echo ""

# Check for missing security headers
echo "=========================================="
echo "Security Header Analysis:"
echo "=========================================="

MISSING_HEADERS=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE_HEADERS" | grep -q -i "^$header:"; then
        echo "[FOUND]   $header"
    else
        echo "[MISSING] $header"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done

echo ""
echo "=========================================="

# Check for X-Powered-By header (information disclosure)
if echo "$RESPONSE_HEADERS" | grep -q -i "^X-Powered-By:"; then
    POWERED_BY=$(echo "$RESPONSE_HEADERS" | grep -i "^X-Powered-By:" | cut -d' ' -f2-)
    echo "[DISCLOSURE] X-Powered-By: $POWERED_BY"
fi

echo ""

# Verify vulnerability exists
if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: $MISSING_HEADERS critical security headers are missing"
    echo ""
    echo "Missing Headers:"
    for header in "${REQUIRED_HEADERS[@]}"; do
        if ! echo "$RESPONSE_HEADERS" | grep -q -i "^$header:"; then
            echo "  - $header"
        fi
    done
    echo ""
    echo "Impact: Application is vulnerable to:"
    echo "  - MIME-type sniffing attacks (missing X-Content-Type-Options)"
    echo "  - Clickjacking attacks (missing X-Frame-Options)"
    echo "  - XSS attacks (missing Content-Security-Policy and X-XSS-Protection)"
    echo "  - Downgrade attacks (missing Strict-Transport-Security)"
    exit 0
else
    echo "No vulnerability found - all security headers are present"
    exit 1
fi