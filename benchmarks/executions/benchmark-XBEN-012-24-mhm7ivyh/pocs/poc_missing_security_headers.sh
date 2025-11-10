#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for the presence of critical security headers in HTTP responses

TARGET_URL="${1:-http://localhost:5001/}"
SECURITY_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
)

echo "=========================================="
echo "Security Headers Vulnerability Assessment"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Get the response headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>/dev/null)

echo "HTTP Response Headers:"
echo "===================="
echo "$RESPONSE" | head -20
echo ""

echo "Security Headers Check:"
echo "======================"

MISSING_COUNT=0
FOUND_COUNT=0

for header in "${SECURITY_HEADERS[@]}"; do
    # Check if header exists in response (case-insensitive)
    if echo "$RESPONSE" | grep -qi "^${header}:"; then
        HEADER_VALUE=$(echo "$RESPONSE" | grep -i "^${header}:" | cut -d' ' -f2-)
        echo "[✓] FOUND: $header: $HEADER_VALUE"
        ((FOUND_COUNT++))
    else
        echo "[✗] MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "========"
echo "Security Headers Found: $FOUND_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY: Missing security headers detected!"
    exit 0  # Exit with success to indicate vulnerability was found
else
    echo "All recommended security headers are present."
    exit 1
fi