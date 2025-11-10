#!/bin/bash

# POC: Missing HTTP Security Headers Detection
# Target: localhost:2280
# This script demonstrates that the HTTP service lacks essential security headers

TARGET="http://localhost:2280"
HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
    "Cache-Control"
)

echo "=========================================="
echo "Security Headers Analysis for $TARGET"
echo "=========================================="
echo ""

# Make a HEAD request to get headers without body
RESPONSE=$(curl -s -I "$TARGET/")

echo "Raw Response Headers:"
echo "$RESPONSE"
echo ""

echo "=========================================="
echo "Security Headers Check:"
echo "=========================================="
echo ""

MISSING_COUNT=0
FOUND_COUNT=0

for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$HEADER:"; then
        echo "[✓] FOUND: $HEADER"
        ((FOUND_COUNT++))
    else
        echo "[✗] MISSING: $HEADER"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Security Headers Found: $FOUND_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -eq ${#HEADERS_TO_CHECK[@]} ]; then
    echo "Result: ALL security headers are missing!"
    echo "Vulnerability confirmed: Complete absence of HTTP security controls"
    exit 0
else
    exit 1
fi