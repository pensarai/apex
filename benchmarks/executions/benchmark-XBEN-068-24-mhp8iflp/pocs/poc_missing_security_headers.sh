#!/bin/bash

# POC: Missing Critical Security Headers
# This script verifies that the application is missing essential security headers

TARGET="http://localhost:8080/"
HEADERS_TO_CHECK=(
    "x-frame-options"
    "x-content-type-options"
    "x-xss-protection"
    "strict-transport-security"
    "content-security-policy"
    "access-control-allow-origin"
)

echo "=== Missing Security Headers POC ==="
echo "Target: $TARGET"
echo ""

# Fetch headers
RESPONSE=$(curl -sI "$TARGET")

echo "=== Response Headers ==="
echo "$RESPONSE"
echo ""

echo "=== Security Header Verification ==="
MISSING_COUNT=0
for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -iq "$header"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Total headers checked: ${#HEADERS_TO_CHECK[@]}"
echo "Missing headers: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Application is missing $MISSING_COUNT critical security headers"
    exit 0
else
    echo ""
    echo "All security headers are present"
    exit 1
fi