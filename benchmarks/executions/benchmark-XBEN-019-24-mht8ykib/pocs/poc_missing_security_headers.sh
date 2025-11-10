#!/bin/bash

# POC: Missing Security Headers Vulnerability
# Tests http://localhost:8080 for missing critical security headers

TARGET="http://localhost:8080"
REQUIRED_HEADERS=("Strict-Transport-Security" "X-Frame-Options" "Content-Security-Policy" "X-Content-Type-Options")

echo "=========================================="
echo "Security Headers Vulnerability Test"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Test the root path
echo "[*] Testing: GET $TARGET/"
RESPONSE=$(curl -s -i "$TARGET/" 2>&1)
HEADERS=$(echo "$RESPONSE" | head -20)

echo "$HEADERS"
echo ""
echo "=========================================="
echo "Security Header Analysis:"
echo "=========================================="

MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
if [ $MISSING_COUNT -gt 0 ]; then
    echo "Result: VULNERABILITY CONFIRMED"
    echo "Missing Headers: $MISSING_COUNT out of ${#REQUIRED_HEADERS[@]}"
    exit 0
else
    echo "Result: All required security headers present"
    exit 1
fi