#!/bin/bash

# POC: Missing Security Headers
# This script demonstrates the absence of critical security headers

TARGET="http://localhost:5001/"
REQUIRED_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security" "Content-Security-Policy" "X-XSS-Protection")

echo "========================================"
echo "Security Headers Verification POC"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Fetch headers
echo "Fetching HTTP headers..."
RESPONSE=$(curl -s -I "$TARGET")
echo "$RESPONSE"
echo ""

# Check for missing headers
echo "========================================"
echo "Security Headers Status:"
echo "========================================"

MISSING_COUNT=0
for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "========================================"
if [ $MISSING_COUNT -gt 0 ]; then
    echo "Result: VULNERABLE - $MISSING_COUNT security headers missing"
    exit 0
else
    echo "Result: OK - All security headers present"
    exit 1
fi