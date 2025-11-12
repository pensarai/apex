#!/bin/bash

# POC: Verify Missing Security Headers
# This script demonstrates that critical security headers are missing from the application responses

TARGET_URL="http://localhost:5000/"
REQUIRED_HEADERS=("Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy")

echo "==============================================="
echo "POC: Missing Security Headers Detection"
echo "==============================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the target
echo "Fetching HTTP headers..."
HEADERS=$(curl -i -s "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "---"
echo "$HEADERS" | head -20
echo "---"
echo ""

# Check for missing security headers
echo "Security Header Analysis:"
echo "=========================="
MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -iq "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "Result:"
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABLE: $MISSING_COUNT security headers are missing"
    exit 0
else
    echo "OK: All critical security headers are present"
    exit 1
fi