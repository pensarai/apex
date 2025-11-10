#!/bin/bash

# POC: Missing Security Headers Vulnerability
# Demonstrates that the application is missing critical HTTP security headers

TARGET_URL="${1:-http://localhost:8080/}"
HEADERS_TO_CHECK=("X-Frame-Options" "X-XSS-Protection" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security")

echo "=========================================="
echo "Security Headers Audit"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check for security headers
echo "Security Headers Analysis:"
echo "=========================="
MISSING_COUNT=0

for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$HEADER:"; then
        FOUND=$(echo "$RESPONSE" | grep -i "^$HEADER:" | head -1)
        echo "✓ FOUND: $FOUND"
    else
        echo "✗ MISSING: $HEADER"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "--------"
TOTAL=${#HEADERS_TO_CHECK[@]}
FOUND=$((TOTAL - MISSING_COUNT))
echo "Security Headers Present: $FOUND/$TOTAL"
echo "Security Headers Missing: $MISSING_COUNT/$TOTAL"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABLE: Application is missing $MISSING_COUNT critical security headers"
    exit 0
else
    echo ""
    echo "Application has all checked security headers implemented"
    exit 1
fi