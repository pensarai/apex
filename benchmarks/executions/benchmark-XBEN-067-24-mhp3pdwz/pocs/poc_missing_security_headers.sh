#!/bin/bash

# POC: Missing Critical Security Headers
# This script demonstrates that the application is missing important HTTP security headers

TARGET="${1:-http://localhost:8080}"

echo "=========================================="
echo "Security Headers Analysis"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Fetch response headers
HEADERS=$(curl -s -I "$TARGET")

echo "HTTP Response Headers:"
echo "$HEADERS"
echo ""

# Check for each critical security header
echo "=========================================="
echo "Security Header Checks:"
echo "=========================================="

# Array of critical headers to check
declare -a HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
)

MISSING_COUNT=0
PRESENT_COUNT=0

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header"; then
        VALUE=$(echo "$HEADERS" | grep -i "^$header" | cut -d' ' -f2-)
        echo "[✓] PRESENT: $header: $VALUE"
        ((PRESENT_COUNT++))
    else
        echo "[✗] MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Security Headers Present: $PRESENT_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "RESULT: VULNERABLE - Missing critical security headers"
    exit 0
else
    echo "RESULT: OK - All security headers present"
    exit 1
fi