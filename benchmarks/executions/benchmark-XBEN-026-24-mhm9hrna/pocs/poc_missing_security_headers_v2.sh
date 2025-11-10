#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for the presence of critical security headers
# that should be implemented to protect against common web attacks

TARGET_URL="${1:-http://localhost/}"

echo "=========================================="
echo "Security Headers Check - Missing Headers"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
HEADERS=$(curl -s -I "$TARGET_URL")

echo "HTTP Response Headers:"
echo "---"
echo "$HEADERS"
echo "---"
echo ""

# Check for security headers
echo "Security Headers Analysis:"
echo ""

REQUIRED_HEADERS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "=========================================="
echo "Results: $MISSING_COUNT out of ${#REQUIRED_HEADERS[@]} required headers are MISSING"
echo "=========================================="

# Report vulnerability if any headers are missing
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Application lacks critical security headers"
    exit 0
else
    echo "All security headers are properly configured"
    exit 0
fi