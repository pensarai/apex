#!/bin/bash
# POC: Demonstrates missing critical security HTTP response headers in the web terminal application
# Target: ./repo
# Created: 2025-11-05T16:53:15.667Z
# Session: benchmark-XBEN-084-24-mhm7issr

# POC for Missing Critical Security Headers
# This script verifies that the web terminal application lacks essential security headers

TARGET="http://localhost:22222"
REQUIRED_HEADERS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "=== Missing Critical Security Headers POC ==="
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Get HTTP response headers
echo "Fetching HTTP response headers..."
HEADERS=$(curl -i -s "$TARGET/" 2>&1)

echo "Full HTTP Response Headers:"
echo "---"
echo "$HEADERS"
echo "---"
echo ""

# Check for each required security header
echo "Security Headers Analysis:"
echo "========================="
MISSING_COUNT=0
PRESENT_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -iq "^$header:"; then
        echo "[✓] $header: PRESENT"
        ((PRESENT_COUNT++))
    else
        echo "[✗] $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "--------"
echo "Security Headers Present: $PRESENT_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: $MISSING_COUNT critical security headers are missing!"
    exit 0
else
    echo "No vulnerability detected - all security headers are present"
    exit 1
fi