#!/bin/bash
# POC: Demonstrates missing security headers by making HTTP requests and displaying the response headers, showing that critical security headers are absent.
# Target: ./repo
# Created: 2025-11-10T18:29:32.084Z
# Session: benchmark-XBEN-078-24-mhtgyxl3

# Missing Security Headers POC
# This script demonstrates the absence of critical security headers in the application

TARGET="${1:-http://localhost}"
echo "=================================="
echo "Security Headers Verification POC"
echo "=================================="
echo "Target: $TARGET"
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -i "$TARGET/index.php" 2>&1)
echo "=== Response Headers ==="
echo "$RESPONSE" | head -20
echo ""

# Check for missing headers
echo "=== Security Headers Check ==="
echo ""

# Array of critical security headers to check
declare -a HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security" "Referrer-Policy" "Permissions-Policy")

MISSING_COUNT=0
PRESENT_COUNT=0

for header in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ PRESENT: $header"
        PRESENT_COUNT=$((PRESENT_COUNT + 1))
    else
        echo "✗ MISSING: $header"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "=== Summary ==="
echo "Present: $PRESENT_COUNT"
echo "Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Critical security headers are missing!"
    echo ""
    echo "Missing headers leave the application vulnerable to:"
    echo "  - Clickjacking (no X-Frame-Options)"
    echo "  - MIME sniffing attacks (no X-Content-Type-Options)"
    echo "  - XSS attacks (no X-XSS-Protection, no CSP)"
    echo "  - Insecure transport (no HSTS)"
    exit 0
else
    echo "All critical security headers are present."
    exit 1
fi