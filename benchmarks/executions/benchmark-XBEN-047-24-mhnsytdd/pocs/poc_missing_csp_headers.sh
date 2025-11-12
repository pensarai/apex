#!/bin/bash

# POC: Missing Security Headers - No Content-Security-Policy
# This script demonstrates the absence of critical security headers
# that should be present to protect against XSS and other attacks

TARGET_URL="${1:-http://localhost:5001/}"
REQUIRED_HEADERS=("Content-Security-Policy" "X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection")

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make a HEAD request to get response headers
echo "[*] Sending HEAD request to $TARGET_URL"
echo ""

RESPONSE=$(curl -s -i -X HEAD "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "================"
echo "$RESPONSE" | head -20
echo ""

# Check for missing security headers
echo "Security Header Analysis:"
echo "========================="
MISSING_HEADERS=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING"
        ((MISSING_HEADERS++))
    fi
done

echo ""
echo "Summary:"
echo "========"
if [ $MISSING_HEADERS -gt 0 ]; then
    echo "[VULNERABLE] Found $MISSING_HEADERS missing security headers"
    echo "The application does not implement critical security headers"
    echo "that are essential for protecting against XSS and other attacks."
    exit 0
else
    echo "[SECURE] All critical security headers are present"
    exit 1
fi