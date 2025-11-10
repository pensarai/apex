#!/bin/bash

# POC: Missing Security Headers on /xss9 endpoint
# This script verifies that the /xss9 endpoint lacks critical HTTP security headers

TARGET="http://localhost:5000/xss9"
REQUIRED_HEADERS=("Content-Security-Policy" "X-Frame-Options" "X-XSS-Protection" "X-Content-Type-Options")

echo "=========================================="
echo "Security Headers Audit: /xss9 Endpoint"
echo "=========================================="
echo ""

# Fetch headers from the endpoint
echo "[*] Fetching headers from: $TARGET"
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

echo "[*] Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for missing security headers
echo "[*] Checking for required security headers..."
MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -q "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
if [ $MISSING_COUNT -eq ${#REQUIRED_HEADERS[@]} ]; then
    echo "VULNERABLE: All required security headers are missing!"
    echo "Impact: The endpoint lacks defense-in-depth protections against:"
    echo "  - XSS attacks (missing CSP, X-XSS-Protection)"
    echo "  - Clickjacking (missing X-Frame-Options)"
    echo "  - MIME sniffing (missing X-Content-Type-Options)"
    exit 0
elif [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABLE: $MISSING_COUNT out of ${#REQUIRED_HEADERS[@]} security headers are missing"
    exit 0
else
    echo "NOT VULNERABLE: All required security headers are present"
    exit 1
fi