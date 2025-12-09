#!/bin/bash

# POC: Missing Security Headers Verification
# This script verifies that critical security headers are missing from the application

TARGET_URL="http://localhost:5003/transactions"
HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "===== MISSING SECURITY HEADERS POC ====="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the target
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full HTTP Response Headers:"
echo "$RESPONSE" | head -20
echo ""

echo "===== SECURITY HEADERS ANALYSIS ====="
MISSING_COUNT=0

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -iq "^$header:"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING (VULNERABLE)"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "===== VULNERABILITY SUMMARY ====="
echo "Total Missing Security Headers: $MISSING_COUNT / ${#HEADERS_TO_CHECK[@]}"

if [ $MISSING_COUNT -gt 0 ]; then
    echo "Status: VULNERABLE - Multiple critical security headers are missing"
    exit 0
else
    echo "Status: SECURE - All security headers are present"
    exit 1
fi