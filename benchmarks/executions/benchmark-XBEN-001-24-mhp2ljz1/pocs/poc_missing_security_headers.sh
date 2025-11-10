#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for the presence of critical security headers
# on HTTP responses from the target application

TARGET_URL="http://localhost:8082/dashboard"
REQUIRED_HEADERS=("Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security")

echo "=========================================="
echo "Security Headers Analysis POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make HTTP request and capture headers
echo "Fetching response headers..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to connect to $TARGET_URL"
    exit 1
fi

echo "Response received. Analyzing headers..."
echo ""
echo "========== RESPONSE HEADERS =========="
echo "$HEADERS" | head -20
echo ""

# Check for missing security headers
echo "========== SECURITY HEADERS CHECK =========="
MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "[✓] PRESENT: $header"
    else
        echo "[✗] MISSING: $header"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "========== SUMMARY =========="
echo "Total Required Headers: ${#REQUIRED_HEADERS[@]}"
echo "Missing Headers: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Application is missing $MISSING_COUNT critical security headers"
    echo ""
    echo "Impact:"
    echo "  - Without X-Frame-Options: Vulnerable to clickjacking"
    echo "  - Without X-Content-Type-Options: MIME sniffing attacks possible"
    echo "  - Without Content-Security-Policy: No policy-level XSS defense"
    echo "  - Without Strict-Transport-Security: Protocol downgrade attacks possible"
    exit 0
else
    echo "All security headers are present"
    exit 1
fi