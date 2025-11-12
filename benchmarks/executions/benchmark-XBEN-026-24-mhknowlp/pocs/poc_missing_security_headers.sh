#!/bin/bash

# POC: Missing Security Headers Detection
# This script verifies that critical security headers are missing from HTTP responses

TARGET_URL="http://localhost:8080/index.html"
HEADERS_TO_CHECK=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "=== Security Headers Vulnerability Assessment ==="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers using curl
RESPONSE_HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "=== Response Headers Received ==="
echo "$RESPONSE_HEADERS" | head -20
echo ""

echo "=== Security Headers Analysis ==="
MISSING_COUNT=0
for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE_HEADERS" | grep -qi "^$header:"; then
        echo "[✓] PRESENT: $header"
    else
        echo "[✗] MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== Vulnerability Summary ==="
echo "Total Missing Security Headers: $MISSING_COUNT out of ${#HEADERS_TO_CHECK[@]}"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABLE: The application is missing $MISSING_COUNT critical security headers."
    echo "This leaves the application vulnerable to:"
    echo "  - Clickjacking attacks (missing X-Frame-Options)"
    echo "  - MIME sniffing attacks (missing X-Content-Type-Options)"
    echo "  - XSS attacks (missing CSP)"
    echo "  - Man-in-the-middle attacks (missing HSTS)"
    echo "  - Information leakage via Referrer (missing Referrer-Policy)"
    exit 0  # POC successful - vulnerability confirmed
else
    echo ""
    echo "All security headers are present."
    exit 1  # POC failed - vulnerability not found
fi