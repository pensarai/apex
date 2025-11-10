#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates that the Flask application lacks critical HTTP security headers

TARGET_URL="http://localhost:80/"
MISSING_HEADERS=0
FOUND_HEADERS=""

echo "================================"
echo "Security Headers Verification POC"
echo "================================"
echo "Target: $TARGET_URL"
echo ""

# Perform HTTP request and capture response headers
echo "[*] Fetching response headers..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

# Extract just the headers portion (before the blank line that separates headers from body)
RESPONSE_HEADERS=$(echo "$HEADERS" | head -n 100)

echo "[*] Checking for security headers..."
echo ""

# Define critical security headers to check
CRITICAL_HEADERS=(
    "x-content-type-options"
    "x-frame-options"
    "x-xss-protection"
    "strict-transport-security"
    "content-security-policy"
    "referrer-policy"
)

# Check each header
for header in "${CRITICAL_HEADERS[@]}"; do
    if echo "$RESPONSE_HEADERS" | grep -iq "^$header:"; then
        VALUE=$(echo "$RESPONSE_HEADERS" | grep -i "^$header:" | cut -d' ' -f2-)
        echo "[✓] FOUND: $header: $VALUE"
        FOUND_HEADERS="$FOUND_HEADERS $header"
    else
        echo "[-] MISSING: $header"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done

echo ""
echo "================================"
echo "Summary:"
echo "================================"
echo "Missing security headers: $MISSING_HEADERS / ${#CRITICAL_HEADERS[@]}"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "[VULNERABLE] Application is missing $MISSING_HEADERS security headers!"
    echo "This exposes the application to:"
    echo "  - MIME-type sniffing attacks (no X-Content-Type-Options)"
    echo "  - Clickjacking attacks (no X-Frame-Options)"
    echo "  - XSS attacks (no X-XSS-Protection / CSP)"
    echo "  - Man-in-the-middle attacks (no HSTS)"
    echo ""
    exit 0  # Successful POC (vulnerability confirmed)
else
    echo "[SECURE] All critical security headers are present"
    exit 1  # POC failed (vulnerability not present)
fi