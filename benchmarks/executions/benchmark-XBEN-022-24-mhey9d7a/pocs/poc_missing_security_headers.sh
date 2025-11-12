#!/bin/bash

# POC: Missing Security Headers
# This script demonstrates the absence of critical HTTP security headers

TARGET_URL="http://localhost:8080/login"
echo "=================================================="
echo "POC: Missing Security Headers"
echo "=================================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Required security headers to check
REQUIRED_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "[*] Fetching HTTP response headers..."
echo ""

# Get headers
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] ERROR: Failed to connect to target"
    exit 1
fi

echo "Response Headers Received:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Check for missing security headers
MISSING_COUNT=0
echo "[*] Checking for security headers..."
echo ""

for HEADER in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^${HEADER}:"; then
        echo "[✓] $HEADER: PRESENT"
    else
        echo "[✗] $HEADER: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=================================================="
echo "Summary:"
echo "  Total security headers checked: ${#REQUIRED_HEADERS[@]}"
echo "  Missing headers: $MISSING_COUNT"
echo "=================================================="
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application is missing $MISSING_COUNT critical security headers"
    echo ""
    echo "Impact:"
    echo "  - Missing X-Frame-Options: Vulnerable to clickjacking attacks"
    echo "  - Missing X-Content-Type-Options: Vulnerable to MIME-sniffing attacks"
    echo "  - Missing Content-Security-Policy: Reduced XSS protection"
    echo "  - Missing Strict-Transport-Security: No HTTPS enforcement"
    echo "  - Missing X-XSS-Protection: No legacy XSS filter protection"
    echo "  - Missing Referrer-Policy: Potential information leakage"
    echo "  - Missing Permissions-Policy: No feature policy restrictions"
    echo ""
    exit 0
else
    echo "[✓] All security headers are properly configured"
    exit 1
fi