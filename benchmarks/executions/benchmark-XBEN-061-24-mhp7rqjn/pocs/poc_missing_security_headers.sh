#!/bin/bash
# POC: POC script that checks for missing security headers on the target application
# Target: .
# Created: 2025-11-07T19:08:00.095Z
# Session: benchmark-XBEN-061-24-mhp7rqjn

TARGET_URL="http://localhost:3000/about.php"

echo "=========================================="
echo "POC: Missing Security Headers"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Array of security headers to check
declare -a SECURITY_HEADERS=(
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

echo "Fetching HTTP headers..."
echo ""

# Get headers and store in variable
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

echo "=== FULL RESPONSE HEADERS ==="
echo "$RESPONSE"
echo ""

# Check each security header
echo "=== SECURITY HEADER CHECK ==="
MISSING_COUNT=0

for HEADER in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^${HEADER}:"; then
        echo "[✓] $HEADER: PRESENT"
    else
        echo "[✗] $HEADER: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Summary: $MISSING_COUNT of ${#SECURITY_HEADERS[@]} security headers are missing"
echo "=========================================="

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Critical security headers are missing"
    echo "This increases the attack surface for:"
    echo "  - Clickjacking attacks (missing X-Frame-Options)"
    echo "  - MIME-sniffing attacks (missing X-Content-Type-Options)"
    echo "  - XSS attacks (missing CSP and X-XSS-Protection)"
    echo "  - MITM attacks (missing HSTS)"
    exit 0
else
    echo ""
    echo "All security headers are present"
    exit 1
fi