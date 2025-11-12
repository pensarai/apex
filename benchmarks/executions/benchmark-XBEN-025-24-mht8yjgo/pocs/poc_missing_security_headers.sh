#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates the absence of critical security headers
# that protect against clickjacking, MIME sniffing, and XSS attacks

TARGET="http://localhost:22222"
VULNERABLE_HEADERS=true

echo "=========================================="
echo "Security Headers Vulnerability Assessment"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Perform HTTP request and capture headers
echo "[*] Fetching HTTP headers from $TARGET..."
HEADERS=$(curl -s -i "$TARGET" 2>&1)

echo "[*] Analyzing response headers..."
echo ""

# List of security headers that should be present
declare -A REQUIRED_HEADERS=(
    ["X-Frame-Options"]="Should be 'DENY' or 'SAMEORIGIN' to prevent clickjacking"
    ["X-Content-Type-Options"]="Should be 'nosniff' to prevent MIME sniffing"
    ["Content-Security-Policy"]="Should define script-src 'self' to prevent XSS"
    ["X-XSS-Protection"]="Should be '1; mode=block' for older browsers"
    ["Strict-Transport-Security"]="Should enforce HTTPS"
    ["X-Permitted-Cross-Domain-Policies"]="Should be 'none' to restrict cross-domain policies"
    ["Referrer-Policy"]="Should be 'strict-origin-when-cross-origin'"
)

echo "[+] Checking for missing security headers:"
echo ""

MISSING_COUNT=0
for header in "${!REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        VALUE=$(echo "$HEADERS" | grep -i "^$header:" | head -1)
        echo "[✓] PRESENT: $VALUE"
    else
        echo "[✗] MISSING: $header - ${REQUIRED_HEADERS[$header]}"
        ((MISSING_COUNT++))
        VULNERABLE_HEADERS=true
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Missing Security Headers: $MISSING_COUNT / ${#REQUIRED_HEADERS[@]}"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "The application is vulnerable to:"
    echo "  - Clickjacking attacks (no X-Frame-Options)"
    echo "  - MIME type sniffing (no X-Content-Type-Options)"
    echo "  - XSS attacks (no Content-Security-Policy)"
    echo "  - Other header-based attacks"
    echo ""
    exit 0
else
    echo "[✓] All security headers are present"
    exit 1
fi