#!/bin/bash

# POC: Missing Security Response Headers Detection
# Tests for the absence of critical security headers:
# - Content-Security-Policy (CSP)
# - X-Frame-Options
# - X-Content-Type-Options
# - X-XSS-Protection
# - Strict-Transport-Security (HSTS)

TARGET="${1:-http://localhost:8000}"

echo "=========================================="
echo "Security Headers Vulnerability Scanner"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Array of security headers to check
declare -a HEADERS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
)

# Fetch HTTP response headers
echo "[*] Fetching response headers..."
RESPONSE_HEADERS=$(curl -s -i "$TARGET" 2>&1)

echo ""
echo "=========================================="
echo "Security Header Check Results:"
echo "=========================================="
echo ""

MISSING_COUNT=0
FOUND_COUNT=0

for HEADER in "${HEADERS[@]}"; do
    # Check if header exists (case-insensitive)
    if echo "$RESPONSE_HEADERS" | grep -qi "^$HEADER:"; then
        HEADER_VALUE=$(echo "$RESPONSE_HEADERS" | grep -i "^$HEADER:" | head -1)
        echo "[✓] FOUND: $HEADER_VALUE"
        ((FOUND_COUNT++))
    else
        echo "[✗] MISSING: $HEADER"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Headers Found: $FOUND_COUNT"
echo "Headers Missing: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application is missing $MISSING_COUNT critical security headers"
    echo ""
    echo "Risks:"
    echo "  - Without X-Frame-Options: Vulnerable to clickjacking attacks"
    echo "  - Without X-Content-Type-Options: Vulnerable to MIME sniffing leading to XSS"
    echo "  - Without CSP: Increased XSS severity and malicious script injection"
    echo "  - Without X-XSS-Protection: Reduced XSS protection in older browsers"
    echo "  - Without HSTS: Vulnerable to SSL stripping attacks"
    echo ""
    echo "POC Result: VULNERABILITY DETECTED ✗"
    exit 0
else
    echo "[+] All security headers are properly configured"
    exit 0
fi