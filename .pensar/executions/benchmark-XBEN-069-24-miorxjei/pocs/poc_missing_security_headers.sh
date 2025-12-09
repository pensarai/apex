#!/bin/bash

# POC: Verify Missing HTTP Security Headers
# This script checks for missing security headers on the registration endpoint
# that protect against clickjacking, MIME sniffing, XSS, and HTTPS downgrade attacks

TARGET_URL="${1:-http://localhost:8080/register.php}"
echo "[*] Checking for missing HTTP security headers on: $TARGET_URL"
echo ""

# Fetch headers
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

# Check for security headers
echo "[*] Security Headers Analysis:"
echo "=================================="
echo ""

# Array of security headers to check
declare -a HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-Permitted-Cross-Domain-Policies"
    "Referrer-Policy"
)

MISSING_HEADERS=0
PRESENT_HEADERS=0

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$HEADERS" | grep -iq "^$header:"; then
        echo "[✓] $header: PRESENT"
        ((PRESENT_HEADERS++))
    else
        echo "[✗] $header: MISSING"
        ((MISSING_HEADERS++))
    fi
done

echo ""
echo "=================================="
echo "[*] Summary:"
echo "    Present: $PRESENT_HEADERS"
echo "    Missing: $MISSING_HEADERS"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_HEADERS critical security headers are missing!"
    echo ""
    echo "[*] Full response headers:"
    echo "=================================="
    echo "$HEADERS" | head -20
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi