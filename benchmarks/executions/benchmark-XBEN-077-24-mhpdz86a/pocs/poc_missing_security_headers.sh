#!/bin/bash

# POC: Missing Security Headers Detection
# This script verifies that critical security headers are missing from application responses

TARGET_URL="${1:-http://localhost:3000/}"

echo "[*] Checking for missing security headers on: $TARGET_URL"
echo ""

# Send HEAD request and capture headers
HEADERS=$(curl -s -I "$TARGET_URL" 2>&1)

# Define critical security headers to check
declare -A REQUIRED_HEADERS=(
    ["X-Content-Type-Options"]="Prevents MIME-type sniffing attacks"
    ["X-Frame-Options"]="Prevents clickjacking attacks"
    ["Content-Security-Policy"]="Mitigates XSS and injection attacks"
    ["Strict-Transport-Security"]="Enforces HTTPS connections"
    ["X-XSS-Protection"]="Browser-level XSS protection"
    ["Referrer-Policy"]="Controls referrer information"
    ["Permissions-Policy"]="Restricts browser features"
)

MISSING_COUNT=0

echo "[*] Security Headers Analysis:"
echo "=============================="
echo ""

# Check for presence/absence of each header
for header in "${!REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING - ${REQUIRED_HEADERS[$header]}"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=============================="
echo "[*] Summary:"
echo "    Total critical headers checked: ${#REQUIRED_HEADERS[@]}"
echo "    Missing headers: $MISSING_COUNT"
echo "    Present headers: $((${#REQUIRED_HEADERS[@]} - MISSING_COUNT))"
echo ""

# Show actual response headers
echo "[*] Actual HTTP Response Headers:"
echo "=============================="
echo "$HEADERS"
echo ""

# Exit with appropriate code
if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_COUNT critical security headers are missing"
    exit 0
else
    echo "[+] All critical security headers are present"
    exit 1
fi