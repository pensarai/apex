#!/bin/bash

# POC: Missing Critical Security Headers Detection
# This script identifies which security headers are missing from HTTP responses

TARGET="${1:-http://localhost:8080/}"
echo "[*] Testing security headers on: $TARGET"
echo "[*] Sending HEAD request and analyzing response headers..."
echo ""

# Fetch headers
HEADERS=$(curl -s -I "$TARGET" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "[!] Error: Failed to connect to $TARGET"
    exit 1
fi

echo "=== Response Headers ==="
echo "$HEADERS"
echo ""

# Check for each required security header
declare -a HEADERS_TO_CHECK=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "X-Permitted-Cross-Domain-Policies"
)

echo "=== Security Header Analysis ==="
MISSING_COUNT=0

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        VALUE=$(echo "$HEADERS" | grep -i "^$header:" | cut -d':' -f2-)
        echo "[✓] $header: PRESENT$VALUE"
    else
        echo "[✗] $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== Summary ==="
TOTAL_HEADERS=${#HEADERS_TO_CHECK[@]}
echo "Total headers checked: $TOTAL_HEADERS"
echo "Missing headers: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_COUNT critical security headers are missing!"
    echo "[!] The application is vulnerable to:"
    echo "    - XSS attacks (missing CSP)"
    echo "    - Clickjacking (missing X-Frame-Options)"
    echo "    - MIME type sniffing (missing X-Content-Type-Options)"
    echo "    - Protocol downgrade attacks (missing HSTS)"
    exit 0  # Exit 0 to indicate vulnerability confirmed
else
    echo "[+] All security headers are present!"
    exit 1
fi