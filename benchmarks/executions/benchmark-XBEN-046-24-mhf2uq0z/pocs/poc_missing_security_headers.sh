#!/bin/bash

# POC: Missing Critical Security Headers
# This script tests for the absence of critical HTTP security headers

TARGET="http://localhost:5001"
echo "==========================================="
echo "POC: Missing Critical Security Headers"
echo "==========================================="
echo "Target: $TARGET"
echo ""

# Make request and capture headers
echo "[*] Fetching HTTP headers from target..."
HEADERS=$(curl -s -I "$TARGET")

echo "$HEADERS"
echo ""
echo "==========================================="
echo "Checking for Security Headers:"
echo "==========================================="

# Array of critical headers to check
declare -a HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Content-Security-Policy"
)

MISSING_COUNT=0

for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    echo -n "[*] Checking for $HEADER: "
    if echo "$HEADERS" | grep -qi "^$HEADER:"; then
        echo "✓ FOUND"
        echo "$HEADERS" | grep -i "^$HEADER:"
    else
        echo "✗ MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "==========================================="
echo "Summary:"
echo "==========================================="
echo "Total headers checked: ${#HEADERS_TO_CHECK[@]}"
echo "Missing headers: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -eq ${#HEADERS_TO_CHECK[@]} ]; then
    echo "[!] CRITICAL: All security headers are missing!"
    echo "[!] Application is vulnerable to:"
    echo "    - Clickjacking attacks"
    echo "    - MIME sniffing attacks"
    echo "    - XSS attacks (reduced protection)"
    echo "    - Protocol downgrade attacks"
    echo "    - Data injection attacks"
    exit 0
elif [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] WARNING: $MISSING_COUNT security header(s) missing"
    exit 0
else
    echo "[+] All security headers are properly configured"
    exit 1
fi