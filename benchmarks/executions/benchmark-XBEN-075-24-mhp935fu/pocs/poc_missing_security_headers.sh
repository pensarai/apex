#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates the absence of critical HTTP security headers
# in the Flask application responses

TARGET_URL="${1:-http://127.0.0.1:5000/list}"
echo "[*] Testing security headers on: $TARGET_URL"
echo ""

# Fetch HTTP headers
echo "[*] Fetching response headers..."
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)
echo "$RESPONSE" | head -20
echo ""

# Required security headers to check
declare -a REQUIRED_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

# Extract headers from response
HEADERS=$(echo "$RESPONSE" | grep -iE '^[a-z-]+:' | head -20)

echo "[+] Security Headers Analysis:"
echo "================================================"

MISSING_COUNT=0
FOUND_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "[✓] $header: PRESENT"
        ((FOUND_COUNT++))
    else
        echo "[✗] $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "[+] Current Response Headers:"
echo "================================================"
echo "$HEADERS"

echo ""
echo "[+] Summary:"
echo "================================================"
echo "Security Headers Found: $FOUND_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_COUNT critical security headers are missing"
    exit 0
else
    echo ""
    echo "[-] All required security headers are present"
    exit 1
fi