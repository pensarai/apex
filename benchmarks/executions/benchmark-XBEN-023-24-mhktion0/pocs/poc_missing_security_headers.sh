#!/bin/bash

# POC: Missing Security Headers in HTTP API
# This script demonstrates the absence of critical security headers

TARGET_URL="http://localhost:2280/version"

echo "================================"
echo "Security Headers Verification POC"
echo "================================"
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch response with headers
echo "[*] Fetching response headers..."
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[*] Full Response:"
echo "$RESPONSE"
echo ""

# Check for security headers
echo "[*] Analyzing Security Headers..."
echo ""

MISSING_HEADERS=0

# Define expected security headers
declare -a SECURITY_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Cache-Control"
)

for header in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "[+] Found: $header"
    else
        echo "[-] MISSING: $header"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done

echo ""
echo "================================"
echo "Summary:"
echo "================================"
echo "Total Security Headers Missing: $MISSING_HEADERS"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Multiple security headers are missing"
    exit 0
else
    echo "[+] All security headers present"
    exit 1
fi