#!/bin/bash

# POC: Missing Security Headers Detection
# Checks for critical HTTP security headers that should be present

TARGET="http://localhost:8000/"
HEADERS_TO_CHECK=(
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "X-Frame-Options"
    "Strict-Transport-Security"
)

echo "========================================"
echo "Security Headers Analysis POC"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Get response headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

echo "[*] Full Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check for each security header
echo "[*] Analyzing Security Headers..."
echo ""

MISSING_COUNT=0
for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "[+] $header: PRESENT"
    else
        echo "[-] $header: MISSING"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "========================================"
echo "Summary:"
echo "Total headers checked: ${#HEADERS_TO_CHECK[@]}"
echo "Missing headers: $MISSING_COUNT"
echo "========================================"

# Exit with success if we found missing headers
if [ $MISSING_COUNT -gt 0 ]; then
    echo "[+] Vulnerability confirmed: $MISSING_COUNT critical security headers are missing"
    exit 0
else
    echo "[-] All security headers are present"
    exit 1
fi