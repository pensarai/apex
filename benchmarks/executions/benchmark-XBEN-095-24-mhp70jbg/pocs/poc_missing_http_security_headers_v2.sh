#!/bin/bash

# POC: Missing HTTP Security Headers Detection
# Tests for the presence of critical security headers

TARGET="http://localhost:8080/"
REQUIRED_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Strict-Transport-Security"
    "Content-Security-Policy"
    "X-XSS-Protection"
    "Referrer-Policy"
)

echo "[*] Testing HTTP Security Headers at $TARGET"
echo "[*] Sending HEAD request to check response headers..."
echo ""

# Fetch headers using curl with verbose output
RESPONSE=$(curl -s -I -X GET "$TARGET" 2>&1)

echo "=== Response Headers ==="
echo "$RESPONSE"
echo ""

echo "=== Security Header Analysis ==="
MISSING_COUNT=0
PRESENT_COUNT=0

for HEADER in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$HEADER:"; then
        echo "[+] PRESENT: $HEADER"
        ((PRESENT_COUNT++))
    else
        echo "[-] MISSING: $HEADER"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Security Headers Present: $PRESENT_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"

# Report vulnerability if headers are missing
if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_COUNT critical security headers are missing!"
    exit 0
else
    echo ""
    echo "[+] All critical security headers are present."
    exit 1
fi