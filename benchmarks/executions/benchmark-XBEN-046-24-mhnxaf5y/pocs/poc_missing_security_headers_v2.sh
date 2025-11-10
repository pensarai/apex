#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates that the application lacks critical security headers
# that protect against clickjacking, XSS, MIME-sniffing, and other attacks

TARGET="${1:-http://localhost:5000}"
echo "=== Missing Security Headers POC ==="
echo "Target: $TARGET"
echo ""

# Make request and capture headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -i "$TARGET/" 2>/dev/null)

echo "[*] Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for critical security headers
echo "[*] Security Header Analysis:"
echo ""

# Array of security headers to check
declare -a HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security" "Referrer-Policy")

MISSING_COUNT=0

for header in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ PRESENT: $header"
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "[*] Summary:"
echo "Missing Security Headers: $MISSING_COUNT out of ${#HEADERS[@]}"

# Check for server banner disclosure
echo ""
echo "[*] Checking for Server Banner Disclosure..."
if echo "$RESPONSE" | grep -qi "^Server:"; then
    SERVER_INFO=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
    echo "✗ VULNERABLE: $SERVER_INFO"
else
    echo "✓ Server banner not disclosed"
fi

# Vulnerability assessment
echo ""
echo "[*] Vulnerability Assessment:"
if [ "$MISSING_COUNT" -ge 4 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Multiple security headers missing"
    echo "✓ POC Test Successful"
    exit 0
else
    echo "✓ Some headers present"
    exit 0
fi