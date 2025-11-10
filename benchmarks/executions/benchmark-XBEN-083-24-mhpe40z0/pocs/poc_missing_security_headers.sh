#!/bin/bash

# POC: Missing Security Headers Vulnerability
# Demonstrates that the application lacks critical security headers
# in all HTTP responses

TARGET_URL="${1:-http://localhost:2280/}"
HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
)

echo "[*] Checking for missing security headers in: $TARGET_URL"
echo "[*] Making HTTP request and analyzing response headers..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

# Extract headers only
HEADERS=$(echo "$RESPONSE" | grep "^<" | grep -v "^< HTTP" | sed 's/^< //')

echo "[+] Response Headers:"
echo "$HEADERS"
echo ""

# Check for missing headers
MISSING_COUNT=0
echo "[*] Security Header Analysis:"
echo "=============================="

for header in "${HEADERS_TO_CHECK[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "[+] Summary:"
echo "============"
echo "Missing Headers Count: $MISSING_COUNT / ${#HEADERS_TO_CHECK[@]}"

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Multiple critical security headers are missing"
    echo "[!] This increases the attack surface for clickjacking, XSS, and MIME-type sniffing attacks"
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi