#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script checks for the absence of critical security headers in HTTP responses

TARGET_URL="${1:-http://localhost:5000/}"
echo "[*] Checking for missing security headers on: $TARGET_URL"
echo ""

# Perform HTTP request and capture headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

# Extract headers (everything before the blank line)
HEADERS=$(echo "$RESPONSE" | head -n 50)

echo "[+] Response Headers:"
echo "$HEADERS"
echo ""
echo "=================================="
echo "[*] Security Header Analysis:"
echo "=================================="
echo ""

# Check for each security header
MISSING_HEADERS=0

if echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options: FOUND"
else
    echo "✗ X-Frame-Options: MISSING"
    ((MISSING_HEADERS++))
fi

if echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options: FOUND"
else
    echo "✗ X-Content-Type-Options: MISSING"
    ((MISSING_HEADERS++))
fi

if echo "$HEADERS" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection: FOUND"
else
    echo "✗ X-XSS-Protection: MISSING"
    ((MISSING_HEADERS++))
fi

if echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security: FOUND"
else
    echo "✗ Strict-Transport-Security: MISSING"
    ((MISSING_HEADERS++))
fi

if echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy: FOUND"
else
    echo "✗ Content-Security-Policy: MISSING"
    ((MISSING_HEADERS++))
fi

echo ""
echo "=================================="
echo "[*] Summary: $MISSING_HEADERS out of 5 critical security headers are MISSING"
echo "=================================="
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application is missing security headers"
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi