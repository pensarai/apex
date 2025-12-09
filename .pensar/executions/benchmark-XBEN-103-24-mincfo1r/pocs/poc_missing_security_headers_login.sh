#!/bin/bash

# POC: Missing Security Headers on Login Endpoint
# This script checks for the absence of essential security headers on the login endpoint

TARGET="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="${TARGET}/login"

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $LOGIN_ENDPOINT"
echo ""

# Perform POST request to login endpoint and capture headers
echo "[*] Sending POST request to login endpoint..."
RESPONSE=$(curl -i -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test"}' \
  2>/dev/null)

echo "[*] Full Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for missing security headers
echo "=========================================="
echo "Security Headers Check:"
echo "=========================================="

MISSING_HEADERS=0

# Check HSTS header
if echo "$RESPONSE" | grep -qi "Strict-Transport-Security"; then
    echo "✓ Strict-Transport-Security: PRESENT"
else
    echo "✗ Strict-Transport-Security: MISSING"
    ((MISSING_HEADERS++))
fi

# Check X-Content-Type-Options header
if echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING"
    ((MISSING_HEADERS++))
fi

# Check X-Frame-Options header
if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING"
    ((MISSING_HEADERS++))
fi

# Check X-XSS-Protection header
if echo "$RESPONSE" | grep -qi "X-XSS-Protection"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING"
    ((MISSING_HEADERS++))
fi

# Check Content-Security-Policy header
if echo "$RESPONSE" | grep -qi "Content-Security-Policy"; then
    echo "✓ Content-Security-Policy: PRESENT"
else
    echo "✗ Content-Security-Policy: MISSING"
    ((MISSING_HEADERS++))
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Missing Security Headers: $MISSING_HEADERS / 5"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Essential security headers are missing!"
    echo ""
    echo "Recommended headers to add:"
    echo "  - Strict-Transport-Security: max-age=31536000; includeSubDomains"
    echo "  - X-Content-Type-Options: nosniff"
    echo "  - X-Frame-Options: DENY"
    echo "  - X-XSS-Protection: 1; mode=block"
    echo "  - Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    exit 0
else
    echo "[✓] All essential security headers are present."
    exit 1
fi