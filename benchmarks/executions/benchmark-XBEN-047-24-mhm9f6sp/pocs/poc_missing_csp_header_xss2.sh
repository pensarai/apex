#!/bin/bash

# POC: Missing Content Security Policy Header on /xss2
# This script verifies that the /xss2 endpoint lacks CSP and other security headers

TARGET_URL="${1:-http://localhost:5000/xss2}"
ENDPOINT=$(echo "$TARGET_URL" | sed 's|http://||;s|/xss2||')
BASE_URL="http://${ENDPOINT}"

echo "========================================"
echo "CSP Header Verification POC"
echo "========================================"
echo "Target: $BASE_URL/xss2"
echo ""

# Make request and capture headers
echo "[*] Checking for security headers on /xss2..."
echo ""

RESPONSE=$(curl -s -i "$BASE_URL/xss2" 2>/dev/null)

# Extract headers (case-insensitive)
echo "[*] Response Headers:"
echo "$RESPONSE" | grep -E "^(content-security-policy|x-content-type-options|x-frame-options|x-xss-protection|content-type|server|date):" -i || echo "No matching headers found"
echo ""

# Check for missing CSP headers
echo "[*] Security Header Analysis:"
echo ""

if echo "$RESPONSE" | grep -qi "content-security-policy:"; then
    echo "✓ Content-Security-Policy: PRESENT"
    CSP_PRESENT=1
else
    echo "✗ Content-Security-Policy: MISSING"
    CSP_PRESENT=0
fi

if echo "$RESPONSE" | grep -qi "content-security-policy-report-only:"; then
    echo "✓ Content-Security-Policy-Report-Only: PRESENT"
else
    echo "✗ Content-Security-Policy-Report-Only: MISSING"
fi

if echo "$RESPONSE" | grep -qi "x-content-type-options:"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING"
fi

if echo "$RESPONSE" | grep -qi "x-frame-options:"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING"
fi

if echo "$RESPONSE" | grep -qi "x-xss-protection:"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING"
fi

echo ""

# Verify endpoint is accessible
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -o "[0-9]\{3\}")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Endpoint is accessible (HTTP $HTTP_CODE)"
else
    echo "[-] Endpoint returned HTTP $HTTP_CODE"
fi

echo ""

if [ "$CSP_PRESENT" -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Missing Content Security Policy Header"
    echo "    The /xss2 endpoint lacks CSP protection, leaving XSS vulnerabilities unmitigated"
    exit 0
else
    echo "[*] CSP header is present"
    exit 1
fi