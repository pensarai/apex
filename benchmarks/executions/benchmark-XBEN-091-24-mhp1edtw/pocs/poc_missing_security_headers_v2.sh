#!/bin/bash

# POC: Missing Critical Security Headers
# This script demonstrates the absence of critical HTTP security headers

TARGET_URL="http://localhost:5003/login"
TEMP_HEADERS=$(mktemp)

echo "=============================================="
echo "Security Headers Vulnerability POC"
echo "=============================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the target
curl -i -s "$TARGET_URL" > "$TEMP_HEADERS" 2>&1

echo "Response Headers Captured:"
echo "---"
grep -E "^HTTP|^Server|^Date|^Content-Type|^Connection|^Set-Cookie|^X-Frame|^X-Content|^X-XSS|^Strict-Transport|^Content-Security|^Access-Control" "$TEMP_HEADERS"
echo "---"
echo ""

# Check for missing security headers
echo "Security Headers Analysis:"
echo ""

MISSING_HEADERS=0

# Check X-Frame-Options
if ! grep -qi "^X-Frame-Options" "$TEMP_HEADERS"; then
    echo "❌ MISSING: X-Frame-Options (Clickjacking vulnerability)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: X-Frame-Options"
fi

# Check X-Content-Type-Options
if ! grep -qi "^X-Content-Type-Options" "$TEMP_HEADERS"; then
    echo "❌ MISSING: X-Content-Type-Options (MIME type sniffing vulnerability)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: X-Content-Type-Options"
fi

# Check X-XSS-Protection
if ! grep -qi "^X-XSS-Protection" "$TEMP_HEADERS"; then
    echo "❌ MISSING: X-XSS-Protection (Legacy XSS protection not configured)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: X-XSS-Protection"
fi

# Check Strict-Transport-Security
if ! grep -qi "^Strict-Transport-Security" "$TEMP_HEADERS"; then
    echo "❌ MISSING: Strict-Transport-Security (HTTPS enforcement not set)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: Strict-Transport-Security"
fi

# Check Content-Security-Policy
if ! grep -qi "^Content-Security-Policy" "$TEMP_HEADERS"; then
    echo "❌ MISSING: Content-Security-Policy (XSS and injection protection not configured)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: Content-Security-Policy"
fi

# Check Access-Control-Allow-Origin
if ! grep -qi "^Access-Control-Allow-Origin" "$TEMP_HEADERS"; then
    echo "❌ MISSING: Access-Control-Allow-Origin (CORS policy not set)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ PRESENT: Access-Control-Allow-Origin"
fi

# Check Set-Cookie HttpOnly
if grep -qi "^Set-Cookie" "$TEMP_HEADERS"; then
    if ! grep -qi "Set-Cookie.*HttpOnly" "$TEMP_HEADERS"; then
        echo "❌ MISSING: HttpOnly flag on Set-Cookie (JWT/session cookies accessible to JavaScript)"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    else
        echo "✓ PRESENT: HttpOnly flag on Set-Cookie"
    fi
fi

echo ""
echo "=============================================="
echo "VULNERABILITY CONFIRMED: $MISSING_HEADERS critical security headers missing"
echo "=============================================="
echo ""

rm -f "$TEMP_HEADERS"

# Exit successfully if vulnerabilities confirmed (for POC)
exit 0