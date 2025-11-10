#!/bin/bash

# POC: Missing Security Headers on Login Page
# Tests for absence of critical security headers on GET /login

TARGET="${1:-http://localhost:80}"
LOGIN_URL="${TARGET}/login"

echo "=========================================="
echo "Security Headers Verification POC"
echo "=========================================="
echo "Target: $LOGIN_URL"
echo ""

# Perform HEAD request to get headers
echo "[*] Fetching headers from $LOGIN_URL..."
RESPONSE=$(curl -s -I "$LOGIN_URL" 2>&1)

echo "[*] Response Headers:"
echo "$RESPONSE"
echo ""

# Check for missing security headers
MISSING_HEADERS=0

echo "[*] Analyzing Security Headers..."
echo ""

# Check X-Frame-Options
if ! echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
    echo "❌ MISSING: X-Frame-Options (Clickjacking Protection)"
    ((MISSING_HEADERS++))
else
    echo "✓ PRESENT: X-Frame-Options"
fi

# Check X-Content-Type-Options
if ! echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "❌ MISSING: X-Content-Type-Options (MIME Sniffing Protection)"
    ((MISSING_HEADERS++))
else
    echo "✓ PRESENT: X-Content-Type-Options"
fi

# Check X-XSS-Protection
if ! echo "$RESPONSE" | grep -qi "X-XSS-Protection"; then
    echo "❌ MISSING: X-XSS-Protection (Reflected XSS Protection)"
    ((MISSING_HEADERS++))
else
    echo "✓ PRESENT: X-XSS-Protection"
fi

# Check Strict-Transport-Security
if ! echo "$RESPONSE" | grep -qi "Strict-Transport-Security"; then
    echo "❌ MISSING: Strict-Transport-Security / HSTS (HTTPS Enforcement)"
    ((MISSING_HEADERS++))
else
    echo "✓ PRESENT: Strict-Transport-Security"
fi

# Check Content-Security-Policy
if ! echo "$RESPONSE" | grep -qi "Content-Security-Policy"; then
    echo "❌ MISSING: Content-Security-Policy (CSP)"
    ((MISSING_HEADERS++))
else
    echo "✓ PRESENT: Content-Security-Policy"
fi

# Check Referrer-Policy
if ! echo "$RESPONSE" | grep -qi "Referrer-Policy"; then
    echo "❌ MISSING: Referrer-Policy (Referer Data Control)"
    ((MISSING_HEADERS++))
else
    echo "✓ PRESENT: Referrer-Policy"
fi

echo ""
echo "=========================================="
echo "Summary: $MISSING_HEADERS security headers missing"
echo "=========================================="

# Exit with success if at least some headers are missing (vulnerability confirmed)
if [ $MISSING_HEADERS -gt 0 ]; then
    exit 0
else
    exit 1
fi