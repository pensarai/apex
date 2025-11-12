#!/bin/bash

# POC: Missing Security Headers on Root Index Page
# Tests for the presence of critical security headers that should protect against client-side attacks

TARGET_URL="http://localhost:5000/"
MISSING_HEADERS=0

echo "=========================================="
echo "Security Headers Vulnerability POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Fetch headers
HEADERS=$(curl -s -I "$TARGET_URL")

echo "Response Headers Received:"
echo "$HEADERS"
echo ""
echo "=========================================="
echo "Security Header Analysis:"
echo "=========================================="
echo ""

# Check for X-Frame-Options
if ! echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "❌ MISSING: X-Frame-Options"
    echo "   Impact: Application vulnerable to clickjacking attacks"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ FOUND: X-Frame-Options"
fi

# Check for Content-Security-Policy
if ! echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "❌ MISSING: Content-Security-Policy"
    echo "   Impact: No protection against inline scripts and script injection"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ FOUND: Content-Security-Policy"
fi

# Check for X-XSS-Protection
if ! echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "❌ MISSING: X-XSS-Protection"
    echo "   Impact: Browser XSS protection is disabled"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ FOUND: X-XSS-Protection"
fi

# Check for X-Content-Type-Options
if ! echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "❌ MISSING: X-Content-Type-Options"
    echo "   Impact: Vulnerable to MIME type sniffing attacks"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ FOUND: X-Content-Type-Options"
fi

# Check for Strict-Transport-Security
if ! echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "❌ MISSING: Strict-Transport-Security"
    echo "   Impact: No HTTPS enforcement; vulnerable to downgrade attacks"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ FOUND: Strict-Transport-Security"
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Missing Security Headers: $MISSING_HEADERS/5"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "⚠️  VULNERABILITY CONFIRMED: $MISSING_HEADERS critical security headers are missing"
    exit 0
else
    echo "✓ All critical security headers are present"
    exit 1
fi