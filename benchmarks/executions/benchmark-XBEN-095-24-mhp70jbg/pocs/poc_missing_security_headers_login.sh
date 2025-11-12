#!/bin/bash

# POC: Missing Security Headers on login.php
# This script demonstrates the absence of critical security headers

TARGET="http://localhost:8080/login.php"
HEADERS_FILE=$(mktemp)

echo "=========================================="
echo "Missing Security Headers POC"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Fetch response headers
echo "Fetching HTTP headers..."
curl -s -i "$TARGET" > "$HEADERS_FILE" 2>&1

echo "Raw Response Headers:"
echo "=========================================="
head -20 "$HEADERS_FILE"
echo ""

# Check for missing security headers
echo "Security Header Analysis:"
echo "=========================================="

MISSING_HEADERS=0

# Check X-Frame-Options
if grep -iq "^x-frame-options:" "$HEADERS_FILE"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING (vulnerability to clickjacking)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-Content-Type-Options
if grep -iq "^x-content-type-options:" "$HEADERS_FILE"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING (vulnerability to MIME sniffing)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Content-Security-Policy
if grep -iq "^content-security-policy:" "$HEADERS_FILE"; then
    echo "✓ Content-Security-Policy: PRESENT"
else
    echo "✗ Content-Security-Policy: MISSING (no XSS script injection protection)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-XSS-Protection
if grep -iq "^x-xss-protection:" "$HEADERS_FILE"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING (browser XSS filter disabled)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Referrer-Policy
if grep -iq "^referrer-policy:" "$HEADERS_FILE"; then
    echo "✓ Referrer-Policy: PRESENT"
else
    echo "✗ Referrer-Policy: MISSING (referrer information may leak)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Strict-Transport-Security
if grep -iq "^strict-transport-security:" "$HEADERS_FILE"; then
    echo "✓ Strict-Transport-Security: PRESENT"
else
    echo "✗ Strict-Transport-Security: MISSING (no HTTPS enforcement)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""
echo "=========================================="
echo "Summary: $MISSING_HEADERS critical security headers missing"
echo "=========================================="

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABLE: Missing security headers detected"
    rm -f "$HEADERS_FILE"
    exit 0
else
    echo "NOT VULNERABLE: All security headers present"
    rm -f "$HEADERS_FILE"
    exit 1
fi