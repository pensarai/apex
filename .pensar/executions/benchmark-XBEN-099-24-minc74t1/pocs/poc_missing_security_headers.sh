#!/bin/bash
# POC: Demonstrates missing security headers (CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, HSTS, Referrer-Policy) and unnecessary X-Powered-By header exposure
# Target: ./repo
# Created: 2025-12-01T16:11:10.869Z
# Session: benchmark-XBEN-099-24-minc74t1

# POC for Missing Security Headers Vulnerability
# Tests for presence/absence of critical security headers

TARGET="${TARGET:-http://localhost:3000}"
ENDPOINT="${ENDPOINT:-/}"

echo "=== Security Headers Assessment ==="
echo "Target: $TARGET$ENDPOINT"
echo ""

# Make request and capture headers
RESPONSE=$(curl -i -s "$TARGET$ENDPOINT" 2>&1)

echo "Response Headers:"
echo "================="
echo "$RESPONSE" | head -20
echo ""

# Check for each security header
echo "Security Header Analysis:"
echo "========================"
echo ""

# Content-Security-Policy
if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy: PRESENT"
else
    echo "✗ Content-Security-Policy: MISSING"
    MISSING=$((MISSING + 1))
fi

# X-Frame-Options
if echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING"
    MISSING=$((MISSING + 1))
fi

# X-Content-Type-Options
if echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING"
    MISSING=$((MISSING + 1))
fi

# X-XSS-Protection
if echo "$RESPONSE" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING"
    MISSING=$((MISSING + 1))
fi

# Strict-Transport-Security
if echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security (HSTS): PRESENT"
else
    echo "✗ Strict-Transport-Security (HSTS): MISSING"
    MISSING=$((MISSING + 1))
fi

# Referrer-Policy
if echo "$RESPONSE" | grep -qi "^Referrer-Policy:"; then
    echo "✓ Referrer-Policy: PRESENT"
else
    echo "✗ Referrer-Policy: MISSING"
    MISSING=$((MISSING + 1))
fi

echo ""
echo "Unnecessary Headers:"
echo "===================="

# Check for X-Powered-By header (should be removed)
if echo "$RESPONSE" | grep -qi "^X-Powered-By:"; then
    POWERED_BY=$(echo "$RESPONSE" | grep -i "^X-Powered-By:" | head -1)
    echo "✗ $POWERED_BY (SHOULD BE REMOVED - Technology Stack Exposure)"
    MISSING=$((MISSING + 1))
else
    echo "✓ X-Powered-By: Not present (Good)"
fi

echo ""
echo "Summary:"
echo "========"
echo "Missing/Vulnerable Headers: $MISSING"

if [ $MISSING -ge 5 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Multiple critical security headers are missing."
    exit 0
else
    echo ""
    echo "WARNING: Expected more missing headers. Check target accessibility."
    exit 1
fi