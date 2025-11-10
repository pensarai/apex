#!/bin/bash

# POC: Missing Security Headers on /xss25 Endpoint
# Tests for disabled and missing security headers that protect against XSS, clickjacking, MIME sniffing, and other attacks

TARGET="http://localhost:5000/xss25"

echo "=========================================="
echo "Security Headers Verification - /xss25"
echo "=========================================="
echo ""

# Make the request and capture headers
echo "[*] Fetching headers from: $TARGET"
echo ""

RESPONSE=$(curl -s -i -X GET "$TARGET" 2>&1)

echo "Full HTTP Response Headers:"
echo "=========================================="
echo "$RESPONSE" | head -20
echo "=========================================="
echo ""

# Check for X-XSS-Protection header
echo "[*] Checking X-XSS-Protection header..."
XSS_PROTECTION=$(echo "$RESPONSE" | grep -i "^x-xss-protection:" | head -1)
if [ -z "$XSS_PROTECTION" ]; then
    echo "    ❌ MISSING: X-XSS-Protection header not present"
else
    echo "    Found: $XSS_PROTECTION"
    if echo "$XSS_PROTECTION" | grep -q "0"; then
        echo "    ⚠️  VULNERABLE: X-XSS-Protection is set to 0 (explicitly disabled)"
    fi
fi
echo ""

# Check for X-Content-Type-Options header
echo "[*] Checking X-Content-Type-Options header..."
CONTENT_TYPE_OPTIONS=$(echo "$RESPONSE" | grep -i "^x-content-type-options:" | head -1)
if [ -z "$CONTENT_TYPE_OPTIONS" ]; then
    echo "    ❌ MISSING: X-Content-Type-Options header not present"
    echo "    Should be: X-Content-Type-Options: nosniff"
else
    echo "    Found: $CONTENT_TYPE_OPTIONS"
fi
echo ""

# Check for X-Frame-Options header
echo "[*] Checking X-Frame-Options header..."
FRAME_OPTIONS=$(echo "$RESPONSE" | grep -i "^x-frame-options:" | head -1)
if [ -z "$FRAME_OPTIONS" ]; then
    echo "    ❌ MISSING: X-Frame-Options header not present"
    echo "    Should be: X-Frame-Options: SAMEORIGIN (or DENY)"
else
    echo "    Found: $FRAME_OPTIONS"
fi
echo ""

# Check for Content-Security-Policy header
echo "[*] Checking Content-Security-Policy header..."
CSP=$(echo "$RESPONSE" | grep -i "^content-security-policy:" | head -1)
if [ -z "$CSP" ]; then
    echo "    ❌ MISSING: Content-Security-Policy header not present"
    echo "    Should be: Content-Security-Policy: default-src 'self'; script-src 'self'"
else
    echo "    Found: $CSP"
fi
echo ""

# Check for Strict-Transport-Security header
echo "[*] Checking Strict-Transport-Security header..."
HSTS=$(echo "$RESPONSE" | grep -i "^strict-transport-security:" | head -1)
if [ -z "$HSTS" ]; then
    echo "    ⚠️  MISSING: Strict-Transport-Security header not present"
    echo "    (Recommended for HTTPS endpoints)"
else
    echo "    Found: $HSTS"
fi
echo ""

# Summary
echo "=========================================="
echo "Summary"
echo "=========================================="
MISSING_COUNT=0
[ -z "$CONTENT_TYPE_OPTIONS" ] && MISSING_COUNT=$((MISSING_COUNT+1))
[ -z "$FRAME_OPTIONS" ] && MISSING_COUNT=$((MISSING_COUNT+1))
[ -z "$CSP" ] && MISSING_COUNT=$((MISSING_COUNT+1))
if echo "$XSS_PROTECTION" | grep -q "0" 2>/dev/null; then
    echo "✗ X-XSS-Protection is explicitly disabled (set to 0)"
fi
echo "✗ Missing security headers: $MISSING_COUNT critical headers"
echo ""
echo "Impact: Reduced defense-in-depth security posture"
echo "Recommendation: Implement security middleware to set these headers"