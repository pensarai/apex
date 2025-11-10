#!/bin/bash

# POC: Missing Critical Security Headers Detection
# Tests for the presence of critical security headers on http://localhost:80

TARGET_URL="http://localhost:80"
MISSING_HEADERS=0
FOUND_HEADERS=0

echo "========================================"
echo "Security Headers Vulnerability Test"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Get response headers
HEADERS=$(curl -I -s "$TARGET_URL")

echo "HTTP Response Headers:"
echo "$HEADERS"
echo ""
echo "========================================"
echo "Security Header Analysis:"
echo "========================================"

# Check for Content-Security-Policy
if echo "$HEADERS" | grep -iq "Content-Security-Policy"; then
    echo "[FOUND] Content-Security-Policy: $(echo "$HEADERS" | grep -i "Content-Security-Policy")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] Content-Security-Policy (CSP)"
    ((MISSING_HEADERS++))
fi

# Check for X-Frame-Options
if echo "$HEADERS" | grep -iq "X-Frame-Options"; then
    echo "[FOUND] X-Frame-Options: $(echo "$HEADERS" | grep -i "X-Frame-Options")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] X-Frame-Options"
    ((MISSING_HEADERS++))
fi

# Check for X-Content-Type-Options
if echo "$HEADERS" | grep -iq "X-Content-Type-Options"; then
    echo "[FOUND] X-Content-Type-Options: $(echo "$HEADERS" | grep -i "X-Content-Type-Options")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] X-Content-Type-Options"
    ((MISSING_HEADERS++))
fi

# Check for X-XSS-Protection
if echo "$HEADERS" | grep -iq "X-XSS-Protection"; then
    echo "[FOUND] X-XSS-Protection: $(echo "$HEADERS" | grep -i "X-XSS-Protection")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] X-XSS-Protection"
    ((MISSING_HEADERS++))
fi

# Check for Strict-Transport-Security
if echo "$HEADERS" | grep -iq "Strict-Transport-Security"; then
    echo "[FOUND] Strict-Transport-Security: $(echo "$HEADERS" | grep -i "Strict-Transport-Security")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] Strict-Transport-Security (HSTS)"
    ((MISSING_HEADERS++))
fi

# Check for Referrer-Policy
if echo "$HEADERS" | grep -iq "Referrer-Policy"; then
    echo "[FOUND] Referrer-Policy: $(echo "$HEADERS" | grep -i "Referrer-Policy")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] Referrer-Policy"
    ((MISSING_HEADERS++))
fi

# Check for Permissions-Policy
if echo "$HEADERS" | grep -iq "Permissions-Policy"; then
    echo "[FOUND] Permissions-Policy: $(echo "$HEADERS" | grep -i "Permissions-Policy")"
    ((FOUND_HEADERS++))
else
    echo "[MISSING] Permissions-Policy"
    ((MISSING_HEADERS++))
fi

echo ""
echo "========================================"
echo "Summary:"
echo "========================================"
echo "Found: $FOUND_HEADERS/7 security headers"
echo "Missing: $MISSING_HEADERS/7 security headers"
echo ""

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Critical security headers are missing"
    exit 0
else
    echo "No vulnerability detected - all security headers are present"
    exit 1
fi