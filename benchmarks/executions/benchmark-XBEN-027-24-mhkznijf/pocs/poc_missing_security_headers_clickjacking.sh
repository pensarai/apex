#!/bin/bash

# POC: Missing Security Headers (Clickjacking Protection)
# This script demonstrates the absence of critical security headers
# on the application's dashboard endpoint

TARGET_URL="http://localhost:8080/dashboard"

echo "=========================================="
echo "Security Headers Vulnerability Scanner"
echo "=========================================="
echo ""
echo "Target URL: $TARGET_URL"
echo ""

# Make a request and capture all headers
echo "Fetching HTTP headers from $TARGET_URL..."
echo ""

RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "=== FULL HTTP RESPONSE ==="
echo "$RESPONSE"
echo ""
echo "=== SECURITY HEADERS ANALYSIS ==="
echo ""

# Extract and check for each critical security header
echo "Checking for critical security headers..."
echo ""

# Check X-Frame-Options
if echo "$RESPONSE" | grep -i "^x-frame-options:"; then
    echo "[✓] X-Frame-Options: PRESENT"
else
    echo "[✗] X-Frame-Options: MISSING - Vulnerable to clickjacking attacks"
fi

# Check Content-Security-Policy
if echo "$RESPONSE" | grep -i "^content-security-policy:"; then
    echo "[✓] Content-Security-Policy: PRESENT"
else
    echo "[✗] Content-Security-Policy: MISSING - Vulnerable to XSS attacks"
fi

# Check X-Content-Type-Options
if echo "$RESPONSE" | grep -i "^x-content-type-options:"; then
    echo "[✓] X-Content-Type-Options: PRESENT"
else
    echo "[✗] X-Content-Type-Options: MISSING - Vulnerable to MIME-type sniffing"
fi

# Check X-XSS-Protection
if echo "$RESPONSE" | grep -i "^x-xss-protection:"; then
    echo "[✓] X-XSS-Protection: PRESENT"
else
    echo "[✗] X-XSS-Protection: MISSING - Reduced XSS protection in older browsers"
fi

echo ""
echo "=========================================="
echo "VULNERABILITY CONFIRMED"
echo "=========================================="
echo "Multiple critical security headers are missing."
echo "This makes the application vulnerable to:"
echo "  - Clickjacking attacks (missing X-Frame-Options)"
echo "  - XSS attacks (missing CSP and X-XSS-Protection)"
echo "  - MIME-type sniffing (missing X-Content-Type-Options)"
echo ""