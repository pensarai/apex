#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for missing security headers that should protect against
# clickjacking, MIME-sniffing, XSS, and cookie-based attacks

TARGET_URL="${1:-http://localhost/index.php}"

echo "=========================================="
echo "Security Headers Analysis"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "=========================================="
echo "$HEADERS"
echo ""
echo "=========================================="
echo "Security Header Analysis:"
echo "=========================================="

# Check for missing security headers
MISSING_HEADERS=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "x-frame-options"; then
    echo "[✓] X-Frame-Options: Present"
else
    echo "[✗] X-Frame-Options: MISSING - No clickjacking protection"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "x-content-type-options"; then
    echo "[✓] X-Content-Type-Options: Present"
else
    echo "[✗] X-Content-Type-Options: MISSING - No MIME-sniffing protection"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "content-security-policy"; then
    echo "[✓] Content-Security-Policy: Present"
else
    echo "[✗] Content-Security-Policy: MISSING - No XSS/injection protection"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "x-xss-protection"; then
    echo "[✓] X-XSS-Protection: Present"
else
    echo "[✗] X-XSS-Protection: MISSING - No legacy XSS protection"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "strict-transport-security"; then
    echo "[✓] Strict-Transport-Security: Present"
else
    echo "[✗] Strict-Transport-Security: MISSING - No HTTPS enforcement"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Set-Cookie with security attributes
if echo "$HEADERS" | grep -qi "set-cookie"; then
    echo "[~] Set-Cookie: Present (checking security attributes...)"
    if echo "$HEADERS" | grep -i "set-cookie" | grep -qi "httponly"; then
        echo "    [✓] HttpOnly flag: Present"
    else
        echo "    [✗] HttpOnly flag: MISSING - XSS attacks could steal cookies"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
    if echo "$HEADERS" | grep -i "set-cookie" | grep -qi "secure"; then
        echo "    [✓] Secure flag: Present"
    else
        echo "    [✗] Secure flag: MISSING - MITM attacks could intercept cookies"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
    if echo "$HEADERS" | grep -i "set-cookie" | grep -qi "samesite"; then
        echo "    [✓] SameSite attribute: Present"
    else
        echo "    [✗] SameSite attribute: MISSING - CSRF attacks could exploit cookies"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
else
    echo "[✓] Set-Cookie: Not present (no session cookies to protect)"
fi

echo ""
echo "=========================================="
echo "Summary: $MISSING_HEADERS security header issues found"
echo "=========================================="

if [ $MISSING_HEADERS -gt 0 ]; then
    exit 0  # Vulnerability confirmed
else
    exit 1  # No vulnerabilities found
fi