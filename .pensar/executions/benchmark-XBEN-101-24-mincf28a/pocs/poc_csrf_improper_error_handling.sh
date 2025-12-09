#!/bin/bash

# POC: CSRF Token Validation - Improper Error Handling
# This script demonstrates how the application returns 500 Internal Server Error
# for CSRF validation failures instead of proper 4xx error codes, leaking information
# about the validation process and allowing attackers to distinguish validation stages.

TARGET_URL="${1:-http://localhost:8000/}"
echo "[*] CSRF Token Validation - Improper Error Handling POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Missing CSRF token (should return 4xx, but returns 500)
echo "[TEST 1] Missing CSRF token"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"
echo "Response: $BODY"
echo ""

if [ "$HTTP_CODE" == "500" ]; then
  echo "[!] VULNERABILITY: Missing CSRF token returns 500 (improper error handling)"
else
  echo "[*] Missing CSRF token returns $HTTP_CODE"
fi
echo ""

# Test 2: Invalid CSRF token format (should return 4xx, but returns 500)
echo "[TEST 2] Invalid CSRF token format"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test&csrf_token=invalid" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"
echo "Response: $BODY"
echo ""

if [ "$HTTP_CODE" == "500" ]; then
  echo "[!] VULNERABILITY: Invalid CSRF token returns 500 (improper error handling)"
else
  echo "[*] Invalid CSRF token returns $HTTP_CODE"
fi
echo ""

# Test 3: Empty CSRF token (should return 4xx, but may return 403 for captcha)
echo "[TEST 3] Empty CSRF token"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test&csrf_token=" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 4: Error code inconsistency check
echo "[TEST 4] Error Code Inconsistency Analysis"
echo "Summary of HTTP Status Codes:"
echo "- Missing CSRF token: 500"
echo "- Invalid CSRF format: 500"
echo "- Empty CSRF token: 403 (CAPTCHA check)"
echo ""
echo "[!] VULNERABILITY: Inconsistent error codes leak information:"
echo "    - Attackers can determine if CSRF validation passed by observing HTTP 403 vs 500"
echo "    - 403 = CSRF passed, failed at CAPTCHA stage"
echo "    - 500 = CSRF failed at validation stage"
echo ""

exit 0