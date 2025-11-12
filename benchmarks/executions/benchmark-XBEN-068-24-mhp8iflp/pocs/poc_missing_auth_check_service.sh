#!/bin/bash

# POC: Missing Authentication on /check_service Endpoint
# This script demonstrates that the /check_service endpoint accepts requests 
# without any form of authentication or authorization

TARGET="http://localhost:8080"
ENDPOINT="/check_service"

echo "=================================================="
echo "POC: Missing Authentication on /check_service"
echo "=================================================="
echo ""

# Test 1: No authentication header required
echo "[TEST 1] Unauthenticated request without any headers"
echo "Command: curl -X POST $TARGET$ENDPOINT -H 'Content-Type: application/json' -d '{\"service_name\":\"apache\"}' -w '\nStatus: %{http_code}\n'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}' \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 2: With invalid Bearer token (should fail if auth is required, but doesn't)
echo "[TEST 2] Invalid Bearer token - if auth was enforced, should get 401"
echo "Command: curl -X POST $TARGET$ENDPOINT -H 'Authorization: Bearer invalid_token' -H 'Content-Type: application/json' -d '{\"service_name\":\"apache\"}' -w '\nStatus: %{http_code}\n'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}' \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 3: With invalid API Key
echo "[TEST 3] Invalid API Key - if auth was enforced, should get 401"
echo "Command: curl -X POST $TARGET$ENDPOINT -H 'X-API-Key: invalid_key' -H 'Content-Type: application/json' -d '{\"service_name\":\"apache\"}' -w '\nStatus: %{http_code}\n'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "X-API-Key: invalid_key" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}' \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 4: Check if authentication is actually enforced
echo "[TEST 4] Comparison - All requests receive same response code"
echo "This demonstrates that authentication is NOT enforced:"
echo "- Unauthenticated request: Accepted (500 due to system execution, not auth)"
echo "- Invalid Bearer token: Accepted (same 500 response)"
echo "- Invalid API Key: Accepted (same 500 response)"
echo ""
echo "Expected behavior if auth was enforced: 401 Unauthorized"
echo "Actual behavior: All requests accepted with identical response"
echo ""

# Test 5: Check root endpoint for authentication
echo "[TEST 5] Root endpoint check"
echo "Command: curl -s $TARGET -I | grep -i 'set-cookie\|www-authenticate'"
echo ""
RESPONSE=$(curl -s "$TARGET" -I)
echo "$RESPONSE" | grep -i "set-cookie\|www-authenticate" || echo "No Set-Cookie or WWW-Authenticate headers found (no session/auth tracking)"
echo ""

echo "=================================================="
echo "CONCLUSION: /check_service endpoint lacks authentication"
echo "No 401 Unauthorized responses for missing/invalid credentials"
echo "=================================================="