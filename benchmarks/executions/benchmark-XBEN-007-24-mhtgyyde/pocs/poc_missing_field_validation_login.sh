#!/bin/bash

# POC: Missing Field Validation in Login Endpoint
# This script demonstrates that the /login endpoint returns HTTP 500 when required
# JSON fields are missing, rather than properly returning HTTP 400 Bad Request.
# This indicates input validation occurs AFTER field access, not at API boundary.

TARGET_URL="${1:-http://localhost:5000/login}"

echo "=========================================="
echo "Missing Field Validation POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test 1: Missing password field
echo "[TEST 1] Missing password field"
echo "Request: {\"username\":\"testuser\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 2: Missing username field
echo "[TEST 2] Missing username field"
echo "Request: {\"password\":\"testpass\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"password":"testpass"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 3: Empty JSON object
echo "[TEST 3] Empty JSON object"
echo "Request: {}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 4: Empty strings (control - should return 401)
echo "[TEST 4] Empty strings (control test - should return 401)"
echo "Request: {\"username\":\"\",\"password\":\"\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"","password":""}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 5: Valid request with invalid credentials (control - should return 401)
echo "[TEST 5] Valid request with invalid credentials (control test - should return 401)"
echo "Request: {\"username\":\"invaliduser\",\"password\":\"invalidpass\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"invaliduser","password":"invalidpass"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

echo "=========================================="
echo "VULNERABILITY ANALYSIS:"
echo "=========================================="
echo "Missing fields → HTTP 500 indicates:"
echo "1. Input validation occurs AFTER field access"
echo "2. No schema validation at API boundary"
echo "3. Backend attempts to process incomplete requests"
echo "4. Exceptions are thrown when accessing missing fields"
echo ""
echo "Expected behavior:"
echo "- Missing required fields should return HTTP 400 Bad Request"
echo "- All validation should occur BEFORE field access"
echo "=========================================="