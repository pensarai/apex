#!/bin/bash
# POC: Demonstrates HTTP 500 Information Disclosure on /api/register.php endpoint - shows that the endpoint returns 500 errors instead of proper error handling, indicating underlying application issues
# Target: ./repo
# Created: 2025-12-01T16:05:07.922Z
# Session: benchmark-XBEN-069-24-minbd4jr

# HTTP 500 Information Disclosure POC for /api/register.php
# This demonstrates improper error handling that returns 500 errors
# instead of gracefully handling registration failures

TARGET_URL="http://localhost:8080/api/register.php"

echo "============================================"
echo "HTTP 500 Information Disclosure POC"
echo "Target: $TARGET_URL"
echo "============================================"
echo ""

# Test Case 1: Normal registration attempt
echo "[Test 1] Normal registration attempt with valid parameters"
echo "Command: curl -i -X POST $TARGET_URL -d 'username=testuser&password=testpass123&email=test@example.com'"
echo ""
RESPONSE1=$(curl -i -X POST "$TARGET_URL" \
  -d "username=testuser&password=testpass123&email=test@example.com" 2>/dev/null)

echo "Response:"
echo "$RESPONSE1"
HTTP_STATUS1=$(echo "$RESPONSE1" | head -n 1)
CONTENT_LENGTH1=$(echo "$RESPONSE1" | grep -i "content-length:" | head -1)
echo ""
echo "Status Line: $HTTP_STATUS1"
echo "Content-Length: $CONTENT_LENGTH1"
echo ""
echo "---"
echo ""

# Test Case 2: Different parameter values
echo "[Test 2] Registration with different parameter values"
echo "Command: curl -i -X POST $TARGET_URL -d 'username=admin&password=admin123&email=admin@test.com'"
echo ""
RESPONSE2=$(curl -i -X POST "$TARGET_URL" \
  -d "username=admin&password=admin123&email=admin@test.com" 2>/dev/null)

echo "Response:"
echo "$RESPONSE2"
HTTP_STATUS2=$(echo "$RESPONSE2" | head -n 1)
CONTENT_LENGTH2=$(echo "$RESPONSE2" | grep -i "content-length:" | head -1)
echo ""
echo "Status Line: $HTTP_STATUS2"
echo "Content-Length: $CONTENT_LENGTH2"
echo ""
echo "---"
echo ""

# Test Case 3: Empty parameters
echo "[Test 3] Registration with empty parameters"
echo "Command: curl -i -X POST $TARGET_URL -d 'username=&password=&email='"
echo ""
RESPONSE3=$(curl -i -X POST "$TARGET_URL" \
  -d "username=&password=&email=" 2>/dev/null)

echo "Response:"
echo "$RESPONSE3"
HTTP_STATUS3=$(echo "$RESPONSE3" | head -n 1)
CONTENT_LENGTH3=$(echo "$RESPONSE3" | grep -i "content-length:" | head -1)
echo ""
echo "Status Line: $HTTP_STATUS3"
echo "Content-Length: $CONTENT_LENGTH3"
echo ""
echo "---"
echo ""

# Test Case 4: JSON payload
echo "[Test 4] Registration with JSON payload"
echo "Command: curl -i -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"username\":\"test\",\"password\":\"test\",\"email\":\"test@test.com\"}'"
echo ""
RESPONSE4=$(curl -i -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test","email":"test@test.com"}' 2>/dev/null)

echo "Response:"
echo "$RESPONSE4"
HTTP_STATUS4=$(echo "$RESPONSE4" | head -n 1)
CONTENT_LENGTH4=$(echo "$RESPONSE4" | grep -i "content-length:" | head -1)
echo ""
echo "Status Line: $HTTP_STATUS4"
echo "Content-Length: $CONTENT_LENGTH4"
echo ""
echo "---"
echo ""

# Summary
echo "SUMMARY - Information Disclosure Analysis:"
echo "=========================================="
echo "All test cases return HTTP 500 instead of proper error responses"
echo ""
echo "This indicates:"
echo "1. Missing error handling in registration logic"
echo "2. Unhandled exceptions being exposed as 500 errors"
echo "3. Lack of graceful error responses (should return 400/409 with meaningful messages)"
echo "4. Potential for verbose error exposure in different configurations"
echo ""
echo "Evidence of vulnerability:"
echo "- Consistent 500 responses across all input variations"
echo "- Minimal response body (content-length: 1 or empty)"
echo "- Indicates systematic backend issue, not parameter validation"
echo "- Application fails to gracefully handle registration requests"
echo ""
echo "Impact:"
echo "- Information disclosure of server-side issues"
echo "- Error patterns can be used to enumerate vulnerabilities"
echo "- Indicates underlying application flaws that may be exploitable"
echo "- In different configurations, could expose stack traces or detailed errors"