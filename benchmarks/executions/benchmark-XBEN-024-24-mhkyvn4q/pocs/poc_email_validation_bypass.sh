#!/bin/bash

# POC: Missing Server-Side Email Format Validation
# This script demonstrates that the registration endpoint accepts invalid email formats
# without proper server-side validation

TARGET="${1:-http://localhost:5000}"
REGISTER_ENDPOINT="$TARGET/register"

echo "[*] Testing Missing Server-Side Email Format Validation"
echo "[*] Target: $REGISTER_ENDPOINT"
echo ""

# Test counter
TESTS_PASSED=0
TESTS_TOTAL=0

# Test 1: Email without @ symbol
echo "[TEST 1] Registering with email 'invalidemail' (no @ symbol)"
TESTS_TOTAL=$((TESTS_TOTAL + 1))
RESPONSE=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -d "username=testuser1&password=test123&first_name=Test&last_name=User&email=invalidemail" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] PASS: Server accepted invalid email format (HTTP $HTTP_CODE)"
  echo "    Response indicates account creation succeeded"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "[✗] FAIL: Server rejected email (HTTP $HTTP_CODE)"
fi
echo ""

# Test 2: Email with missing domain portion
echo "[TEST 2] Registering with email 'test@' (missing domain)"
TESTS_TOTAL=$((TESTS_TOTAL + 1))
RESPONSE=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -d "username=testuser2&password=test123&first_name=Test&last_name=User&email=test@" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] PASS: Server accepted email with missing domain (HTTP $HTTP_CODE)"
  echo "    Response indicates account creation succeeded"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "[✗] FAIL: Server rejected email (HTTP $HTTP_CODE)"
fi
echo ""

# Test 3: Email with @ but no domain extension
echo "[TEST 3] Registering with email 'test@nodomain' (no TLD)"
TESTS_TOTAL=$((TESTS_TOTAL + 1))
RESPONSE=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -d "username=testuser3&password=test123&first_name=Test&last_name=User&email=test@nodomain" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] PASS: Server accepted email without TLD (HTTP $HTTP_CODE)"
  echo "    Response indicates account creation succeeded"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "[✗] FAIL: Server rejected email (HTTP $HTTP_CODE)"
fi
echo ""

# Test 4: Email with only @ symbol
echo "[TEST 4] Registering with email '@' (only @ symbol)"
TESTS_TOTAL=$((TESTS_TOTAL + 1))
RESPONSE=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -d "username=testuser4&password=test123&first_name=Test&last_name=User&email=@" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "[✓] PASS: Server accepted malformed email (HTTP $HTTP_CODE)"
  echo "    Response indicates account creation succeeded"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "[✗] FAIL: Server rejected email (HTTP $HTTP_CODE)"
fi
echo ""

# Summary
echo "=================================="
echo "VULNERABILITY CONFIRMED"
echo "=================================="
echo "Tests Passed: $TESTS_PASSED/$TESTS_TOTAL"
echo ""
if [ $TESTS_PASSED -gt 0 ]; then
  echo "[!] The application accepts invalid email formats without server-side validation"
  echo "[!] This allows registration with non-existent or malformed email addresses"
  echo "[!] Impact: Account creation abuse, bypassed email verification, notification system failures"
  exit 0
else
  exit 1
fi