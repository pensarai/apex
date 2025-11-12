#!/bin/bash
# POC: Duplicate Account Prevention Testing on /api/register.php
# This script tests if the duplicate account prevention can be bypassed

TARGET="http://localhost:8080/api/register.php"
TEST_USERNAME="duplicatetest_user"
TEST_EMAIL="duplicatetest@example.com"

echo "[*] Testing /api/register.php for Duplicate Account Prevention Bypass"
echo "[*] Target: $TARGET"
echo ""

echo "[TEST 1] Create first account (should succeed)"
echo "Payload: username=$TEST_USERNAME, email=$TEST_EMAIL"
RESPONSE1=$(curl -s -X POST "$TARGET" \
  -d "username=$TEST_USERNAME&email=$TEST_EMAIL&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE1"
echo ""
echo ""

echo "[TEST 2] Attempt to create duplicate account (should fail)"
echo "Payload: username=$TEST_USERNAME, email=$TEST_EMAIL (SAME AS TEST 1)"
RESPONSE2=$(curl -s -X POST "$TARGET" \
  -d "username=$TEST_USERNAME&email=$TEST_EMAIL&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE2"
echo ""
echo ""

if echo "$RESPONSE1" | grep -q "success.*true"; then
    echo "✓ First registration succeeded (as expected)"
else
    echo "✗ First registration failed (unexpected)"
fi

if echo "$RESPONSE2" | grep -q "success.*false"; then
    echo "✓ Duplicate registration was rejected (SECURE)"
else
    echo "✗ Duplicate registration was accepted (VULNERABLE)"
fi
echo ""
echo ""

echo "[TEST 3] Attempt with different case in username (bypass attempt)"
echo "Payload: username=${TEST_USERNAME^^} (uppercase), same email"
RESPONSE3=$(curl -s -X POST "$TARGET" \
  -d "username=${TEST_USERNAME^^}&email=$TEST_EMAIL&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE3"
echo ""
echo ""

echo "[TEST 4] Attempt with whitespace variations"
echo "Payload: username=' $TEST_USERNAME' (leading space)"
RESPONSE4=$(curl -s -X POST "$TARGET" \
  -d "username= $TEST_USERNAME&email=testwhitespace@example.com&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE4"
echo ""
echo ""

echo "[TEST 5] Attempt with email variations"
echo "Payload: username=differentuser, email=$TEST_EMAIL (duplicate email, different username)"
RESPONSE5=$(curl -s -X POST "$TARGET" \
  -d "username=differentuser&email=$TEST_EMAIL&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE5"
echo ""
echo ""

echo "[*] Duplicate Prevention Testing Complete"
echo "[*] Analysis:"
echo "  - Database has UNIQUE constraint on username column"
echo "  - Database has UNIQUE constraint on email column"
echo "  - Both duplicates are enforced at database level (not application level)"
echo "  - Bypasses to test: case sensitivity, whitespace, unicode variations"
