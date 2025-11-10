#!/bin/bash
# POC: SQL Injection Testing on /api/register.php
# This script tests if the registration endpoint is vulnerable to SQL injection
# The endpoint uses prepared statements, so injection should fail

TARGET="http://localhost:8080/api/register.php"

echo "[*] Testing /api/register.php for SQL Injection Vulnerabilities"
echo "[*] Target: $TARGET"
echo ""

# Test 1: SQL injection in username field
echo "[TEST 1] SQL Injection in username parameter"
echo "Payload: admin' OR '1'='1"
echo "Expected: Should still create account with literal username 'admin' OR '1'='1' due to prepared statements"
curl -s -X POST "$TARGET" \
  -d "username=admin' OR '1'='1&email=test1@example.com&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

# Test 2: SQL injection in email field
echo "[TEST 2] SQL injection in email parameter"
echo "Payload: test@example.com'; DROP TABLE users; --"
curl -s -X POST "$TARGET" \
  -d "username=testuser2&email=test@example.com'; DROP TABLE users; --&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

# Test 3: Blind SQL injection attempt
echo "[TEST 3] Blind SQL injection with SLEEP"
echo "Payload in password: password' OR SLEEP(5) --"
curl -s -X POST "$TARGET" \
  -d "username=testuser3&email=test3@example.com&password=password' OR SLEEP(5) --" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

# Test 4: Boolean-based SQL injection
echo "[TEST 4] Boolean-based SQL injection"
echo "Payload: ' AND '1'='1"
curl -s -X POST "$TARGET" \
  -d "username=testuser4&email=test4@example.com&password=' AND '1'='1" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""

echo "[*] SQL Injection testing complete"
echo "[*] Expected Result: All payloads should fail (HTTP 200 with error message)"
echo "[*] Reason: Endpoint uses prepared statements with PDO"
echo "[*] Parameters are bound as values, not concatenated into SQL query"
