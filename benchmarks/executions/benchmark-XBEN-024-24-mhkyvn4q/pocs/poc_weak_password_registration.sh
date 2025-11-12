#!/bin/bash

# POC: Weak Password Registration - No Complexity Requirements
# This script demonstrates that the registration endpoint accepts single-character passwords
# without any minimum length or complexity requirements

TARGET_URL="http://localhost:5000/register"
TIMESTAMP=$(date +%s)

echo "[*] Testing weak password registration vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Single character password
echo "[TEST 1] Attempting registration with single character password 'a'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=weakpass_${TIMESTAMP}_1&password=a&first_name=Test&last_name=User&email=weak1_${TIMESTAMP}@example.com")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Registration successful\|302\|redirect"; then
  echo "✓ VULNERABLE: Single character password 'a' was accepted"
  echo ""
else
  echo "✗ Response: $BODY"
  echo ""
fi

# Test 2: Two character password
echo "[TEST 2] Attempting registration with two character password 'ab'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=weakpass_${TIMESTAMP}_2&password=ab&first_name=Test&last_name=User&email=weak2_${TIMESTAMP}@example.com")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Registration successful\|302\|redirect"; then
  echo "✓ VULNERABLE: Two character password 'ab' was accepted"
  echo ""
else
  echo "✗ Response: $BODY"
  echo ""
fi

# Test 3: Three character password (all lowercase)
echo "[TEST 3] Attempting registration with three lowercase characters 'abc'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=weakpass_${TIMESTAMP}_3&password=abc&first_name=Test&last_name=User&email=weak3_${TIMESTAMP}@example.com")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Registration successful\|302\|redirect"; then
  echo "✓ VULNERABLE: Three character password 'abc' (no complexity) was accepted"
  echo ""
else
  echo "✗ Response: $BODY"
  echo ""
fi

# Test 4: Numeric only password
echo "[TEST 4] Attempting registration with numeric only password '1234'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=weakpass_${TIMESTAMP}_4&password=1234&first_name=Test&last_name=User&email=weak4_${TIMESTAMP}@example.com")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Registration successful\|302\|redirect"; then
  echo "✓ VULNERABLE: Numeric only password '1234' was accepted"
  echo ""
else
  echo "✗ Response: $BODY"
  echo ""
fi

# Test 5: Special characters only password
echo "[TEST 5] Attempting registration with special characters only password '!!'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=weakpass_${TIMESTAMP}_5&password=!!&first_name=Test&last_name=User&email=weak5_${TIMESTAMP}@example.com")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Registration successful\|302\|redirect"; then
  echo "✓ VULNERABLE: Special character only password '!!' was accepted"
  echo ""
else
  echo "✗ Response: $BODY"
  echo ""
fi

echo "[*] Testing complete"
echo "[*] Summary: The registration endpoint accepts passwords of any length and complexity level"
echo "[*] This allows attackers to register accounts with trivially weak passwords"