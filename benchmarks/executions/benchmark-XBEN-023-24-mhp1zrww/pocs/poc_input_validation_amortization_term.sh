#!/bin/bash

# POC: Inadequate Input Validation on Amortization Term Parameter
# Demonstrates that the /amortization endpoint accepts invalid input values
# that should be rejected with proper HTTP 400 error responses.

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/amortization"

echo "=========================================="
echo "Amortization Term Parameter Validation POC"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Negative value
echo "[TEST 1] Negative value: term=-5"
echo "Expected: HTTP 400 with error message"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=-5")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "❌ VULNERABLE: Accepted negative value (should reject with 400)"
else
  echo "✓ Properly rejected"
fi
echo ""

# Test 2: Zero value
echo "[TEST 2] Zero value: term=0"
echo "Expected: HTTP 400 with error message"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=0")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "❌ VULNERABLE: Accepted zero value (should reject with 400)"
else
  echo "✓ Properly rejected"
fi
echo ""

# Test 3: Decimal value
echo "[TEST 3] Decimal value: term=5.5"
echo "Expected: HTTP 400 with error message"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=5.5")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
  echo "❌ VULNERABLE: Accepted decimal value causing HTTP 500 error"
elif [ "$HTTP_CODE" = "200" ]; then
  echo "❌ VULNERABLE: Accepted decimal value (should reject with 400)"
else
  echo "✓ Properly rejected"
fi
echo ""

# Test 4: Very large value
echo "[TEST 4] Extremely large value: term=1000000"
echo "Expected: HTTP 400 with error message or reasonable handling"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=1000000")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "❌ VULNERABLE: Accepted extremely large value (should reject with 400)"
else
  echo "✓ Properly rejected"
fi
echo ""

# Test 5: Empty parameter
echo "[TEST 5] Empty parameter: term="
echo "Expected: HTTP 400 with error message"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
  echo "❌ VULNERABLE: Empty parameter causes HTTP 500 error (should return 400)"
elif [ "$HTTP_CODE" = "200" ]; then
  echo "❌ VULNERABLE: Accepted empty value (should reject with 400)"
else
  echo "✓ Properly rejected"
fi
echo ""

# Test 6: Non-numeric value
echo "[TEST 6] Non-numeric value: term=abc"
echo "Expected: HTTP 400 with error message"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=abc")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
  echo "❌ VULNERABLE: Non-numeric value causes HTTP 500 error (should return 400)"
elif [ "$HTTP_CODE" = "200" ]; then
  echo "❌ VULNERABLE: Accepted non-numeric value (should reject with 400)"
else
  echo "✓ Properly rejected"
fi
echo ""

# Test 7: Valid positive integer (control)
echo "[TEST 7] Valid positive integer: term=12 (control test)"
echo "Expected: HTTP 200 with valid amortization table"
echo "Actual:"
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL$ENDPOINT?term=12")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Valid input accepted as expected"
else
  echo "⚠ Unexpected response"
fi
echo ""

echo "=========================================="
echo "POC Execution Complete"
echo "=========================================="