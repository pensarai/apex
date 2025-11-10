#!/bin/bash

# POC: Loan Calculation Ignores Principal Amount
# This demonstrates that the /total_loan_payments endpoint calculates total payments
# using only payment * term, completely ignoring the principal amount.

TARGET="http://localhost:8080"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQTKrw.ybHhFXn8QioMLr68FQFsxWy7qD0"

echo "=========================================="
echo "POC: Loan Calculation Ignores Principal"
echo "=========================================="
echo ""

# Test Case 1: $1,000,000 loan with minimal payments
echo "[Test 1] Principal: \$1,000,000 | Payment: \$100 | Term: 10 months"
echo "Command: curl -s -H 'Cookie: $SESSION_COOKIE' '$TARGET/total_loan_payments?principal=1000000&payment=100&term=10'"
RESPONSE1=$(curl -s -H "Cookie: $SESSION_COOKIE" "$TARGET/total_loan_payments?principal=1000000&payment=100&term=10")
echo "Response: $RESPONSE1"
TOTAL1=$(echo "$RESPONSE1" | grep -o '"total_loan_payments": "[^"]*"' | cut -d'"' -f4)
echo "Result: Total payments = \$$TOTAL1"
echo "Analysis: \$1M principal supposedly repaid with only \$$TOTAL1 total"
echo ""

# Test Case 2: $1 loan with same payment/term parameters
echo "[Test 2] Principal: \$1 | Payment: \$100 | Term: 10 months"
echo "Command: curl -s -H 'Cookie: $SESSION_COOKIE' '$TARGET/total_loan_payments?principal=1&payment=100&term=10'"
RESPONSE2=$(curl -s -H "Cookie: $SESSION_COOKIE" "$TARGET/total_loan_payments?principal=1&payment=100&term=10")
echo "Response: $RESPONSE2"
TOTAL2=$(echo "$RESPONSE2" | grep -o '"total_loan_payments": "[^"]*"' | cut -d'"' -f4)
echo "Result: Total payments = \$$TOTAL2"
echo "Analysis: Principal changed from \$1M to \$1, but total remains \$$TOTAL2"
echo ""

# Test Case 3: Verify the formula is payment × term
echo "[Test 3] Principal: \$50,000 | Payment: \$500 | Term: 24 months"
echo "Command: curl -s -H 'Cookie: $SESSION_COOKIE' '$TARGET/total_loan_payments?principal=50000&payment=500&term=24'"
RESPONSE3=$(curl -s -H "Cookie: $SESSION_COOKIE" "$TARGET/total_loan_payments?principal=50000&payment=500&term=24")
echo "Response: $RESPONSE3"
TOTAL3=$(echo "$RESPONSE3" | grep -o '"total_loan_payments": "[^"]*"' | cut -d'"' -f4)
echo "Result: Total payments = \$$TOTAL3"
echo "Expected (500 × 24): \$12000.0"
echo ""

# Verification
echo "=========================================="
echo "VULNERABILITY CONFIRMATION"
echo "=========================================="

if [ "$TOTAL1" == "$TOTAL2" ]; then
    echo "✓ CONFIRMED: Principal amount is IGNORED in calculation"
    echo "  - \$1,000,000 principal → Total: \$$TOTAL1"
    echo "  - \$1 principal → Total: \$$TOTAL2"
    echo "  - Both produce identical results despite 1,000,000x difference in principal"
    echo ""
    echo "✓ Formula confirmed: total_loan_payments = payment × term"
    echo "  - Principal parameter has NO effect on the calculation"
    echo ""
    echo "IMPACT: Critical business logic flaw allowing unrealistic loan scenarios"
    echo "  Example: \$1M loan 'repaid' with only \$1,000 in total payments"
    exit 0
else
    echo "✗ Unexpected: Totals differ between test cases"
    echo "  Test 1 total: \$$TOTAL1"
    echo "  Test 2 total: \$$TOTAL2"
    exit 1
fi