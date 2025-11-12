#!/bin/bash

# POC: Missing Input Validation on Term Parameter
# Tests that the amortization calculator accepts negative values without validation
# Expected behavior: Should reject with error
# Actual behavior: Accepts with HTTP 200

TARGET="${1:-http://localhost}"

echo "========================================"
echo "Testing Missing Input Validation - Term Parameter"
echo "Target: $TARGET"
echo "========================================"
echo ""

# Test 1: Negative term value
echo "[TEST 1] Sending negative term value (term=-5)"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET/amortization?term=-5")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" == "200" ]; then
    echo "⚠️  VULNERABILITY CONFIRMED: Negative term accepted with HTTP 200"
    echo "Response length: $(echo "$BODY1" | wc -c) bytes"
else
    echo "Response: $BODY1"
fi
echo ""

# Test 2: Zero term value
echo "[TEST 2] Sending zero term value (term=0)"
RESPONSE2=$(curl -s -w "\n%{http_code}" "$TARGET/amortization?term=0")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" == "200" ]; then
    echo "⚠️  VULNERABILITY CONFIRMED: Zero term accepted with HTTP 200"
    echo "Response length: $(echo "$BODY2" | wc -c) bytes"
else
    echo "Response: $BODY2"
fi
echo ""

# Test 3: Valid positive term value (baseline)
echo "[TEST 3] Sending valid positive term value (term=5)"
RESPONSE3=$(curl -s -w "\n%{http_code}" "$TARGET/amortization?term=5")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE3"
echo "⏹️  Baseline: Valid term accepted with HTTP $HTTP_CODE3"
echo "Response length: $(echo "$BODY3" | wc -c) bytes"
echo ""

# Test 4: Decimal term value
echo "[TEST 4] Sending decimal term value (term=5.5)"
RESPONSE4=$(curl -s -w "\n%{http_code}" "$TARGET/amortization?term=5.5")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE4"
if [ "$HTTP_CODE4" == "400" ] || [ "$HTTP_CODE4" == "422" ]; then
    echo "✓ Type validation working: Decimal rejected with HTTP $HTTP_CODE4"
elif [ "$HTTP_CODE4" == "200" ]; then
    echo "⚠️  POTENTIAL ISSUE: Decimal accepted with HTTP 200"
else
    echo "Response: $BODY4"
fi
echo ""

# Summary
echo "========================================"
echo "VULNERABILITY ASSESSMENT:"
echo "========================================"
if [ "$HTTP_CODE1" == "200" ] || [ "$HTTP_CODE2" == "200" ]; then
    echo "✓ CONFIRMED: Missing input validation detected"
    echo "  - Negative values: ACCEPTED (should be rejected)"
    echo "  - Zero values: ACCEPTED (should be rejected)"
    echo "  - Application lacks positive integer validation"
    exit 0
else
    echo "✗ Validation appears to be in place"
    exit 1
fi