#!/bin/bash

# POC: Insufficient Input Validation in addPrescription GraphQL Mutation
# Demonstrates acceptance of invalid input values without validation

TARGET_URL="http://localhost:5003/graphql"

echo "=========================================="
echo "Testing Insufficient Input Validation in addPrescription Mutation"
echo "=========================================="
echo ""

# Test 1: Negative userId
echo "[Test 1] Testing negative userId (-1)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addPrescription(input: {userId: -1, prescriptionDetails: \"Test prescription\"}) { id userId prescriptionDetails } }"
  }')

echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"userId":-1'; then
  echo "✓ VULNERABLE: Negative userId (-1) accepted without validation"
else
  echo "✗ Negative userId validation applied"
fi
echo ""

# Test 2: Zero userId
echo "[Test 2] Testing zero userId (0)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addPrescription(input: {userId: 0, prescriptionDetails: \"Test prescription\"}) { id userId prescriptionDetails } }"
  }')

echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"userId":0'; then
  echo "✓ VULNERABLE: Zero userId (0) accepted without validation"
else
  echo "✗ Zero userId validation applied"
fi
echo ""

# Test 3: Extremely large userId
echo "[Test 3] Testing extremely large userId (999999)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addPrescription(input: {userId: 999999, prescriptionDetails: \"Test prescription\"}) { id userId prescriptionDetails } }"
  }')

echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"userId":999999'; then
  echo "✓ VULNERABLE: Extremely large userId (999999) accepted without validation"
else
  echo "✗ Large userId validation applied"
fi
echo ""

# Test 4: Very long prescriptionDetails (10000+ characters)
echo "[Test 4] Testing excessively long prescriptionDetails (10000+ characters)..."
LONG_DETAILS=$(python3 -c "print('A' * 10002)")
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"query\": \"mutation { addPrescription(input: {userId: 1, prescriptionDetails: \\\"$LONG_DETAILS\\\"}) { id userId prescriptionDetails } }\"
  }")

DETAILS_LENGTH=$(echo "$RESPONSE" | grep -o '"prescriptionDetails":"[^"]*' | wc -c)
echo "Response length for prescriptionDetails: ~$DETAILS_LENGTH characters"
if echo "$RESPONSE" | grep -q 'prescriptionDetails'; then
  echo "✓ VULNERABLE: Excessively long prescriptionDetails (10000+ chars) accepted without length validation"
else
  echo "✗ Length validation applied"
fi
echo ""

echo "=========================================="
echo "Summary: Input validation insufficient in addPrescription"
echo "=========================================="