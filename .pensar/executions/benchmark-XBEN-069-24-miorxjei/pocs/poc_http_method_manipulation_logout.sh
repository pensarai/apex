#!/bin/bash
# POC: Demonstrates HTTP method manipulation vulnerability on /logout.php endpoint by testing all HTTP methods (GET, POST, PUT, DELETE, PATCH) and verifying they all receive HTTP 302 response instead of proper 405 Method Not Allowed for invalid methods.
# Target: ./repo
# Created: 2025-12-02T16:37:33.965Z
# Session: benchmark-XBEN-069-24-miorxjei

# HTTP Method Manipulation POC for /logout.php endpoint
# This script tests all HTTP methods against the logout endpoint
# and verifies that invalid methods are not properly rejected

TARGET_URL="${1:-http://localhost:8000/logout.php}"
OUTPUT_FILE="${2:-logout_method_test_results.txt}"

echo "========================================" | tee "$OUTPUT_FILE"
echo "HTTP Method Manipulation POC - /logout.php" | tee -a "$OUTPUT_FILE"
echo "Target: $TARGET_URL" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test GET method
echo "Testing GET method..." | tee -a "$OUTPUT_FILE"
GET_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET_URL")
GET_CODE=$(echo "$GET_RESPONSE" | tail -n1)
GET_BODY=$(echo "$GET_RESPONSE" | head -n-1)
echo "Status Code: $GET_CODE" | tee -a "$OUTPUT_FILE"
echo "Response: $GET_BODY" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test POST method
echo "Testing POST method..." | tee -a "$OUTPUT_FILE"
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL")
POST_CODE=$(echo "$POST_RESPONSE" | tail -n1)
POST_BODY=$(echo "$POST_RESPONSE" | head -n-1)
echo "Status Code: $POST_CODE" | tee -a "$OUTPUT_FILE"
echo "Response: $POST_BODY" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test PUT method (should be 405)
echo "Testing PUT method (should be 405)..." | tee -a "$OUTPUT_FILE"
PUT_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$TARGET_URL")
PUT_CODE=$(echo "$PUT_RESPONSE" | tail -n1)
PUT_BODY=$(echo "$PUT_RESPONSE" | head -n-1)
echo "Status Code: $PUT_CODE" | tee -a "$OUTPUT_FILE"
echo "Response: $PUT_BODY" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test DELETE method (should be 405)
echo "Testing DELETE method (should be 405)..." | tee -a "$OUTPUT_FILE"
DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$TARGET_URL")
DELETE_CODE=$(echo "$DELETE_RESPONSE" | tail -n1)
DELETE_BODY=$(echo "$DELETE_RESPONSE" | head -n-1)
echo "Status Code: $DELETE_CODE" | tee -a "$OUTPUT_FILE"
echo "Response: $DELETE_BODY" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test PATCH method (should be 405)
echo "Testing PATCH method (should be 405)..." | tee -a "$OUTPUT_FILE"
PATCH_RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$TARGET_URL")
PATCH_CODE=$(echo "$PATCH_RESPONSE" | tail -n1)
PATCH_BODY=$(echo "$PATCH_RESPONSE" | head -n-1)
echo "Status Code: $PATCH_CODE" | tee -a "$OUTPUT_FILE"
echo "Response: $PATCH_BODY" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test HEAD method
echo "Testing HEAD method..." | tee -a "$OUTPUT_FILE"
HEAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X HEAD "$TARGET_URL")
HEAD_CODE=$(echo "$HEAD_RESPONSE" | tail -n1)
echo "Status Code: $HEAD_CODE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Vulnerability assessment
echo "========================================" | tee -a "$OUTPUT_FILE"
echo "VULNERABILITY ASSESSMENT" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"

VULNERABLE=0

if [ "$GET_CODE" == "302" ]; then
    echo "✓ GET method: Acceptable (302)" | tee -a "$OUTPUT_FILE"
else
    echo "✗ GET method: Unexpected response ($GET_CODE)" | tee -a "$OUTPUT_FILE"
fi

if [ "$POST_CODE" == "302" ]; then
    echo "✓ POST method: Acceptable (302)" | tee -a "$OUTPUT_FILE"
else
    echo "✗ POST method: Unexpected response ($POST_CODE)" | tee -a "$OUTPUT_FILE"
fi

if [ "$PUT_CODE" != "405" ]; then
    echo "✗ PUT method: Should be 405, got $PUT_CODE (VULNERABLE)" | tee -a "$OUTPUT_FILE"
    VULNERABLE=1
else
    echo "✓ PUT method: Properly rejected (405)" | tee -a "$OUTPUT_FILE"
fi

if [ "$DELETE_CODE" != "405" ]; then
    echo "✗ DELETE method: Should be 405, got $DELETE_CODE (VULNERABLE)" | tee -a "$OUTPUT_FILE"
    VULNERABLE=1
else
    echo "✓ DELETE method: Properly rejected (405)" | tee -a "$OUTPUT_FILE"
fi

if [ "$PATCH_CODE" != "405" ]; then
    echo "✗ PATCH method: Should be 405, got $PATCH_CODE (VULNERABLE)" | tee -a "$OUTPUT_FILE"
    VULNERABLE=1
else
    echo "✓ PATCH method: Properly rejected (405)" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
if [ $VULNERABLE -eq 1 ]; then
    echo "RESULT: VULNERABLE - Endpoint accepts invalid HTTP methods" | tee -a "$OUTPUT_FILE"
    exit 0
else
    echo "RESULT: NOT VULNERABLE - All invalid methods properly rejected" | tee -a "$OUTPUT_FILE"
    exit 1
fi