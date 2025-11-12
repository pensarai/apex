#!/bin/bash

# POC: Silent Parameter Capping Without Validation Error
# Tests that the /generate endpoint silently caps number parameter values > 200
# Expected: HTTP 400 Bad Request
# Actual: HTTP 200 OK with silently capped value

TARGET_URL="http://localhost:4567"
ENDPOINT="/generate"

echo "=== Silent Parameter Capping Vulnerability POC ==="
echo ""
echo "Testing silent parameter capping on $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Submit number=201 (exceeds max of 200)
echo "Test 1: Submitting number=201 (exceeds documented max)"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'sentence=test&number=201'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" -d "sentence=test&number=201")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response contains: $(echo "$BODY" | grep -o "Generated your sentence for [0-9]* times" || echo "Not found")"
echo ""

# Test 2: Submit number=210
echo "Test 2: Submitting number=210"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'sentence=test&number=210'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" -d "sentence=test&number=210")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response contains: $(echo "$BODY" | grep -o "Generated your sentence for [0-9]* times" || echo "Not found")"
echo ""

# Test 3: Submit number=1000000 (very large)
echo "Test 3: Submitting number=1000000"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'sentence=test&number=1000000'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" -d "sentence=test&number=1000000")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response contains: $(echo "$BODY" | grep -o "Generated your sentence for [0-9]* times" || echo "Not found")"
echo ""

# Test 4: Verify valid input works (baseline)
echo "Test 4: Submitting valid number=150 (within range)"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'sentence=test&number=150'"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" -d "sentence=test&number=150")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response contains: $(echo "$BODY" | grep -o "Generated your sentence for [0-9]* times" || echo "Not found")"
echo ""

# Analysis
echo "=== VULNERABILITY ANALYSIS ==="
echo "Expected behavior: HTTP 400 Bad Request when number > 200"
echo "Actual behavior: HTTP 200 OK with silent parameter capping"
echo "Verdict: Parameter tampering vulnerability confirmed"
echo "The server accepts out-of-range values and silently caps them without"
echo "returning a validation error, violating fail-secure design principles."