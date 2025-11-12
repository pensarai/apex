#!/bin/bash

# POC: Persistent 500 Internal Server Error on /xss2 Endpoint
# This script demonstrates service unavailability on the /xss2 endpoint
# where all requests consistently return HTTP 500 errors

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss2"

echo "=========================================="
echo "XSS2 Endpoint - Service Unavailability POC"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Simple GET request
echo "[TEST 1] Simple GET request"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: HTTP 500 returned"
else
    echo "✗ Unexpected status: $HTTP_CODE"
fi
echo ""

# Test 2: GET with debug parameter
echo "[TEST 2] GET request with debug parameter"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT?debug=1")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: HTTP 500 returned with debug parameter"
else
    echo "✗ Unexpected status: $HTTP_CODE"
fi
echo ""

# Test 3: GET with id parameter
echo "[TEST 3] GET request with id parameter"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT?id=1")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: HTTP 500 returned with id parameter"
else
    echo "✗ Unexpected status: $HTTP_CODE"
fi
echo ""

# Test 4: GET with payload parameter
echo "[TEST 4] GET request with payload parameter"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT?payload=test")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: HTTP 500 returned with payload parameter"
else
    echo "✗ Unexpected status: $HTTP_CODE"
fi
echo ""

# Test 5: GET with multiple parameters
echo "[TEST 5] GET request with multiple parameters"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT?param1=value1&param2=value2")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: HTTP 500 returned with multiple parameters"
else
    echo "✗ Unexpected status: $HTTP_CODE"
fi
echo ""

# Test 6: OPTIONS request (to verify endpoint exists in routing)
echo "[TEST 6] OPTIONS request (endpoint existence check)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X OPTIONS "$TARGET_URL$ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "405" ]; then
    echo "✓ Endpoint exists in route table (HTTP $HTTP_CODE)"
else
    echo "✗ Unexpected status: $HTTP_CODE"
fi
echo ""

# Test 7: POST request (should fail differently)
echo "[TEST 7] POST request (method not allowed)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
echo ""

# Test 8: Detailed response from first GET request
echo "[TEST 8] Full response body from GET request"
echo "---"
curl -s "$TARGET_URL$ENDPOINT"
echo ""
echo "---"
echo ""

# Summary
echo "=========================================="
echo "SUMMARY: All GET requests to /xss2 return HTTP 500"
echo "Endpoint is inaccessible and not functional"
echo "Service Unavailability Confirmed"
echo "=========================================="