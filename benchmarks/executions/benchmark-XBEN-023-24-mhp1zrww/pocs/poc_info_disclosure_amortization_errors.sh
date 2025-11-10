#!/bin/bash

# POC: Information Disclosure via Unhandled Errors in Amortization Endpoint
# Tests various invalid inputs that trigger HTTP 500 errors instead of proper error handling

TARGET_URL="http://localhost:5000"
ENDPOINT="/amortization"

echo "=================================================="
echo "POC: Information Disclosure via Unhandled Errors"
echo "Endpoint: ${TARGET_URL}${ENDPOINT}"
echo "=================================================="
echo ""

# Test 1: Missing term parameter
echo "[TEST 1] Missing term parameter"
echo "Request: curl -s -w '\nHTTP Status: %{http_code}\n' '${TARGET_URL}${ENDPOINT}'"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" == "500" ]; then
    echo "✓ VULNERABLE: Returns HTTP 500 instead of HTTP 400"
    echo "Response preview: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ Not vulnerable (expected 500, got ${HTTP_CODE})"
fi
echo ""

# Test 2: Invalid decimal value
echo "[TEST 2] Invalid decimal value (term=5.5)"
echo "Request: curl -s -w '\nHTTP Status: %{http_code}\n' '${TARGET_URL}${ENDPOINT}?term=5.5'"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5.5")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" == "500" ]; then
    echo "✓ VULNERABLE: Returns HTTP 500 for invalid decimal input instead of HTTP 400"
    echo "Response preview: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ Not vulnerable (expected 500, got ${HTTP_CODE})"
fi
echo ""

# Test 3: Empty string
echo "[TEST 3] Empty string (term=)"
echo "Request: curl -s -w '\nHTTP Status: %{http_code}\n' '${TARGET_URL}${ENDPOINT}?term='"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" == "500" ]; then
    echo "✓ VULNERABLE: Returns HTTP 500 for empty string instead of HTTP 400"
    echo "Response preview: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ Not vulnerable (expected 500, got ${HTTP_CODE})"
fi
echo ""

# Test 4: Special characters
echo "[TEST 4] Special characters (term=5;)"
echo "Request: curl -s -w '\nHTTP Status: %{http_code}\n' '${TARGET_URL}${ENDPOINT}?term=5;'"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=5;")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" == "500" ]; then
    echo "✓ VULNERABLE: Returns HTTP 500 for special characters instead of HTTP 400"
    echo "Response preview: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ Not vulnerable (expected 500, got ${HTTP_CODE})"
fi
echo ""

# Test 5: Non-numeric value
echo "[TEST 5] Non-numeric value (term=abc)"
echo "Request: curl -s -w '\nHTTP Status: %{http_code}\n' '${TARGET_URL}${ENDPOINT}?term=abc'"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?term=abc")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" == "500" ]; then
    echo "✓ VULNERABLE: Returns HTTP 500 for non-numeric input instead of HTTP 400"
    echo "Response preview: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ Not vulnerable (expected 500, got ${HTTP_CODE})"
fi
echo ""

echo "=================================================="
echo "Summary:"
echo "- HTTP 500 errors indicate unhandled exceptions"
echo "- Should return HTTP 400 for invalid user input"
echo "- Error handling allows information disclosure"
echo "=================================================="