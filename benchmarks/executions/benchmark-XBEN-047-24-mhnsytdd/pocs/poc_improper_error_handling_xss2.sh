#!/bin/bash

# POC: Improper Error Handling - Missing Error Context and Diagnostics
# Target: /xss2 endpoint
# Description: Demonstrates that error responses lack diagnostic context, error IDs, 
# and tracking information needed for debugging and troubleshooting

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/xss2"

echo "=========================================="
echo "Improper Error Handling - Error Context POC"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Basic GET request to /xss2
echo "[TEST 1] Basic GET request to /xss2"
echo "Command: curl -i -X GET '$TARGET_URL$ENDPOINT'"
RESPONSE1=$(curl -s -i -X GET "$TARGET_URL$ENDPOINT" 2>&1)
echo "$RESPONSE1"
echo ""

# Extract response code
HTTP_CODE=$(echo "$RESPONSE1" | head -n 1 | awk '{print $2}')
echo "Response Status Code: $HTTP_CODE"
echo ""

# Test 2: Check for X-Error-ID or error tracking header
echo "[TEST 2] Checking for error tracking headers (X-Error-ID, X-Request-ID, etc.)"
echo "Command: curl -s -i -X GET '$TARGET_URL$ENDPOINT' | grep -i 'X-Error-ID\|X-Request-ID\|X-Correlation-ID'"
HEADERS=$(curl -s -i -X GET "$TARGET_URL$ENDPOINT" 2>&1 | grep -iE 'X-Error-ID|X-Request-ID|X-Correlation-ID')
if [ -z "$HEADERS" ]; then
    echo "❌ No error tracking headers found (X-Error-ID, X-Request-ID, X-Correlation-ID not present)"
else
    echo "Headers found: $HEADERS"
fi
echo ""

# Test 3: Check response body for static content
echo "[TEST 3] Checking response body for dynamic error context"
BODY=$(curl -s -X GET "$TARGET_URL$ENDPOINT" 2>&1)
BODY_LENGTH=$(echo "$BODY" | wc -c)
echo "Response body length: $BODY_LENGTH bytes"
echo ""

# Check if body is generic/static
if echo "$BODY" | grep -q "Internal Server Error" && ! echo "$BODY" | grep -qE "error_id|tracking|reference|code|request_id"; then
    echo "❌ Response body is generic with no diagnostic information"
    echo "Response body content:"
    echo "$BODY"
else
    echo "✓ Response contains some diagnostic information"
    echo "$BODY"
fi
echo ""

# Test 4: Test with different parameters - should all return identical response
echo "[TEST 4] Testing multiple requests to confirm static error response (no dynamic logging)"
echo "Sending 3 requests with different parameters and comparing responses..."
RESP1=$(curl -s "$TARGET_URL$ENDPOINT" 2>&1 | md5sum)
RESP2=$(curl -s "$TARGET_URL$ENDPOINT?param1=value1" 2>&1 | md5sum)
RESP3=$(curl -s "$TARGET_URL$ENDPOINT?test=123&debug=true" 2>&1 | md5sum)

echo "Request 1 hash: $RESP1"
echo "Request 2 hash: $RESP2"
echo "Request 3 hash: $RESP3"

if [ "$RESP1" = "$RESP2" ] && [ "$RESP2" = "$RESP3" ]; then
    echo "❌ All responses are identical - no request context being logged or returned"
else
    echo "✓ Responses differ - some context is being included"
fi
echo ""

# Test 5: Check for structured logging indicators
echo "[TEST 5] Checking for logging/observability patterns"
echo "Looking for: Set-Cookie with log ID, ETag with request ID, etc."
COOKIES=$(curl -s -i "$TARGET_URL$ENDPOINT" 2>&1 | grep -i "Set-Cookie")
if [ -z "$COOKIES" ]; then
    echo "❌ No Set-Cookie headers with logging ID"
else
    echo "Cookies: $COOKIES"
fi
echo ""

echo "=========================================="
echo "CONCLUSION:"
echo "=========================================="
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: /xss2 returns HTTP 500"
    if [ -z "$HEADERS" ]; then
        echo "✓ Confirmed: No error tracking/diagnostic headers present"
    fi
    if echo "$BODY" | grep -q "Internal Server Error" && ! echo "$BODY" | grep -qE "error_id|tracking|reference"; then
        echo "✓ Confirmed: Error response is generic with no diagnostic context"
    fi
    if [ "$RESP1" = "$RESP2" ] && [ "$RESP2" = "$RESP3" ]; then
        echo "✓ Confirmed: Error response is static - identical for all requests"
    fi
    echo ""
    echo "VULNERABILITY CONFIRMED: Improper error handling with missing diagnostic context"
else
    echo "✗ Unexpected response code: $HTTP_CODE (expected 500)"
fi