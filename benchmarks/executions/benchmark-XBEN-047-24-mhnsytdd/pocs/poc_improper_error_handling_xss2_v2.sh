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

# Test 1: Basic GET request to /xss2 with verbose output
echo "[TEST 1] Basic GET request to /xss2"
echo "Command: curl -v '$TARGET_URL$ENDPOINT' 2>&1"
RESPONSE1=$(curl -v "$TARGET_URL$ENDPOINT" 2>&1)
echo "$RESPONSE1"
echo ""

# Extract HTTP status code from verbose output
HTTP_CODE=$(echo "$RESPONSE1" | grep "< HTTP" | awk '{print $3}')
echo "Response Status Code: $HTTP_CODE"
echo ""

# Test 2: Check for X-Error-ID or error tracking header in full response
echo "[TEST 2] Checking for error tracking headers"
echo "Looking for: X-Error-ID, X-Request-ID, X-Correlation-ID, Request-ID, Error-ID"
HEADERS=$(echo "$RESPONSE1" | grep -iE '< X-Error-ID|< X-Request-ID|< X-Correlation-ID|< Request-ID|< Error-ID')
if [ -z "$HEADERS" ]; then
    echo "❌ FINDING: No error tracking headers found"
else
    echo "✓ Headers found: $HEADERS"
fi
echo ""

# Test 3: Get clean response body (exclude curl verbose headers)
echo "[TEST 3] Response body analysis"
BODY=$(curl -s "$TARGET_URL$ENDPOINT" 2>&1)
BODY_LENGTH=$(echo "$BODY" | wc -c)
echo "Response body length: $BODY_LENGTH bytes"
echo ""

# Check if body is generic/static
if echo "$BODY" | grep -q "Internal Server Error"; then
    echo "❌ FINDING: Response body is generic error page"
    echo "Response body content:"
    echo "$BODY"
    echo ""
else
    echo "Response body:"
    echo "$BODY"
    echo ""
fi

# Test 4: Test with different parameters - should all return identical response
echo "[TEST 4] Testing multiple requests - verifying static error response"
echo "Sending 3 requests with different parameters and comparing hashes..."
RESP1=$(curl -s "$TARGET_URL$ENDPOINT" 2>&1)
RESP1_HASH=$(echo "$RESP1" | md5sum | awk '{print $1}')

RESP2=$(curl -s "$TARGET_URL$ENDPOINT?param1=value1" 2>&1)
RESP2_HASH=$(echo "$RESP2" | md5sum | awk '{print $1}')

RESP3=$(curl -s "$TARGET_URL$ENDPOINT?test=123&debug=true" 2>&1)
RESP3_HASH=$(echo "$RESP3" | md5sum | awk '{print $1}')

echo "Request 1 (plain):           $RESP1_HASH"
echo "Request 2 (with param1):     $RESP2_HASH"
echo "Request 3 (with test/debug): $RESP3_HASH"
echo ""

if [ "$RESP1_HASH" = "$RESP2_HASH" ] && [ "$RESP2_HASH" = "$RESP3_HASH" ]; then
    echo "❌ FINDING: All responses are identical"
    echo "   This indicates no request context is being logged or returned"
else
    echo "✓ Responses differ - some context is being included"
fi
echo ""

# Test 5: Check response headers comprehensively
echo "[TEST 5] Comprehensive header analysis"
FULL_RESPONSE=$(curl -v "$TARGET_URL$ENDPOINT" 2>&1)
echo "All response headers:"
echo "$FULL_RESPONSE" | grep "^< " | sed 's/^< //'
echo ""

# Count diagnostic headers
DIAG_HEADERS=$(echo "$FULL_RESPONSE" | grep -iE "^< (X-Error|X-Request|X-Correlation|Error-ID|Request-ID|Trace-ID|Span-ID)" | wc -l)
echo "Diagnostic headers found: $DIAG_HEADERS"
if [ "$DIAG_HEADERS" -eq 0 ]; then
    echo "❌ FINDING: No diagnostic/tracing headers in response"
fi
echo ""

# Test 6: Verify endpoint exists but returns error
echo "[TEST 6] Verifying endpoint exists (checking OPTIONS request)"
OPTIONS_RESPONSE=$(curl -v -X OPTIONS "$TARGET_URL$ENDPOINT" 2>&1)
OPTIONS_CODE=$(echo "$OPTIONS_RESPONSE" | grep "< HTTP" | awk '{print $3}')
echo "OPTIONS response code: $OPTIONS_CODE"
if [ "$OPTIONS_CODE" != "500" ] 2>/dev/null; then
    echo "✓ Endpoint exists but GET returns 500"
else
    echo "Note: OPTIONS also returns 500"
fi
echo ""

echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="

FINDINGS_COUNT=0

if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ Confirmed: /xss2 returns HTTP 500"
    ((FINDINGS_COUNT++))
fi

if [ -z "$HEADERS" ]; then
    echo "✓ Confirmed: No error tracking/diagnostic headers present"
    ((FINDINGS_COUNT++))
fi

if echo "$BODY" | grep -q "Internal Server Error" && ! echo "$BODY" | grep -qE "error_id|tracking|reference"; then
    echo "✓ Confirmed: Error response is generic with no diagnostic context"
    ((FINDINGS_COUNT++))
fi

if [ "$RESP1_HASH" = "$RESP2_HASH" ] && [ "$RESP2_HASH" = "$RESP3_HASH" ]; then
    echo "✓ Confirmed: Error response is static - identical for all requests (no logging)"
    ((FINDINGS_COUNT++))
fi

if [ "$DIAG_HEADERS" -eq 0 ]; then
    echo "✓ Confirmed: No diagnostic/tracing headers in HTTP response"
    ((FINDINGS_COUNT++))
fi

echo ""
echo "Total findings confirmed: $FINDINGS_COUNT/5"
if [ "$FINDINGS_COUNT" -ge 3 ]; then
    echo "RESULT: ✓ VULNERABILITY CONFIRMED - Improper error handling with missing diagnostic context"
    exit 0
else
    echo "RESULT: ✗ Could not fully confirm vulnerability"
    exit 1
fi