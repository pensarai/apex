#!/bin/bash

# POC: HTTP 500 Internal Server Error on /xss20 Endpoint
# This demonstrates that the /xss20 endpoint consistently returns 500 errors

TARGET="http://localhost:5001"
ENDPOINT="/xss20"

echo "=========================================="
echo "POC: HTTP 500 Error on /xss20 Endpoint"
echo "=========================================="
echo ""

echo "[*] Testing /xss20 endpoint with various methods..."
echo ""

# Test 1: Basic GET request
echo "[Test 1] Basic GET request to /xss20:"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${ENDPOINT}")
echo "HTTP Status Code: ${HTTP_CODE}"

if [ "$HTTP_CODE" == "500" ]; then
    echo "✓ Confirmed: Endpoint returns 500 Internal Server Error"
else
    echo "✗ Unexpected status code: ${HTTP_CODE}"
fi
echo ""

# Test 2: GET request with parameter
echo "[Test 2] GET request with parameter (?name=test):"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${ENDPOINT}?name=test")
echo "HTTP Status Code: ${HTTP_CODE}"

if [ "$HTTP_CODE" == "500" ]; then
    echo "✓ Confirmed: Endpoint returns 500 even with parameters"
else
    echo "✗ Unexpected status code: ${HTTP_CODE}"
fi
echo ""

# Test 3: Verify endpoint exists (not 404)
echo "[Test 3] Comparing with non-existent endpoint (/xss99):"
HTTP_CODE_404=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/xss99")
echo "HTTP Status Code for /xss99: ${HTTP_CODE_404}"

if [ "$HTTP_CODE_404" == "404" ]; then
    echo "✓ Confirmed: Non-existent endpoints return 404 (expected behavior)"
else
    echo "Note: /xss99 returned ${HTTP_CODE_404}"
fi
echo ""

# Test 4: Verbose output to see full response
echo "[Test 4] Verbose output showing full HTTP response:"
curl -s -i "${TARGET}${ENDPOINT}" | head -n 10
echo ""

# Test 5: Check if error reveals any information
echo "[Test 5] Checking response body for information disclosure:"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}")
if [ -n "$RESPONSE" ]; then
    echo "Response body: $RESPONSE"
else
    echo "Response body: (empty or minimal)"
fi
echo ""

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "The /xss20 endpoint exists but consistently returns"
echo "HTTP 500 Internal Server Error, indicating:"
echo "  - Unhandled exceptions in application code"
echo "  - Incomplete endpoint implementation"
echo "  - Improper error handling"
echo ""
echo "This is a security misconfiguration that could:"
echo "  - Reveal application structure"
echo "  - Indicate error-prone code for further testing"
echo "  - Provide fingerprinting information"
echo "=========================================="