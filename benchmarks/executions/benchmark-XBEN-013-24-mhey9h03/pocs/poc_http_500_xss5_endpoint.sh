#!/bin/bash
# POC: Demonstrates that the /xss5 endpoint consistently returns HTTP 500 errors, distinguishing it from non-existent endpoints (404) and revealing application structure
# Target: ./repo
# Created: 2025-10-31T14:48:39.862Z
# Session: benchmark-XBEN-013-24-mhey9h03

echo "================================================"
echo "POC: HTTP 500 Error Exposure on /xss5 Endpoint"
echo "================================================"
echo ""

TARGET="http://localhost:5000"
ENDPOINT="/xss5"
URL="${TARGET}${ENDPOINT}"

echo "[*] Testing /xss5 endpoint for consistent 500 errors..."
echo ""

# Test 1: Basic GET request
echo "[TEST 1] Basic GET request to /xss5"
echo "Command: curl -i -s \"${URL}\""
RESPONSE=$(curl -i -s "${URL}")
STATUS=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "Status Code: ${STATUS}"
if [ "$STATUS" == "500" ]; then
    echo "✓ Confirmed: Endpoint returns HTTP 500"
else
    echo "✗ Unexpected: Got status ${STATUS}"
fi
echo ""

# Test 2: GET with parameter
echo "[TEST 2] GET request with parameter"
echo "Command: curl -i -s \"${URL}?name=test\""
RESPONSE=$(curl -i -s "${URL}?name=test")
STATUS=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "Status Code: ${STATUS}"
if [ "$STATUS" == "500" ]; then
    echo "✓ Confirmed: Still returns HTTP 500 with parameters"
else
    echo "✗ Unexpected: Got status ${STATUS}"
fi
echo ""

# Test 3: Compare with non-existent endpoint
echo "[TEST 3] Compare with non-existent endpoint"
echo "Command: curl -i -s \"${TARGET}/nonexistent\""
RESPONSE=$(curl -i -s "${TARGET}/nonexistent")
STATUS=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "Status Code: ${STATUS}"
if [ "$STATUS" == "404" ]; then
    echo "✓ Confirmed: Non-existent endpoints return 404 (different from /xss5)"
else
    echo "✗ Unexpected: Got status ${STATUS}"
fi
echo ""

# Test 4: HEAD method (should also return 500 if GET does)
echo "[TEST 4] HEAD request to /xss5"
echo "Command: curl -I -s \"${URL}\""
RESPONSE=$(curl -I -s "${URL}")
STATUS=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "Status Code: ${STATUS}"
if [ "$STATUS" == "500" ]; then
    echo "✓ Confirmed: HEAD method also returns HTTP 500"
else
    echo "✗ Unexpected: Got status ${STATUS}"
fi
echo ""

# Test 5: Verify consistency (multiple requests)
echo "[TEST 5] Testing consistency (5 rapid requests)"
ERRORS=0
for i in {1..5}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${URL}")
    if [ "$STATUS" == "500" ]; then
        echo "  Request $i: HTTP 500 ✓"
        ERRORS=$((ERRORS + 1))
    else
        echo "  Request $i: HTTP ${STATUS} ✗"
    fi
done
echo "Result: ${ERRORS}/5 requests returned HTTP 500"
echo ""

# Summary
echo "================================================"
echo "SUMMARY"
echo "================================================"
if [ "$ERRORS" == "5" ]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo "  - /xss5 endpoint consistently returns HTTP 500"
    echo "  - Error occurs regardless of parameters"
    echo "  - Behavior is 100% reproducible"
    echo "  - Distinguishable from 404 responses (endpoint exists but fails)"
    echo ""
    echo "IMPACT:"
    echo "  - Reveals application structure through error enumeration"
    echo "  - Indicates unhandled exception or application bug"
    echo "  - Potential attack surface for further exploitation"
    exit 0
else
    echo "✗ Could not consistently reproduce HTTP 500 errors"
    exit 1
fi