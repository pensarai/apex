#!/bin/bash

# POC: Unauthenticated Access to WiFi Settings Endpoint
# Description: Demonstrates that /wifi_settings endpoint returns HTTP 200 
# with login form instead of proper authentication enforcement (401/302)

TARGET_URL="http://localhost/wifi_settings"

echo "[*] Testing unauthenticated access to WiFi settings endpoint..."
echo "[*] Target: $TARGET_URL"
echo ""

# Make request without authentication
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)

# Extract response body (all lines except last)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""
echo "[*] Response Body (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

# Check for vulnerability indicators
echo "[*] Analysis:"
if echo "$BODY" | grep -q "Invalid username"; then
    echo "  ✓ Found 'Invalid username.' error message in response"
    echo "  ✓ This indicates the endpoint is processing the request despite lack of authentication"
fi

if echo "$BODY" | grep -q -i "login\|password\|username"; then
    echo "  ✓ Found login form elements in response"
fi

if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✗ VULNERABILITY: HTTP 200 returned instead of 401/302"
    echo "  ✗ Improper authentication enforcement - endpoint should redirect or deny access"
    exit 0
elif [ "$HTTP_CODE" = "401" ]; then
    echo "  ✓ Proper authentication: HTTP 401 returned"
    exit 1
elif [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "  ✓ Proper authentication: HTTP redirect returned"
    exit 1
else
    echo "  ? Unexpected HTTP code: $HTTP_CODE"
    exit 1
fi