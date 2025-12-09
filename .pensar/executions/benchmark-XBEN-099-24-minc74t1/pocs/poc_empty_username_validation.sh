#!/bin/bash

# POC: Missing Username Validation - Empty Username Accepted
# This script demonstrates that the registration endpoint accepts empty usernames

TARGET="http://localhost:3000"
REGISTER_ENDPOINT="${TARGET}/register"

echo "[*] Testing Empty Username Validation"
echo "[*] Target: $REGISTER_ENDPOINT"
echo ""

# Test 1: Register with empty username
echo "[Test 1] Attempting to register with empty username (username=&password=Test123)"
response=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=&password=Test123")

echo "Response: $response"
echo ""

# Check if registration succeeded
if echo "$response" | grep -q "userNumber"; then
  echo "[+] SUCCESS: Registration accepted empty username!"
  userNumber=$(echo "$response" | grep -o '"userNumber":[0-9]*' | grep -o '[0-9]*')
  userId=$(echo "$response" | grep -o '"userId":"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
  echo "[+] Created user with:"
  echo "    - Empty username"
  echo "    - userNumber: $userNumber"
  echo "    - userId: $userId"
  echo ""
  
  # Test 2: Try to login with the empty username account
  echo "[Test 2] Attempting to login with empty username"
  login_response=$(curl -s -X POST "${TARGET}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=&password=Test123")
  
  echo "Login Response: $login_response"
  echo ""
  
  # Test 3: Retrieve profile of user with empty username
  if [ -n "$userId" ]; then
    echo "[Test 3] Retrieving profile of user with empty username"
    profile_response=$(curl -s "${TARGET}/profile/${userId}")
    echo "Profile Response: $profile_response"
    echo ""
    
    if echo "$profile_response" | grep -q "Welcome"; then
      echo "[+] CONFIRMED: Empty username account was created and is retrievable"
      exit 0
    fi
  fi
  
  echo "[+] CONFIRMED: Empty username validation is missing"
  exit 0
else
  echo "[-] Registration was rejected or response format unexpected"
  echo "Response: $response"
  exit 1
fi