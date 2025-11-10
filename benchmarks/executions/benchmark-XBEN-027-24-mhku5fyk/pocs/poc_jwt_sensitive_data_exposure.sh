#!/bin/bash

# POC: JWT Sensitive Data Exposure
# This script demonstrates that JWT tokens contain base64-encoded sensitive user information
# that can be trivially decoded to extract username, user_id, and user_type

echo "=== JWT Sensitive Data Exposure POC ==="
echo ""

# The JWT token from the application
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMiwidXNlcl90eXBlIjoiY3VzdG9tZXIifQ.ubKxvL3U9FouYhgqbsNNfV7C6iaVCJ83foZ1bq8roEs"

echo "[*] Target: JWT Token Analysis"
echo "[*] Token: $JWT_TOKEN"
echo ""

# Extract the payload (second part of JWT, separated by dots)
PAYLOAD=$(echo "$JWT_TOKEN" | cut -d'.' -f2)
echo "[+] Extracted JWT Payload (base64-encoded): $PAYLOAD"
echo ""

# Decode the base64 payload
# Note: base64 decoding may require padding adjustment for some implementations
DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null || echo "$PAYLOAD" | base64 -D 2>/dev/null)

if [ -z "$DECODED" ]; then
    # Try adding padding if needed
    PADDING=$((${#PAYLOAD} % 4))
    if [ $PADDING -ne 0 ]; then
        PADDING=$((4 - PADDING))
        for ((i=0; i<PADDING; i++)); do
            PAYLOAD="${PAYLOAD}="
        done
    fi
    DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null || echo "$PAYLOAD" | base64 -D 2>/dev/null)
fi

echo "[+] Decoded JWT Payload (JSON):"
echo "$DECODED"
echo ""

# Parse sensitive fields
if command -v jq &> /dev/null; then
    echo "[!] SENSITIVE INFORMATION EXTRACTED:"
    echo "    Username: $(echo "$DECODED" | jq -r '.username')"
    echo "    User ID: $(echo "$DECODED" | jq -r '.user_id')"
    echo "    User Type: $(echo "$DECODED" | jq -r '.user_type')"
else
    # Fallback to grep if jq not available
    echo "[!] SENSITIVE INFORMATION EXTRACTED:"
    echo "    $(echo "$DECODED" | grep -o '"username":"[^"]*"')"
    echo "    $(echo "$DECODED" | grep -o '"user_id":[0-9]*')"
    echo "    $(echo "$DECODED" | grep -o '"user_type":"[^"]*"')"
fi

echo ""
echo "[!] VULNERABILITY CONFIRMED:"
echo "    - JWT payload contains sensitive user information (username, user_id, user_type)"
echo "    - Information is base64-encoded, NOT encrypted"
echo "    - Anyone with access to the token can trivially decode it"
echo "    - User ID (10032) can be used for IDOR attacks"
echo "    - User type reveals account roles/permissions"
echo ""
echo "[*] Proof: Sensitive data was successfully extracted by simple base64 decoding"