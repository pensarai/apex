#!/bin/bash

# POC: Missing Secure Flag on Session Cookie
# This script demonstrates that the session cookie lacks the Secure flag,
# which could allow transmission over unencrypted HTTP connections

TARGET="http://localhost:3000"
LOGIN_ENDPOINT="/login"

echo "[*] Testing for missing Secure flag on session cookie"
echo "[*] Target: $TARGET$LOGIN_ENDPOINT"
echo ""

# Perform login and capture Set-Cookie headers
echo "[*] Sending login request with valid credentials..."
RESPONSE=$(curl -s -v -X POST "${TARGET}${LOGIN_ENDPOINT}" \
  -d "username=sessiontester&password=Test123456" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^< Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[!] ERROR: No Set-Cookie header found in response"
  exit 1
fi

echo "[+] Found Set-Cookie header:"
echo "    $SET_COOKIE"
echo ""

# Check for Secure flag
SECURE_PRESENT=0
if echo "$SET_COOKIE" | grep -qi "Secure"; then
  echo "[+] Secure flag is PRESENT"
  SECURE_PRESENT=1
else
  echo "[-] VULNERABILITY CONFIRMED: Secure flag is MISSING"
  SECURE_PRESENT=0
fi

# Check for HttpOnly flag (should be present)
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
  echo "[+] HttpOnly flag is present"
else
  echo "[-] WARNING: HttpOnly flag is also missing"
fi

# Check for SameSite attribute (for completeness)
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
  echo "[+] SameSite attribute is present"
else
  echo "[-] WARNING: SameSite attribute is missing"
fi

echo ""
echo "[*] VULNERABILITY ANALYSIS:"
if [ $SECURE_PRESENT -eq 0 ]; then
  echo "    - Secure flag: NOT PRESENT ✗"
  echo "    - Cookie transmission: Allows HTTP (unencrypted)"
  echo "    - Risk: Session hijacking via network interception"
  echo "    - Remediation: Add Secure flag to session cookie configuration"
  echo ""
  echo "[*] POC RESULT: VULNERABILITY CONFIRMED"
  exit 0
else
  echo "    - Secure flag: PRESENT ✓"
  echo "    - No vulnerability detected"
  exit 1
fi