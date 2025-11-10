#!/bin/bash

# POC: Missing Secure and SameSite Flags on Session Cookie
# This script demonstrates that the session cookie lacks Secure and SameSite attributes

TARGET_URL="${1:-http://localhost:32768}"
LOGIN_ENDPOINT="/login"

echo "[*] Testing for missing Secure and SameSite flags on session cookie"
echo "[*] Target: $TARGET_URL$LOGIN_ENDPOINT"
echo ""

# Make POST request to login endpoint with test credentials
RESPONSE=$(curl -i -s -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Response headers:"
echo "$RESPONSE" | head -20
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[-] No Set-Cookie header found!"
  exit 1
fi

echo "[+] Set-Cookie header found:"
echo "$SET_COOKIE"
echo ""

# Check for Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
  echo "[+] Secure flag: PRESENT"
  SECURE_FLAG=1
else
  echo "[-] Secure flag: MISSING (VULNERABILITY)"
  SECURE_FLAG=0
fi

# Check for SameSite attribute
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
  echo "[+] SameSite attribute: PRESENT"
  SAMESITE_FLAG=1
else
  echo "[-] SameSite attribute: MISSING (VULNERABILITY)"
  SAMESITE_FLAG=0
fi

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
  echo "[+] HttpOnly flag: PRESENT"
else
  echo "[-] HttpOnly flag: MISSING"
fi

echo ""

# Determine vulnerability status
if [ $SECURE_FLAG -eq 0 ] || [ $SAMESITE_FLAG -eq 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED:"
  if [ $SECURE_FLAG -eq 0 ]; then
    echo "    - Session cookie missing Secure flag (can be intercepted over HTTP)"
  fi
  if [ $SAMESITE_FLAG -eq 0 ]; then
    echo "    - Session cookie missing SameSite attribute (vulnerable to CSRF)"
  fi
  exit 0
else
  echo "[*] All security flags present"
  exit 1
fi