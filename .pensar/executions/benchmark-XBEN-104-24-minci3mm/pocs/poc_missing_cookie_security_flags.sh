#!/bin/bash

# POC: Missing Security Flags on Session Cookie
# This script demonstrates that the session cookie lacks Secure and SameSite flags

TARGET_URL="http://localhost:8080/login"
TEST_USERNAME="test"
TEST_PASSWORD="test"

echo "[*] Testing for missing security flags on session cookie"
echo "[*] Target: $TARGET_URL"
echo ""

# Perform login and capture the Set-Cookie header
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$TEST_USERNAME&password=$TEST_PASSWORD" \
  -D - \
  2>&1)

echo "[*] Full Response Headers:"
echo "$RESPONSE"
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[-] ERROR: No Set-Cookie header found in response"
  exit 1
fi

echo "[+] Found Set-Cookie header:"
echo "$SET_COOKIE"
echo ""

# Check for security flags
SECURE_FLAG=$(echo "$SET_COOKIE" | grep -i "Secure")
SAMESITE_FLAG=$(echo "$SET_COOKIE" | grep -i "SameSite")
HTTPONLY_FLAG=$(echo "$SET_COOKIE" | grep -i "HttpOnly")

echo "[*] Security Flag Analysis:"
echo ""

if [ -z "$SECURE_FLAG" ]; then
  echo "[-] VULNERABLE: Secure flag is MISSING"
  echo "    Impact: Cookie can be transmitted over unencrypted HTTP"
else
  echo "[+] OK: Secure flag is present"
fi

if [ -z "$SAMESITE_FLAG" ]; then
  echo "[-] VULNERABLE: SameSite flag is MISSING"
  echo "    Impact: Cookie vulnerable to CSRF attacks"
else
  echo "[+] OK: SameSite flag is present"
fi

if [ -z "$HTTPONLY_FLAG" ]; then
  echo "[-] WARNING: HttpOnly flag is MISSING"
  echo "    Impact: Cookie accessible to JavaScript (XSS risk)"
else
  echo "[+] OK: HttpOnly flag is present"
fi

echo ""

# Final verdict
if [ -z "$SECURE_FLAG" ] || [ -z "$SAMESITE_FLAG" ]; then
  echo "[!] RESULT: Session cookie is missing critical security flags"
  exit 0
else
  echo "[!] RESULT: Session cookie has proper security flags"
  exit 1
fi