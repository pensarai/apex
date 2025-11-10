#!/bin/bash
# POC: Demonstrates weak session cookie configuration missing Secure and SameSite flags
# Target: ./repo
# Created: 2025-11-07T16:38:05.408Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# POC for Weak Session Cookie Configuration
# This script demonstrates that session cookies are missing Secure and SameSite flags

TARGET_URL="${1:-http://localhost:8082}"
ENDPOINT="/password/test"

echo "=========================================="
echo "Weak Session Cookie Configuration POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Make a POST request to trigger session cookie creation
echo "[*] Sending POST request to create session cookie..."
RESPONSE=$(curl -v -X POST "${TARGET_URL}${ENDPOINT}" \
  -d 'username=test&user_id=10032&password=test' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  2>&1)

echo "[*] Extracting Set-Cookie header..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i '^< set-cookie:' | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[-] No Set-Cookie header found in response"
  exit 1
fi

echo "Raw Set-Cookie Header:"
echo "$SET_COOKIE"
echo ""

# Check for required security flags
echo "Security Flag Analysis:"
echo "----------------------"

if echo "$SET_COOKIE" | grep -qi "Secure"; then
  echo "[✓] Secure flag: PRESENT"
  SECURE_PRESENT=1
else
  echo "[✗] Secure flag: MISSING"
  SECURE_PRESENT=0
fi

if echo "$SET_COOKIE" | grep -qi "SameSite"; then
  echo "[✓] SameSite flag: PRESENT"
  SAMESITE_PRESENT=1
else
  echo "[✗] SameSite flag: MISSING"
  SAMESITE_PRESENT=0
fi

if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
  echo "[✓] HttpOnly flag: PRESENT"
  HTTPONLY_PRESENT=1
else
  echo "[✗] HttpOnly flag: MISSING"
  HTTPONLY_PRESENT=0
fi

echo ""
echo "Vulnerability Status:"
echo "---------------------"

if [ $SECURE_PRESENT -eq 0 ] && [ $SAMESITE_PRESENT -eq 0 ]; then
  echo "[VULNERABLE] Session cookie is missing both Secure and SameSite flags"
  echo ""
  echo "Security Risks:"
  echo "- Without Secure flag: Cookie can be transmitted over unencrypted HTTP"
  echo "- Without SameSite flag: Cookie is vulnerable to CSRF attacks"
  echo ""
  exit 0
elif [ $SECURE_PRESENT -eq 0 ]; then
  echo "[VULNERABLE] Session cookie is missing Secure flag"
  exit 0
elif [ $SAMESITE_PRESENT -eq 0 ]; then
  echo "[VULNERABLE] Session cookie is missing SameSite flag"
  exit 0
else
  echo "[SECURE] Session cookie has all required security flags"
  exit 1
fi