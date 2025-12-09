#!/bin/bash

# POC: Missing Security Attributes on Session Cookie (Secure and SameSite Flags)
# This script demonstrates that the session cookie lacks Secure and SameSite flags

TARGET_URL="${1:-http://localhost:5003}"
LOGIN_ENDPOINT="/login"

echo "========================================"
echo "POC: Missing Cookie Security Attributes"
echo "========================================"
echo ""
echo "Target: $TARGET_URL"
echo ""

# Perform login and capture Set-Cookie headers
echo "[*] Sending login request with default credentials (user/user)..."
echo ""

RESPONSE=$(curl -s -i -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -d "username=user&password=user" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

# Extract Set-Cookie header
SET_COOKIE_HEADER=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

echo "[+] Response Set-Cookie header received:"
echo "$SET_COOKIE_HEADER"
echo ""

# Check for required security flags
echo "[*] Analyzing cookie security attributes..."
echo ""

HAS_SECURE=$(echo "$SET_COOKIE_HEADER" | grep -i "Secure")
HAS_SAMESITE=$(echo "$SET_COOKIE_HEADER" | grep -i "SameSite")
HAS_HTTPONLY=$(echo "$SET_COOKIE_HEADER" | grep -i "HttpOnly")

echo "Security Attribute Analysis:"
echo "================================"

if [ -n "$HAS_HTTPONLY" ]; then
  echo "✓ HttpOnly flag: PRESENT (protects against JavaScript access)"
else
  echo "✗ HttpOnly flag: MISSING (vulnerable to JavaScript XSS attacks)"
fi

if [ -n "$HAS_SECURE" ]; then
  echo "✓ Secure flag: PRESENT (forces HTTPS transmission)"
else
  echo "✗ Secure flag: MISSING (vulnerability - allows HTTP transmission)"
fi

if [ -n "$HAS_SAMESITE" ]; then
  echo "✓ SameSite attribute: PRESENT (provides CSRF protection)"
else
  echo "✗ SameSite attribute: MISSING (vulnerability - no CSRF cookie protection)"
fi

echo ""
echo "================================"
echo ""

# Determine vulnerability status
if [ -z "$HAS_SECURE" ] && [ -z "$HAS_SAMESITE" ]; then
  echo "[!] VULNERABILITY CONFIRMED:"
  echo "    - Missing Secure flag: Session cookies can be transmitted over HTTP"
  echo "    - Missing SameSite attribute: No CSRF protection via cookie policy"
  echo ""
  exit 0
elif [ -z "$HAS_SECURE" ]; then
  echo "[!] VULNERABILITY CONFIRMED:"
  echo "    - Missing Secure flag: Session cookies can be transmitted over HTTP"
  echo ""
  exit 0
elif [ -z "$HAS_SAMESITE" ]; then
  echo "[!] VULNERABILITY CONFIRMED:"
  echo "    - Missing SameSite attribute: No CSRF protection via cookie policy"
  echo ""
  exit 0
else
  echo "[+] Both Secure and SameSite flags are present. No vulnerability detected."
  echo ""
  exit 1
fi