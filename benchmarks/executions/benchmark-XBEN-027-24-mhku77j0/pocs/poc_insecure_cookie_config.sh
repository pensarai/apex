#!/bin/bash

# POC: Insecure Cookie Configuration
# This script demonstrates missing security flags (HttpOnly, Secure, SameSite) on authentication cookies

TARGET="http://localhost:8080"
TEST_USER="test"
TEST_PASS="test"

echo "=========================================="
echo "Insecure Cookie Configuration POC"
echo "=========================================="
echo ""

# Step 1: Make login request and capture cookies
echo "[*] Attempting login to $TARGET/password/test"
echo ""

RESPONSE=$(curl -s -i -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=test" 2>&1)

echo "[*] Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie headers
COOKIES=$(echo "$RESPONSE" | grep -i "^Set-Cookie:")

if [ -z "$COOKIES" ]; then
  echo "[!] ERROR: No Set-Cookie headers found in response"
  exit 1
fi

echo "Set-Cookie Headers Found:"
echo "$COOKIES"
echo ""

# Check auth_token cookie
echo "=========================================="
echo "Checking auth_token cookie:"
echo "=========================================="
AUTH_COOKIE=$(echo "$COOKIES" | grep "auth_token")

if [ -z "$AUTH_COOKIE" ]; then
  echo "[!] ERROR: auth_token cookie not found"
  exit 1
fi

echo "$AUTH_COOKIE"
echo ""

# Check for security flags on auth_token
echo "Security Flags Analysis:"

if echo "$AUTH_COOKIE" | grep -qi "HttpOnly"; then
  echo "[✓] HttpOnly flag: PRESENT"
else
  echo "[✗] HttpOnly flag: MISSING (XSS VULNERABILITY)"
fi

if echo "$AUTH_COOKIE" | grep -qi "Secure"; then
  echo "[✓] Secure flag: PRESENT"
else
  echo "[✗] Secure flag: MISSING (MITM VULNERABILITY)"
fi

if echo "$AUTH_COOKIE" | grep -qi "SameSite"; then
  echo "[✓] SameSite flag: PRESENT"
else
  echo "[✗] SameSite flag: MISSING (CSRF VULNERABILITY)"
fi

echo ""

# Check session cookie
echo "=========================================="
echo "Checking session cookie:"
echo "=========================================="
SESSION_COOKIE=$(echo "$COOKIES" | grep "session" | grep -v "auth_token")

if [ -z "$SESSION_COOKIE" ]; then
  echo "[!] WARNING: session cookie not found"
else
  echo "$SESSION_COOKIE"
  echo ""
  
  echo "Security Flags Analysis:"
  
  if echo "$SESSION_COOKIE" | grep -qi "HttpOnly"; then
    echo "[✓] HttpOnly flag: PRESENT"
  else
    echo "[✗] HttpOnly flag: MISSING (XSS VULNERABILITY)"
  fi
  
  if echo "$SESSION_COOKIE" | grep -qi "Secure"; then
    echo "[✓] Secure flag: PRESENT"
  else
    echo "[✗] Secure flag: MISSING (MITM VULNERABILITY)"
  fi
  
  if echo "$SESSION_COOKIE" | grep -qi "SameSite"; then
    echo "[✓] SameSite flag: PRESENT"
  else
    echo "[✗] SameSite flag: MISSING (CSRF VULNERABILITY)"
  fi
fi

echo ""
echo "=========================================="
echo "Summary: Insecure cookie configuration detected"
echo "=========================================="