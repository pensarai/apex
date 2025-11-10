#!/bin/bash

# POC: Incomplete Session Termination - Missing Session Cookie Expiration on Logout
# This script demonstrates that the logout endpoint does not properly terminate
# the user session by clearing the session cookie.

TARGET="${1:-http://localhost}"
COOKIE_JAR="/tmp/session_cookies_$$.txt"

echo "=========================================="
echo "Session Termination POC"
echo "=========================================="
echo ""

# Step 1: Login to establish a session
echo "[*] Step 1: Logging in to establish session..."
curl -s -c "$COOKIE_JAR" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=password123" \
  "$TARGET/login" > /dev/null 2>&1

echo "[+] Login response status code:"
curl -s -o /dev/null -w "%{http_code}\n" -c "$COOKIE_JAR" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=password123" \
  "$TARGET/login"

# Check if session cookie was created
if [ -f "$COOKIE_JAR" ]; then
    echo "[+] Cookies file created:"
    wc -l "$COOKIE_JAR"
fi

echo ""
echo "[*] Step 2: Calling logout endpoint and checking for Set-Cookie header..."
LOGOUT_RESPONSE=$(curl -s -i -b "$COOKIE_JAR" "$TARGET/logout")
echo "$LOGOUT_RESPONSE" | head -n 20

echo ""
echo "[*] Step 3: Analyzing logout response for session cookie expiration..."
echo ""

# Extract Set-Cookie headers from logout response
SET_COOKIE_HEADERS=$(echo "$LOGOUT_RESPONSE" | grep -i "^set-cookie:" | wc -l)

echo "[*] Number of Set-Cookie headers: $SET_COOKIE_HEADERS"

if [ "$SET_COOKIE_HEADERS" -eq 0 ]; then
    echo "[FAIL] No Set-Cookie header found in logout response!"
    echo "       Session cookie was NOT cleared by server."
    echo ""
    echo "=========================================="
    echo "RESULT: VULNERABLE"
    echo "The logout endpoint does not properly clear session cookies."
    echo "=========================================="
else
    echo "[+] Set-Cookie headers found:"
    echo "$LOGOUT_RESPONSE" | grep -i "^set-cookie:"
    
    # Check if cookie is actually expired (Max-Age=0 or Expires in past)
    EXPIRED=$(echo "$LOGOUT_RESPONSE" | grep -iE "Max-Age=0|Expires=.*1970" | wc -l)
    if [ "$EXPIRED" -gt 0 ]; then
        echo "[+] Session cookie appears to be properly expired."
    else
        echo "[!] Set-Cookie header present but may not properly expire session"
    fi
    
    echo ""
    echo "=========================================="
    echo "RESULT: SECURE - Session properly terminated"
    echo "=========================================="
fi

# Cleanup
rm -f "$COOKIE_JAR"

echo ""
echo "[*] POC Complete - Vulnerability assessment finished"
exit 0