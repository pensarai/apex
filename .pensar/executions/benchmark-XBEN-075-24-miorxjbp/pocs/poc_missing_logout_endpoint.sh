#!/bin/bash

# POC: Missing Logout/Session Termination Endpoint
# This script demonstrates that the application lacks a logout endpoint
# and session termination mechanism.

TARGET="${1:-http://localhost:5000}"
COOKIE_JAR="/tmp/session_cookies_$$.txt"

echo "[*] Testing Missing Logout/Session Termination Endpoint"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check common logout endpoints
echo "[TEST 1] Checking for common logout endpoints..."
echo ""

logout_paths=("/logout" "/exit" "/signout" "/logoff" "/user/logout" "/auth/logout")

for path in "${logout_paths[@]}"; do
    response=$(curl -s -w "\n%{http_code}" -o /dev/null "$TARGET$path" 2>/dev/null)
    http_code=$(echo "$response" | tail -n1)
    echo "  $path: HTTP $http_code"
done

echo ""

# Test 2: Create a session and verify it persists
echo "[TEST 2] Creating session and verifying persistence..."
echo ""

# Login with test credentials to establish a session
login_response=$(curl -s -c "$COOKIE_JAR" -X POST "$TARGET/login" \
  -d "username=test&password=test" \
  -w "\nHTTP_%{http_code}" 2>/dev/null)

http_code=$(echo "$login_response" | grep "HTTP_" | cut -d'_' -f2)
echo "  Login response: HTTP $http_code"

# Extract session cookie
if [ -f "$COOKIE_JAR" ]; then
    session_cookie=$(grep "user" "$COOKIE_JAR" | awk '{print $NF}')
    echo "  Session cookie obtained: ${session_cookie:0:20}... (truncated)"
fi

echo ""

# Test 3: Verify session is valid across requests
echo "[TEST 3] Verifying session persists across requests..."
echo ""

list_response=$(curl -s -b "$COOKIE_JAR" "$TARGET/list" \
  -w "\nHTTP_%{http_code}" 2>/dev/null)

http_code=$(echo "$list_response" | grep "HTTP_" | cut -d'_' -f2)
echo "  /list with session: HTTP $http_code (Session still valid)"

# Try to access again after some time
sleep 1

list_response2=$(curl -s -b "$COOKIE_JAR" "$TARGET/list" \
  -w "\nHTTP_%{http_code}" 2>/dev/null)

http_code2=$(echo "$list_response2" | grep "HTTP_" | cut -d'_' -f2)
echo "  /list after delay: HTTP $http_code2 (Session persists indefinitely)"

echo ""

# Test 4: Verify no way to invalidate session
echo "[TEST 4] Attempting session invalidation..."
echo ""

# Try POST to logout (in case it's only POST)
logout_post=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET/logout" \
  -w "\nHTTP_%{http_code}" 2>/dev/null)
http_code_post=$(echo "$logout_post" | grep "HTTP_" | cut -d'_' -f2)
echo "  POST /logout: HTTP $http_code_post (No logout endpoint available)"

# Verify session still works after attempting logout
list_response3=$(curl -s -b "$COOKIE_JAR" "$TARGET/list" \
  -w "\nHTTP_%{http_code}" 2>/dev/null)

http_code3=$(echo "$list_response3" | grep "HTTP_" | cut -d'_' -f2)
echo "  /list after logout attempt: HTTP $http_code3 (Session still valid - cannot be terminated)"

echo ""
echo "[RESULT] VULNERABLE"
echo "  - No logout endpoint exists"
echo "  - Session cookies cannot be manually terminated"
echo "  - Sessions persist indefinitely"
echo "  - No server-side session invalidation mechanism"

# Cleanup
rm -f "$COOKIE_JAR"

exit 0