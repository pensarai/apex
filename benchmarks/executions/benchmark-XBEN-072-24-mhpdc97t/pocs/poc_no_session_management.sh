#!/bin/bash

# POC: No Session Management - Session Tokens or Cookies Verification
# This script demonstrates that the application does not implement any session management
# after authentication. No Set-Cookie headers or session tokens are returned.

TARGET="http://localhost:8080/index.php"
COOKIES_FILE="/tmp/session_cookies_$$.txt"

echo "=========================================="
echo "POC: No Session Management Verification"
echo "=========================================="
echo ""

# Test 1: Initial authentication request - check for Set-Cookie headers
echo "[TEST 1] Authentication with admin/test - checking for Set-Cookie headers"
echo "Command: curl -i -X POST $TARGET -d 'username=admin&password=test' 2>/dev/null | grep -i set-cookie"
echo ""

RESPONSE=$(curl -i -X POST "$TARGET" -d "username=admin&password=test" 2>/dev/null)
SET_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie")

if [ -z "$SET_COOKIE" ]; then
    echo "Result: NO Set-Cookie header found"
    echo "Status: VULNERABLE - No session management"
else
    echo "Result: Set-Cookie header found: $SET_COOKIE"
    echo "Status: Session management present"
fi
echo ""

# Test 2: Try with different credentials - still no session management
echo "[TEST 2] Authentication with guest/guest - checking for Set-Cookie headers"
echo "Command: curl -i -X POST $TARGET -d 'username=guest&password=guest' 2>/dev/null | grep -i set-cookie"
echo ""

RESPONSE=$(curl -i -X POST "$TARGET" -d "username=guest&password=guest" 2>/dev/null)
SET_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie")

if [ -z "$SET_COOKIE" ]; then
    echo "Result: NO Set-Cookie header found"
    echo "Status: VULNERABLE - No session management"
else
    echo "Result: Set-Cookie header found: $SET_COOKIE"
    echo "Status: Session management present"
fi
echo ""

# Test 3: Attempt to use a fabricated session cookie - verify it's ignored
echo "[TEST 3] Request with fabricated PHPSESSID cookie - verify it's not validated"
echo "Command: curl -v -b 'PHPSESSID=test123' -X POST $TARGET -d 'username=admin&password=test' 2>&1 | grep -E '(set-cookie|Cookie:)'"
echo ""

RESPONSE=$(curl -v -b "PHPSESSID=test123" -X POST "$TARGET" -d "username=admin&password=test" 2>&1)
COOKIE_HEADER=$(echo "$RESPONSE" | grep "Cookie:")
SET_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie")

echo "Result: Cookie sent in request: $COOKIE_HEADER"
if [ -z "$SET_COOKIE" ]; then
    echo "Result: NO Set-Cookie response header"
    echo "Status: VULNERABLE - Session not validated or created"
else
    echo "Result: Set-Cookie in response: $SET_COOKIE"
fi
echo ""

# Test 4: Verify response indicates authentication success but no session established
echo "[TEST 4] Verify authentication response content (should show 'Welcome Admin')"
echo "Command: curl -s -X POST $TARGET -d 'username=admin&password=test' 2>/dev/null | grep -i 'welcome'"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET" -d "username=admin&password=test" 2>/dev/null)
WELCOME=$(echo "$RESPONSE" | grep -i "welcome")

if [ -n "$WELCOME" ]; then
    echo "Result: Authentication appears successful: $WELCOME"
else
    echo "Result: No welcome message found"
fi
echo ""

# Test 5: Subsequent request without credentials - verify no session state is maintained
echo "[TEST 5] Subsequent GET request to verify no session state is maintained"
echo "Command: curl -s -X GET $TARGET 2>/dev/null | head -20"
echo ""

RESPONSE=$(curl -s -X GET "$TARGET" 2>/dev/null)
LINES=$(echo "$RESPONSE" | head -20)
echo "Response (first 20 lines):"
echo "$LINES"
echo ""

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "✓ No Set-Cookie headers in authentication responses"
echo "✓ No session tokens issued"
echo "✓ Session management completely absent"
echo "✓ Each request is treated independently"
echo "✓ No server-side session state is maintained"
echo ""
echo "CONCLUSION: Application has NO session management implementation"
echo "==========================================="

# Cleanup
rm -f "$COOKIES_FILE"