#!/bin/bash

# POC: Improper HTTP Method Validation on about.php
# This script tests whether the application properly validates HTTP methods

TARGET="http://localhost:3000/about.php"
echo "=== Testing HTTP Method Validation on $TARGET ==="
echo ""

# Test standard methods that should work
echo "[*] Testing GET method (should return 200):"
GET_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET")
echo "    GET response: HTTP $GET_RESPONSE"
echo ""

# Test methods that should be rejected with 405
echo "[*] Testing PUT method (should return 405 Method Not Allowed):"
PUT_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$TARGET")
echo "    PUT response: HTTP $PUT_RESPONSE"
if [ "$PUT_RESPONSE" = "200" ]; then
    echo "    ❌ VULNERABLE: PUT method accepted (should be 405)"
else
    echo "    ✓ PUT method properly rejected"
fi
echo ""

echo "[*] Testing DELETE method (should return 405 Method Not Allowed):"
DELETE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$TARGET")
echo "    DELETE response: HTTP $DELETE_RESPONSE"
if [ "$DELETE_RESPONSE" = "200" ]; then
    echo "    ❌ VULNERABLE: DELETE method accepted (should be 405)"
else
    echo "    ✓ DELETE method properly rejected"
fi
echo ""

echo "[*] Testing PATCH method (should return 405 Method Not Allowed):"
PATCH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X PATCH "$TARGET")
echo "    PATCH response: HTTP $PATCH_RESPONSE"
if [ "$PATCH_RESPONSE" = "200" ]; then
    echo "    ❌ VULNERABLE: PATCH method accepted (should be 405)"
else
    echo "    ✓ PATCH method properly rejected"
fi
echo ""

echo "[*] Testing OPTIONS method:"
OPTIONS_RESPONSE=$(curl -s -w "\nHTTP Code: %{http_code}\n" -X OPTIONS "$TARGET" -i | head -n 20)
echo "$OPTIONS_RESPONSE"
echo ""

# Summary
echo "=== SUMMARY ==="
VULN_COUNT=0
if [ "$PUT_RESPONSE" = "200" ]; then
    ((VULN_COUNT++))
fi
if [ "$DELETE_RESPONSE" = "200" ]; then
    ((VULN_COUNT++))
fi
if [ "$PATCH_RESPONSE" = "200" ]; then
    ((VULN_COUNT++))
fi

if [ $VULN_COUNT -gt 0 ]; then
    echo "❌ VULNERABLE: Application accepts $VULN_COUNT unexpected HTTP method(s)"
    echo "The application should return HTTP 405 (Method Not Allowed) for unsupported methods"
    exit 0
else
    echo "✓ HTTP methods are properly validated"
    exit 1
fi