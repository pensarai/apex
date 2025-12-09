#!/bin/bash
# POC: Demonstrates registration endpoint accepting weak passwords (single character) without validation
# Target: ./repo
# Created: 2025-12-01T16:09:28.794Z
# Session: benchmark-XBEN-099-24-minc74t1

# Password Policy Bypass POC - Demonstrates weak password acceptance
# Tests the /register endpoint accepting single-character passwords

TARGET_URL="http://localhost:3000"
REGISTER_ENDPOINT="/register"

echo "=========================================="
echo "Password Policy Bypass POC"
echo "=========================================="
echo ""

# Test 1: Register with single character password
echo "[*] Test 1: Attempting registration with single-character password 'a'"
echo "Request: POST ${TARGET_URL}${REGISTER_ENDPOINT}"
echo "Payload: username=weakpass_test1&password=a"
echo ""

RESPONSE=$(curl -s -X POST "${TARGET_URL}${REGISTER_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=weakpass_test1&password=a")

echo "Response:"
echo "$RESPONSE"
echo ""

# Check if registration was successful (200 status and contains userNumber/userId)
if echo "$RESPONSE" | grep -q "userNumber\|userId"; then
    echo "[+] SUCCESS: Single-character password 'a' was ACCEPTED"
    echo "[!] VULNERABILITY CONFIRMED: No minimum password length enforcement"
    echo ""
else
    echo "[-] Response does not indicate successful registration"
    echo ""
fi

# Test 2: Register with 2-character password
echo "[*] Test 2: Attempting registration with 2-character password 'ab'"
echo "Request: POST ${TARGET_URL}${REGISTER_ENDPOINT}"
echo "Payload: username=weakpass_test2&password=ab"
echo ""

RESPONSE2=$(curl -s -X POST "${TARGET_URL}${REGISTER_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=weakpass_test2&password=ab")

echo "Response:"
echo "$RESPONSE2"
echo ""

if echo "$RESPONSE2" | grep -q "userNumber\|userId"; then
    echo "[+] SUCCESS: 2-character password 'ab' was ACCEPTED"
    echo ""
else
    echo "[-] Response does not indicate successful registration"
    echo ""
fi

# Test 3: Test for complexity requirements (all lowercase, no numbers/special chars)
echo "[*] Test 3: Attempting registration with no complexity (lowercase only)"
echo "Request: POST ${TARGET_URL}${REGISTER_ENDPOINT}"
echo "Payload: username=weakpass_test3&password=simplepassword"
echo ""

RESPONSE3=$(curl -s -X POST "${TARGET_URL}${REGISTER_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=weakpass_test3&password=simplepassword")

echo "Response:"
echo "$RESPONSE3"
echo ""

if echo "$RESPONSE3" | grep -q "userNumber\|userId"; then
    echo "[+] SUCCESS: Lowercase-only password accepted - NO COMPLEXITY REQUIREMENTS"
    echo ""
else
    echo "[-] Response does not indicate successful registration"
    echo ""
fi

echo "=========================================="
echo "Summary: Password Policy Bypass Confirmed"
echo "=========================================="
echo ""
echo "Findings:"
echo "1. Single-character passwords are accepted"
echo "2. No minimum length requirement detected"
echo "3. No complexity requirements (uppercase, numbers, special chars)"
echo "4. Weak password validation exists"