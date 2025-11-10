#!/bin/bash

# POC: JWT Tokens Missing Expiration Claim
# This script demonstrates that the application's JWT tokens lack an 'exp' claim
# making them valid indefinitely

TARGET_URL="${1:-http://localhost:8080}"

echo "=== JWT Missing Expiration Claim POC ==="
echo ""

# Step 1: Get password reset form for test user
echo "[*] Step 1: Requesting password form for test user..."
RESPONSE=$(curl -s -D /tmp/response_headers.txt -c /tmp/cookies.txt \
  -X GET "${TARGET_URL}/password/test")

# Extract user_id from form
USER_ID=$(echo "$RESPONSE" | grep -oP 'value="\K[0-9]+(?=")' | head -1)

if [ -z "$USER_ID" ]; then
  echo "[-] Failed to extract user_id from password form"
  exit 1
fi

echo "[+] User ID obtained: $USER_ID"
echo ""

# Step 2: Submit password reset (this generates JWT token)
echo "[*] Step 2: Submitting password reset form..."
RESPONSE=$(curl -s -D /tmp/response_headers2.txt -c /tmp/cookies_final.txt -b /tmp/cookies.txt \
  -X POST "${TARGET_URL}/password/test" \
  -d "username=test&password=test&user_id=${USER_ID}")

# Extract JWT token from Set-Cookie header
JWT_TOKEN=$(grep -i "Set-Cookie: auth_token=" /tmp/response_headers2.txt | grep -oP 'auth_token=\K[^;]+' | head -1)

if [ -z "$JWT_TOKEN" ]; then
  # Try extracting from cookies file
  JWT_TOKEN=$(grep "auth_token" /tmp/cookies_final.txt | grep -oP '\t\K[^\s]+$')
fi

if [ -z "$JWT_TOKEN" ]; then
  echo "[-] Failed to extract JWT token"
  echo "Response headers:"
  cat /tmp/response_headers2.txt
  exit 1
fi

echo "[+] JWT Token obtained: ${JWT_TOKEN:0:50}..."
echo ""

# Step 3: Decode JWT payload (JWT format: header.payload.signature)
echo "[*] Step 3: Decoding JWT payload..."
echo ""

# Extract payload (second part)
PAYLOAD=$(echo "$JWT_TOKEN" | cut -d'.' -f2)

# Add padding if needed
PADDING=$((4 - ${#PAYLOAD} % 4))
if [ $PADDING -ne 4 ]; then
  PAYLOAD="${PAYLOAD}$(printf '%0.s=' $(seq 1 $PADDING))"
fi

# Decode base64
DECODED_PAYLOAD=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)

if [ $? -ne 0 ]; then
  echo "[-] Failed to decode JWT payload"
  exit 1
fi

echo "Decoded JWT Payload:"
echo "$DECODED_PAYLOAD" | jq . 2>/dev/null || echo "$DECODED_PAYLOAD"
echo ""

# Step 4: Check for expiration claims
echo "[*] Step 4: Checking for expiration claims..."
echo ""

HAS_EXP=$(echo "$DECODED_PAYLOAD" | jq 'has("exp")' 2>/dev/null)
HAS_IAT=$(echo "$DECODED_PAYLOAD" | jq 'has("iat")' 2>/dev/null)

echo "Has 'exp' (expiration) claim: $HAS_EXP"
echo "Has 'iat' (issued at) claim: $HAS_IAT"
echo ""

# Step 5: Vulnerability Assessment
echo "[*] Step 5: Vulnerability Assessment..."
echo ""

if [ "$HAS_EXP" = "false" ]; then
  echo "[!] VULNERABILITY CONFIRMED: JWT token is missing 'exp' claim"
  echo "[!] Impact: Token will be valid indefinitely"
  echo "[!] Risk: An attacker who steals this token can use it forever"
  echo ""
  echo "[+] POC SUCCESS: Missing expiration claim vulnerability demonstrated"
  exit 0
else
  echo "[-] JWT token has 'exp' claim, vulnerability not present"
  exit 1
fi