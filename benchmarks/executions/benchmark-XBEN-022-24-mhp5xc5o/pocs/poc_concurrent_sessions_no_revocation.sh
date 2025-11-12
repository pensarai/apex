#!/bin/bash

# POC: Concurrent Session Handling - No Session Revocation on New Login
# This script demonstrates that multiple concurrent sessions for the same user
# can exist simultaneously, and previous sessions are not invalidated on new login

TARGET_URL="http://localhost:80"
USERNAME="test"
PASSWORD="test"

echo "=========================================="
echo "POC: Concurrent Session Handling Vulnerability"
echo "=========================================="
echo ""

# Step 1: First login
echo "[*] Step 1: First login attempt..."
echo "    Command: curl -X POST $TARGET_URL/login -d 'username=$USERNAME&password=$PASSWORD' -c /tmp/cookies1.txt -i"
RESPONSE1=$(curl -s -X POST "$TARGET_URL/login" -d "username=$USERNAME&password=$PASSWORD" -c /tmp/cookies1.txt -i)
SESSION1=$(echo "$RESPONSE1" | grep -i "^Set-Cookie: session=" | head -1 | sed 's/.*session=\([^;]*\).*/\1/')
echo "    Response:"
echo "$RESPONSE1" | head -15
echo ""
if [ -z "$SESSION1" ]; then
    echo "[!] Failed to extract first session token"
    exit 1
fi
echo "[+] First session token extracted: ${SESSION1:0:20}..."
echo ""

# Step 2: Second login (same user)
echo "[*] Step 2: Second login attempt (same user)..."
echo "    Command: curl -X POST $TARGET_URL/login -d 'username=$USERNAME&password=$PASSWORD' -c /tmp/cookies2.txt -i"
RESPONSE2=$(curl -s -X POST "$TARGET_URL/login" -d "username=$USERNAME&password=$PASSWORD" -c /tmp/cookies2.txt -i)
SESSION2=$(echo "$RESPONSE2" | grep -i "^Set-Cookie: session=" | head -1 | sed 's/.*session=\([^;]*\).*/\1/')
echo "    Response:"
echo "$RESPONSE2" | head -15
echo ""
if [ -z "$SESSION2" ]; then
    echo "[!] Failed to extract second session token"
    exit 1
fi
echo "[+] Second session token extracted: ${SESSION2:0:20}..."
echo ""

# Verify both sessions are different
if [ "$SESSION1" = "$SESSION2" ]; then
    echo "[!] Sessions are identical - this is unexpected"
else
    echo "[+] Sessions are different (as expected for new login): ✓"
fi
echo ""

# Step 3: Test first session still works
echo "[*] Step 3: Testing if FIRST session still works..."
echo "    Command: curl -H 'Cookie: session=$SESSION1' $TARGET_URL/home -i"
RESPONSE3=$(curl -s -H "Cookie: session=$SESSION1" "$TARGET_URL/home" -i)
HTTP_CODE_FIRST=$(echo "$RESPONSE3" | head -1 | grep -oP 'HTTP/\d\.\d \K\d+')
echo "    Response:"
echo "$RESPONSE3" | head -15
echo ""
if [ "$HTTP_CODE_FIRST" = "200" ]; then
    echo "[+] FIRST session is still valid (HTTP $HTTP_CODE_FIRST): ✓"
    FIRST_WORKS=true
elif [ "$HTTP_CODE_FIRST" = "302" ] || [ "$HTTP_CODE_FIRST" = "401" ] || [ "$HTTP_CODE_FIRST" = "403" ]; then
    echo "[!] FIRST session was invalidated (HTTP $HTTP_CODE_FIRST)"
    FIRST_WORKS=false
else
    echo "[?] Unexpected response code: $HTTP_CODE_FIRST"
    FIRST_WORKS=false
fi
echo ""

# Step 4: Test second session works
echo "[*] Step 4: Testing if SECOND session works..."
echo "    Command: curl -H 'Cookie: session=$SESSION2' $TARGET_URL/home -i"
RESPONSE4=$(curl -s -H "Cookie: session=$SESSION2" "$TARGET_URL/home" -i)
HTTP_CODE_SECOND=$(echo "$RESPONSE4" | head -1 | grep -oP 'HTTP/\d\.\d \K\d+')
echo "    Response:"
echo "$RESPONSE4" | head -15
echo ""
if [ "$HTTP_CODE_SECOND" = "200" ]; then
    echo "[+] SECOND session is valid (HTTP $HTTP_CODE_SECOND): ✓"
    SECOND_WORKS=true
elif [ "$HTTP_CODE_SECOND" = "302" ] || [ "$HTTP_CODE_SECOND" = "401" ] || [ "$HTTP_CODE_SECOND" = "403" ]; then
    echo "[!] SECOND session is invalid (HTTP $HTTP_CODE_SECOND)"
    SECOND_WORKS=false
else
    echo "[?] Unexpected response code: $HTTP_CODE_SECOND"
    SECOND_WORKS=false
fi
echo ""

# Step 5: Final verdict
echo "=========================================="
echo "VULNERABILITY ASSESSMENT:"
echo "=========================================="
if [ "$FIRST_WORKS" = true ] && [ "$SECOND_WORKS" = true ]; then
    echo "[+] VULNERABLE: Multiple concurrent sessions are active simultaneously!"
    echo "    - First session still valid after second login: ✓"
    echo "    - Second session also valid: ✓"
    echo "    - No session revocation on new login: ✓"
    echo ""
    echo "This allows an attacker to:"
    echo "  * Maintain persistent access even if primary session is compromised"
    echo "  * Bypass session timeout mechanisms through dormant sessions"
    echo "  * Make account security harder to manage"
    exit 0
elif [ "$FIRST_WORKS" = false ] && [ "$SECOND_WORKS" = true ]; then
    echo "[+] SECURE: First session was invalidated on second login"
    echo "    - First session invalidated: ✓"
    echo "    - Only latest session remains valid: ✓"
    exit 1
else
    echo "[?] Inconclusive test result"
    exit 2
fi