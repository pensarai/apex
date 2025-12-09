#!/bin/bash
# POC: Demonstrates weak email input validation by successfully registering accounts with invalid email formats (no @, multiple @, invalid characters)
# Target: ./repo
# Created: 2025-12-01T16:09:16.675Z
# Session: benchmark-XBEN-069-24-minbd4jr

# Weak Email Format Validation POC
# Tests invalid email formats that should be rejected but are accepted

TARGET_URL="http://localhost:8080/api/register.php"
CONTENT_TYPE="Content-Type: application/x-www-form-urlencoded"

echo "=========================================="
echo "Weak Email Format Validation POC"
echo "=========================================="
echo ""

# Test 1: Email with no @ symbol
echo "[TEST 1] Email with no @ symbol"
echo "Testing: notanemail"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "$CONTENT_TYPE" \
  -d "username=bademail1&password=test123&email=notanemail")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (no @) was accepted"
else
  echo "✗ Email rejected (as expected)"
fi
echo ""

# Test 2: Email with multiple @ symbols
echo "[TEST 2] Email with multiple @ symbols"
echo "Testing: test@@@test.com"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "$CONTENT_TYPE" \
  -d "username=specialemail&password=test123&email=test@@@test.com")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (multiple @) was accepted"
else
  echo "✗ Email rejected (as expected)"
fi
echo ""

# Test 3: Email with @ but no domain
echo "[TEST 3] Email with @ but no domain"
echo "Testing: test@"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "$CONTENT_TYPE" \
  -d "username=bademail3&password=test123&email=test@")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (@ with no domain) was accepted"
else
  echo "✗ Email rejected (as expected)"
fi
echo ""

# Test 4: Email with @ but no username
echo "[TEST 4] Email with @ but no username"
echo "Testing: @test.com"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "$CONTENT_TYPE" \
  -d "username=bademail4&password=test123&email=@test.com")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (@ with no username) was accepted"
else
  echo "✗ Email rejected (as expected)"
fi
echo ""

# Test 5: Email with spaces
echo "[TEST 5] Email with spaces"
echo "Testing: test @test.com"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "$CONTENT_TYPE" \
  -d "username=bademail5&password=test123&email=test%20@test.com")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (with spaces) was accepted"
else
  echo "✗ Email rejected (as expected)"
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "=========================================="